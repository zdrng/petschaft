//! Protocol state machine tests against a fake helper over in-memory pipes, plus a few
//! tests that spawn a real Python interpreter running a fake helper script.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::collections::VecDeque;
use std::io::{PipeReader, PipeWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use petschaft_core::{Config, Curve, Fingerprint, Slip13Identity, Transport};
use petschaft_helper_proto::{
    self as proto, DeviceInfo, ErrorCode, ErrorResponse, Event, EventKind, HelperMessage,
    HostMessage, Ready, Signed,
};
use proptest::prelude::*;

use crate::helper::{HelperProcess, Timeouts, resolve_path};
use crate::*;

// ---------------------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------------------

#[derive(Default, Debug)]
struct ProcState {
    killed: bool,
    shut_down: bool,
}

struct FakeProc(Arc<Mutex<ProcState>>);

impl HelperProcess for FakeProc {
    fn kill(&mut self) {
        self.0.lock().unwrap().killed = true;
    }
    fn shutdown(&mut self, _grace: Duration) {
        self.0.lock().unwrap().shut_down = true;
    }
}

#[derive(Default)]
struct TestUi {
    confirms: AtomicUsize,
    pairing_calls: AtomicUsize,
    codes: Mutex<VecDeque<Result<String, Error>>>,
}

impl TestUi {
    fn with_code(code: &str) -> Self {
        let ui = TestUi::default();
        ui.codes.lock().unwrap().push_back(Ok(code.to_owned()));
        ui
    }
    fn confirms(&self) -> usize {
        self.confirms.load(Ordering::SeqCst)
    }
    fn pairing_calls(&self) -> usize {
        self.pairing_calls.load(Ordering::SeqCst)
    }
}

impl Ui for TestUi {
    fn confirm_on_device(&self) {
        self.confirms.fetch_add(1, Ordering::SeqCst);
    }
    fn pairing_code(&self) -> Result<String, Error> {
        self.pairing_calls.fetch_add(1, Ordering::SeqCst);
        self.codes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(Error::Cancelled))
    }
}

/// In-memory store; can be told to fail.
#[derive(Default)]
struct MemStore {
    slot: Mutex<Option<Credential>>,
    fail_load: Option<StoreError>,
    fail_store: Option<StoreError>,
    stores: AtomicUsize,
}

impl MemStore {
    fn with(c: Credential) -> Self {
        let s = MemStore::default();
        *s.slot.lock().unwrap() = Some(c);
        s
    }
    fn get(&self) -> Option<Credential> {
        self.slot.lock().unwrap().clone()
    }
}

impl CredentialStore for MemStore {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        match &self.fail_load {
            Some(e) => Err(e.clone()),
            None => Ok(self.get()),
        }
    }
    fn store(&self, c: &Credential) -> Result<(), StoreError> {
        self.stores.fetch_add(1, Ordering::SeqCst);
        match &self.fail_store {
            Some(e) => Err(e.clone()),
            None => {
                *self.slot.lock().unwrap() = Some(c.clone());
                Ok(())
            }
        }
    }
    fn delete(&self) -> Result<(), StoreError> {
        *self.slot.lock().unwrap() = None;
        Ok(())
    }
}

/// The helper side of the pipes.
struct Fake {
    rx: PipeReader,
    tx: PipeWriter,
}

impl Fake {
    /// Next host message; `None` on EOF (host closed stdin / killed us).
    fn recv(&mut self) -> Option<HostMessage> {
        proto::read_host_message(&mut self.rx).unwrap()
    }
    fn send(&mut self, m: HelperMessage) {
        // Ignore EPIPE: the host may already have given up on us.
        let _ = proto::write_helper_message(&mut self.tx, &m);
    }
    fn raw(&mut self, bytes: &[u8]) {
        let _ = self.tx.write_all(bytes);
        let _ = self.tx.flush();
    }
    fn button(&mut self) {
        self.send(HelperMessage::Event(Event {
            event: EventKind::Button,
        }));
    }
    fn expect_hello(&mut self) -> proto::Hello {
        match self.recv() {
            Some(HostMessage::Hello(h)) => h,
            other => panic!("expected hello, got {other:?}"),
        }
    }
    fn expect_sign(&mut self) -> proto::SignIdentity {
        match self.recv() {
            Some(HostMessage::SignIdentity(s)) => s,
            other => panic!("expected sign_identity, got {other:?}"),
        }
    }
    fn ready(&mut self, credential: Option<Credential>) {
        self.send(HelperMessage::Ready(Ready {
            device: device_info(),
            credential,
        }));
    }
    fn error(&mut self, id: Option<u32>, code: ErrorCode, fatal: bool) {
        self.send(HelperMessage::Error(ErrorResponse {
            id,
            code,
            message: "test \u{1b}[31merror".into(),
            fatal,
        }));
    }
    /// Block until the host closes the stream.
    fn wait_eof(&mut self) {
        while self.recv().is_some() {}
    }
}

fn device_info() -> DeviceInfo {
    DeviceInfo {
        model: "Safe 7".into(),
        internal_model: "T3W1".into(),
        firmware: "2.13.1".into(),
        passphrase_protection: true,
    }
}

const FAST: Timeouts = Timeouts {
    hello_first: Duration::from_secs(20),
    request: Duration::from_secs(20),
    shutdown_grace: Duration::from_millis(50),
};

struct Run<'a> {
    signer: Result<HelperSigner<&'a TestUi>, Error>,
    proc_state: Arc<Mutex<ProcState>>,
    fake: JoinHandle<()>,
}

fn is_killed(p: &Arc<Mutex<ProcState>>) -> bool {
    p.lock().unwrap().killed
}

fn is_shut_down(p: &Arc<Mutex<ProcState>>) -> bool {
    p.lock().unwrap().shut_down
}

fn start<'a, F>(script: F, ui: &'a TestUi, store: &dyn CredentialStore, t: Timeouts) -> Run<'a>
where
    F: FnOnce(&mut Fake) + Send + 'static,
{
    let (host_rx, helper_tx) = std::io::pipe().unwrap();
    let (helper_rx, host_tx) = std::io::pipe().unwrap();
    let fake = std::thread::spawn(move || {
        let mut f = Fake {
            rx: helper_rx,
            tx: helper_tx,
        };
        script(&mut f);
    });
    let proc_state = Arc::new(Mutex::new(ProcState::default()));
    let signer = HelperSigner::connect(
        host_rx,
        Box::new(host_tx),
        Box::new(FakeProc(proc_state.clone())),
        &ConnectOptions::new("testhost", Transport::Auto),
        ui,
        store,
        t,
    );
    Run {
        signer,
        proc_state,
        fake,
    }
}

// ---------------------------------------------------------------------------------------
// Software "device"
// ---------------------------------------------------------------------------------------

#[derive(Clone)]
enum Key {
    Ed(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

fn ed_key(seed: u8) -> Key {
    Key::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn p_key(seed: u8) -> Key {
    let mut b = [seed; 32];
    b[0] = 1;
    Key::P256(p256::ecdsa::SigningKey::from_slice(&b).unwrap())
}

impl Key {
    fn device_public_key(&self) -> Vec<u8> {
        match self {
            Key::Ed(k) => {
                let mut v = vec![0];
                v.extend_from_slice(k.verifying_key().as_bytes());
                v
            }
            Key::P256(k) => k.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
        }
    }

    /// Exactly what the firmware signs (see `petschaft_core::verify_identity_signature`).
    fn device_sign(&self, req: &proto::SignIdentity) -> Vec<u8> {
        let mut out = vec![0];
        match self {
            Key::Ed(k) => out.extend_from_slice(&k.sign(&req.challenge_hidden).to_bytes()),
            Key::P256(k) => {
                let sig: p256::ecdsa::Signature = match req.identity.proto {
                    proto::Proto::Ssh => {
                        p256::ecdsa::signature::Signer::sign(k, &req.challenge_hidden)
                    }
                    proto::Proto::Gpg => k.sign_prehash(&req.challenge_hidden).unwrap(),
                };
                out.extend_from_slice(&sig.to_bytes());
            }
        }
        out
    }

    fn fingerprint(&self, curve: Curve) -> Fingerprint {
        petschaft_core::PublicKey::from_device(curve, &self.device_public_key())
            .unwrap()
            .fingerprint()
    }

    /// Answer a sign request correctly.
    fn signed(&self, req: &proto::SignIdentity) -> HelperMessage {
        HelperMessage::Signed(Signed {
            id: req.id,
            public_key: self.device_public_key(),
            signature: self.device_sign(req),
        })
    }
}

/// A slip13 identity, produced the only way there is: by the config parser.
fn slip13(uri: &str, curve: Curve, pin: Option<&Fingerprint>) -> Slip13Identity {
    let mut s = format!(
        "[[identity]]\nname = \"t\"\nuri = \"{uri}\"\ncurve = \"{}\"\npassphrase = \"standard\"\n",
        curve.as_str()
    );
    if let Some(p) = pin {
        s.push_str(&format!("fingerprint = \"{p}\"\n"));
    }
    Config::from_toml_str(&s)
        .unwrap()
        .slip13("t")
        .unwrap()
        .clone()
}

const CHALLENGE: &[u8] = b"session-id and stuff";
const VISUAL: &str = "pets: Login homelab";

fn request(curve: Curve) -> SignRequest {
    SignRequest::for_identity(
        &slip13("ssh://user@homelab", curve, None),
        CHALLENGE.to_vec(),
        VISUAL.into(),
    )
}

fn pinned_request(curve: Curve, pin: &Fingerprint) -> SignRequest {
    SignRequest::for_identity(
        &slip13("ssh://user@homelab", curve, Some(pin)),
        CHALLENGE.to_vec(),
        VISUAL.into(),
    )
}

fn cred(b: u8) -> Credential {
    Credential::new(vec![b; 48]).unwrap()
}

// ---------------------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------------------

#[test]
fn pairing_then_sign_stores_credential() {
    let ui = TestUi::with_code(" 620567\n");
    let store = MemStore::default();
    let key = ed_key(3);
    let k = key.clone();
    let run = start(
        move |f| {
            let hello = f.expect_hello();
            assert_eq!(hello.credential, None);
            assert_eq!(hello.app_name, "petschaft");
            assert_eq!(hello.host_name, "testhost");
            assert_eq!(hello.transport, proto::Transport::Auto);
            f.send(HelperMessage::Event(Event {
                event: EventKind::PairingCodeRequired,
            }));
            match f.recv() {
                Some(HostMessage::PairingCode(c)) => assert_eq!(c.code, "620567"),
                other => panic!("{other:?}"),
            }
            f.button();
            f.ready(Some(cred(7)));
            let req = f.expect_sign();
            assert_eq!(req.id, 1);
            assert_eq!(req.curve, proto::Curve::Ed25519);
            assert_eq!(req.passphrase, proto::Passphrase::Standard);
            assert_eq!(req.identity.user.as_deref(), Some("user"));
            assert_eq!(req.identity.host, "homelab");
            f.button();
            f.send(k.signed(&req));
            let req2 = f.expect_sign();
            assert_eq!(req2.id, 2);
            f.send(k.signed(&req2));
            f.wait_eof();
        },
        &ui,
        &store,
        FAST,
    );
    let mut signer = run.signer.unwrap();
    assert_eq!(ui.pairing_calls(), 1);
    assert_eq!(ui.confirms(), 1);
    assert_eq!(store.get(), Some(cred(7)));
    assert!(signer.store_warning().is_none());
    assert_eq!(signer.device(), &device_info());

    let req = pinned_request(Curve::Ed25519, &key.fingerprint(Curve::Ed25519));
    let signed = signer.sign_identity(&req).unwrap();
    assert_eq!(ui.confirms(), 2);
    assert_eq!(
        signed.public_key(),
        &petschaft_core::PublicKey::from_device(Curve::Ed25519, &key.device_public_key()).unwrap()
    );
    signer.sign_identity(&req).unwrap();
    drop(signer);
    run.fake.join().unwrap();
    assert!(!is_killed(&run.proc_state));
    assert!(is_shut_down(&run.proc_state));
}

#[test]
fn stored_credential_is_reused() {
    let ui = TestUi::default();
    let store = MemStore::with(cred(1));
    let run = start(
        |f| {
            let hello = f.expect_hello();
            assert_eq!(hello.credential, Some(cred(1)));
            f.ready(None);
            f.wait_eof();
        },
        &ui,
        &store,
        FAST,
    );
    let signer = run.signer.unwrap();
    assert_eq!(ui.pairing_calls(), 0);
    assert_eq!(store.stores.load(Ordering::SeqCst), 0);
    assert_eq!(store.get(), Some(cred(1)));
    drop(signer);
    run.fake.join().unwrap();
}

#[test]
fn rejected_credential_falls_back_to_pairing() {
    let ui = TestUi::with_code("111111");
    let store = MemStore::with(cred(1));
    let run = start(
        |f| {
            assert_eq!(f.expect_hello().credential, Some(cred(1)));
            // Device does not accept the old credential: code-entry pairing.
            f.send(HelperMessage::Event(Event {
                event: EventKind::PairingCodeRequired,
            }));
            assert!(matches!(f.recv(), Some(HostMessage::PairingCode(_))));
            f.ready(Some(cred(2)));
            f.wait_eof();
        },
        &ui,
        &store,
        FAST,
    );
    let signer = run.signer.unwrap();
    assert_eq!(store.get(), Some(cred(2)));
    drop(signer);
    run.fake.join().unwrap();
}

#[test]
fn invalid_stored_credential_is_not_sent() {
    let ui = TestUi::default();
    // Bypass the validating constructor (as a broken custom store could).
    let store = MemStore::with(raw_credential(5000));
    let run = start(
        |f| {
            assert_eq!(f.expect_hello().credential, None);
            f.ready(None);
            f.wait_eof();
        },
        &ui,
        &store,
        FAST,
    );
    let signer = run.signer.unwrap();
    assert_eq!(signer.store_warning(), Some(&StoreError::Corrupt));
    drop(signer);
    run.fake.join().unwrap();
}

/// A `Credential` of any length: its `Deserialize` impl does not check the length
/// (message validation does).
fn raw_credential(len: usize) -> Credential {
    use base64::Engine as _;
    let s = base64::engine::general_purpose::STANDARD.encode(vec![0u8; len]);
    serde_json::from_value(serde_json::Value::String(s)).unwrap()
}

#[test]
fn store_failures_do_not_abort_and_do_not_leak() {
    let ui = TestUi::with_code("123456");
    let store = MemStore {
        fail_load: Some(StoreError::AccessDenied("locked".into())),
        fail_store: Some(StoreError::Backend("nope".into())),
        ..MemStore::default()
    };
    let run = start(
        |f| {
            assert_eq!(f.expect_hello().credential, None);
            f.send(HelperMessage::Event(Event {
                event: EventKind::PairingCodeRequired,
            }));
            assert!(matches!(f.recv(), Some(HostMessage::PairingCode(_))));
            f.ready(Some(Credential::new(b"SECRETCRED".to_vec()).unwrap()));
            f.wait_eof();
        },
        &ui,
        &store,
        FAST,
    );
    let signer = run.signer.unwrap();
    let w = signer.store_warning().unwrap();
    assert_eq!(w, &StoreError::Backend("nope".into()));
    let dbg = format!("{signer:?} {w} {w:?}");
    assert!(!dbg.contains("SECRETCRED"), "{dbg}");
    drop(signer);
    run.fake.join().unwrap();
}

#[test]
fn nist256p1_ssh_and_gpg() {
    let ui = TestUi::default();
    let key = p_key(9);
    let k = key.clone();
    let run = start(
        move |f| {
            f.expect_hello();
            f.ready(None);
            for _ in 0..2 {
                let req = f.expect_sign();
                f.send(k.signed(&req));
            }
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    let mut signer = run.signer.unwrap();
    let pin = key.fingerprint(Curve::Nist256p1);
    let s = signer
        .sign_identity(&pinned_request(Curve::Nist256p1, &pin))
        .unwrap();
    assert!(s.signature().to_der().is_some());
    let gpg = SignRequest::for_identity(
        &slip13("gpg://apk@release", Curve::Nist256p1, Some(&pin)),
        vec![0x42; 32],
        VISUAL.into(),
    );
    signer.sign_identity(&gpg).unwrap();
    drop(signer);
    run.fake.join().unwrap();
}

// ---------------------------------------------------------------------------------------
// Helper errors
// ---------------------------------------------------------------------------------------

#[test]
fn cancelled_is_not_fatal() {
    let ui = TestUi::default();
    let key = ed_key(1);
    let run = start(
        move |f| {
            f.expect_hello();
            f.ready(None);
            let req = f.expect_sign();
            f.button();
            f.error(Some(req.id), ErrorCode::Cancelled, false);
            let req = f.expect_sign();
            f.send(key.signed(&req));
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    let mut signer = run.signer.unwrap();
    let req = request(Curve::Ed25519);
    assert!(matches!(signer.sign_identity(&req), Err(Error::Cancelled)));
    assert!(signer.is_open());
    signer.sign_identity(&req).unwrap();
    drop(signer);
    run.fake.join().unwrap();
    assert!(!is_killed(&run.proc_state));
}

/// A factory Trezor has passphrase protection off: the error says how to fix it.
#[test]
fn passphrase_unavailable_explains_the_fix() {
    let msg = Error::PassphraseUnavailable.to_string();
    assert!(
        msg.contains("set passphrase = \"standard\" for this identity"),
        "{msg}"
    );
    assert!(
        msg.contains("enable passphrase protection on the device"),
        "{msg}"
    );
}

#[test]
fn error_codes_map_to_variants() {
    type Check = fn(&Error) -> bool;
    let cases: [(ErrorCode, bool, Check); 8] = [
        (ErrorCode::Cancelled, false, |e| {
            matches!(e, Error::Cancelled)
        }),
        (ErrorCode::PassphraseUnavailable, false, |e| {
            matches!(e, Error::PassphraseUnavailable)
        }),
        (ErrorCode::DeviceError, false, |e| {
            matches!(e, Error::Device(_))
        }),
        (ErrorCode::DeviceNotFound, true, |e| {
            matches!(e, Error::DeviceNotFound(_))
        }),
        (ErrorCode::DeviceNotInitialized, true, |e| {
            matches!(e, Error::DeviceNotInitialized)
        }),
        (ErrorCode::PairingFailed, true, |e| {
            matches!(e, Error::PairingFailed(_))
        }),
        (ErrorCode::BadRequest, true, |e| {
            matches!(e, Error::HelperBadRequest(_))
        }),
        (ErrorCode::Internal, true, |e| {
            matches!(e, Error::HelperInternal(_))
        }),
    ];
    for (code, fatal, check) in cases {
        let ui = TestUi::default();
        let run = start(
            move |f| {
                f.expect_hello();
                f.ready(None);
                let req = f.expect_sign();
                f.error(Some(req.id), code, fatal);
                f.wait_eof();
            },
            &ui,
            &MemStore::default(),
            FAST,
        );
        let mut signer = run.signer.unwrap();
        let err = signer.sign_identity(&request(Curve::Ed25519)).unwrap_err();
        assert!(check(&err), "{code:?}: {err:?}");
        // Helper text is sanitized (no raw escape sequences reach the terminal).
        assert!(!err.to_string().contains('\u{1b}'), "{err}");
        assert_eq!(signer.is_open(), !fatal, "{code:?}");
        if fatal {
            assert!(matches!(
                signer.sign_identity(&request(Curve::Ed25519)),
                Err(Error::Closed)
            ));
            assert!(is_shut_down(&run.proc_state));
        }
        drop(signer);
        run.fake.join().unwrap();
    }
}

#[test]
fn hello_errors() {
    let ui = TestUi::default();
    let run = start(
        |f| {
            f.expect_hello();
            f.error(None, ErrorCode::DeviceNotFound, true);
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    assert!(matches!(run.signer, Err(Error::DeviceNotFound(_))));
    run.fake.join().unwrap();
    // Hello errors with an id are a violation.
    let run = start(
        |f| {
            f.expect_hello();
            f.error(Some(1), ErrorCode::Cancelled, false);
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    assert!(matches!(run.signer, Err(Error::Protocol(_))));
    assert!(is_killed(&run.proc_state));
    run.fake.join().unwrap();
}

#[test]
fn pairing_ui_failures_abort() {
    for (code, expect_invalid) in [(Err(Error::Cancelled), false), (Ok("12345".into()), true)] {
        let ui = TestUi::default();
        ui.codes.lock().unwrap().push_back(code);
        let run = start(
            |f| {
                f.expect_hello();
                f.send(HelperMessage::Event(Event {
                    event: EventKind::PairingCodeRequired,
                }));
                // No pairing_code must arrive; only EOF.
                assert!(f.recv().is_none());
            },
            &ui,
            &MemStore::default(),
            FAST,
        );
        let err = run.signer.as_ref().unwrap_err();
        if expect_invalid {
            assert!(matches!(err, Error::InvalidPairingCode), "{err:?}");
        } else {
            assert!(matches!(err, Error::Cancelled), "{err:?}");
        }
        assert!(is_killed(&run.proc_state));
        run.fake.join().unwrap();
    }
}

// ---------------------------------------------------------------------------------------
// Fail closed on bad device output
// ---------------------------------------------------------------------------------------

fn one_sign(
    respond: impl FnOnce(&proto::SignIdentity) -> HelperMessage + Send + 'static,
    req: &SignRequest,
) -> (Result<SignedIdentity, Error>, bool, bool) {
    let ui = TestUi::default();
    let run = start(
        move |f| {
            f.expect_hello();
            f.ready(None);
            let r = f.expect_sign();
            f.send(respond(&r));
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    let mut signer = run.signer.unwrap();
    let res = signer.sign_identity(req);
    let open = signer.is_open();
    drop(signer);
    run.fake.join().unwrap();
    let killed = is_killed(&run.proc_state);
    (res, open, killed)
}

#[test]
fn fingerprint_mismatch_is_an_error() {
    let req = pinned_request(Curve::Ed25519, &ed_key(2).fingerprint(Curve::Ed25519));
    let key = ed_key(1);
    let (res, open, _) = one_sign(move |r| key.signed(r), &req);
    assert!(
        matches!(
            res,
            Err(Error::Verification(
                petschaft_core::Error::FingerprintMismatch { .. }
            ))
        ),
        "{res:?}"
    );
    assert!(open);
}

#[test]
fn bad_signature_is_an_error() {
    let req = request(Curve::Ed25519);
    let key = ed_key(1);
    // Valid signature, but over different data.
    let (res, ..) = one_sign(
        move |r| {
            let mut other = r.clone();
            other.challenge_hidden.push(0);
            let HelperMessage::Signed(mut s) = key.signed(&other) else {
                unreachable!()
            };
            s.id = r.id;
            HelperMessage::Signed(s)
        },
        &req,
    );
    assert!(matches!(res, Err(Error::Verification(_))), "{res:?}");

    // Flipped bit in the signature.
    let key = ed_key(1);
    let (res, ..) = one_sign(
        move |r| {
            let HelperMessage::Signed(mut s) = key.signed(r) else {
                unreachable!()
            };
            s.signature[10] ^= 1;
            HelperMessage::Signed(s)
        },
        &req,
    );
    assert!(matches!(res, Err(Error::Verification(_))), "{res:?}");

    // Key of the other curve.
    let key = p_key(1);
    let (res, ..) = one_sign(move |r| key.signed(r), &req);
    assert!(matches!(res, Err(Error::Verification(_))), "{res:?}");

    // Wrong prefix byte on an otherwise valid ed25519 signature.
    let key = ed_key(1);
    let (res, ..) = one_sign(
        move |r| {
            let HelperMessage::Signed(mut s) = key.signed(r) else {
                unreachable!()
            };
            s.signature[0] = 1;
            HelperMessage::Signed(s)
        },
        &req,
    );
    assert!(matches!(res, Err(Error::Verification(_))), "{res:?}");
}

#[test]
fn signed_with_wrong_id_is_a_violation() {
    let key = ed_key(1);
    let (res, open, killed) = one_sign(
        move |r| {
            let HelperMessage::Signed(mut s) = key.signed(r) else {
                unreachable!()
            };
            s.id = r.id + 1;
            HelperMessage::Signed(s)
        },
        &request(Curve::Ed25519),
    );
    assert!(matches!(res, Err(Error::Protocol(_))), "{res:?}");
    assert!(!open);
    assert!(killed);
}

#[test]
fn non_fatal_error_with_null_id_is_a_violation() {
    let (res, open, killed) = one_sign(
        |_| {
            HelperMessage::Error(ErrorResponse {
                id: None,
                code: ErrorCode::Cancelled,
                message: String::new(),
                fatal: false,
            })
        },
        &request(Curve::Ed25519),
    );
    assert!(matches!(res, Err(Error::Protocol(_))), "{res:?}");
    assert!(!open && killed);
}

#[test]
fn unexpected_messages_are_violations() {
    for msg in [
        HelperMessage::Ready(Ready {
            device: device_info(),
            credential: None,
        }),
        HelperMessage::Event(Event {
            event: EventKind::PairingCodeRequired,
        }),
    ] {
        let (res, open, killed) = one_sign(move |_| msg, &request(Curve::Ed25519));
        assert!(matches!(res, Err(Error::Protocol(_))), "{res:?}");
        assert!(!open && killed);
    }
}

#[test]
fn credential_without_pairing_is_a_violation() {
    let ui = TestUi::default();
    let store = MemStore::default();
    let run = start(
        |f| {
            f.expect_hello();
            f.ready(Some(cred(5)));
            f.wait_eof();
        },
        &ui,
        &store,
        FAST,
    );
    assert!(matches!(run.signer, Err(Error::Protocol(_))));
    assert!(is_killed(&run.proc_state));
    assert_eq!(store.get(), None);
    run.fake.join().unwrap();
}

// ---------------------------------------------------------------------------------------
// Garbage, oversize, unknown types, EOF
// ---------------------------------------------------------------------------------------

fn garbage_after_hello(bytes: Vec<u8>) -> (Result<HelperSigner<&'static TestUi>, Error>, bool) {
    let ui: &'static TestUi = Box::leak(Box::default());
    let run = start(
        move |f| {
            f.expect_hello();
            f.raw(&bytes);
            f.wait_eof();
        },
        ui,
        &MemStore::default(),
        FAST,
    );
    let killed = is_killed(&run.proc_state);
    let signer = run.signer;
    // The fake ends once the link is gone (EOF on its stdin).
    if signer.is_err() {
        run.fake.join().unwrap();
    }
    (signer, killed)
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut v = (payload.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(payload);
    v
}

#[test]
fn garbage_is_rejected_and_helper_killed() {
    let cases: Vec<Vec<u8>> = vec![
        // Oversize length, no payload follows (must not wait for / allocate 4 GiB).
        u32::MAX.to_be_bytes().to_vec(),
        65537u32.to_be_bytes().to_vec(),
        0u32.to_be_bytes().to_vec(),
        frame(b"not json"),
        frame(b"[1,2,3]"),
        frame(br#"{"type":"bogus"}"#),
        frame(br#"{"type":"event","event":"button","x":1}"#),
        frame(br#"{"type":"signed","id":1,"public_key":"AA==","signature":"AA=="}"#),
    ];
    for bytes in cases {
        let (res, killed) = garbage_after_hello(bytes.clone());
        assert!(matches!(res, Err(Error::Protocol(_))), "{bytes:?}: {res:?}");
        assert!(killed, "{bytes:?}");
    }
}

#[test]
fn truncated_frame_then_exit_is_a_violation() {
    let ui = TestUi::default();
    let run = start(
        |f| {
            f.expect_hello();
            let mut v = frame(br#"{"type":"event","event":"button"}"#);
            v.truncate(10);
            f.raw(&v);
            // Returning closes the helper's stdout.
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    assert!(
        matches!(run.signer, Err(Error::Protocol(_))),
        "{:?}",
        run.signer
    );
    assert!(is_killed(&run.proc_state));
    run.fake.join().unwrap();
}

#[test]
fn eof_during_hello_and_request() {
    let ui = TestUi::default();
    let run = start(
        |f| {
            f.expect_hello();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    assert!(matches!(run.signer, Err(Error::HelperExited)));
    assert!(is_killed(&run.proc_state));
    run.fake.join().unwrap();

    let run = start(
        |f| {
            f.expect_hello();
            f.ready(None);
            f.expect_sign();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    let mut signer = run.signer.unwrap();
    assert!(matches!(
        signer.sign_identity(&request(Curve::Ed25519)),
        Err(Error::HelperExited)
    ));
    assert!(matches!(
        signer.sign_identity(&request(Curve::Ed25519)),
        Err(Error::Closed)
    ));
    drop(signer);
    run.fake.join().unwrap();
}

#[test]
fn unsolicited_message_between_requests_is_a_violation() {
    let ui = TestUi::default();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (sent_tx, sent_rx) = std::sync::mpsc::channel::<()>();
    let run = start(
        move |f| {
            f.expect_hello();
            f.ready(None);
            go_rx.recv().unwrap();
            f.button();
            sent_tx.send(()).unwrap();
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    let mut signer = run.signer.unwrap();
    go_tx.send(()).unwrap();
    sent_rx.recv().unwrap();
    // Give the reader thread a moment to deliver the frame.
    std::thread::sleep(Duration::from_millis(100));
    assert!(matches!(
        signer.sign_identity(&request(Curve::Ed25519)),
        Err(Error::Protocol(_))
    ));
    assert_eq!(ui.confirms(), 0);
    drop(signer);
    run.fake.join().unwrap();
    assert!(is_killed(&run.proc_state));
}

#[test]
fn event_flood_is_a_violation() {
    let ui = TestUi::default();
    let run = start(
        |f| {
            f.expect_hello();
            f.ready(None);
            f.expect_sign();
            for _ in 0..1000 {
                f.button();
            }
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    let mut signer = run.signer.unwrap();
    assert!(matches!(
        signer.sign_identity(&request(Curve::Ed25519)),
        Err(Error::Protocol(_))
    ));
    assert_eq!(ui.confirms(), 64);
    drop(signer);
    run.fake.join().unwrap();
}

// ---------------------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------------------

const SHORT: Timeouts = Timeouts {
    hello_first: Duration::from_millis(150),
    request: Duration::from_millis(400),
    shutdown_grace: Duration::from_millis(10),
};

#[test]
fn hello_first_response_timeout() {
    let ui = TestUi::default();
    let t0 = std::time::Instant::now();
    let run = start(
        |f| {
            f.expect_hello();
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        SHORT,
    );
    let elapsed = t0.elapsed();
    assert!(
        matches!(run.signer, Err(Error::Timeout("hello: first response"))),
        "{:?}",
        run.signer
    );
    assert!(elapsed >= Duration::from_millis(150) && elapsed < Duration::from_millis(400));
    assert!(is_killed(&run.proc_state));
    run.fake.join().unwrap();
}

#[test]
fn hello_overall_timeout_after_first_event() {
    let ui = TestUi::default();
    let run = start(
        |f| {
            f.expect_hello();
            f.button();
            std::thread::sleep(Duration::from_millis(100));
            f.button();
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        SHORT,
    );
    assert!(
        matches!(run.signer, Err(Error::Timeout("hello"))),
        "{:?}",
        run.signer
    );
    assert_eq!(ui.confirms(), 2);
    assert!(is_killed(&run.proc_state));
    run.fake.join().unwrap();
}

#[test]
fn request_timeout_kills_and_closes() {
    let ui = TestUi::default();
    let run = start(
        |f| {
            f.expect_hello();
            f.ready(None);
            f.expect_sign();
            // Events keep coming, but no final response: the overall deadline holds.
            for _ in 0..3 {
                f.button();
                std::thread::sleep(Duration::from_millis(100));
            }
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        SHORT,
    );
    let mut signer = run.signer.unwrap();
    let t0 = std::time::Instant::now();
    let res = signer.sign_identity(&request(Curve::Ed25519));
    assert!(
        matches!(res, Err(Error::Timeout("sign_identity"))),
        "{res:?}"
    );
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert!(!signer.is_open());
    assert!(matches!(
        signer.sign_identity(&request(Curve::Ed25519)),
        Err(Error::Closed)
    ));
    drop(signer);
    run.fake.join().unwrap();
    assert!(is_killed(&run.proc_state));
}

// ---------------------------------------------------------------------------------------
// Requests and configuration
// ---------------------------------------------------------------------------------------

#[test]
fn invalid_requests_are_not_sent() {
    let ui = TestUi::default();
    let key = ed_key(4);
    let run = start(
        move |f| {
            f.expect_hello();
            f.ready(None);
            // Only the valid request arrives.
            let req = f.expect_sign();
            assert_eq!(req.id, 1);
            f.send(key.signed(&req));
            f.wait_eof();
        },
        &ui,
        &MemStore::default(),
        FAST,
    );
    let mut signer = run.signer.unwrap();
    let ed = slip13("ssh://user@homelab", Curve::Ed25519, None);
    let bad = SignRequest::for_identity(&ed, vec![0; 513], VISUAL.into());
    assert!(matches!(
        signer.sign_identity(&bad),
        Err(Error::InvalidRequest(_))
    ));
    let bad = SignRequest::for_identity(&ed, CHALLENGE.to_vec(), "line1\nline2".into());
    assert!(matches!(
        signer.sign_identity(&bad),
        Err(Error::InvalidRequest(_))
    ));
    let gpg = slip13("gpg://apk@release", Curve::Nist256p1, None);
    let bad = SignRequest::for_identity(&gpg, vec![0; 31], VISUAL.into());
    let err = signer.sign_identity(&bad).unwrap_err();
    assert!(matches!(err, Error::InvalidRequest(_)));
    // Error texts never echo the challenge.
    assert!(!err.to_string().contains("31"));
    assert!(signer.is_open());
    signer.sign_identity(&request(Curve::Ed25519)).unwrap();
    drop(signer);
    run.fake.join().unwrap();
}

#[test]
fn invalid_host_name_fails_before_spawning() {
    let paths = HelperPaths {
        python: "/nonexistent/python3".into(),
        script: "/nonexistent/helper.py".into(),
    };
    let ui = TestUi::default();
    let mut opts = ConnectOptions::new("bad\nname", Transport::Usb);
    assert!(matches!(
        HelperSigner::spawn(&paths, &opts, &ui, &NoStore),
        Err(Error::InvalidRequest(_))
    ));
    opts.host_name = "ok".into();
    assert!(matches!(
        HelperSigner::spawn(&paths, &opts, &ui, &NoStore),
        Err(Error::Spawn(_))
    ));
}

#[test]
fn helper_path_resolution() {
    let rt = |s: &str| Some(std::ffi::OsString::from(s));
    assert_eq!(
        resolve_path("X", Some("/nix/store/py"), rt("/usr/bin/py")).unwrap(),
        std::path::PathBuf::from("/nix/store/py")
    );
    assert_eq!(
        resolve_path("X", None, rt("/usr/bin/py")).unwrap(),
        std::path::PathBuf::from("/usr/bin/py")
    );
    assert_eq!(
        resolve_path("X", Some(""), rt("/usr/bin/py")).unwrap(),
        std::path::PathBuf::from("/usr/bin/py")
    );
    assert!(matches!(
        resolve_path("X", None, None),
        Err(Error::HelperNotConfigured(_))
    ));
    assert!(matches!(
        resolve_path("X", None, rt("")),
        Err(Error::HelperNotConfigured(_))
    ));
    assert!(matches!(
        resolve_path("X", None, rt("python3")),
        Err(Error::HelperNotConfigured(_))
    ));
    assert!(matches!(
        resolve_path("X", Some("rel/py"), rt("/abs")),
        Err(Error::HelperNotConfigured(_))
    ));
}

#[test]
fn helper_command_shape() {
    let paths = HelperPaths {
        python: "/py".into(),
        script: "/helper.py".into(),
    };
    let cmd = crate::helper::helper_command(&paths);
    assert_eq!(cmd.get_program(), "/py");
    let args: Vec<_> = cmd.get_args().collect();
    assert_eq!(args, ["-I", "-B", "/helper.py"]);
    assert_eq!(cmd.get_current_dir(), Some(std::path::Path::new("/")));
    for (k, _) in cmd.get_envs() {
        let k = k.to_str().unwrap();
        assert!(PASSED_ENV.contains(&k), "{k}");
        assert!(!k.starts_with("PYTHON") && k != "TREZOR_PATH");
    }
}

// ---------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary device output never yields a SignedIdentity.
    #[test]
    fn random_device_output_never_verifies(
        pk in prop::collection::vec(any::<u8>(), 33),
        sig in prop::collection::vec(any::<u8>(), 65),
        ed in any::<bool>(),
    ) {
        let req = request(if ed { Curve::Ed25519 } else { Curve::Nist256p1 });
        prop_assert!(SignedIdentity::from_device(&req, &pk, &sig).is_err());
    }

    /// Arbitrary bytes from the helper during a request: never Ok, never a panic, and
    /// the helper is killed unless the bytes form a valid non-final frame sequence
    /// (then the deadline kills it).
    #[test]
    fn arbitrary_helper_bytes_fail_closed(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        let ui = TestUi::default();
        let b = bytes.clone();
        let run = start(
            move |f| {
                f.expect_hello();
                f.ready(None);
                f.expect_sign();
                f.raw(&b);
                f.wait_eof();
            },
            &ui,
            &MemStore::default(),
            Timeouts { hello_first: Duration::from_secs(5), request: Duration::from_millis(300),
                       shutdown_grace: Duration::from_millis(1) },
        );
        let mut signer = run.signer.unwrap();
        let res = signer.sign_identity(&request(Curve::Ed25519));
        prop_assert!(res.is_err());
        drop(signer);
        run.fake.join().unwrap();
    }
}

// ---------------------------------------------------------------------------------------
// Real process (Python interpreter from the build environment, fake helper script)
// ---------------------------------------------------------------------------------------

const FAKE_HELPER_PY: &str = r#"
import json, os, struct, sys, time
inp = sys.stdin.buffer
out = sys.stdout.buffer
def read():
    h = inp.read(4)
    if len(h) < 4:
        return None
    (n,) = struct.unpack(">I", h)
    return json.loads(inp.read(n))
def send(o):
    b = json.dumps(o).encode()
    out.write(struct.pack(">I", len(b)) + b)
    out.flush()
mode = sys.argv[0].rsplit("_", 1)[-1].split(".")[0]
hello = read()
allowed = set(ALLOWED)
extra = sorted(k for k in os.environ if k not in allowed)
problems = []
if extra:
    problems.append("env:" + ",".join(extra))
if os.getcwd() != "/":
    problems.append("cwd")
if sys.flags.isolated != 1:
    problems.append("not isolated")
if not hello or hello.get("type") != "hello":
    problems.append("no hello")
if problems:
    send({"type": "error", "id": None, "code": "internal",
          "message": ";".join(problems)[:256], "fatal": True})
    sys.exit(1)
send({"type": "ready", "device": {"model": "Fake %d" % os.getpid(),
      "internal_model": "FAKE", "firmware": "0.0.0", "passphrase_protection": False},
      "credential": None})
if mode == "garbage":
    read()
    out.write(b"\xff\xff\xff\xff")
    out.flush()
    time.sleep(60)
elif mode == "stubborn":
    time.sleep(60)
else:
    while read() is not None:
        pass
"#;

fn python() -> Option<std::path::PathBuf> {
    option_env!("PETSCHAFT_HELPER_PYTHON").map(std::path::PathBuf::from)
}

fn write_script(dir: &tempfile::TempDir, mode: &str) -> std::path::PathBuf {
    let allowed: Vec<String> = PASSED_ENV.iter().map(|k| format!("{k:?}")).collect();
    // Added below us, not by petschaft: the nixpkgs `python3.withPackages` binary wrapper sets
    // PYTHONNOUSERSITE=true (and `-I` ignores PYTHON* anyway); macOS may add
    // __CF_USER_TEXT_ENCODING to processes.
    let allowed = format!(
        "[{}, \"PYTHONNOUSERSITE\", \"__CF_USER_TEXT_ENCODING\"]",
        allowed.join(", ")
    );
    let path = dir.path().join(format!("fake_helper_{mode}.py"));
    std::fs::write(&path, FAKE_HELPER_PY.replace("ALLOWED", &allowed)).unwrap();
    path
}

fn pid_alive(python: &std::path::Path, pid: u32) -> bool {
    std::process::Command::new(python)
        .args([
            "-I",
            "-c",
            &format!("import os,sys\ntry:\n os.kill({pid},0)\nexcept OSError:\n sys.exit(1)"),
        ])
        .status()
        .unwrap()
        .success()
}

fn spawn_fake(mode: &str) -> Option<(HelperSigner<&'static TestUi>, u32, std::path::PathBuf)> {
    let Some(python) = python() else {
        eprintln!("PETSCHAFT_HELPER_PYTHON not set at build time; skipping real-process test");
        return None;
    };
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let paths = HelperPaths {
        python: python.clone(),
        script: write_script(dir, mode),
    };
    let ui: &'static TestUi = Box::leak(Box::default());
    let signer = HelperSigner::spawn_with(
        &paths,
        &ConnectOptions::new("testhost", Transport::Usb),
        ui,
        &NoStore,
        Timeouts {
            hello_first: Duration::from_secs(20),
            request: Duration::from_secs(20),
            shutdown_grace: Duration::from_millis(300),
        },
    )
    .unwrap();
    let pid: u32 = signer
        .device()
        .model
        .strip_prefix("Fake ")
        .unwrap()
        .parse()
        .unwrap();
    Some((signer, pid, python))
}

#[test]
fn real_process_clean_environment_and_orderly_shutdown() {
    let Some((signer, pid, python)) = spawn_fake("normal") else {
        return;
    };
    assert!(pid_alive(&python, pid));
    drop(signer);
    assert!(!pid_alive(&python, pid));
}

#[test]
fn real_process_killed_if_it_ignores_eof() {
    let Some((signer, pid, python)) = spawn_fake("stubborn") else {
        return;
    };
    let t0 = std::time::Instant::now();
    drop(signer);
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert!(!pid_alive(&python, pid));
}

#[test]
fn real_process_killed_on_protocol_violation() {
    let Some((mut signer, pid, python)) = spawn_fake("garbage") else {
        return;
    };
    let res = signer.sign_identity(&request(Curve::Ed25519));
    assert!(matches!(res, Err(Error::Protocol(_))), "{res:?}");
    assert!(!pid_alive(&python, pid));
}
