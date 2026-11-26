//! Daemon tests with a software signer: no device, no helper. The socket is driven with
//! hand-built protocol messages (encoders below, written from `PROTOCOL.agent` and
//! RFC 4252 independently of `petschaft-agent`).
//!
//! Test keys come from public fixed seeds (`docs/testing.md`): identity `[0x61; 32]`,
//! other identity `[0x62; 32]`, pinned host key `[0x51; 32]`, unpinned host `[0x52; 32]`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use petschaft_core::{Config, Curve, PublicKey};
use petschaft_device::{SignRequest, SignedIdentity, Signer};
use proptest::prelude::*;

use super::*;

const IDENTITY_SEED: u8 = 0x61;
const OTHER_SEED: u8 = 0x62;
const HOST_SEED: u8 = 0x51;
const UNPINNED_HOST_SEED: u8 = 0x52;
const SESSION: [u8; 32] = [0xA5; 32];

// --- encoders (test-only) ---

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    put_u32(out, u32::try_from(data.len()).unwrap());
    out.extend_from_slice(data);
}

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn ed_blob(seed: u8) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"ssh-ed25519");
    put_string(&mut b, sk(seed).verifying_key().as_bytes());
    b
}

fn public_key(seed: u8) -> PublicKey {
    let device = [&[0u8][..], sk(seed).verifying_key().as_bytes()].concat();
    PublicKey::from_device(Curve::Ed25519, &device).unwrap()
}

/// `SSH_AGENTC_EXTENSION "session-bind@openssh.com"`, signed by host key `host`.
fn session_bind(host: u8, session: &[u8], forwarding: bool, valid_signature: bool) -> Vec<u8> {
    let mut signed = session.to_vec();
    if !valid_signature {
        signed[0] ^= 1;
    }
    let mut sig = Vec::new();
    put_string(&mut sig, b"ssh-ed25519");
    put_string(&mut sig, &sk(host).sign(&signed).to_bytes());
    let mut m = vec![27];
    put_string(&mut m, b"session-bind@openssh.com");
    put_string(&mut m, &ed_blob(host));
    put_string(&mut m, session);
    put_string(&mut m, &sig);
    m.push(u8::from(forwarding));
    m
}

/// RFC 4252 §7 "publickey" request with signature, as signed by the client.
fn userauth(session: &[u8], user: &str, algorithm: &str, key_blob: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    put_string(&mut d, session);
    d.push(50);
    put_string(&mut d, user.as_bytes());
    put_string(&mut d, b"ssh-connection");
    put_string(&mut d, b"publickey");
    d.push(1);
    put_string(&mut d, algorithm.as_bytes());
    put_string(&mut d, key_blob);
    d
}

fn sign_request(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = vec![13];
    put_string(&mut m, key_blob);
    put_string(&mut m, data);
    put_u32(&mut m, 0);
    m
}

fn login(user: &str) -> Vec<u8> {
    sign_request(
        &ed_blob(IDENTITY_SEED),
        &userauth(&SESSION, user, "ssh-ed25519", &ed_blob(IDENTITY_SEED)),
    )
}

/// `challenge_visual` expected for a login of `user` to the pinned host.
fn visual(user: &str) -> String {
    let fp = Fingerprint::of_openssh_blob(&ed_blob(HOST_SEED));
    format!("ssh login {user} (desktop) {}", &fp.as_str()[7..15])
}

const FAILURE: &[u8] = &[5];
const SUCCESS: &[u8] = &[6];

// --- fake device ---

/// What the fake device saw: challenge_visual of every request it signed.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<String>>>);

impl Seen {
    fn visuals(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// Software device: signs like the Trezor does for ssh/ed25519 (`0x00 || sig` over
/// `challenge_hidden`), with key `seed`; the result passes the same verification.
struct FakeSigner {
    seed: u8,
    seen: Seen,
    fail: bool,
    /// Time the "user" takes to confirm.
    delay: Duration,
}

impl Signer for FakeSigner {
    fn sign_identity(
        &mut self,
        req: &SignRequest,
    ) -> Result<SignedIdentity, petschaft_device::Error> {
        if self.fail {
            return Err(petschaft_device::Error::HelperExited);
        }
        self.seen
            .0
            .lock()
            .unwrap()
            .push(req.challenge_visual().to_owned());
        std::thread::sleep(self.delay);
        let key = sk(self.seed);
        let pk = [&[0u8][..], key.verifying_key().as_bytes()].concat();
        let sig = [&[0u8][..], &key.sign(req.challenge_hidden()).to_bytes()[..]].concat();
        SignedIdentity::from_device(req, &pk, &sig)
    }
}

/// Factory of fake signers; `opens` counts connections; signers listed in `fail_first`
/// fail (by open number, 0-based).
fn factory(
    seed: u8,
    seen: &Seen,
    opens: &Arc<Mutex<usize>>,
    fail_first: usize,
    delay: Duration,
) -> SignerFactory {
    let seen = seen.clone();
    let opens = Arc::clone(opens);
    Box::new(move || {
        let mut n = opens.lock().unwrap();
        let fail = *n < fail_first;
        *n += 1;
        Ok(Box::new(FakeSigner {
            seed,
            seen: seen.clone(),
            fail,
            delay,
        }) as Box<dyn Signer>)
    })
}

fn config() -> Config {
    let toml = format!(
        r#"
[[identity]]
name = "desktop"
uri = "ssh://user@desktop"
curve = "ed25519"
comment = "user desktop"
public_key = "{}"
host_keys = ["{}"]

[[identity]]
name = "nohost"
uri = "ssh://user@nohost"
curve = "ed25519"
public_key = "{}"

[[identity]]
name = "plain"
uri = "ssh://user@plain"
curve = "ed25519"

[[identity]]
name = "fido"
kind = "fido2"
algorithm = "ed25519-sk"
"#,
        public_key(IDENTITY_SEED).openssh_line("ignored"),
        Fingerprint::of_openssh_blob(&ed_blob(HOST_SEED)),
        public_key(OTHER_SEED).openssh_line(""),
    );
    Config::from_toml_str(&toml).unwrap()
}

struct Daemon {
    _dir: tempfile::TempDir,
    path: PathBuf,
    seen: Seen,
    opens: Arc<Mutex<usize>>,
}

/// A running agent on a fresh socket, signing with key `device_seed`.
fn start_with(device_seed: u8, fail_first: usize) -> Daemon {
    start_custom(Limits::DEFAULT, |seen, opens| {
        factory(device_seed, seen, opens, fail_first, Duration::ZERO)
    })
}

/// A running agent with `limits` and the device from `make`.
fn start_custom(
    limits: Limits,
    make: impl FnOnce(&Seen, &Arc<Mutex<usize>>) -> SignerFactory,
) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s").join("agent.sock");
    let seen = Seen::default();
    let opens = Arc::new(Mutex::new(0));
    let (keys, _) = agent_keys(&config());
    let agent = Arc::new(Agent::with_limits(keys, make(&seen, &opens), limits).unwrap());
    let listener = bind(&path).unwrap();
    std::thread::spawn(move || serve(&listener, &agent));
    Daemon {
        _dir: dir,
        path,
        seen,
        opens,
    }
}

fn start() -> Daemon {
    start_with(IDENTITY_SEED, 0)
}

struct Client(UnixStream);

impl Client {
    fn connect(path: &Path) -> Self {
        let s = UnixStream::connect(path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        Client(s)
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).unwrap();
    }

    /// `None` if the agent closed the connection.
    fn read(&mut self) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        match self.0.read_exact(&mut len) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return None;
            }
            Err(e) => panic!("read: {e}"),
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        self.0.read_exact(&mut body).unwrap();
        Some(body)
    }

    fn call(&mut self, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        put_string(&mut m, body);
        self.send_raw(&m);
        self.read().expect("connection closed")
    }

    fn closed(&mut self) -> bool {
        self.read().is_none()
    }
}

/// Parse `SSH_AGENT_IDENTITIES_ANSWER`.
fn identities(body: &[u8]) -> Vec<(Vec<u8>, String)> {
    assert_eq!(body[0], 12);
    let mut r = &body[1..];
    let mut take = |n: usize| {
        let (a, b) = r.split_at(n);
        r = b;
        a.to_vec()
    };
    let count = u32::from_be_bytes(take(4).try_into().unwrap());
    let mut out = Vec::new();
    for _ in 0..count {
        let n = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        let blob = take(n);
        let n = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        out.push((blob, String::from_utf8(take(n)).unwrap()));
    }
    assert!(r.is_empty());
    out
}

// --- protocol tests ---

#[test]
fn lists_only_identities_with_public_key_and_host_keys() {
    let d = start();
    let mut c = Client::connect(&d.path);
    let ids = identities(&c.call(&[11]));
    assert_eq!(
        ids,
        vec![(ed_blob(IDENTITY_SEED), "user desktop".to_owned())]
    );
    // listing needs no device
    assert_eq!(*d.opens.lock().unwrap(), 0);
}

#[test]
fn signs_a_bound_pinned_login() {
    let d = start();
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    let data = userauth(&SESSION, "user", "ssh-ed25519", &ed_blob(IDENTITY_SEED));
    let reply = c.call(&sign_request(&ed_blob(IDENTITY_SEED), &data));
    // SSH_AGENT_SIGN_RESPONSE: string(string "ssh-ed25519", string sig64)
    assert_eq!(reply[0], 14);
    let mut expected = Vec::new();
    put_string(&mut expected, b"ssh-ed25519");
    let sig = sk(IDENTITY_SEED).sign(&data);
    put_string(&mut expected, &sig.to_bytes());
    let mut framed = vec![14];
    put_string(&mut framed, &expected);
    assert_eq!(reply, framed);
    sk(IDENTITY_SEED)
        .verifying_key()
        .verify(&data, &sig)
        .unwrap();
    assert_eq!(d.seen.visuals(), vec![visual("user")]);
    // the connection stays usable; the device connection is reused
    let reply = c.call(&sign_request(&ed_blob(IDENTITY_SEED), &data));
    assert_eq!(reply[0], 14);
    assert_eq!(*d.opens.lock().unwrap(), 1);
}

#[test]
fn user_name_is_sanitized_on_the_device() {
    let d = start();
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    // bidi override and space are escaped (control characters are refused earlier)
    let reply = c.call(&login("r\u{202e}t x"));
    assert_eq!(reply[0], 14);
    assert_eq!(d.seen.visuals(), vec![visual("r\\u{202e}t\\u{20}x")]);
}

/// Every denial reason answers FAILURE without touching the device.
#[test]
fn denials_never_reach_the_device() {
    let d = start();
    let key = ed_blob(IDENTITY_SEED);
    let other = ed_blob(OTHER_SEED);
    let bound = |c: &mut Client| {
        assert_eq!(
            c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
            SUCCESS
        );
    };
    type Case = (&'static str, Box<dyn Fn(&mut Client) -> Vec<u8>>);
    let cases: Vec<Case> = vec![
        (
            "not bound",
            Box::new(|c: &mut Client| c.call(&login("user"))),
        ),
        (
            "forwarded",
            Box::new(|c: &mut Client| {
                assert_eq!(
                    c.call(&session_bind(HOST_SEED, &SESSION, true, true)),
                    SUCCESS
                );
                c.call(&login("user"))
            }),
        ),
        (
            "forwarded earlier binding",
            Box::new(|c: &mut Client| {
                assert_eq!(
                    c.call(&session_bind(HOST_SEED, &[1; 32], true, true)),
                    SUCCESS
                );
                assert_eq!(
                    c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
                    SUCCESS
                );
                c.call(&login("user"))
            }),
        ),
        ("sshsig data", {
            let key = key.clone();
            Box::new(move |c: &mut Client| {
                bound(c);
                let mut data = b"SSHSIG".to_vec();
                put_string(&mut data, b"git");
                c.call(&sign_request(&key, &data))
            })
        }),
        ("not userauth", {
            let key = key.clone();
            Box::new(move |c: &mut Client| {
                bound(c);
                let mut data = userauth(&SESSION, "user", "ssh-ed25519", &key);
                data.push(0); // trailing byte
                c.call(&sign_request(&key, &data))
            })
        }),
        ("session mismatch", {
            let key = key.clone();
            Box::new(move |c: &mut Client| {
                bound(c);
                c.call(&sign_request(
                    &key,
                    &userauth(&[0x5A; 32], "user", "ssh-ed25519", &key),
                ))
            })
        }),
        ("not the last binding's session", {
            Box::new(move |c: &mut Client| {
                bound(c);
                assert_eq!(
                    c.call(&session_bind(HOST_SEED, &[0x5A; 32], false, true)),
                    SUCCESS
                );
                c.call(&login("user"))
            })
        }),
        ("key mismatch", {
            let (key, other) = (key.clone(), other.clone());
            Box::new(move |c: &mut Client| {
                bound(c);
                c.call(&sign_request(
                    &key,
                    &userauth(&SESSION, "user", "ssh-ed25519", &other),
                ))
            })
        }),
        ("algorithm mismatch", {
            let key = key.clone();
            Box::new(move |c: &mut Client| {
                bound(c);
                c.call(&sign_request(
                    &key,
                    &userauth(&SESSION, "user", "ecdsa-sha2-nistp256", &key),
                ))
            })
        }),
        (
            "host not pinned",
            Box::new(|c: &mut Client| {
                assert_eq!(
                    c.call(&session_bind(UNPINNED_HOST_SEED, &SESSION, false, true)),
                    SUCCESS
                );
                c.call(&login("user"))
            }),
        ),
        ("key not offered (no host_keys)", {
            let other = other.clone();
            Box::new(move |c: &mut Client| {
                bound(c);
                c.call(&sign_request(
                    &other,
                    &userauth(&SESSION, "user", "ssh-ed25519", &other),
                ))
            })
        }),
    ];
    for (name, case) in cases {
        let mut c = Client::connect(&d.path);
        assert_eq!(case(&mut c), FAILURE, "{name}");
        // a denial does not close the connection
        assert_eq!(identities(&c.call(&[11])).len(), 1, "{name}");
    }
    assert!(d.seen.visuals().is_empty());
    assert_eq!(*d.opens.lock().unwrap(), 0);
}

#[test]
fn tainted_connection_refuses_all_signatures() {
    let d = start();
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, false)),
        FAILURE
    );
    assert_eq!(c.call(&login("user")), FAILURE);
    // a later valid binding does not lift it
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    assert_eq!(c.call(&login("user")), FAILURE);
    assert!(d.seen.visuals().is_empty());
    // other connections are not affected
    let mut c2 = Client::connect(&d.path);
    assert_eq!(
        c2.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    assert_eq!(c2.call(&login("user"))[0], 14);
}

#[test]
fn too_many_bindings_close_the_connection() {
    let d = start();
    let mut c = Client::connect(&d.path);
    for _ in 0..MAX_BINDINGS {
        assert_eq!(
            c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
            SUCCESS
        );
    }
    let mut m = Vec::new();
    put_string(&mut m, &session_bind(HOST_SEED, &SESSION, false, true));
    c.send_raw(&m);
    assert!(c.closed());
    assert!(d.seen.visuals().is_empty());
}

/// OpenSSH >= 8.9 signs `publickey-hostbound-v00@openssh.com`, which carries the
/// server host key: it must be the bound one.
fn hostbound(host_key: &[u8]) -> Vec<u8> {
    let key = ed_blob(IDENTITY_SEED);
    let mut d = Vec::new();
    put_string(&mut d, &SESSION);
    d.push(50);
    put_string(&mut d, b"user");
    put_string(&mut d, b"ssh-connection");
    put_string(&mut d, b"publickey-hostbound-v00@openssh.com");
    d.push(1);
    put_string(&mut d, b"ssh-ed25519");
    put_string(&mut d, &key);
    put_string(&mut d, host_key);
    sign_request(&key, &d)
}

#[test]
fn hostbound_userauth_must_name_the_bound_host() {
    let d = start();
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    assert_eq!(c.call(&hostbound(&ed_blob(UNPINNED_HOST_SEED))), FAILURE);
    assert!(d.seen.visuals().is_empty());
    assert_eq!(c.call(&hostbound(&ed_blob(HOST_SEED)))[0], 14);
    assert_eq!(d.seen.visuals(), vec![visual("user")]);
}

#[test]
fn device_returning_another_key_is_refused() {
    // The fake device signs with a key that is not the configured public_key: the pin
    // derived from public_key rejects it inside petschaft-device.
    let d = start_with(OTHER_SEED, 0);
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    assert_eq!(c.call(&login("user")), FAILURE);
    // the failed connection was dropped and is re-opened for the next request
    assert_eq!(c.call(&login("user")), FAILURE);
    assert_eq!(*d.opens.lock().unwrap(), 2);
}

#[test]
fn device_connection_is_reopened_after_an_error() {
    let d = start_with(IDENTITY_SEED, 1);
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    assert_eq!(c.call(&login("user")), FAILURE);
    assert_eq!(c.call(&login("user"))[0], 14);
    assert_eq!(*d.opens.lock().unwrap(), 2);
}

#[test]
fn unsupported_requests_fail_without_closing() {
    let d = start();
    let mut c = Client::connect(&d.path);
    // add identity, remove all, lock, unknown extension
    for m in [&[17u8][..], &[19], &[22, 0, 0, 0, 0]] {
        assert_eq!(c.call(m), FAILURE);
    }
    let mut ext = vec![27];
    put_string(&mut ext, b"query");
    assert_eq!(c.call(&ext), FAILURE);
    assert_eq!(identities(&c.call(&[11])).len(), 1);
}

#[test]
fn oversize_or_empty_messages_close_the_connection() {
    let d = start();
    for len in [petschaft_agent::MAX_MESSAGE + 1, 0, u32::MAX as usize] {
        let mut c = Client::connect(&d.path);
        c.send_raw(&u32::try_from(len).unwrap().to_be_bytes());
        assert!(c.closed(), "length {len}");
    }
    // the agent keeps serving
    let mut c = Client::connect(&d.path);
    assert_eq!(identities(&c.call(&[11])).len(), 1);
}

#[test]
fn seventeenth_client_is_rejected() {
    let d = start();
    let mut clients: Vec<Client> = (0..MAX_CLIENTS).map(|_| Client::connect(&d.path)).collect();
    // each one is accepted and served
    for c in &mut clients {
        assert_eq!(identities(&c.call(&[11])).len(), 1);
    }
    let mut extra = Client::connect(&d.path);
    let mut m = Vec::new();
    put_string(&mut m, &[11]);
    // the write may fail once the agent has closed the socket
    let _ = extra.0.write_all(&m);
    assert!(extra.closed());
    // closing one frees a slot
    drop(clients.pop());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut c = Client::connect(&d.path);
        let _ = c.0.write_all(&m);
        if let Some(body) = c.read() {
            assert_eq!(identities(&body).len(), 1);
            break;
        }
        assert!(Instant::now() < deadline, "slot was not released");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn stale_queued_request_is_dropped_without_reaching_the_device() {
    let limits = Limits {
        max_queue_wait: Duration::from_millis(100),
        ..Limits::DEFAULT
    };
    let d = start_custom(limits, |seen, opens| {
        factory(IDENTITY_SEED, seen, opens, 0, Duration::from_millis(500))
    });
    let path = d.path.clone();
    // A: on the device, the "user" takes 500 ms to confirm
    let a = std::thread::spawn(move || {
        let mut c = Client::connect(&path);
        assert_eq!(
            c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
            SUCCESS
        );
        c.call(&login("first"))
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while d.seen.visuals().is_empty() {
        assert!(
            Instant::now() < deadline,
            "first request never reached the device"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // B queues behind A for longer than 100 ms: dropped
    let mut b = Client::connect(&d.path);
    assert_eq!(
        b.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    assert_eq!(b.call(&login("second")), FAILURE);
    assert_eq!(a.join().unwrap()[0], 14);
    assert_eq!(d.seen.visuals(), vec![visual("first")]);
    // a request that does not wait is served
    assert_eq!(b.call(&login("third"))[0], 14);
}

/// A device that never answers (in time) does not hold the client: it gets FAILURE
/// after `max_reply_wait`, keeps its connection, and later requests that find the
/// queue full fail at once instead of blocking.
#[test]
fn hung_device_answers_failure_in_time() {
    let limits = Limits {
        max_reply_wait: Duration::from_millis(100),
        max_queue_wait: Duration::from_millis(50),
        ..Limits::DEFAULT
    };
    let d = start_custom(limits, |seen, opens| {
        factory(IDENTITY_SEED, seen, opens, 0, Duration::from_secs(30))
    });
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    let started = Instant::now();
    assert_eq!(c.call(&login("user")), FAILURE);
    // queue capacity (MAX_CLIENTS) plus one: the last ones find the queue full
    for _ in 0..=MAX_CLIENTS {
        assert_eq!(c.call(&login("user")), FAILURE);
    }
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "client was held"
    );
    assert_eq!(identities(&c.call(&[11])).len(), 1);
    assert_eq!(d.seen.visuals().len(), 1);
}

/// Credential store whose calls take `SLOW_STORE` (a locked keychain, a prompt nobody
/// answers).
struct SlowStore;

const SLOW_STORE: Duration = Duration::from_secs(30);

impl CredentialStore for SlowStore {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        std::thread::sleep(SLOW_STORE);
        Ok(None)
    }
    fn store(&self, _credential: &Credential) -> Result<(), StoreError> {
        std::thread::sleep(SLOW_STORE);
        Ok(())
    }
    fn delete(&self) -> Result<(), StoreError> {
        std::thread::sleep(SLOW_STORE);
        Ok(())
    }
}

/// Answers at once: `load` returns a credential.
struct FastStore;

impl CredentialStore for FastStore {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        Ok(Some(Credential::new(vec![7]).unwrap()))
    }
    fn store(&self, _credential: &Credential) -> Result<(), StoreError> {
        Ok(())
    }
    fn delete(&self) -> Result<(), StoreError> {
        Err(StoreError::AccessDenied("locked".into()))
    }
}

#[test]
fn credential_store_calls_are_bounded() {
    let slow = TimedStore {
        open: || Ok(SlowStore),
        timeout: Duration::from_millis(100),
    };
    let c = Credential::new(vec![1]).unwrap();
    let started = Instant::now();
    for r in [slow.load().map(|_| ()), slow.store(&c), slow.delete()] {
        assert!(
            matches!(&r, Err(StoreError::Backend(m)) if m.contains("no answer within")),
            "{r:?}"
        );
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    // A store that answers in time is passed through, errors included.
    let fast = TimedStore {
        open: || Ok(FastStore),
        timeout: Duration::from_secs(10),
    };
    assert_eq!(
        fast.load().unwrap(),
        Some(Credential::new(vec![7]).unwrap())
    );
    fast.store(&c).unwrap();
    assert!(matches!(fast.delete(), Err(StoreError::AccessDenied(_))));
    let unavailable: TimedStore<FastStore> = TimedStore {
        open: || Err(StoreError::Unavailable("no D-Bus".into())),
        timeout: Duration::from_secs(10),
    };
    assert!(matches!(
        unavailable.load(),
        Err(StoreError::Unavailable(_))
    ));
}

static WORKER_DEATHS: AtomicUsize = AtomicUsize::new(0);

fn record_worker_death() {
    WORKER_DEATHS.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn worker_death_is_fatal() {
    let limits = Limits {
        on_worker_death: record_worker_death,
        ..Limits::DEFAULT
    };
    // Opening the device panics: the worker thread ends (release builds abort).
    let d = start_custom(limits, |_, _| {
        Box::new(|| -> Result<Box<dyn Signer>, petschaft_device::Error> {
            panic!("device worker test panic")
        })
    });
    let mut c = Client::connect(&d.path);
    assert_eq!(
        c.call(&session_bind(HOST_SEED, &SESSION, false, true)),
        SUCCESS
    );
    // the reply channel is dropped by the dying worker
    assert_eq!(c.call(&login("user")), FAILURE);
    assert_eq!(WORKER_DEATHS.load(Ordering::SeqCst), 1);
    // the job queue is closed
    assert_eq!(c.call(&login("user")), FAILURE);
    assert_eq!(WORKER_DEATHS.load(Ordering::SeqCst), 2);
}

#[test]
fn connection_lifetime_is_bounded() {
    let limits = Limits {
        max_connection_time: Duration::from_millis(300),
        ..Limits::DEFAULT
    };
    let d = start_custom(limits, |seen, opens| {
        factory(IDENTITY_SEED, seen, opens, 0, Duration::ZERO)
    });
    let started = Instant::now();
    let mut c = Client::connect(&d.path);
    let mut m = Vec::new();
    put_string(&mut m, &[11]);
    // a busy client (never idle) is still closed after its lifetime
    loop {
        if c.0.write_all(&m).is_err() || c.read().is_none() {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "never closed");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(started.elapsed() >= Duration::from_millis(300));
    // a silent client too (before the 120 s idle timeout)
    let mut c = Client::connect(&d.path);
    assert!(c.closed());
    // new connections are served
    let mut c = Client::connect(&d.path);
    assert_eq!(identities(&c.call(&[11])).len(), 1);
}

// --- pure parts ---

#[test]
fn agent_keys_and_notes() {
    let (keys, notes) = agent_keys(&config());
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name(), "desktop");
    assert_eq!(keys[0].comment, "user desktop");
    assert_eq!(keys[0].algorithm, "ssh-ed25519");
    assert_eq!(keys[0].key_blob, ed_blob(IDENTITY_SEED));
    assert_eq!(notes.len(), 2);
    assert!(notes[0].contains("\"nohost\""));
    assert!(notes[1].contains("\"plain\""));
}

#[test]
fn daemon_ui_never_asks_for_a_pairing_code() {
    let e = DaemonUi.pairing_code().unwrap_err();
    assert!(e.to_string().contains("pets pair"), "{e}");
}

#[test]
fn display_safe_examples() {
    assert_eq!(display_safe("user"), "user");
    assert_eq!(display_safe("a b"), "a\\u{20}b");
    assert_eq!(display_safe("\u{1b}[31m"), "\\u{1b}[31m");
    assert_eq!(
        display_safe(&"x".repeat(40)),
        format!("{}...", "x".repeat(32))
    );
    assert_eq!(display_safe(""), "");
}

#[test]
fn challenge_visual_example() {
    let host = Fingerprint::parse("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU").unwrap();
    assert_eq!(
        challenge_visual("user", "desktop", &host),
        "ssh login user (desktop) 47DEQpj8"
    );
}

#[test]
fn startup_summary_names_config_and_identities() {
    let (keys, _) = agent_keys(&config());
    assert_eq!(
        startup_summary(Path::new("/c/config.toml"), &keys),
        "config /c/config.toml: 1 identity offered (desktop)"
    );
    assert_eq!(
        startup_summary(Path::new("/c/config.toml"), &[]),
        "config /c/config.toml: 0 identities offered ()"
    );
}

#[test]
fn log_limiter_allows_ten_per_minute_then_reports() {
    let t0 = Instant::now();
    let mut l = LogLimiter::new(t0);
    for _ in 0..NOISY_PER_WINDOW {
        assert_eq!(l.admit(t0), (None, true));
    }
    for i in 1..=5 {
        let t = t0 + Duration::from_secs(i);
        assert_eq!(l.admit(t), (None, false));
    }
    // a new window: the suppressed count is reported once, then logging resumes
    let t1 = t0 + NOISY_WINDOW;
    assert_eq!(l.admit(t1), (Some(5), true));
    assert_eq!(l.admit(t1), (None, true));
    // a quiet window reports nothing
    assert_eq!(l.admit(t1 + NOISY_WINDOW), (None, true));
}

proptest! {
    /// The device text is always printable ASCII within the protocol limit.
    #[test]
    fn display_safe_is_printable_and_bounded(s in any::<String>()) {
        let out = display_safe(&s);
        prop_assert!(out.bytes().all(|b| b.is_ascii_graphic()));
        prop_assert!(out.len() <= MAX_USER_CHARS + 3);
        if s.len() <= MAX_USER_CHARS && s.bytes().all(|b| b.is_ascii_graphic()) {
            prop_assert_eq!(out, s);
        }
    }

    /// The whole login text: printable ASCII (single spaces as separators), within
    /// the 128-character protocol limit, for any user, any host key and the longest name.
    #[test]
    fn challenge_visual_is_display_safe(user in any::<String>(), blob in any::<Vec<u8>>()) {
        let host = Fingerprint::of_openssh_blob(&blob);
        let v = challenge_visual(&user, &"a".repeat(32), &host);
        prop_assert!(v.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
        prop_assert!(v.len() <= 128);
        prop_assert!(v.ends_with(&host.as_str()[7..15]));
    }
}

// --- socket ---

#[test]
fn socket_paths() {
    let p = socket::socket_path_from(false, Some("/run/user/1000".into()), Some("/home/a".into()));
    assert_eq!(p.unwrap(), Path::new("/run/user/1000/petschaft/agent.sock"));
    for xdg in [None, Some("".into()), Some("relative".into())] {
        let e = socket::socket_path_from(false, xdg, Some("/home/a".into())).unwrap_err();
        assert!(e.to_string().contains("XDG_RUNTIME_DIR"), "{e}");
    }
    let p = socket::socket_path_from(true, Some("/run/user/1".into()), Some("/home/a".into()));
    assert_eq!(
        p.unwrap(),
        Path::new("/home/a/Library/Application Support/petschaft/agent.sock")
    );
    assert!(socket::socket_path_from(true, None, None).is_err());
    assert!(socket::socket_path_from(true, None, Some("rel".into())).is_err());
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn bind_creates_private_dir_and_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock_dir = dir.path().join("petschaft");
    let path = sock_dir.join("agent.sock");
    let _l = bind(&path).unwrap();
    assert_eq!(mode(&sock_dir), 0o700);
    assert_eq!(mode(&path), 0o600);
    // only the socket is left behind (no temporary file)
    let entries: Vec<_> = std::fs::read_dir(&sock_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    // a second agent on the same path is refused while the first listens
    let e = bind(&path).unwrap_err();
    assert!(e.to_string().contains("already listening"), "{e}");
    assert_eq!(std::fs::read_dir(&sock_dir).unwrap().count(), 1);
}

#[test]
fn bind_replaces_a_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("agent.sock");
    let old = UnixListener::bind(&path).unwrap();
    drop(old); // the file stays: a stale socket, as after SIGTERM
    assert!(path.exists());
    let l = bind(&path).unwrap();
    // the new socket is the one at the path
    let _c = UnixStream::connect(&path).unwrap();
    l.set_nonblocking(true).unwrap();
    assert!(l.accept().is_ok());
}

#[test]
fn bind_refuses_unsafe_locations() {
    let dir = tempfile::tempdir().unwrap();
    // group/other-accessible directory
    let open = dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o750)).unwrap();
    let e = bind(&open.join("agent.sock")).unwrap_err();
    assert!(e.to_string().contains("chmod 700"), "{e}");
    assert!(!open.join("agent.sock").exists());

    // symlinked directory
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let e = bind(&link.join("agent.sock")).unwrap_err();
    assert!(e.to_string().contains("not a directory"), "{e}");

    // a regular file at the socket path is never removed
    let file = real.join("agent.sock");
    std::fs::write(&file, b"keep").unwrap();
    let e = bind(&file).unwrap_err();
    assert!(e.to_string().contains("not a socket"), "{e}");
    assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 1);

    // relative path, missing parent of the socket directory
    assert!(bind(Path::new("agent.sock")).is_err());
    assert!(bind(&dir.path().join("a").join("b").join("agent.sock")).is_err());

    // owner check: the directory must be owned by us (uid of our own socket)
    let ok = dir.path().join("ok");
    let _l = bind(&ok.join("agent.sock")).unwrap();
    assert_eq!(
        std::fs::metadata(&ok).unwrap().uid(),
        std::fs::metadata(ok.join("agent.sock")).unwrap().uid()
    );
}
