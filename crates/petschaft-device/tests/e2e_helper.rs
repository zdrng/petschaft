//! End to end: `HelperSigner` against the real Python helper.
//!
//! `helper/fake_helper.py` runs the real `petschaft_helper.main` (framing, validation, state
//! machine, stdout isolation) with the test-only `FakeDevice`, which pairs with code
//! `620567` and signs for real with fixed keys in the device formats. The production
//! entry point `helper/petschaft_helper.py` has no switch that selects the fake.
//!
//! Needs `PETSCHAFT_HELPER_PYTHON` (set at build time by the flake, or at run time in
//! `nix develop`); without it the tests fail instead of silently skipping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use petschaft_core::{Config, Curve, Fingerprint, PublicKey, Slip13Identity, Transport};
use petschaft_device::{
    ConnectOptions, Credential, CredentialStore, Error, HelperPaths, HelperSigner, NoStore,
    SignRequest, Signer as _, StoreError, Ui,
};

/// Constants of `helper/fake_helper.py`.
const PAIRING_CODE: &str = "620567";
const CANCEL_VISUAL: &str = "fake: reject";

fn paths() -> HelperPaths {
    let python = option_env!("PETSCHAFT_HELPER_PYTHON")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("PETSCHAFT_HELPER_PYTHON").map(PathBuf::from))
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| {
            panic!(
                "PETSCHAFT_HELPER_PYTHON is not set to an absolute path (neither at build time nor \
                 at run time); run the tests via `nix develop -c cargo nextest run` or \
                 `nix flake check`"
            )
        });
    let script = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../helper/fake_helper.py"
    ));
    assert!(
        script.is_file(),
        "{} is missing (is helper/ part of the build source?)",
        script.display()
    );
    HelperPaths { python, script }
}

#[derive(Default)]
struct TestUi {
    codes: AtomicUsize,
    buttons: AtomicUsize,
}

impl Ui for TestUi {
    fn confirm_on_device(&self) {
        self.buttons.fetch_add(1, Ordering::SeqCst);
    }
    fn pairing_code(&self) -> Result<String, Error> {
        self.codes.fetch_add(1, Ordering::SeqCst);
        Ok(PAIRING_CODE.to_owned())
    }
}

/// In-memory credential store (test only; production uses the OS secret store).
#[derive(Default)]
struct MemoryStore(Mutex<Option<Credential>>);

impl CredentialStore for MemoryStore {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn store(&self, credential: &Credential) -> Result<(), StoreError> {
        *self.0.lock().unwrap() = Some(credential.clone());
        Ok(())
    }
    fn delete(&self) -> Result<(), StoreError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

fn spawn<'a>(ui: &'a TestUi, store: &dyn CredentialStore) -> HelperSigner<&'a TestUi> {
    HelperSigner::spawn(
        &paths(),
        &ConnectOptions::new("e2e-host", Transport::Auto),
        ui,
        store,
    )
    .unwrap()
}

/// A slip13 identity from the config parser (the only way to get one).
fn identity(uri: &str, curve: Curve, pin: Option<&Fingerprint>) -> Slip13Identity {
    let mut toml = format!(
        "[[identity]]\nname = \"e2e\"\nuri = \"{uri}\"\ncurve = \"{}\"\npassphrase = \"standard\"\n",
        curve.as_str()
    );
    if let Some(pin) = pin {
        toml.push_str(&format!("fingerprint = \"{pin}\"\n"));
    }
    Config::from_toml_str(&toml)
        .unwrap()
        .slip13("e2e")
        .unwrap()
        .clone()
}

fn request(uri: &str, curve: Curve, challenge: &[u8], visual: &str) -> SignRequest {
    SignRequest::for_identity(
        &identity(uri, curve, None),
        challenge.to_vec(),
        visual.to_owned(),
    )
}

/// The fake's keys, derived independently: Ed25519 seed 0x00..0x1f, P-256 scalar 0x01..0x20.
fn ed25519_key() -> PublicKey {
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    PublicKey::from_device(Curve::Ed25519, &[&[0u8][..], vk.as_bytes()].concat()).unwrap()
}

fn p256_key() -> PublicKey {
    let scalar: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let sk = p256::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let point = sk.verifying_key().to_sec1_point(true);
    PublicKey::from_device(Curve::Nist256p1, point.as_bytes()).unwrap()
}

#[test]
fn pairing_stores_credential_and_second_spawn_reuses_it() {
    let store = MemoryStore::default();

    let ui = TestUi::default();
    let signer = spawn(&ui, &store);
    assert_eq!(ui.codes.load(Ordering::SeqCst), 1);
    assert_eq!(ui.buttons.load(Ordering::SeqCst), 1); // "pair with this app?"
    assert!(signer.store_warning().is_none());
    let device = signer.device();
    assert_eq!(
        (device.model.as_str(), device.internal_model.as_str()),
        ("Safe 7", "T3W1")
    );
    assert_eq!(device.firmware, "2.13.1");
    drop(signer);
    let stored = store
        .load()
        .unwrap()
        .expect("credential stored after pairing");
    // Opaque to Rust, but the helper's layout is pubkey(32) || privkey(32) || credential.
    assert_eq!(stored.as_bytes().len(), 32 + 32 + b"fake-credential".len());

    let ui = TestUi::default();
    let mut signer = spawn(&ui, &store);
    assert_eq!(
        ui.codes.load(Ordering::SeqCst),
        0,
        "known credential: no pairing"
    );
    assert!(signer.store_warning().is_none());
    assert_eq!(store.load().unwrap(), Some(stored));
    let req = request(
        "ssh://user@homelab",
        Curve::Ed25519,
        b"challenge",
        "pets: e2e",
    );
    signer.sign_identity(&req).unwrap();
}

#[test]
fn real_signatures_verify_for_every_data_rule() {
    let ui = TestUi::default();
    let mut signer = spawn(&ui, &NoStore);
    let digest = [0x5a; 32];
    let cases = [
        (
            "ssh://user@homelab",
            Curve::Ed25519,
            &b"ssh raw challenge"[..],
            ed25519_key(),
        ),
        (
            "ssh://user@homelab:2222",
            Curve::Nist256p1,
            &[7u8; 300][..],
            p256_key(),
        ),
        (
            "gpg://user@example.org",
            Curve::Nist256p1,
            &digest[..],
            p256_key(),
        ),
        (
            "gpg://user@example.org",
            Curve::Ed25519,
            &b"gpg raw"[..],
            ed25519_key(),
        ),
    ];
    for (uri, curve, challenge, expected) in cases {
        let req = request(uri, curve, challenge, "pets: e2e");
        let before = ui.buttons.load(Ordering::SeqCst);
        let signed = signer
            .sign_identity(&req)
            .unwrap_or_else(|e| panic!("{uri} {curve:?}: {e}"));
        // `Ok` means `SignedIdentity::from_device` verified the signature locally.
        assert_eq!(signed.public_key(), &expected, "{uri} {curve:?}");
        assert_eq!(ui.buttons.load(Ordering::SeqCst), before + 1);
    }
    assert!(signer.is_open());
}

#[test]
fn pinned_fingerprint_is_enforced() {
    let ui = TestUi::default();
    let mut signer = spawn(&ui, &NoStore);
    let pinned = |pin: &Fingerprint| {
        SignRequest::for_identity(
            &identity("ssh://user@homelab", Curve::Ed25519, Some(pin)),
            b"challenge".to_vec(),
            "pets: pin".to_owned(),
        )
    };

    signer
        .sign_identity(&pinned(&ed25519_key().fingerprint()))
        .unwrap();

    let wrong = p256_key().fingerprint();
    match signer.sign_identity(&pinned(&wrong)) {
        Err(Error::Verification(petschaft_core::Error::FingerprintMismatch {
            expected,
            actual,
        })) => {
            assert_eq!(expected, wrong);
            assert_eq!(actual, ed25519_key().fingerprint());
        }
        other => panic!("expected a fingerprint mismatch, got {other:?}"),
    }
    assert!(signer.is_open());
}

#[test]
fn cancelled_on_device_is_not_fatal() {
    let ui = TestUi::default();
    let mut signer = spawn(&ui, &NoStore);
    let rejected = request("ssh://user@homelab", Curve::Ed25519, b"c", CANCEL_VISUAL);
    assert!(matches!(
        signer.sign_identity(&rejected),
        Err(Error::Cancelled)
    ));
    assert!(signer.is_open());
    let req = request("ssh://user@homelab", Curve::Ed25519, b"c", "pets: again");
    assert_eq!(
        signer.sign_identity(&req).unwrap().public_key(),
        &ed25519_key()
    );
}
