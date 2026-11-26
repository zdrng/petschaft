//! `PublicKey::from_device` + `verify_identity_signature` on device-supplied bytes.
//! Input: 1 selector byte (bit 0: curve, bit 1: proto), 33 key bytes, 65 signature
//! bytes, the rest is `challenge_hidden`. Invariant: nothing verifies. The fuzzer holds
//! no private key, so an accepted signature would be a forgery (or a verifier bug).
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_core::{Curve, Proto, PublicKey, verify_identity_signature};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let curve = if sel & 1 == 0 {
        Curve::Ed25519
    } else {
        Curve::Nist256p1
    };
    let proto = if sel & 2 == 0 { Proto::Ssh } else { Proto::Gpg };
    let key_bytes = rest.get(..33).unwrap_or(rest);
    let Ok(key) = PublicKey::from_device(curve, key_bytes) else {
        return;
    };
    assert_eq!(key.curve(), curve);
    // The OpenSSH encodings of a device key round-trip.
    let blob = key.openssh_blob();
    assert_eq!(PublicKey::from_openssh_blob(&blob).expect("own blob"), key);
    assert_eq!(
        PublicKey::from_openssh_line(&key.openssh_line("c")).expect("own line"),
        key
    );
    let _ = key.fingerprint();

    let rest = rest.get(33..).unwrap_or_default();
    let (sig, challenge) = rest.split_at(rest.len().min(65));
    let result = verify_identity_signature(proto, &key, challenge, sig);
    assert!(
        result.is_err(),
        "a fuzzer-made signature verified: {result:?}"
    );
});
