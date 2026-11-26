//! `petschaft_sshsig::KeyLine::parse` (the key line git passes to `pets`).
//! Invariants: only the two supported algorithms, and the blob starts with
//! `string algorithm`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_sshsig::KeyLine;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(k) = KeyLine::parse(s) {
        assert!(k.algorithm == "ssh-ed25519" || k.algorithm == "ecdsa-sha2-nistp256");
        let mut prefix = u32::try_from(k.algorithm.len())
            .expect("short")
            .to_be_bytes()
            .to_vec();
        prefix.extend_from_slice(k.algorithm.as_bytes());
        assert!(k.blob.starts_with(&prefix));
        assert!(k.comment.as_deref() != Some(""));
        let _ = k.fingerprint();
    }
});
