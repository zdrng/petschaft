//! `PublicKey::from_openssh_line` (pinned keys, `pets` input) and
//! `PublicKey::from_openssh_blob`. Invariants: an accepted blob is canonical
//! (`openssh_blob() == input`); a key re-parses from its own line; its fingerprint parses.
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_core::{Fingerprint, PublicKey};

fn check(key: &PublicKey) {
    assert_eq!(
        PublicKey::from_openssh_line(&key.openssh_line("")).expect("own line"),
        *key
    );
    assert_eq!(
        PublicKey::from_openssh_blob(&key.openssh_blob()).expect("own blob"),
        *key
    );
    let fp = key.fingerprint();
    assert_eq!(
        Fingerprint::parse(fp.as_str()).expect("own fingerprint"),
        fp
    );
    assert!(key.check_fingerprint(&fp).is_ok());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = PublicKey::from_openssh_blob(data) {
        assert_eq!(key.openssh_blob(), data, "accepted blob is not canonical");
        check(&key);
    }
    if let Ok(line) = std::str::from_utf8(data) {
        if let Ok(key) = PublicKey::from_openssh_line(line) {
            assert!(line.starts_with(key.openssh_algorithm()));
            check(&key);
        }
    }
});
