//! `Apk::parse` on arbitrary bytes (the input APK of `pets apk sign` is untrusted), then
//! everything `pets apk sign` does before asking the device: alignment check, signing
//! block removal, alignment and the content digest. Signing itself needs a key and is
//! covered by the crate's tests (verification is never switched off for fuzzing).
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_apk::{Apk, Error};

fuzz_target!(|data: &[u8]| {
    let Ok(mut apk) = Apk::parse(data) else {
        return;
    };
    assert!(!apk.is_empty());
    let _ = apk.is_aligned();
    let digest = apk.content_digest();
    if apk.has_signing_block() {
        // A signed APK is never digested (or signed) without the explicit removal.
        assert!(matches!(digest, Err(Error::SigningBlockPresent)));
        assert!(apk.remove_signing_block());
        let _ = apk.content_digest();
    }
    let _ = apk.is_aligned();
    if apk.align().is_ok() {
        // Alignment reaches a fixed point: aligned afterwards, and aligning again
        // changes nothing.
        assert!(matches!(apk.is_aligned(), Ok(true)));
        let once = apk.content_digest().ok();
        apk.align().expect("align is idempotent");
        assert_eq!(apk.content_digest().ok(), once);
    }
});
