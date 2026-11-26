//! `Fingerprint::parse` (config pins). Invariant: exact, so the accepted text is kept
//! byte for byte and re-parses to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_core::Fingerprint;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(fp) = Fingerprint::parse(s) {
        assert_eq!(fp.as_str(), s);
        assert_eq!(fp.to_string(), s);
        assert_eq!(Fingerprint::parse(fp.as_str()).expect("re-parse"), fp);
    }
});
