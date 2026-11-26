//! `Identity::parse(uri, index)`. Input: 4 bytes big-endian index, then the URI.
//! Invariant: `parse(to_uri(id), index) == id`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_core::Identity;

fuzz_target!(|data: &[u8]| {
    let Some((index, uri)) = data.split_first_chunk::<4>() else {
        return;
    };
    let index = u32::from_be_bytes(*index);
    let Ok(uri) = std::str::from_utf8(uri) else {
        return;
    };
    if let Ok(id) = Identity::parse(uri, index) {
        let back = Identity::parse(&id.to_uri(), id.index()).expect("to_uri must re-parse");
        assert_eq!(back, id);
        assert_eq!(id.index(), index);
        let _ = id.slip13_path();
    }
});
