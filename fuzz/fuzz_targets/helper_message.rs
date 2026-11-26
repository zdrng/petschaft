//! Helper protocol: one frame payload (JSON) decoded as a host and as a helper message.
//! Invariant: decode -> encode -> decode is the identity, and encoding is stable.
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_helper_proto::{
    decode_helper_message, decode_host_message, encode_helper_message, encode_host_message,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = decode_host_message(data) {
        let enc = encode_host_message(&msg).expect("a decoded host message must encode");
        let back = decode_host_message(&enc).expect("re-decode");
        assert_eq!(back, msg);
        assert_eq!(encode_host_message(&back).expect("re-encode"), enc);
    }
    if let Ok(msg) = decode_helper_message(data) {
        let enc = encode_helper_message(&msg).expect("a decoded helper message must encode");
        let back = decode_helper_message(&enc).expect("re-decode");
        assert_eq!(back, msg);
        assert_eq!(encode_helper_message(&back).expect("re-encode"), enc);
    }
});
