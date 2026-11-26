//! Helper protocol: a byte stream of frames (`read_frame`), each payload decoded as both
//! a host and a helper message. Invariant: an accepted frame is written back identically.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use petschaft_helper_proto::{
    decode_helper_message, decode_host_message, encode_helper_message, encode_host_message,
    read_frame, write_frame,
};

fuzz_target!(|data: &[u8]| {
    let mut r = Cursor::new(data);
    // Each iteration consumes at least the 4-byte header or ends the loop.
    while let Ok(Some(payload)) = read_frame(&mut r) {
        let mut out = Vec::new();
        write_frame(&mut out, &payload).expect("a read frame must be writable");
        let again = read_frame(&mut Cursor::new(&out)).expect("re-read");
        assert_eq!(again.as_deref(), Some(payload.as_slice()));

        if let Ok(msg) = decode_host_message(&payload) {
            let enc = encode_host_message(&msg).expect("a decoded host message must encode");
            assert_eq!(decode_host_message(&enc).expect("re-decode"), msg);
        }
        if let Ok(msg) = decode_helper_message(&payload) {
            let enc = encode_helper_message(&msg).expect("a decoded helper message must encode");
            assert_eq!(decode_helper_message(&enc).expect("re-decode"), msg);
        }
    }
});
