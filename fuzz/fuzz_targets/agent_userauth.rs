//! `petschaft_agent::parse_userauth` directly on sign-request data (the bytes a client
//! asks the agent to sign). Invariants: SSHSIG data is never a userauth; the bounds of
//! the parsed fields hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_agent::parse_userauth;

fuzz_target!(|data: &[u8]| {
    if let Ok(auth) = parse_userauth(data) {
        assert!(!data.starts_with(b"SSHSIG"));
        assert!(!auth.session_id.is_empty() && auth.session_id.len() <= 128);
        assert!(!auth.user.is_empty() && !auth.user.chars().any(char::is_control));
        assert!(!auth.algorithm.is_empty() && auth.algorithm.bytes().all(|b| b.is_ascii_graphic()));
        assert!(!auth.key_blob.is_empty());
    }
});
