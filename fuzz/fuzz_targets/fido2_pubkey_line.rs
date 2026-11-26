//! `petschaft_fido2::PublicKeyLine::parse` (`<key>.pub` written by ssh-keygen).
//! Invariant: `parse(to_line(k)) == k`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_fido2::PublicKeyLine;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(k) = PublicKeyLine::parse(s) {
        let line = k.to_line();
        assert_eq!(
            PublicKeyLine::parse(&line).expect("to_line must re-parse"),
            k
        );
        assert!(k.fingerprint().starts_with("SHA256:"));
        assert!(
            k.application().starts_with("ssh:"),
            "application {:?}",
            k.application()
        );
    }
});
