//! One ssh-agent connection as the daemon handles it: a byte stream of messages
//! (`read_message`), each parsed (`parse_request`); verified session-binds are recorded,
//! sign requests go through `parse_userauth` and `authorize` with the parsed values.
//! The identity key is the requested key and the pinned host keys are the fingerprints
//! of all bound host keys, so `authorize` can succeed (seeds from real OpenSSH captures).
//! Invariant: whenever `authorize` says Ok, every documented rule holds.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use petschaft_agent::{
    Request, SessionBind, authorize, parse_request, parse_userauth, read_message, write_message,
};

/// Upper bound on messages per input (keeps a single run fast).
const MAX_MESSAGES: usize = 64;

fuzz_target!(|data: &[u8]| {
    let mut r = Cursor::new(data);
    let mut bindings: Vec<SessionBind> = Vec::new();
    for _ in 0..MAX_MESSAGES {
        let Ok(Some(body)) = read_message(&mut r) else {
            break;
        };
        // Framing round-trip.
        let mut framed = Vec::new();
        write_message(&mut framed, &body).expect("a read message must be writable");
        assert_eq!(
            read_message(&mut Cursor::new(&framed)),
            Ok(Some(body.clone()))
        );

        let Ok(request) = parse_request(&body) else {
            break; // the daemon closes the connection on a protocol error
        };
        match request {
            Request::SessionBind(bind) => {
                assert!(!bind.session_id().is_empty() && bind.session_id().len() <= 128);
                bindings.push(bind);
            }
            Request::Sign { key_blob, data, .. } => {
                let Ok(auth) = parse_userauth(&data) else {
                    continue;
                };
                assert!(!data.starts_with(b"SSHSIG"));
                let pins: Vec<_> = bindings
                    .iter()
                    .map(SessionBind::host_key_fingerprint)
                    .collect();
                if authorize(&bindings, &auth, &key_blob, &pins).is_ok() {
                    let last = bindings.last().expect("authorized without a binding");
                    assert!(bindings.iter().all(|b| !b.is_forwarding()));
                    assert_eq!(auth.session_id, last.session_id());
                    assert_eq!(auth.key_blob, key_blob);
                    assert!(pins.contains(&last.host_key_fingerprint()));
                    // Unpinned host: always denied.
                    assert!(authorize(&bindings, &auth, &key_blob, &[]).is_err());
                }
                // No binding: always denied.
                assert!(authorize(&[], &auth, &key_blob, &pins).is_err());
            }
            Request::RequestIdentities
            | Request::InvalidSessionBind(_)
            | Request::Unsupported(_) => {}
        }
    }
});
