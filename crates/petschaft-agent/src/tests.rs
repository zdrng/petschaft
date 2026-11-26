//! Tests: framing, request parsing, session-bind verification, userauth parsing, the
//! signing policy and the response encodings. Real-world vectors from OpenSSH are in
//! `test_vectors.rs`; everything else uses software keys (no device, no ~/.ssh).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::io::{self, Cursor, Read};

use ed25519_dalek::Signer as _;
use petschaft_core::{Curve, Proto, PublicKey, verify_identity_signature};
use proptest::prelude::*;

use super::*;
use crate::test_vectors::CAPTURES;

// ---------------------------------------------------------------------------------------
// Independent test encoders (deliberately not the crate's own helpers)
// ---------------------------------------------------------------------------------------

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn string(data: &[u8]) -> Vec<u8> {
    let mut v = (data.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Minimal mpint written the long way, for comparing against `put_mpint`.
fn mpint_ref(be: &[u8]) -> Vec<u8> {
    let mut d: Vec<u8> = be.iter().copied().skip_while(|&b| b == 0).collect();
    if d.first().is_some_and(|&b| b >= 0x80) {
        d.insert(0, 0);
    }
    string(&d)
}

fn ed_key(seed: [u8; 32]) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn p256_key(seed: [u8; 32]) -> Option<p256::ecdsa::SigningKey> {
    p256::ecdsa::SigningKey::from_slice(&seed).ok()
}

fn ed_blob(pk: &[u8; 32]) -> Vec<u8> {
    cat(&[&string(b"ssh-ed25519"), &string(pk)])
}

fn p256_blob(vk: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
    let point = vk.to_sec1_point(false);
    cat(&[
        &string(b"ecdsa-sha2-nistp256"),
        &string(b"nistp256"),
        &string(point.as_bytes()),
    ])
}

fn ed_sig_blob(sig: &[u8]) -> Vec<u8> {
    cat(&[&string(b"ssh-ed25519"), &string(sig)])
}

fn p256_sig_blob_raw(r: &[u8], s: &[u8]) -> Vec<u8> {
    cat(&[
        &string(b"ecdsa-sha2-nistp256"),
        &string(&cat(&[&string(r), &string(s)])),
    ])
}

fn p256_sig_blob(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    cat(&[
        &string(b"ecdsa-sha2-nistp256"),
        &string(&cat(&[&mpint_ref(r), &mpint_ref(s)])),
    ])
}

fn split_rs(sig: &p256::ecdsa::Signature) -> ([u8; 32], [u8; 32]) {
    let bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    (r, s)
}

/// A software host key standing in for a server.
enum Host {
    Ed(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Host {
    fn blob(&self) -> Vec<u8> {
        match self {
            Host::Ed(k) => ed_blob(k.verifying_key().as_bytes()),
            Host::P256(k) => p256_blob(k.verifying_key()),
        }
    }
    /// The server's KEX signature over the session identifier, as an SSH signature blob.
    fn sign(&self, sid: &[u8]) -> Vec<u8> {
        match self {
            Host::Ed(k) => ed_sig_blob(&k.sign(sid).to_bytes()),
            Host::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(sid);
                let (r, s) = split_rs(&sig);
                p256_sig_blob(&r, &s)
            }
        }
    }
}

fn ed_host() -> Host {
    Host::Ed(ed_key([3u8; 32]))
}

fn p256_host() -> Host {
    Host::P256(p256_key([5u8; 32]).unwrap())
}

/// Raw fields of a session-bind extension message.
#[derive(Debug, Clone)]
struct RawBind {
    name: Vec<u8>,
    host_key: Vec<u8>,
    sid: Vec<u8>,
    sig: Vec<u8>,
    fwd: u8,
}

impl RawBind {
    fn signed(host: &Host, sid: &[u8], fwd: bool) -> Self {
        RawBind {
            name: b"session-bind@openssh.com".to_vec(),
            host_key: host.blob(),
            sid: sid.to_vec(),
            sig: host.sign(sid),
            fwd: u8::from(fwd),
        }
    }
    fn encode(&self) -> Vec<u8> {
        cat(&[
            &[27],
            &string(&self.name),
            &string(&self.host_key),
            &string(&self.sid),
            &string(&self.sig),
            &[self.fwd],
        ])
    }
}

/// Raw fields of userauth signed data (RFC 4252 §7 / publickey-hostbound-v00).
#[derive(Debug, Clone)]
struct RawAuth {
    sid: Vec<u8>,
    msg: u8,
    user: Vec<u8>,
    service: Vec<u8>,
    method: Vec<u8>,
    has_sig: u8,
    alg: Vec<u8>,
    key: Vec<u8>,
    host_key: Option<Vec<u8>>,
}

impl RawAuth {
    fn plain(sid: &[u8], user: &str, key: &[u8]) -> Self {
        RawAuth {
            sid: sid.to_vec(),
            msg: 50,
            user: user.as_bytes().to_vec(),
            service: b"ssh-connection".to_vec(),
            method: b"publickey".to_vec(),
            has_sig: 1,
            alg: key_type(key).unwrap().to_vec(),
            key: key.to_vec(),
            host_key: None,
        }
    }
    fn hostbound(sid: &[u8], user: &str, key: &[u8], host_key: &[u8]) -> Self {
        RawAuth {
            method: b"publickey-hostbound-v00@openssh.com".to_vec(),
            host_key: Some(host_key.to_vec()),
            ..Self::plain(sid, user, key)
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut v = cat(&[
            &string(&self.sid),
            &[self.msg],
            &string(&self.user),
            &string(&self.service),
            &string(&self.method),
            &[self.has_sig],
            &string(&self.alg),
            &string(&self.key),
        ]);
        if let Some(hk) = &self.host_key {
            v.extend_from_slice(&string(hk));
        }
        v
    }
}

fn sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    cat(&[
        &[13],
        &string(key_blob),
        &string(data),
        &flags.to_be_bytes(),
    ])
}

fn bind_of(body: &[u8]) -> SessionBind {
    match parse_request(body) {
        Ok(Request::SessionBind(b)) => b,
        other => panic!("expected a verified session-bind, got {other:?}"),
    }
}

fn invalid_bind(body: &[u8]) -> &'static str {
    match parse_request(body) {
        Ok(Request::InvalidSessionBind(why)) => why,
        other => panic!("expected InvalidSessionBind, got {other:?}"),
    }
}

fn fp(blob: &[u8]) -> Fingerprint {
    Fingerprint::of_openssh_blob(blob)
}

// ---------------------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------------------

/// A reader that hands out one byte per call and interrupts before every byte.
struct Trickle {
    data: Vec<u8>,
    pos: usize,
    interrupt: bool,
}

impl Read for Trickle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        match (self.data.get(self.pos), buf.first_mut()) {
            (Some(&b), Some(slot)) => {
                *slot = b;
                self.pos += 1;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

/// A reader that claims an endless stream; counts how much was read.
struct Endless {
    header: [u8; 4],
    read: usize,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for b in buf.iter_mut() {
            *b = self.header.get(self.read).copied().unwrap_or(0xAA);
            self.read += 1;
        }
        Ok(buf.len())
    }
}

#[test]
fn read_message_eof_and_errors() {
    assert_eq!(read_message(&mut Cursor::new(Vec::new())), Ok(None));
    assert_eq!(
        read_message(&mut Cursor::new(vec![0, 0])),
        Err(Error::Protocol("truncated message length"))
    );
    assert_eq!(
        read_message(&mut Cursor::new(vec![0, 0, 0, 0])),
        Err(Error::Protocol("empty message"))
    );
    assert_eq!(
        read_message(&mut Cursor::new(vec![0, 0, 0, 3, 1, 2])),
        Err(Error::Protocol("truncated message"))
    );
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }
    assert!(matches!(read_message(&mut Broken), Err(Error::Io(_))));
}

#[test]
fn read_message_rejects_oversize_before_reading_the_body() {
    for len in [MAX_MESSAGE as u32 + 1, u32::MAX] {
        let mut r = Endless {
            header: len.to_be_bytes(),
            read: 0,
        };
        assert_eq!(
            read_message(&mut r),
            Err(Error::Protocol("message too large"))
        );
        assert_eq!(r.read, 4, "only the length may be read");
    }
    let mut r = Endless {
        header: (MAX_MESSAGE as u32).to_be_bytes(),
        read: 0,
    };
    let body = read_message(&mut r).unwrap().unwrap();
    assert_eq!(body.len(), MAX_MESSAGE);
}

#[test]
fn read_message_handles_short_and_interrupted_reads() {
    let mut data = Vec::new();
    write_message(&mut data, &[11]).unwrap();
    write_message(&mut data, b"hello").unwrap();
    let mut r = Trickle {
        data,
        pos: 0,
        interrupt: false,
    };
    assert_eq!(read_message(&mut r), Ok(Some(vec![11])));
    assert_eq!(read_message(&mut r), Ok(Some(b"hello".to_vec())));
    assert_eq!(read_message(&mut r), Ok(None));
}

#[test]
fn write_message_bounds() {
    let mut out = Vec::new();
    assert_eq!(
        write_message(&mut out, &[]),
        Err(Error::Protocol("empty message"))
    );
    assert_eq!(
        write_message(&mut out, &vec![0; MAX_MESSAGE + 1]),
        Err(Error::Protocol("message too large"))
    );
    assert!(out.is_empty(), "nothing written on error");
    write_message(&mut out, &[6]).unwrap();
    assert_eq!(out, [0, 0, 0, 1, 6]);
}

proptest! {
    #[test]
    fn framing_round_trips(bodies in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..512), 0..8)) {
        let mut wire = Vec::new();
        for b in &bodies {
            write_message(&mut wire, b).unwrap();
        }
        let mut r = Cursor::new(wire);
        for b in &bodies {
            prop_assert_eq!(read_message(&mut r), Ok(Some(b.clone())));
        }
        prop_assert_eq!(read_message(&mut r), Ok(None));
    }

    #[test]
    fn read_message_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let mut r = Cursor::new(data);
        for _ in 0..8 {
            match read_message(&mut r) {
                Ok(Some(body)) => prop_assert!(!body.is_empty() && body.len() <= MAX_MESSAGE),
                Ok(None) | Err(_) => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// parse_request
// ---------------------------------------------------------------------------------------

#[test]
fn request_identities() {
    assert_eq!(parse_request(&[11]), Ok(Request::RequestIdentities));
    assert_eq!(
        parse_request(&[11, 0]),
        Err(Error::Protocol("trailing bytes"))
    );
    assert_eq!(parse_request(&[]), Err(Error::Protocol("empty message")));
}

#[test]
fn everything_else_is_unsupported() {
    for t in 0..=255u8 {
        if [11, 13, 27].contains(&t) {
            continue;
        }
        // Add/remove identities, lock/unlock, smartcard, ... (draft-miller-ssh-agent §6.1).
        assert_eq!(
            parse_request(&[t, 1, 2, 3]),
            Ok(Request::Unsupported(t)),
            "{t}"
        );
    }
    for name in [
        &b"query"[..],
        b"session-bind@openssh.co",
        b"session-bind@openssh.comX",
        b"SESSION-BIND@OPENSSH.COM",
        b"",
    ] {
        let body = cat(&[&[27], &string(name), b"whatever"]);
        assert_eq!(parse_request(&body), Ok(Request::Unsupported(27)));
    }
    assert_eq!(
        parse_request(&[27, 0, 0, 0, 9, b'a']),
        Err(Error::Protocol("bad extension request"))
    );
}

#[test]
fn sign_request_strictness() {
    let good = sign_request(b"key", b"data", 7);
    assert_eq!(
        parse_request(&good),
        Ok(Request::Sign {
            key_blob: b"key".to_vec(),
            data: b"data".to_vec(),
            flags: 7
        })
    );
    // Every proper prefix is truncated; one extra byte is trailing.
    for n in 1..good.len() {
        assert_eq!(
            parse_request(&good[..n]),
            Err(Error::Protocol("bad sign request"))
        );
    }
    assert_eq!(
        parse_request(&cat(&[&good, &[0]])),
        Err(Error::Protocol("bad sign request"))
    );
    // A length larger than the rest of the message.
    assert_eq!(
        parse_request(&[13, 0xff, 0xff, 0xff, 0xff, 1, 2, 3]),
        Err(Error::Protocol("bad sign request"))
    );
}

proptest! {
    #[test]
    fn sign_request_round_trips(
        key in prop::collection::vec(any::<u8>(), 0..300),
        data in prop::collection::vec(any::<u8>(), 0..300),
        flags in any::<u32>(),
    ) {
        prop_assert_eq!(
            parse_request(&sign_request(&key, &data, flags)),
            Ok(Request::Sign { key_blob: key, data, flags })
        );
    }

    #[test]
    fn parse_request_never_panics(body in prop::collection::vec(any::<u8>(), 0..600)) {
        let _ = parse_request(&body);
    }

    /// Structured garbage: the right message type and extension name with random contents.
    #[test]
    fn session_bind_garbage_never_panics(contents in prop::collection::vec(any::<u8>(), 0..600)) {
        let body = cat(&[&[27], &string(b"session-bind@openssh.com"), &contents]);
        prop_assert!(!matches!(parse_request(&body), Ok(Request::SessionBind(_))));
    }

    /// Well-framed session-binds with random key and signature blobs never verify.
    #[test]
    fn session_bind_random_blobs_are_refused(
        key_body in prop::collection::vec(any::<u8>(), 0..120),
        sig_body in prop::collection::vec(any::<u8>(), 0..120),
        sid in prop::collection::vec(any::<u8>(), 1..64),
        ecdsa in any::<bool>(),
    ) {
        let t: &[u8] = if ecdsa { b"ecdsa-sha2-nistp256" } else { b"ssh-ed25519" };
        let raw = RawBind {
            name: b"session-bind@openssh.com".to_vec(),
            host_key: cat(&[&string(t), &key_body]),
            sid,
            sig: cat(&[&string(t), &sig_body]),
            fwd: 0,
        };
        prop_assert!(matches!(parse_request(&raw.encode()), Ok(Request::InvalidSessionBind(_))));
    }
}

// ---------------------------------------------------------------------------------------
// session-bind@openssh.com
// ---------------------------------------------------------------------------------------

#[test]
fn session_bind_ed25519_and_p256() {
    for host in [ed_host(), p256_host()] {
        for fwd in [false, true] {
            let raw = RawBind::signed(&host, b"exchange hash", fwd);
            let b = bind_of(&raw.encode());
            assert_eq!(b.session_id(), b"exchange hash");
            assert_eq!(b.is_forwarding(), fwd);
            assert_eq!(b.host_key_fingerprint(), fp(&host.blob()));
            assert_eq!(b.host_key_blob, host.blob());
        }
    }
}

#[test]
fn session_bind_framing_errors_are_protocol_errors() {
    let good = RawBind::signed(&ed_host(), b"sid", false).encode();
    for n in 1..good.len() {
        let r = parse_request(&good[..n]);
        assert!(
            matches!(r, Err(Error::Protocol(_)) | Ok(Request::Unsupported(27))),
            "prefix {n}: {r:?}"
        );
    }
    assert_eq!(
        parse_request(&cat(&[&good, &[0]])),
        Err(Error::Protocol("bad session-bind"))
    );
    for fwd in [2u8, 0x80, 0xff] {
        let mut raw = RawBind::signed(&ed_host(), b"sid", false);
        raw.fwd = fwd;
        assert_eq!(
            parse_request(&raw.encode()),
            Err(Error::Protocol("bad session-bind"))
        );
    }
}

#[test]
fn session_bind_session_id_bounds() {
    let host = ed_host();
    assert!(bind_of(&RawBind::signed(&host, &[1; 128], false).encode()).session_id() == [1; 128]);
    assert_eq!(
        invalid_bind(&RawBind::signed(&host, &[1; 129], false).encode()),
        "session identifier length out of range"
    );
    assert_eq!(
        invalid_bind(&RawBind::signed(&host, &[], false).encode()),
        "session identifier length out of range"
    );
}

#[test]
fn session_bind_signature_must_cover_the_session_id() {
    for host in [ed_host(), p256_host()] {
        let mut raw = RawBind::signed(&host, b"session A", false);
        raw.sid = b"session B".to_vec();
        assert_eq!(
            invalid_bind(&raw.encode()),
            "host key signature does not verify"
        );
        // A valid signature by another key of the same type.
        let mut raw = RawBind::signed(&host, b"session A", false);
        raw.sig = match host {
            Host::Ed(_) => Host::Ed(ed_key([4; 32])).sign(b"session A"),
            Host::P256(_) => Host::P256(p256_key([6; 32]).unwrap()).sign(b"session A"),
        };
        assert_eq!(
            invalid_bind(&raw.encode()),
            "host key signature does not verify"
        );
    }
}

#[test]
fn session_bind_unsupported_host_key_types() {
    for t in [
        &b"ssh-rsa"[..],
        b"rsa-sha2-512",
        b"ssh-dss",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
        b"sk-ssh-ed25519@openssh.com",
        b"sk-ecdsa-sha2-nistp256@openssh.com",
        b"ssh-ed25519-cert-v01@openssh.com",
        b"",
    ] {
        let raw = RawBind {
            name: b"session-bind@openssh.com".to_vec(),
            host_key: cat(&[&string(t), &string(&[1; 32])]),
            sid: b"sid".to_vec(),
            sig: cat(&[&string(t), &string(&[2; 64])]),
            fwd: 0,
        };
        assert_eq!(
            invalid_bind(&raw.encode()),
            "unsupported host key type (only ssh-ed25519 and ecdsa-sha2-nistp256)"
        );
    }
}

#[test]
fn session_bind_signature_type_must_match_key_type() {
    let ed = ed_host();
    let p = p256_host();
    let mut raw = RawBind::signed(&ed, b"sid", false);
    raw.sig = p.sign(b"sid");
    assert_eq!(
        invalid_bind(&raw.encode()),
        "signature type does not match the host key"
    );
    let mut raw = RawBind::signed(&p, b"sid", false);
    raw.sig = ed.sign(b"sid");
    assert_eq!(
        invalid_bind(&raw.encode()),
        "signature type does not match the host key"
    );
}

#[test]
fn session_bind_malformed_ed25519_blobs() {
    let k = ed_key([3; 32]);
    let pk = *k.verifying_key().as_bytes();
    let sig = k.sign(b"sid").to_bytes();
    let base = RawBind::signed(&Host::Ed(k), b"sid", false);
    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (
            cat(&[&string(b"ssh-ed25519"), &string(&pk[..31])]),
            ed_sig_blob(&sig),
        ),
        (cat(&[&ed_blob(&pk), &[0]]), ed_sig_blob(&sig)),
        (string(b"ssh-ed25519"), ed_sig_blob(&sig)),
        (ed_blob(&pk), ed_sig_blob(&sig[..63])),
        (ed_blob(&pk), cat(&[&ed_sig_blob(&sig), &[0]])),
        (ed_blob(&pk), string(b"ssh-ed25519")),
        (ed_blob(&pk), Vec::new()),
        (Vec::new(), ed_sig_blob(&sig)),
    ];
    for (host_key, sig) in cases {
        let raw = RawBind {
            host_key,
            sig,
            ..base.clone()
        };
        assert!(
            matches!(
                parse_request(&raw.encode()),
                Ok(Request::InvalidSessionBind(_))
            ),
            "{raw:?}"
        );
    }
}

#[test]
fn session_bind_small_order_ed25519_key_is_refused() {
    // The identity point (y = 1) with the trivially "valid" signature (R = identity,
    // S = 0) verifies under the lax equation; verify_strict must refuse it.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut sig = [0u8; 64];
    sig[0] = 1;
    let raw = RawBind {
        name: b"session-bind@openssh.com".to_vec(),
        host_key: ed_blob(&identity),
        sid: b"sid".to_vec(),
        sig: ed_sig_blob(&sig),
        fwd: 0,
    };
    assert_eq!(
        invalid_bind(&raw.encode()),
        "host key signature does not verify"
    );
}

/// P-256 group order n.
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// `a - b` for 256-bit big-endian values with `a >= b`.
fn sub256(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = d as u8;
    }
    assert_eq!(borrow, 0);
    out
}

#[test]
fn session_bind_p256_signature_encodings() {
    let k = p256_key([5; 32]).unwrap();
    let host = p256_blob(k.verifying_key());
    let sig: p256::ecdsa::Signature = k.sign(b"sid");
    let (r, s) = split_rs(&sig);
    let s_flip = sub256(&P256_N, &s);
    let bind = |sig: Vec<u8>| RawBind {
        name: b"session-bind@openssh.com".to_vec(),
        host_key: host.clone(),
        sid: b"sid".to_vec(),
        sig,
        fwd: 0,
    };
    // Both S and n - S verify (OpenSSH does not require low S).
    bind_of(&bind(p256_sig_blob(&r, &s)).encode());
    bind_of(&bind(p256_sig_blob(&r, &s_flip)).encode());
    // Non-minimal mpint: an extra leading zero.
    let padded = |x: &[u8; 32]| cat(&[&[0, 0], x]);
    let cases = vec![
        p256_sig_blob_raw(&padded(&r), &mpint_ref(&s)[4..]),
        // Negative: high bit set without the 0x00.
        {
            let mut neg = r;
            neg[0] |= 0x80;
            p256_sig_blob_raw(&neg, &mpint_ref(&s)[4..])
        },
        // Zero (empty mpint), and zero encoded as "00".
        p256_sig_blob_raw(&[], &mpint_ref(&s)[4..]),
        p256_sig_blob_raw(&[0], &mpint_ref(&s)[4..]),
        // r = n (out of range) and wider than 32 bytes.
        p256_sig_blob_raw(&mpint_ref(&P256_N)[4..], &mpint_ref(&s)[4..]),
        p256_sig_blob_raw(&[1; 33], &mpint_ref(&s)[4..]),
        // Missing s, extra mpint, trailing bytes after the inner string.
        cat(&[&string(b"ecdsa-sha2-nistp256"), &string(&mpint_ref(&r))]),
        cat(&[
            &string(b"ecdsa-sha2-nistp256"),
            &string(&cat(&[&mpint_ref(&r), &mpint_ref(&s), &string(&[1])])),
        ]),
        cat(&[&p256_sig_blob(&r, &s), &[0]]),
        // Raw 64-byte r||s instead of two mpints.
        cat(&[&string(b"ecdsa-sha2-nistp256"), &string(&sig.to_bytes())]),
    ];
    for c in cases {
        assert!(
            matches!(
                parse_request(&bind(c.clone()).encode()),
                Ok(Request::InvalidSessionBind(_))
            ),
            "{c:02x?}"
        );
    }
}

#[test]
fn session_bind_malformed_p256_keys() {
    let k = p256_key([5; 32]).unwrap();
    let sig = Host::P256(k.clone()).sign(b"sid");
    let compressed = k.verifying_key().to_sec1_point(true);
    let uncompressed = k.verifying_key().to_sec1_point(false);
    let mut off_curve = uncompressed.as_bytes().to_vec();
    off_curve[64] ^= 1;
    let keys = vec![
        cat(&[
            &string(b"ecdsa-sha2-nistp256"),
            &string(b"nistp256"),
            &string(compressed.as_bytes()),
        ]),
        cat(&[
            &string(b"ecdsa-sha2-nistp256"),
            &string(b"nistp384"),
            &string(uncompressed.as_bytes()),
        ]),
        cat(&[
            &string(b"ecdsa-sha2-nistp256"),
            &string(b"nistp256"),
            &string(&off_curve),
        ]),
        cat(&[
            &string(b"ecdsa-sha2-nistp256"),
            &string(b"nistp256"),
            &string(&[0]),
        ]),
        cat(&[&p256_blob(k.verifying_key()), &[0]]),
        cat(&[&string(b"ecdsa-sha2-nistp256"), &string(b"nistp256")]),
    ];
    for host_key in keys {
        let raw = RawBind {
            name: b"session-bind@openssh.com".to_vec(),
            host_key,
            sid: b"sid".to_vec(),
            sig: sig.clone(),
            fwd: 0,
        };
        assert!(
            matches!(
                parse_request(&raw.encode()),
                Ok(Request::InvalidSessionBind(_))
            ),
            "{raw:?}"
        );
    }
}

fn host_strategy() -> impl Strategy<Value = Host> {
    prop_oneof![
        any::<[u8; 32]>().prop_map(|s| Host::Ed(ed_key(s))),
        any::<[u8; 32]>().prop_filter_map("valid p256 scalar", |s| p256_key(s).map(Host::P256)),
    ]
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Host({:02x?})", self.blob())
    }
}

proptest! {
    #[test]
    fn session_bind_round_trips(
        host in host_strategy(),
        sid in prop::collection::vec(any::<u8>(), 1..=128),
        fwd in any::<bool>(),
    ) {
        let b = bind_of(&RawBind::signed(&host, &sid, fwd).encode());
        prop_assert_eq!(b, SessionBind { host_key_blob: host.blob(), session_id: sid, is_forwarding: fwd });
    }

    /// Replacing any one field of a valid session-bind with a different value is
    /// rejected or yields a different binding (never the original).
    #[test]
    fn session_bind_field_mutations(
        host in host_strategy(),
        sid in prop::collection::vec(any::<u8>(), 1..=64),
        field in 0usize..5,
        replacement in prop::collection::vec(any::<u8>(), 0..130),
        fwd_byte in any::<u8>(),
    ) {
        let raw = RawBind::signed(&host, &sid, false);
        let original = Ok(Request::SessionBind(bind_of(&raw.encode())));
        let mut m = raw.clone();
        match field {
            0 => m.name = replacement,
            1 => m.host_key = replacement,
            2 => m.sid = replacement,
            3 => m.sig = replacement,
            _ => m.fwd = fwd_byte,
        }
        prop_assume!(m.encode() != raw.encode());
        prop_assert_ne!(parse_request(&m.encode()), original);
    }

    /// Single-byte mutations of a valid session-bind: rejected or a different binding.
    #[test]
    fn session_bind_byte_mutations(
        host in host_strategy(),
        sid in prop::collection::vec(any::<u8>(), 1..=64),
        pos in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let good = RawBind::signed(&host, &sid, false).encode();
        let original = parse_request(&good);
        let mut m = good.clone();
        let i = pos.index(m.len());
        m[i] ^= xor;
        prop_assert_ne!(parse_request(&m), original);
    }
}

// ---------------------------------------------------------------------------------------
// Real OpenSSH vectors
// ---------------------------------------------------------------------------------------

struct Parsed {
    bind: SessionBind,
    key_blob: Vec<u8>,
    data: Vec<u8>,
    auth: UserAuth,
}

fn parse_capture(c: &crate::test_vectors::Capture) -> Parsed {
    let bind = bind_of(&hex(c.session_bind));
    let Ok(Request::Sign {
        key_blob,
        data,
        flags,
    }) = parse_request(&hex(c.sign_request))
    else {
        panic!("{}: sign request did not parse", c.name);
    };
    assert_eq!(flags, 0, "{}", c.name);
    let auth = parse_userauth(&data).unwrap();
    Parsed {
        bind,
        key_blob,
        data,
        auth,
    }
}

#[test]
fn openssh_vectors_parse_and_authorize() {
    for c in CAPTURES {
        let p = parse_capture(c);
        let pin = Fingerprint::parse(c.host_fp).unwrap();
        // The binding: verified signature, fingerprint as printed by ssh-keygen.
        assert_eq!(p.bind.host_key_fingerprint(), pin, "{}", c.name);
        assert!(!p.bind.is_forwarding(), "{}", c.name);
        // The userauth data: hostbound variant, same session, same key, same host.
        assert_eq!(p.auth.user, "nobody");
        assert_eq!(p.auth.session_id, p.bind.session_id());
        assert_eq!(p.auth.key_blob, p.key_blob);
        assert_eq!(
            p.auth.server_host_key.as_deref(),
            Some(&p.bind.host_key_blob[..])
        );
        assert_eq!(key_type(&p.key_blob), Some(p.auth.algorithm.as_bytes()));
        // Re-encoding the parsed fields reproduces the captured data exactly.
        let mut raw = RawAuth::hostbound(
            &p.auth.session_id,
            &p.auth.user,
            &p.auth.key_blob,
            &p.bind.host_key_blob,
        );
        raw.alg = p.auth.algorithm.as_bytes().to_vec();
        assert_eq!(raw.encode(), p.data, "{}", c.name);

        let binds = [p.bind.clone()];
        assert_eq!(
            authorize(&binds, &p.auth, &p.key_blob, std::slice::from_ref(&pin)),
            Ok(())
        );
        let other_pin = Fingerprint::of_openssh_blob(b"other host");
        assert_eq!(
            authorize(&binds, &p.auth, &p.key_blob, &[other_pin]),
            Err(Denied::HostNotPinned(pin.clone()))
        );
        assert_eq!(
            authorize(&[], &p.auth, &p.key_blob, std::slice::from_ref(&pin)),
            Err(Denied::NotBound)
        );
        let mut fwd = hex(c.session_bind);
        *fwd.last_mut().unwrap() = 1;
        let fwd = bind_of(&fwd);
        assert!(fwd.is_forwarding());
        assert_eq!(
            authorize(&[fwd], &p.auth, &p.key_blob, std::slice::from_ref(&pin)),
            Err(Denied::Forwarded)
        );
    }
}

#[test]
fn openssh_vectors_do_not_cross_sessions() {
    let parsed: Vec<Parsed> = CAPTURES.iter().map(parse_capture).collect();
    let pins: Vec<Fingerprint> = CAPTURES
        .iter()
        .map(|c| Fingerprint::parse(c.host_fp).unwrap())
        .collect();
    for (i, a) in parsed.iter().enumerate() {
        for (j, b) in parsed.iter().enumerate() {
            let r = authorize(std::slice::from_ref(&a.bind), &b.auth, &b.key_blob, &pins);
            if i == j {
                assert_eq!(r, Ok(()));
            } else {
                assert_eq!(r, Err(Denied::SessionMismatch), "bind {i}, auth {j}");
            }
        }
    }
}

#[test]
fn openssh_vectors_every_byte_mutation_changes_the_result() {
    for c in CAPTURES {
        let bind = hex(c.session_bind);
        let original_bind = parse_request(&bind);
        let p = parse_capture(c);
        let original_auth = parse_userauth(&p.data);
        for i in 0..bind.len() {
            for xor in [0x01u8, 0x80, 0xff] {
                let mut m = bind.clone();
                m[i] ^= xor;
                assert_ne!(parse_request(&m), original_bind, "{} bind byte {i}", c.name);
            }
        }
        for i in 0..p.data.len() {
            for xor in [0x01u8, 0x80, 0xff] {
                let mut m = p.data.clone();
                m[i] ^= xor;
                assert_ne!(
                    parse_userauth(&m),
                    original_auth,
                    "{} auth byte {i}",
                    c.name
                );
            }
        }
        for n in 0..bind.len() {
            assert!(!matches!(
                parse_request(&bind[..n]),
                Ok(Request::SessionBind(_))
            ));
        }
        for n in 0..p.data.len() {
            assert_eq!(parse_userauth(&p.data[..n]), Err(Denied::NotUserAuth));
        }
    }
}

// ---------------------------------------------------------------------------------------
// parse_userauth
// ---------------------------------------------------------------------------------------

fn id_blob() -> Vec<u8> {
    ed_blob(ed_key([1; 32]).verifying_key().as_bytes())
}

#[test]
fn userauth_plain_and_hostbound() {
    let key = id_blob();
    let raw = RawAuth::plain(b"sid", "alice", &key);
    assert_eq!(
        parse_userauth(&raw.encode()),
        Ok(UserAuth {
            session_id: b"sid".to_vec(),
            user: "alice".into(),
            algorithm: "ssh-ed25519".into(),
            key_blob: key.clone(),
            server_host_key: None,
        })
    );
    let raw = RawAuth::hostbound(b"sid", "alice", &key, b"host");
    assert_eq!(
        parse_userauth(&raw.encode()).unwrap().server_host_key,
        Some(b"host".to_vec())
    );
}

#[test]
fn userauth_rejections() {
    let key = id_blob();
    let base = RawAuth::plain(b"sid", "alice", &key);
    let hb = RawAuth::hostbound(b"sid", "alice", &key, b"host");
    let mut cases: Vec<Vec<u8>> = Vec::new();
    let mut with = |f: &dyn Fn(&mut RawAuth), from: &RawAuth| {
        let mut r = from.clone();
        f(&mut r);
        cases.push(r.encode());
    };
    with(&|r| r.sid.clear(), &base);
    with(&|r| r.sid = vec![0; 129], &base);
    with(&|r| r.msg = 51, &base);
    with(&|r| r.msg = 0, &base);
    with(&|r| r.user.clear(), &base);
    with(&|r| r.user = vec![0xff, 0xfe], &base);
    with(&|r| r.user = b"ali\nce".to_vec(), &base);
    with(&|r| r.user = b"alice\x1b[2J".to_vec(), &base);
    with(&|r| r.user = "\u{85}".as_bytes().to_vec(), &base);
    with(&|r| r.user = vec![b'a'; 257], &base);
    with(&|r| r.service = b"ssh-userauth".to_vec(), &base);
    with(&|r| r.service = b"ssh-connection\0".to_vec(), &base);
    for m in [
        &b"password"[..],
        b"hostbased",
        b"keyboard-interactive",
        b"publickey ",
        b"PUBLICKEY",
        b"publickey-hostbound@openssh.com",
        b"",
    ] {
        with(&|r| r.method = m.to_vec(), &base);
    }
    // Hostbound method without the host key, plain method with one.
    with(&|r| r.host_key = None, &hb);
    with(&|r| r.host_key = Some(b"host".to_vec()), &base);
    with(&|r| r.host_key = Some(Vec::new()), &hb);
    with(&|r| r.has_sig = 0, &base);
    with(&|r| r.has_sig = 2, &base);
    with(&|r| r.has_sig = 0xff, &base);
    with(&|r| r.alg.clear(), &base);
    with(&|r| r.alg = b"ssh ed25519".to_vec(), &base);
    with(&|r| r.alg = vec![b'a'; 65], &base);
    with(&|r| r.alg = vec![0xc3, 0xa4], &base);
    with(&|r| r.key.clear(), &base);
    with(&|r| r.key = vec![0; MAX_KEY_BLOB + 1], &base);
    for c in &cases {
        assert_eq!(parse_userauth(c), Err(Denied::NotUserAuth), "{c:02x?}");
    }
    // Trailing bytes, for both variants.
    for r in [&base, &hb] {
        assert_eq!(
            parse_userauth(&cat(&[&r.encode(), &[0]])),
            Err(Denied::NotUserAuth)
        );
    }
    // Bounds are inclusive.
    let mut edge = base.clone();
    edge.sid = vec![7; 128];
    edge.user = vec![b'u'; 256];
    edge.alg = vec![b'a'; 64];
    assert!(parse_userauth(&edge.encode()).is_ok());
}

#[test]
fn sshsig_data_is_not_userauth() {
    // PROTOCOL.sshsig signed data: "SSHSIG", string namespace, string reserved,
    // string hash_algorithm, string H(message).
    let sshsig = cat(&[
        b"SSHSIG",
        &string(b"git"),
        &string(b""),
        &string(b"sha512"),
        &string(&[0x42; 64]),
    ]);
    assert_eq!(parse_userauth(&sshsig), Err(Denied::NotUserAuth));
    assert_eq!(parse_userauth(b"SSHSIG"), Err(Denied::NotUserAuth));
    // Even a valid userauth behind the magic.
    let valid = RawAuth::plain(b"sid", "alice", &id_blob()).encode();
    assert_eq!(
        parse_userauth(&cat(&[b"SSHSIG", &valid])),
        Err(Denied::NotUserAuth)
    );
    assert_eq!(parse_userauth(&[]), Err(Denied::NotUserAuth));
}

fn user_strategy() -> impl Strategy<Value = String> {
    "[^\\p{Cc}]{1,40}".prop_filter("at most 256 bytes", |u| u.len() <= MAX_USER)
}

fn raw_auth_strategy() -> impl Strategy<Value = RawAuth> {
    (
        prop::collection::vec(any::<u8>(), 1..=128),
        user_strategy(),
        prop_oneof![Just(&b"ssh-ed25519"[..]), Just(&b"ecdsa-sha2-nistp256"[..])],
        prop::collection::vec(any::<u8>(), 1..200),
        prop::option::of(prop::collection::vec(any::<u8>(), 1..200)),
    )
        .prop_map(|(sid, user, alg, key, host_key)| {
            let mut r = match &host_key {
                Some(hk) => RawAuth::hostbound(&sid, &user, &id_blob(), hk),
                None => RawAuth::plain(&sid, &user, &id_blob()),
            };
            r.alg = alg.to_vec();
            r.key = key;
            r
        })
}

proptest! {
    #[test]
    fn userauth_round_trips(raw in raw_auth_strategy()) {
        let parsed = parse_userauth(&raw.encode()).unwrap();
        prop_assert_eq!(parsed.session_id, raw.sid);
        prop_assert_eq!(parsed.user.as_bytes(), &raw.user[..]);
        prop_assert_eq!(parsed.algorithm.as_bytes(), &raw.alg[..]);
        prop_assert_eq!(parsed.key_blob, raw.key);
        prop_assert_eq!(parsed.server_host_key, raw.host_key);
    }

    #[test]
    fn parse_userauth_never_panics(data in prop::collection::vec(any::<u8>(), 0..600)) {
        let _ = parse_userauth(&data);
    }

    /// Replacing any one field with a different value is rejected or parses differently.
    #[test]
    fn userauth_field_mutations(
        raw in raw_auth_strategy(),
        field in 0usize..9,
        bytes in prop::collection::vec(any::<u8>(), 0..140),
        byte in any::<u8>(),
    ) {
        let original = parse_userauth(&raw.encode());
        prop_assert!(original.is_ok());
        let mut m = raw.clone();
        match field {
            0 => m.sid = bytes,
            1 => m.msg = byte,
            2 => m.user = bytes,
            3 => m.service = bytes,
            4 => m.method = bytes,
            5 => m.has_sig = byte,
            6 => m.alg = bytes,
            7 => m.key = bytes,
            _ => m.host_key = if m.host_key.is_some() && byte % 2 == 0 { None } else { Some(bytes) },
        }
        prop_assume!(m.encode() != raw.encode());
        prop_assert_ne!(parse_userauth(&m.encode()), original);
    }

    #[test]
    fn userauth_byte_mutations(raw in raw_auth_strategy(), pos in any::<prop::sample::Index>(), xor in 1u8..=255) {
        let good = raw.encode();
        let original = parse_userauth(&good);
        let mut m = good.clone();
        let i = pos.index(m.len());
        m[i] ^= xor;
        prop_assert_ne!(parse_userauth(&m), original);
    }
}

// ---------------------------------------------------------------------------------------
// authorize
// ---------------------------------------------------------------------------------------

fn binding(host: &[u8], sid: &[u8], fwd: bool) -> SessionBind {
    SessionBind {
        host_key_blob: host.to_vec(),
        session_id: sid.to_vec(),
        is_forwarding: fwd,
    }
}

fn auth_for(sid: &[u8], key: &[u8], alg: &str, host_key: Option<&[u8]>) -> UserAuth {
    UserAuth {
        session_id: sid.to_vec(),
        user: "alice".into(),
        algorithm: alg.into(),
        key_blob: key.to_vec(),
        server_host_key: host_key.map(<[u8]>::to_vec),
    }
}

/// The rules of docs/agent.md, written as an independent oracle in check order.
fn oracle(
    bindings: &[SessionBind],
    auth: &UserAuth,
    identity: &[u8],
    pins: &[Fingerprint],
) -> Result<(), Denied> {
    if bindings.is_empty() {
        return Err(Denied::NotBound);
    }
    for b in bindings {
        if b.is_forwarding {
            return Err(Denied::Forwarded);
        }
    }
    let last = &bindings[bindings.len() - 1];
    let sid_ok = auth.session_id == last.session_id;
    let host_ok = match &auth.server_host_key {
        None => true,
        Some(hk) => *hk == last.host_key_blob,
    };
    if !(sid_ok && host_ok) {
        return Err(Denied::SessionMismatch);
    }
    let expected_alg = if identity.starts_with(&string(b"ssh-ed25519")) {
        "ssh-ed25519"
    } else {
        "ecdsa-sha2-nistp256"
    };
    if auth.key_blob != identity || auth.algorithm != expected_alg {
        return Err(Denied::KeyMismatch);
    }
    let f = fp(&last.host_key_blob);
    if pins.contains(&f) {
        Ok(())
    } else {
        Err(Denied::HostNotPinned(f))
    }
}

#[test]
fn authorize_exhaustive_matrix() {
    let pinned_host = ed_blob(&[0x11; 32]);
    let other_host = ed_blob(&[0x22; 32]);
    let hosts = [&pinned_host[..], &other_host[..]];
    let sids: [&[u8]; 3] = [b"session one", b"session two", b"session three"];
    let identity = id_blob();
    let other_key = ed_blob(ed_key([2; 32]).verifying_key().as_bytes());
    let pins = [fp(&pinned_host), Fingerprint::of_openssh_blob(b"unrelated")];

    // Every binding is one of 2 hosts x 2 session ids x forwarding or not.
    let mut options = Vec::new();
    for h in hosts {
        for s in &sids[..2] {
            for f in [false, true] {
                options.push(binding(h, s, f));
            }
        }
    }
    let mut lists: Vec<Vec<SessionBind>> = vec![Vec::new()];
    let mut frontier = lists.clone();
    for _ in 0..3 {
        let mut next = Vec::new();
        for l in &frontier {
            for o in &options {
                let mut l = l.clone();
                l.push(o.clone());
                next.push(l);
            }
        }
        lists.extend(next.iter().cloned());
        frontier = next;
    }
    assert_eq!(lists.len(), 1 + 8 + 64 + 512);

    let mut auths = Vec::new();
    for s in sids {
        for k in [&identity[..], &other_key[..]] {
            for alg in ["ssh-ed25519", "ecdsa-sha2-nistp256"] {
                for hk in [None, Some(&pinned_host[..]), Some(&other_host[..])] {
                    auths.push(auth_for(s, k, alg, hk));
                }
            }
        }
    }

    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for l in &lists {
        for a in &auths {
            for p in [&pins[..], &[]] {
                let got = authorize(l, a, &identity, p);
                assert_eq!(got, oracle(l, a, &identity, p), "{l:?} {a:?} {p:?}");
                let key = match &got {
                    Ok(()) => "ok".to_string(),
                    Err(Denied::HostNotPinned(_)) => "unpinned".to_string(),
                    Err(e) => format!("{e:?}"),
                };
                *outcomes.entry(key).or_default() += 1;
            }
        }
    }
    // Every outcome is actually reached by the matrix.
    for k in [
        "ok",
        "unpinned",
        "NotBound",
        "Forwarded",
        "SessionMismatch",
        "KeyMismatch",
    ] {
        assert!(
            outcomes.get(k).copied().unwrap_or(0) > 0,
            "{k} never reached: {outcomes:?}"
        );
    }
}

#[test]
fn authorize_named_scenarios() {
    let host_a = ed_blob(&[0xA; 32]);
    let host_b = ed_blob(&[0xB; 32]);
    let id = id_blob();
    let pins = [fp(&host_a)];
    let ok_auth = auth_for(b"s2", &id, "ssh-ed25519", Some(&host_a));

    // Only the last binding counts: its session id and its host key.
    let earlier_then_last = [
        binding(&host_b, b"s1", false),
        binding(&host_a, b"s2", false),
    ];
    assert_eq!(authorize(&earlier_then_last, &ok_auth, &id, &pins), Ok(()));
    let stale = auth_for(b"s1", &id, "ssh-ed25519", None);
    assert_eq!(
        authorize(&earlier_then_last, &stale, &id, &[fp(&host_a), fp(&host_b)]),
        Err(Denied::SessionMismatch)
    );
    // Earlier binding pinned, last one not.
    let last_unpinned = [
        binding(&host_a, b"s1", false),
        binding(&host_b, b"s2", false),
    ];
    assert_eq!(
        authorize(
            &last_unpinned,
            &auth_for(b"s2", &id, "ssh-ed25519", None),
            &id,
            &pins
        ),
        Err(Denied::HostNotPinned(fp(&host_b)))
    );
    // Any forwarding binding, even an earlier one, refuses.
    let fwd_earlier = [
        binding(&host_a, b"s1", true),
        binding(&host_a, b"s2", false),
    ];
    assert_eq!(
        authorize(&fwd_earlier, &ok_auth, &id, &pins),
        Err(Denied::Forwarded)
    );
    // Hostbound request naming another host than the binding.
    let bound = [binding(&host_a, b"s2", false)];
    assert_eq!(
        authorize(
            &bound,
            &auth_for(b"s2", &id, "ssh-ed25519", Some(&host_b)),
            &id,
            &pins
        ),
        Err(Denied::SessionMismatch)
    );
    // Algorithm must be the identity's key type; a garbage identity blob never matches.
    let p256_id = p256_blob(p256_key([8; 32]).unwrap().verifying_key());
    let p256_auth = auth_for(b"s2", &p256_id, "ecdsa-sha2-nistp256", None);
    assert_eq!(authorize(&bound, &p256_auth, &p256_id, &pins), Ok(()));
    let mut wrong_alg = p256_auth.clone();
    wrong_alg.algorithm = "ssh-ed25519".into();
    assert_eq!(
        authorize(&bound, &wrong_alg, &p256_id, &pins),
        Err(Denied::KeyMismatch)
    );
    let garbage = auth_for(b"s2", b"\xff\xff", "ssh-ed25519", None);
    assert_eq!(
        authorize(&bound, &garbage, b"\xff\xff", &pins),
        Err(Denied::KeyMismatch)
    );
    // Empty pin list: nothing is allowed.
    assert_eq!(
        authorize(&bound, &ok_auth, &id, &[]),
        Err(Denied::HostNotPinned(fp(&host_a)))
    );
}

// ---------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------

#[test]
fn success_and_failure() {
    assert_eq!(success(), [6]);
    assert_eq!(failure(), [5]);
}

proptest! {
    #[test]
    fn identities_answer_layout(keys in prop::collection::vec(
        (prop::collection::vec(any::<u8>(), 0..80), "\\PC{0,20}"), 0..6)
    ) {
        let body = identities_answer(&keys);
        let mut expected = vec![12];
        expected.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for (blob, comment) in &keys {
            expected.extend_from_slice(&string(blob));
            expected.extend_from_slice(&string(comment.as_bytes()));
        }
        prop_assert_eq!(body, expected);
    }

    #[test]
    fn put_mpint_matches_reference_and_round_trips(be in any::<[u8; 32]>(), zeros in 0usize..32) {
        let mut be = be;
        for b in be.iter_mut().take(zeros) {
            *b = 0;
        }
        let mut out = Vec::new();
        put_mpint(&mut out, &be);
        prop_assert_eq!(&out, &mpint_ref(&be));
        let mut r = Reader(&out);
        let m = r.string().unwrap();
        prop_assert!(r.finish().is_some());
        if be == [0; 32] {
            prop_assert!(m.is_empty());
            prop_assert_eq!(mpint_scalar(m), None);
        } else {
            prop_assert_eq!(mpint_scalar(m), Some(be));
        }
    }

    #[test]
    fn sign_response_ed25519(seed in any::<[u8; 32]>(), msg in prop::collection::vec(any::<u8>(), 0..200)) {
        let k = ed_key(seed);
        let key = PublicKey::from_device(Curve::Ed25519, &cat(&[&[0], k.verifying_key().as_bytes()])).unwrap();
        let raw = k.sign(&msg).to_bytes();
        let sig = verify_identity_signature(Proto::Ssh, &key, &msg, &cat(&[&[0], &raw])).unwrap();
        let body = sign_response(&sig);
        prop_assert_eq!(body, cat(&[&[14], &string(&ed_sig_blob(&raw))]));
    }

    #[test]
    fn sign_response_p256(seed in any::<[u8; 32]>(), msg in prop::collection::vec(any::<u8>(), 0..200)) {
        let Some(k) = p256_key(seed) else { return Ok(()) };
        let key = PublicKey::from_device(Curve::Nist256p1, k.verifying_key().to_sec1_point(true).as_bytes()).unwrap();
        let s: p256::ecdsa::Signature = k.sign(&msg);
        let sig = verify_identity_signature(Proto::Ssh, &key, &msg, &cat(&[&[0], &s.to_bytes()])).unwrap();
        let body = sign_response(&sig);
        let (r, s) = split_rs(&s);
        prop_assert_eq!(&body, &cat(&[&[14], &string(&p256_sig_blob(&r, &s))]));
        // The blob is accepted by this crate's own strict verifier, as a server would.
        let mut rd = Reader(&body[1..]);
        let blob = rd.string().unwrap();
        prop_assert!(rd.finish().is_some());
        prop_assert_eq!(verify_host_signature(&key.openssh_blob(), &msg, blob), Ok(()));
    }
}

#[test]
fn put_mpint_edges() {
    let enc = |be: &[u8]| {
        let mut out = Vec::new();
        put_mpint(&mut out, be);
        out
    };
    assert_eq!(enc(&[0; 32]), [0, 0, 0, 0]);
    assert_eq!(enc(&[0, 0, 1]), [0, 0, 0, 1, 1]);
    assert_eq!(enc(&[0x7f]), [0, 0, 0, 1, 0x7f]);
    assert_eq!(enc(&[0x80]), [0, 0, 0, 2, 0, 0x80]);
    assert_eq!(enc(&[0, 0, 0x80, 1]), [0, 0, 0, 3, 0, 0x80, 1]);
    let mut max = [0xffu8; 32];
    assert_eq!(enc(&max).len(), 4 + 33);
    max[0] = 0x7f;
    assert_eq!(enc(&max).len(), 4 + 32);
}

#[test]
fn mpint_scalar_strictness() {
    assert_eq!(mpint_scalar(&[]), None);
    assert_eq!(mpint_scalar(&[0]), None);
    assert_eq!(mpint_scalar(&[0, 1]), None);
    assert_eq!(mpint_scalar(&[0x80]), None);
    assert_eq!(mpint_scalar(&[1; 33]), None);
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(mpint_scalar(&[1]), Some(one));
    let mut v = vec![0u8];
    v.extend_from_slice(&[0xff; 32]);
    assert_eq!(mpint_scalar(&v), Some([0xff; 32]));
    v.insert(0, 0);
    assert_eq!(mpint_scalar(&v), None);
}
