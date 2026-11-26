//! SSH agent protocol (draft-miller-ssh-agent, OpenSSH `PROTOCOL.agent`) and the signing
//! policy of `pets agent`. Pure: no I/O besides `Read`/`Write` framing, no device access.
//! Design: `docs/agent.md`.
//!
//! API CONTRACT: used by the daemon in `crates/petschaft`. Keep these signatures.
//!
//! Every parser here reads untrusted bytes from a local socket: every length is checked
//! against the remaining input before use, nothing is allocated from an unchecked length,
//! booleans are exactly 0 or 1, and trailing bytes are rejected.

#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read, Write};

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use petschaft_core::{Fingerprint, Signature, SignatureParts};
use sha2::{Digest as _, Sha256};

/// Largest accepted message body (after the 4-byte length).
pub const MAX_MESSAGE: usize = 256 * 1024;

// draft-miller-ssh-agent §6.1 (message numbers).
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;

/// OpenSSH `PROTOCOL.agent`, "session-bind@openssh.com".
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
/// Upper bound for a session identifier (an exchange hash: at most 64 bytes for
/// SHA-512 KEX). Same limit as OpenSSH's `AGENT_MAX_SID_LEN`.
const MAX_SESSION_ID: usize = 128;

// RFC 4252 §7 / OpenSSH `PROTOCOL` "publickey-hostbound-v00@openssh.com".
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SERVICE_CONNECTION: &[u8] = b"ssh-connection";
const METHOD_PUBLICKEY: &[u8] = b"publickey";
const METHOD_HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
/// SSHSIG magic (OpenSSH `PROTOCOL.sshsig`): git/file signatures, never a login.
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
/// Bounds for userauth fields (RFC 4250 §4.6.1: algorithm names are at most 64 ASCII
/// characters). User names are shown on the device, so they are bounded and must not
/// contain control characters.
const MAX_USER: usize = 256;
const MAX_ALGORITHM: usize = 64;
const MAX_KEY_BLOB: usize = 16 * 1024;

const SSH_ED25519: &[u8] = b"ssh-ed25519";
const SSH_ECDSA_P256: &[u8] = b"ecdsa-sha2-nistp256";
const NISTP256: &[u8] = b"nistp256";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Malformed or oversized message; the connection should be closed.
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("i/o error: {0}")]
    Io(String),
}

/// Why a sign request is refused. Logged by the daemon; the client only sees FAILURE.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    #[error("no verified session-bind on this connection")]
    NotBound,
    #[error("agent forwarding is not allowed")]
    Forwarded,
    #[error("data is not an SSH userauth request")]
    NotUserAuth,
    #[error("session identifier does not match the bound session")]
    SessionMismatch,
    #[error("requested key does not match the identity")]
    KeyMismatch,
    #[error("server host key {0} is not pinned for this identity")]
    HostNotPinned(Fingerprint),
}

/// A verified `session-bind@openssh.com`: only constructed by [`parse_request`] after
/// checking the host key's signature over the session identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBind {
    host_key_blob: Vec<u8>,
    session_id: Vec<u8>,
    is_forwarding: bool,
}

impl SessionBind {
    pub fn host_key_fingerprint(&self) -> Fingerprint {
        Fingerprint::of_openssh_blob(&self.host_key_blob)
    }
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
    pub fn is_forwarding(&self) -> bool {
        self.is_forwarding
    }
}

/// A parsed client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    RequestIdentities,
    Sign {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Verified session binding (answer SUCCESS and record it for the connection).
    SessionBind(SessionBind),
    /// A session-bind whose host key type is unsupported or whose signature is invalid
    /// (answer FAILURE; the connection must then refuse all sign requests).
    InvalidSessionBind(&'static str),
    /// Anything else: answer FAILURE.
    Unsupported(u8),
}

/// The parsed fields of an SSH userauth "publickey" request (RFC 4252 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuth {
    pub session_id: Vec<u8>,
    pub user: String,
    pub algorithm: String,
    pub key_blob: Vec<u8>,
    /// The trailing `string server host key` of the OpenSSH method
    /// `publickey-hostbound-v00@openssh.com` (OpenSSH `PROTOCOL`, section of that name;
    /// sent by OpenSSH >= 8.9 to servers that support it); `None` for plain `publickey`.
    /// [`authorize`] requires it to equal the bound host key.
    pub server_host_key: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------------------
// Wire primitives (RFC 4251 §5)
// ---------------------------------------------------------------------------------------

/// Cursor over untrusted bytes. Every accessor checks the remaining length first and
/// returns `None` instead of reading past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*head))
    }

    /// RFC 4251 `boolean`: only 0 and 1 are accepted (stricter than "any non-zero").
    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// RFC 4251 `string`: the length is checked against the remaining input; the result
    /// borrows from the input (no allocation).
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        let (s, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(s)
    }

    /// `Some(())` only if all input was consumed.
    fn finish(self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

/// RFC 4251 `string`. A length above `u32::MAX` cannot occur for a sendable message:
/// such a body exceeds [`MAX_MESSAGE`] and [`write_message`] rejects it.
fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
}

/// RFC 4251 `mpint` of a non-negative big-endian integer: minimal (leading zero bytes
/// stripped, zero is the empty string), with a 0x00 prepended if the high bit is set.
fn put_mpint(out: &mut Vec<u8>, be: &[u8]) {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let digits = be.get(first..).unwrap_or_default();
    match digits.first() {
        Some(&b) if b & 0x80 != 0 => {
            let mut v = Vec::with_capacity(digits.len().saturating_add(1));
            v.push(0);
            v.extend_from_slice(digits);
            put_string(out, &v);
        }
        _ => put_string(out, digits),
    }
}

/// Strict RFC 4251 `mpint` → 32-byte big-endian scalar. Rejects negative values,
/// non-minimal encodings (a 0x00 not needed for the sign bit, or `00` for zero), zero
/// (an invalid ECDSA scalar anyway) and values wider than 32 bytes.
fn mpint_scalar(m: &[u8]) -> Option<[u8; 32]> {
    let digits = match m {
        [] => return None,
        [0, rest @ ..] => {
            // The 0x00 is only allowed (and required) before a byte with the high bit set.
            if rest.first()? & 0x80 == 0 {
                return None;
            }
            rest
        }
        [b, ..] if b & 0x80 != 0 => return None,
        _ => m,
    };
    let mut out = [0u8; 32];
    let start = out.len().checked_sub(digits.len())?;
    out.get_mut(start..)?.copy_from_slice(digits);
    Some(out)
}

/// The key type (first `string`) of an OpenSSH public key blob.
fn key_type(blob: &[u8]) -> Option<&[u8]> {
    Reader(blob).string()
}

// ---------------------------------------------------------------------------------------
// Framing (draft-miller-ssh-agent §3: uint32 length, then the message)
// ---------------------------------------------------------------------------------------

/// Read one message body (`u32` length, then body). `Ok(None)` on clean EOF before a
/// message. Lengths of 0 or above [`MAX_MESSAGE`] are protocol errors; never allocates
/// based on an unchecked length.
pub fn read_message(r: &mut impl Read) -> Result<Option<Vec<u8>>, Error> {
    let mut header = [0u8; 4];
    let mut filled = 0usize;
    while filled < header.len() {
        let buf = header
            .get_mut(filled..)
            .ok_or(Error::Protocol("bad read length"))?;
        match r.read(buf) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(Error::Protocol("truncated message length")),
            Ok(n) => {
                filled = filled
                    .checked_add(n)
                    .ok_or(Error::Protocol("bad read length"))?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
    let len = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| Error::Protocol("message too large"))?;
    if len == 0 {
        return Err(Error::Protocol("empty message"));
    }
    if len > MAX_MESSAGE {
        return Err(Error::Protocol("message too large"));
    }
    // `len` is bounded by MAX_MESSAGE here.
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| match e.kind() {
        ErrorKind::UnexpectedEof => Error::Protocol("truncated message"),
        _ => Error::Io(e.to_string()),
    })?;
    Ok(Some(body))
}

/// Write one message body with its length prefix.
///
/// Bodies that are empty or larger than [`MAX_MESSAGE`] (OpenSSH clients refuse larger
/// agent replies) are a protocol error and nothing is written.
pub fn write_message(w: &mut impl Write, body: &[u8]) -> Result<(), Error> {
    if body.is_empty() {
        return Err(Error::Protocol("empty message"));
    }
    if body.len() > MAX_MESSAGE {
        return Err(Error::Protocol("message too large"));
    }
    let len = u32::try_from(body.len()).map_err(|_| Error::Protocol("message too large"))?;
    // One buffer, one write: a reply is never split by a partial header write.
    let mut frame = Vec::with_capacity(body.len().saturating_add(4));
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(body);
    w.write_all(&frame)
        .and_then(|()| w.flush())
        .map_err(|e| Error::Io(e.to_string()))
}

// ---------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------

/// Parse a message body. Session-bind signatures are verified here
/// (`ssh-ed25519`, `ecdsa-sha2-nistp256` host keys; others → `InvalidSessionBind`).
///
/// Malformed framing (truncated fields, trailing bytes, a boolean other than 0/1) is
/// `Err(Error::Protocol)`. A well-framed session-bind whose key, signature or session
/// identifier is unusable is `Ok(Request::InvalidSessionBind)`.
pub fn parse_request(body: &[u8]) -> Result<Request, Error> {
    let mut r = Reader(body);
    let kind = r.u8().ok_or(Error::Protocol("empty message"))?;
    match kind {
        // draft-miller-ssh-agent §4.4: no contents.
        SSH_AGENTC_REQUEST_IDENTITIES => {
            r.finish().ok_or(Error::Protocol("trailing bytes"))?;
            Ok(Request::RequestIdentities)
        }
        // draft-miller-ssh-agent §4.5: string key blob, string data, uint32 flags.
        SSH_AGENTC_SIGN_REQUEST => {
            let parsed = (|| {
                let key_blob = r.string()?;
                let data = r.string()?;
                let flags = r.u32()?;
                r.finish()?;
                Some((key_blob, data, flags))
            })();
            let (key_blob, data, flags) = parsed.ok_or(Error::Protocol("bad sign request"))?;
            Ok(Request::Sign {
                key_blob: key_blob.to_vec(),
                data: data.to_vec(),
                flags,
            })
        }
        // draft-miller-ssh-agent §4.8: string extension type, then type-specific contents.
        SSH_AGENTC_EXTENSION => {
            let name = r.string().ok_or(Error::Protocol("bad extension request"))?;
            if name != SESSION_BIND {
                return Ok(Request::Unsupported(SSH_AGENTC_EXTENSION));
            }
            parse_session_bind(r)
        }
        other => Ok(Request::Unsupported(other)),
    }
}

/// OpenSSH `PROTOCOL.agent` "session-bind@openssh.com": string hostkey, string session
/// identifier, string signature, bool is_forwarding.
fn parse_session_bind(mut r: Reader<'_>) -> Result<Request, Error> {
    let parsed = (|| {
        let host_key = r.string()?;
        let session_id = r.string()?;
        let signature = r.string()?;
        let is_forwarding = r.bool()?;
        r.finish()?;
        Some((host_key, session_id, signature, is_forwarding))
    })();
    let (host_key, session_id, signature, is_forwarding) =
        parsed.ok_or(Error::Protocol("bad session-bind"))?;
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
        return Ok(Request::InvalidSessionBind(
            "session identifier length out of range",
        ));
    }
    if let Err(why) = verify_host_signature(host_key, session_id, signature) {
        return Ok(Request::InvalidSessionBind(why));
    }
    Ok(Request::SessionBind(SessionBind {
        host_key_blob: host_key.to_vec(),
        session_id: session_id.to_vec(),
        is_forwarding,
    }))
}

/// Verify `signature` (SSH signature blob, RFC 4253 §6.6) by `host_key` (SSH public key
/// blob) over `session_id`.
fn verify_host_signature(
    host_key: &[u8],
    session_id: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    let mut key = Reader(host_key);
    let key_type = key.string().ok_or("malformed host key")?;
    let mut sig = Reader(signature);
    let sig_type = sig.string().ok_or("malformed signature")?;
    match key_type {
        // RFC 8709 §4 (key: string "ssh-ed25519", string key[32]) and §6 (signature:
        // string "ssh-ed25519", string sig[64]); Ed25519 signs the data itself.
        SSH_ED25519 => {
            let raw = key.string().ok_or("malformed host key")?;
            key.finish().ok_or("malformed host key")?;
            let raw: &[u8; 32] = raw.try_into().map_err(|_| "malformed host key")?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(raw)
                .map_err(|_| "invalid ed25519 host key")?;
            if sig_type != SSH_ED25519 {
                return Err("signature type does not match the host key");
            }
            let raw_sig = sig.string().ok_or("malformed signature")?;
            sig.finish().ok_or("malformed signature")?;
            let raw_sig: &[u8; 64] = raw_sig.try_into().map_err(|_| "malformed signature")?;
            // verify_strict: canonical S, no small-order R or key.
            vk.verify_strict(session_id, &ed25519_dalek::Signature::from_bytes(raw_sig))
                .map_err(|_| "host key signature does not verify")
        }
        // RFC 5656 §3.1 (key: string "ecdsa-sha2-nistp256", string "nistp256", string Q)
        // and §3.1.2 (signature: string "ecdsa-sha2-nistp256", string(mpint r, mpint s)
        // over SHA-256 of the signed data).
        SSH_ECDSA_P256 => {
            let curve = key.string().ok_or("malformed host key")?;
            let point = key.string().ok_or("malformed host key")?;
            key.finish().ok_or("malformed host key")?;
            if curve != NISTP256 {
                return Err("host key curve does not match its type");
            }
            // OpenSSH always sends the uncompressed point (SEC1 0x04 || x || y).
            if point.len() != 65 || point.first() != Some(&0x04) {
                return Err("host key is not an uncompressed nistp256 point");
            }
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| "invalid nistp256 host key")?;
            if sig_type != SSH_ECDSA_P256 {
                return Err("signature type does not match the host key");
            }
            let inner = sig.string().ok_or("malformed signature")?;
            sig.finish().ok_or("malformed signature")?;
            let mut scalars = Reader(inner);
            let r = scalars.string().and_then(mpint_scalar);
            let s = scalars.string().and_then(mpint_scalar);
            let (Some(r), Some(s), Some(())) = (r, s, scalars.finish()) else {
                return Err("malformed signature");
            };
            // Rejects r or s equal to 0 or >= n. High S is accepted, as by OpenSSH.
            let sig = p256::ecdsa::Signature::from_scalars(r, s)
                .map_err(|_| "signature scalar out of range")?;
            let digest: [u8; 32] = Sha256::digest(session_id).into();
            vk.verify_prehash(&digest, &sig)
                .map_err(|_| "host key signature does not verify")
        }
        _ => Err("unsupported host key type (only ssh-ed25519 and ecdsa-sha2-nistp256)"),
    }
}

/// Strict parser for the data of a sign request; anything else (incl. `SSHSIG` data)
/// is `Denied::NotUserAuth`.
///
/// Accepts the data signed for RFC 4252 §7 `publickey` (string session id, byte 50,
/// string user, string "ssh-connection", string "publickey", bool TRUE, string
/// algorithm, string key) and for OpenSSH's `publickey-hostbound-v00@openssh.com`
/// (OpenSSH `PROTOCOL`, section of that name: the same with that method name and a
/// trailing string server host key), which OpenSSH >= 8.9 uses whenever the server
/// supports it.
pub fn parse_userauth(data: &[u8]) -> Result<UserAuth, Denied> {
    if data.starts_with(SSHSIG_MAGIC) {
        return Err(Denied::NotUserAuth);
    }
    let mut r = Reader(data);
    let parsed = (|| {
        let session_id = r.string()?;
        if session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
            return None;
        }
        if r.u8()? != SSH_MSG_USERAUTH_REQUEST {
            return None;
        }
        let user = std::str::from_utf8(r.string()?).ok()?;
        if user.is_empty() || user.len() > MAX_USER || user.chars().any(char::is_control) {
            return None;
        }
        if r.string()? != SERVICE_CONNECTION {
            return None;
        }
        let hostbound = match r.string()? {
            METHOD_PUBLICKEY => false,
            METHOD_HOSTBOUND => true,
            _ => return None,
        };
        // has_signature: must be TRUE in signed data.
        if !r.bool()? {
            return None;
        }
        let algorithm = r.string()?;
        if algorithm.is_empty()
            || algorithm.len() > MAX_ALGORITHM
            || !algorithm.iter().all(u8::is_ascii_graphic)
        {
            return None;
        }
        let algorithm = std::str::from_utf8(algorithm).ok()?;
        let key_blob = r.string()?;
        if key_blob.is_empty() || key_blob.len() > MAX_KEY_BLOB {
            return None;
        }
        let server_host_key = if hostbound {
            let hk = r.string()?;
            if hk.is_empty() || hk.len() > MAX_KEY_BLOB {
                return None;
            }
            Some(hk.to_vec())
        } else {
            None
        };
        r.finish()?;
        Some(UserAuth {
            session_id: session_id.to_vec(),
            user: user.to_owned(),
            algorithm: algorithm.to_owned(),
            key_blob: key_blob.to_vec(),
            server_host_key,
        })
    })();
    parsed.ok_or(Denied::NotUserAuth)
}

/// The signing policy of `docs/agent.md` ("Signing rules"): all bindings of the
/// connection non-forwarding, at least one binding, userauth session id equals the
/// LAST binding's session id, key equals `identity_key_blob`, bound host key pinned.
///
/// Checked in this order (the first failing check is returned):
/// 1. at least one binding (`NotBound`);
/// 2. no binding is forwarding (`Forwarded`);
/// 3. `auth.session_id` equals the last binding's session id, and a hostbound
///    request's server host key equals the last binding's host key (`SessionMismatch`);
/// 4. `auth.key_blob` equals `identity_key_blob` and `auth.algorithm` is the key type of
///    `identity_key_blob` (`KeyMismatch`);
/// 5. the last binding's host key fingerprint is in `host_keys` (`HostNotPinned`).
pub fn authorize(
    bindings: &[SessionBind],
    auth: &UserAuth,
    identity_key_blob: &[u8],
    host_keys: &[Fingerprint],
) -> Result<(), Denied> {
    let last = bindings.last().ok_or(Denied::NotBound)?;
    if bindings.iter().any(SessionBind::is_forwarding) {
        return Err(Denied::Forwarded);
    }
    if auth.session_id != last.session_id {
        return Err(Denied::SessionMismatch);
    }
    if let Some(hk) = &auth.server_host_key
        && *hk != last.host_key_blob
    {
        return Err(Denied::SessionMismatch);
    }
    if auth.key_blob != identity_key_blob
        || key_type(identity_key_blob) != Some(auth.algorithm.as_bytes())
    {
        return Err(Denied::KeyMismatch);
    }
    let fingerprint = last.host_key_fingerprint();
    if !host_keys.contains(&fingerprint) {
        return Err(Denied::HostNotPinned(fingerprint));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------

/// `SSH_AGENT_IDENTITIES_ANSWER` body for `(key blob, comment)` pairs.
///
/// draft-miller-ssh-agent §4.4: byte 12, uint32 nkeys, then nkeys × (string key blob,
/// string comment).
pub fn identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    let count = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for (blob, comment) in keys {
        put_string(&mut out, blob);
        put_string(&mut out, comment.as_bytes());
    }
    out
}

/// `SSH_AGENT_SIGN_RESPONSE` body for a verified signature, encoded as an SSH
/// signature blob (`ssh-ed25519` / `ecdsa-sha2-nistp256` with mpint r, s).
///
/// draft-miller-ssh-agent §4.5: byte 14, string signature. Blob: RFC 8709 §6 /
/// RFC 5656 §3.1.2.
pub fn sign_response(signature: &Signature) -> Vec<u8> {
    let mut blob = Vec::with_capacity(96);
    match signature.parts() {
        SignatureParts::Ed25519(sig) => {
            put_string(&mut blob, SSH_ED25519);
            put_string(&mut blob, sig);
        }
        SignatureParts::Nist256p1 { r, s } => {
            let mut inner = Vec::with_capacity(74);
            put_mpint(&mut inner, r);
            put_mpint(&mut inner, s);
            put_string(&mut blob, SSH_ECDSA_P256);
            put_string(&mut blob, &inner);
        }
    }
    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut out, &blob);
    out
}

/// `SSH_AGENT_SUCCESS` body.
pub fn success() -> Vec<u8> {
    vec![SSH_AGENT_SUCCESS]
}

/// `SSH_AGENT_FAILURE` body.
pub fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;
