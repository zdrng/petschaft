//! OpenSSH signatures (`PROTOCOL.sshsig`) as used by `git` with `gpg.format = ssh`.
//!
//! The Trezor signs [`signed_data`] through `SignIdentity` with an `ssh://` identity:
//! for ed25519 it signs those bytes directly, for nist256p1 their SHA-256, exactly what
//! SSHSIG prescribes for `ssh-ed25519` and `ecdsa-sha2-nistp256`. [`armor`] then builds
//! the `-----BEGIN SSH SIGNATURE-----` block that `ssh-keygen -Y verify` checks.

#![forbid(unsafe_code)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use petschaft_core::{Fingerprint, PublicKey, Signature, SignatureParts};
use sha2::{Digest, Sha512};

/// `MAGIC_PREAMBLE` of PROTOCOL.sshsig.
pub const MAGIC: &[u8; 6] = b"SSHSIG";
/// `SIG_VERSION` of PROTOCOL.sshsig.
pub const VERSION: u32 = 1;
/// Message hash algorithm (the one `ssh-keygen -Y sign` uses by default).
pub const HASH_ALG: &str = "sha512";
/// Line length of the armored base64 body (as written by OpenSSH).
const ARMOR_LINE: usize = 70;
const MAX_NAMESPACE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("namespace must be 1-{MAX_NAMESPACE} printable ASCII characters without spaces")]
    InvalidNamespace,
    #[error("invalid public key line: {0}")]
    InvalidKeyLine(&'static str),
    #[error("signature type does not match the public key")]
    KeyMismatch,
}

/// RFC 4251 `string`. All inputs here are short (hash, namespace, keys, signatures).
fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
}

/// RFC 4251 `mpint` of a non-negative big-endian integer.
fn put_mpint(out: &mut Vec<u8>, be: &[u8]) {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let digits = be.get(first..).unwrap_or(&[]);
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

fn check_namespace(namespace: &str) -> Result<(), Error> {
    if (1..=MAX_NAMESPACE).contains(&namespace.len())
        && namespace.bytes().all(|b| (0x21..=0x7E).contains(&b))
    {
        Ok(())
    } else {
        Err(Error::InvalidNamespace)
    }
}

/// SHA-512 of the message (the `H(message)` of PROTOCOL.sshsig).
pub fn message_hash(message: &[u8]) -> [u8; 64] {
    Sha512::digest(message).into()
}

/// The blob the key signs: `MAGIC || string namespace || string reserved ||
/// string hash_algorithm || string H(message)`.
pub fn signed_data(namespace: &str, message_hash: &[u8; 64]) -> Result<Vec<u8>, Error> {
    check_namespace(namespace)?;
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(MAGIC);
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, HASH_ALG.as_bytes());
    put_string(&mut out, message_hash);
    Ok(out)
}

/// The armored signature file content.
///
/// `signature` must have been verified against `public_key` (both come from the same
/// `SignedIdentity`); a signature of the other curve is [`Error::KeyMismatch`].
pub fn armor(
    public_key: &PublicKey,
    namespace: &str,
    signature: &Signature,
) -> Result<String, Error> {
    check_namespace(namespace)?;
    if signature.curve() != public_key.curve() {
        return Err(Error::KeyMismatch);
    }
    // RFC 8709 §6 / RFC 5656 §3.1.2: string algorithm, string signature blob.
    let mut sig = Vec::new();
    put_string(&mut sig, public_key.openssh_algorithm().as_bytes());
    match signature.parts() {
        SignatureParts::Ed25519(s) => put_string(&mut sig, s),
        SignatureParts::Nist256p1 { r, s } => {
            let mut rs = Vec::new();
            put_mpint(&mut rs, r);
            put_mpint(&mut rs, s);
            put_string(&mut sig, &rs);
        }
    }
    let key_blob = public_key.openssh_blob();

    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&VERSION.to_be_bytes());
    put_string(&mut body, &key_blob);
    put_string(&mut body, namespace.as_bytes());
    put_string(&mut body, b"");
    put_string(&mut body, HASH_ALG.as_bytes());
    put_string(&mut body, &sig);

    let b64 = STANDARD.encode(body);
    let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for line in b64.as_bytes().chunks(ARMOR_LINE) {
        // base64 output is ASCII, so every chunk is valid UTF-8.
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str("-----END SSH SIGNATURE-----\n");
    Ok(out)
}

/// A parsed `authorized_keys`-style line: `<algorithm> <base64 blob> [comment]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLine {
    pub algorithm: String,
    pub blob: Vec<u8>,
    pub comment: Option<String>,
}

impl KeyLine {
    /// Parse one line. The blob must start with `string algorithm` (consistency check).
    pub fn parse(line: &str) -> Result<Self, Error> {
        let mut parts = line.trim().splitn(3, ' ');
        let algorithm = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or(Error::InvalidKeyLine("empty"))?;
        if algorithm != "ssh-ed25519" && algorithm != "ecdsa-sha2-nistp256" {
            return Err(Error::InvalidKeyLine("unsupported algorithm"));
        }
        let blob = parts
            .next()
            .and_then(|b| STANDARD.decode(b).ok())
            .ok_or(Error::InvalidKeyLine("invalid base64 key"))?;
        let mut prefix = Vec::new();
        put_string(&mut prefix, algorithm.as_bytes());
        if !blob.starts_with(&prefix) {
            return Err(Error::InvalidKeyLine(
                "key blob does not match its algorithm",
            ));
        }
        let comment = parts
            .next()
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty());
        Ok(KeyLine {
            algorithm: algorithm.to_owned(),
            blob,
            comment,
        })
    }

    /// OpenSSH `SHA256:` fingerprint of the blob.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_openssh_blob(&self.blob)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests;
