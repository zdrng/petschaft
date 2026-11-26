//! Public keys and signatures as returned by the Trezor, OpenSSH encoding and local
//! verification. Device formats (see `docs/helper-protocol.md`, `signed`):
//! - ed25519: public key 33 bytes `0x00 || key`, signature 65 bytes `0x00 || sig`
//! - nist256p1: public key 33 bytes SEC1 compressed, signature 65 bytes `0x00 || r || s`
//!
//! [`PublicKey`] and [`Signature`] are opaque: a `PublicKey` only comes out of
//! [`PublicKey::from_device`] or the strict OpenSSH parsers
//! [`PublicKey::from_openssh_blob`] / [`PublicKey::from_openssh_line`] (fully validated point), a `Signature` only out of
//! [`verify_identity_signature`] (verified against a `PublicKey`). Nothing can build
//! either from unchecked bytes, so code holding one never needs to re-check it.

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

use crate::{Curve, Error, Proto};

/// Length of a public key and of a signature as returned by the device.
const DEVICE_KEY_LEN: usize = 33;
const DEVICE_SIG_LEN: usize = 65;
/// Prefix of the fingerprint string.
const FINGERPRINT_PREFIX: &str = "SHA256:";
/// base64 (no padding) of a 32-byte digest.
const FINGERPRINT_B64_LEN: usize = 43;

const SSH_ED25519: &str = "ssh-ed25519";
const SSH_ECDSA_P256: &str = "ecdsa-sha2-nistp256";
const SSH_P256_CURVE_ID: &str = "nistp256";

// ---------------------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------------------

/// An OpenSSH SHA-256 fingerprint: `"SHA256:"` followed by exactly 43 characters of the
/// standard base64 alphabet (no padding) that decode canonically to 32 bytes, so each
/// digest has exactly one spelling. Comparison is exact.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

/// `true` if `s` is a syntactically valid fingerprint (see [`Fingerprint`]).
fn is_valid_fingerprint(s: &str) -> bool {
    let Some(b64) = s.strip_prefix(FINGERPRINT_PREFIX) else {
        return false;
    };
    if b64.len() != FINGERPRINT_B64_LEN
        || !b64
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return false;
    }
    // STANDARD_NO_PAD rejects non-zero trailing bits, so only one spelling per digest
    // is accepted.
    matches!(STANDARD_NO_PAD.decode(b64), Ok(d) if d.len() == 32)
}

impl Fingerprint {
    /// Parse a fingerprint (e.g. a pin from the config). Exact: no trimming, no case
    /// folding, no padding.
    pub fn parse(s: &str) -> Result<Self, Error> {
        if is_valid_fingerprint(s) {
            Ok(Fingerprint(s.to_owned()))
        } else {
            Err(Error::InvalidConfig(format!(
                "fingerprint must be {FINGERPRINT_PREFIX} followed by {FINGERPRINT_B64_LEN} base64 characters"
            )))
        }
    }

    /// Fingerprint of an OpenSSH public key blob (RFC 4253 wire format):
    /// `"SHA256:" + base64-without-padding(SHA-256(blob))`. Total: any blob has one.
    pub fn of_openssh_blob(blob: &[u8]) -> Self {
        Fingerprint(format!(
            "{FINGERPRINT_PREFIX}{}",
            STANDARD_NO_PAD.encode(Sha256::digest(blob))
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.0)
    }
}

impl FromStr for Fingerprint {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Fingerprint::parse(s)
    }
}

// ---------------------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------------------

/// A validated public key of a SLIP-0013 identity. Only [`PublicKey::from_device`],
/// the strict OpenSSH parsers ([`PublicKey::from_openssh_blob`],
/// [`PublicKey::from_openssh_line`]) and [`PublicKey::from_p256_uncompressed`] create one.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(KeyRepr);

#[derive(Clone, PartialEq, Eq)]
enum KeyRepr {
    /// Canonically encoded, not of small order.
    Ed25519(ed25519_dalek::VerifyingKey),
    /// On the curve, not the identity.
    Nist256p1(p256::ecdsa::VerifyingKey),
}

/// Decode and fully validate an Ed25519 key: a canonical encoding of a point that is
/// not of small order.
fn ed25519_key(bytes: &[u8; 32]) -> Result<ed25519_dalek::VerifyingKey, Error> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|_| Error::InvalidPublicKey("ed25519 key is not a valid point".into()))?;
    if vk.is_weak() {
        return Err(Error::InvalidPublicKey(
            "ed25519 key is of small order".into(),
        ));
    }
    // Reject non-canonical encodings (y >= p): the device never produces them, and the
    // fingerprint must identify exactly one encoding.
    if vk.to_edwards().compress().to_bytes() != *bytes {
        return Err(Error::InvalidPublicKey(
            "ed25519 key is not canonically encoded".into(),
        ));
    }
    Ok(vk)
}

/// Decode and validate a compressed P-256 point (prefix 0x02/0x03, on the curve, not
/// the identity).
fn p256_key(bytes: &[u8; 33]) -> Result<p256::ecdsa::VerifyingKey, Error> {
    if !matches!(bytes.first(), Some(0x02 | 0x03)) {
        return Err(Error::InvalidPublicKey(
            "nist256p1 key is not a compressed SEC1 point".into(),
        ));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|_| Error::InvalidPublicKey("nist256p1 key is not a valid point".into()))
}

/// RFC 4251 `string`: u32 big-endian length, then the bytes.
fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    // All callers pass short constants or keys (<= 65 bytes); the fallback is unreachable
    // but keeps the encoding total without panicking.
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
}

/// Reader for RFC 4251 `string`s with every length checked.
struct WireReader<'a>(&'a [u8]);

impl<'a> WireReader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if len > rest.len() {
            return None;
        }
        let (s, rest) = rest.split_at(len);
        self.0 = rest;
        Some(s)
    }
}

impl PublicKey {
    /// Validate and normalize a public key exactly as the device returns it for `curve`.
    ///
    /// ed25519: 33 bytes `0x00 || key`, the key must be a canonically encoded point
    /// that is not of small order. nist256p1: 33 bytes SEC1 compressed (`0x02`/`0x03`),
    /// on the curve.
    pub fn from_device(curve: Curve, bytes: &[u8]) -> Result<Self, Error> {
        let raw: [u8; DEVICE_KEY_LEN] = bytes.try_into().map_err(|_| {
            Error::InvalidPublicKey(format!(
                "expected {DEVICE_KEY_LEN} bytes, got {}",
                bytes.len()
            ))
        })?;
        match curve {
            Curve::Ed25519 => {
                let [prefix, key @ ..] = raw;
                if prefix != 0x00 {
                    return Err(Error::InvalidPublicKey(
                        "ed25519 key must start with 0x00".into(),
                    ));
                }
                Ok(PublicKey(KeyRepr::Ed25519(ed25519_key(&key)?)))
            }
            Curve::Nist256p1 => Ok(PublicKey(KeyRepr::Nist256p1(p256_key(&raw)?))),
        }
    }

    pub fn curve(&self) -> Curve {
        match self.0 {
            KeyRepr::Ed25519(_) => Curve::Ed25519,
            KeyRepr::Nist256p1(_) => Curve::Nist256p1,
        }
    }

    /// The OpenSSH key type (`ssh-ed25519` / `ecdsa-sha2-nistp256`), which is also the
    /// signature algorithm name in SSH and SSHSIG signature blobs.
    pub fn openssh_algorithm(&self) -> &'static str {
        match self.0 {
            KeyRepr::Ed25519(_) => SSH_ED25519,
            KeyRepr::Nist256p1(_) => SSH_ECDSA_P256,
        }
    }

    /// OpenSSH wire-format public key blob (RFC 4253 §6.6, RFC 5656 §3.1, RFC 8709):
    /// ed25519: string "ssh-ed25519", string key;
    /// nist256p1: string "ecdsa-sha2-nistp256", string "nistp256", string uncompressed point (65 bytes).
    pub fn openssh_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.0 {
            KeyRepr::Ed25519(vk) => {
                put_string(&mut out, SSH_ED25519.as_bytes());
                put_string(&mut out, vk.as_bytes());
            }
            KeyRepr::Nist256p1(vk) => {
                let point = vk.to_sec1_point(false);
                put_string(&mut out, SSH_ECDSA_P256.as_bytes());
                put_string(&mut out, SSH_P256_CURVE_ID.as_bytes());
                put_string(&mut out, point.as_bytes());
            }
        }
        out
    }

    /// `"<algorithm> <base64(blob)> <comment>"` as in `authorized_keys`.
    ///
    /// Control characters (including newlines) are removed from `comment` so the result
    /// is always a single line; an empty comment omits the trailing separator.
    pub fn openssh_line(&self, comment: &str) -> String {
        let comment: String = comment.chars().filter(|c| !c.is_control()).collect();
        let mut line = format!(
            "{} {}",
            self.openssh_algorithm(),
            STANDARD.encode(self.openssh_blob())
        );
        if !comment.is_empty() {
            line.push(' ');
            line.push_str(&comment);
        }
        line
    }

    /// Parse an OpenSSH public key blob (the format of [`PublicKey::openssh_blob`]) of
    /// type `ssh-ed25519` or `ecdsa-sha2-nistp256`, with the same validation as
    /// [`PublicKey::from_device`]: a canonically encoded ed25519 point that is not of
    /// small order, or an uncompressed P-256 point on the curve. Strict: every length is
    /// checked, no trailing bytes, and the blob must be exactly the canonical encoding
    /// of the key (`from_openssh_blob(b)?.openssh_blob() == b`), so a key has exactly
    /// one accepted blob and fingerprint.
    pub fn from_openssh_blob(blob: &[u8]) -> Result<Self, Error> {
        let bad = |m: &'static str| Error::InvalidKeyLine(m);
        let mut r = WireReader(blob);
        let algorithm = r.string().ok_or(bad("truncated key blob"))?;
        let key = match algorithm {
            a if a == SSH_ED25519.as_bytes() => {
                let raw = r.string().ok_or(bad("truncated key blob"))?;
                let raw: &[u8; 32] = raw
                    .try_into()
                    .map_err(|_| bad("ed25519 key is not 32 bytes"))?;
                PublicKey(KeyRepr::Ed25519(
                    ed25519_key(raw).map_err(|_| bad("ed25519 key is not a valid point"))?,
                ))
            }
            a if a == SSH_ECDSA_P256.as_bytes() => {
                let curve_id = r.string().ok_or(bad("truncated key blob"))?;
                if curve_id != SSH_P256_CURVE_ID.as_bytes() {
                    return Err(bad("ecdsa key is not on nistp256"));
                }
                let point = r.string().ok_or(bad("truncated key blob"))?;
                if point.len() != 65 || point.first() != Some(&0x04) {
                    return Err(bad("nistp256 key is not an uncompressed point"));
                }
                PublicKey(KeyRepr::Nist256p1(
                    p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                        .map_err(|_| bad("nistp256 key is not a valid point"))?,
                ))
            }
            _ => return Err(bad("key type must be ssh-ed25519 or ecdsa-sha2-nistp256")),
        };
        if !r.0.is_empty() {
            return Err(bad("trailing bytes after the key"));
        }
        if key.openssh_blob() != blob {
            return Err(bad("key blob is not canonically encoded"));
        }
        Ok(key)
    }

    /// Parse an OpenSSH public key line `<type> <base64 blob> [comment]` as printed by
    /// [`PublicKey::openssh_line`] (and `pets pubkey`). Fields are separated by single
    /// spaces; the type must match the blob; the base64 must be canonical (padded, no
    /// stray bits); the comment is ignored. Lines with control characters or longer
    /// than [`PublicKey::MAX_LINE_LEN`] bytes are rejected. Errors never quote the input.
    pub fn from_openssh_line(line: &str) -> Result<Self, Error> {
        let bad = |m: &'static str| Error::InvalidKeyLine(m);
        if line.len() > Self::MAX_LINE_LEN {
            return Err(bad("line is too long"));
        }
        if line.chars().any(char::is_control) {
            return Err(bad("line contains control characters"));
        }
        let mut parts = line.splitn(3, ' ');
        let algorithm = parts.next().unwrap_or_default();
        let b64 = parts.next().unwrap_or_default();
        if algorithm.is_empty() || b64.is_empty() {
            return Err(bad("expected \"<type> <base64 key> [comment]\""));
        }
        let blob = STANDARD
            .decode(b64)
            .map_err(|_| bad("key is not valid base64"))?;
        let key = Self::from_openssh_blob(&blob)?;
        if key.openssh_algorithm() != algorithm {
            return Err(bad("key type does not match the key"));
        }
        Ok(key)
    }

    /// A nist256p1 key from an uncompressed SEC1 point (`0x04 || x || y`, e.g. from an
    /// X.509 `SubjectPublicKeyInfo`), on the curve and not the identity.
    pub fn from_p256_uncompressed(point: &[u8; 65]) -> Result<Self, Error> {
        if point.first() != Some(&0x04) {
            return Err(Error::InvalidPublicKey(
                "nist256p1 key is not an uncompressed SEC1 point".into(),
            ));
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(|vk| PublicKey(KeyRepr::Nist256p1(vk)))
            .map_err(|_| Error::InvalidPublicKey("nist256p1 key is not a valid point".into()))
    }

    /// The uncompressed SEC1 point (`0x04 || x || y`) of a nist256p1 key (as used in
    /// X.509 and APK signatures); `None` for ed25519.
    pub fn p256_uncompressed(&self) -> Option<[u8; 65]> {
        match &self.0 {
            KeyRepr::Ed25519(_) => None,
            KeyRepr::Nist256p1(vk) => vk.to_sec1_point(false).as_bytes().try_into().ok(),
        }
    }

    /// Longest line accepted by [`PublicKey::from_openssh_line`].
    pub const MAX_LINE_LEN: usize = 1024;

    /// OpenSSH fingerprint of [`PublicKey::openssh_blob`].
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_openssh_blob(&self.openssh_blob())
    }

    /// Ok if `expected` matches exactly, otherwise `Error::FingerprintMismatch`.
    pub fn check_fingerprint(&self, expected: &Fingerprint) -> Result<(), Error> {
        let actual = self.fingerprint();
        if actual == *expected {
            Ok(())
        } else {
            Err(Error::FingerprintMismatch {
                expected: expected.clone(),
                actual,
            })
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("curve", &self.curve())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

// ---------------------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------------------

/// A signature that [`verify_identity_signature`] has verified. There is no other
/// constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(SigRepr);

#[derive(Debug, Clone, PartialEq, Eq)]
enum SigRepr {
    Ed25519([u8; 64]),
    /// ECDSA P-256 scalars, big-endian, both in `1..n`.
    Nist256p1 {
        r: [u8; 32],
        s: [u8; 32],
    },
}

/// Read-only view of a [`Signature`]'s raw parts, for encoders (SSHSIG, DER). A view
/// cannot be turned back into a `Signature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureParts<'a> {
    /// The 64-byte Ed25519 signature `R || S`.
    Ed25519(&'a [u8; 64]),
    /// ECDSA P-256 scalars, big-endian, `s` exactly as the device produced it.
    Nist256p1 { r: &'a [u8; 32], s: &'a [u8; 32] },
}

/// DER INTEGER for a non-negative big-endian value: minimal length, with a leading 0x00
/// if the high bit of the first content byte is set.
fn der_uint(out: &mut Vec<u8>, be: &[u8; 32]) -> Option<()> {
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let digits = be.get(start..)?;
    let mut content = Vec::with_capacity(33);
    match digits.first() {
        None => content.push(0x00),
        Some(&b) if b & 0x80 != 0 => {
            content.push(0x00);
            content.extend_from_slice(digits);
        }
        Some(_) => content.extend_from_slice(digits),
    }
    out.push(0x02);
    // At most 33 content bytes: short-form length.
    out.push(u8::try_from(content.len()).ok()?);
    out.extend_from_slice(&content);
    Some(())
}

impl Signature {
    /// Curve of the key that verified this signature.
    pub fn curve(&self) -> Curve {
        match self.0 {
            SigRepr::Ed25519(_) => Curve::Ed25519,
            SigRepr::Nist256p1 { .. } => Curve::Nist256p1,
        }
    }

    /// The raw parts, for encoding.
    pub fn parts(&self) -> SignatureParts<'_> {
        match &self.0 {
            SigRepr::Ed25519(sig) => SignatureParts::Ed25519(sig),
            SigRepr::Nist256p1 { r, s } => SignatureParts::Nist256p1 { r, s },
        }
    }

    /// ASN.1 DER `ECDSA-Sig-Value` for nist256p1 (as used in APK and X.509); `None` for ed25519.
    pub fn to_der(&self) -> Option<Vec<u8>> {
        match &self.0 {
            SigRepr::Ed25519(_) => None,
            SigRepr::Nist256p1 { r, s } => {
                let mut body = Vec::with_capacity(70);
                der_uint(&mut body, r)?;
                der_uint(&mut body, s)?;
                // At most 2 * 35 = 70 bytes: short-form length.
                let mut out = Vec::with_capacity(72);
                out.push(0x30);
                out.push(u8::try_from(body.len()).ok()?);
                out.extend_from_slice(&body);
                Some(out)
            }
        }
    }
}

/// Verify a `SignedIdentity` from the device. Returns the parsed signature only if it
/// is valid for `public_key` over the data the firmware signs for (`proto`, curve):
///
/// | proto | ed25519 | nist256p1 |
/// |---|---|---|
/// | ssh | Ed25519 over `challenge_hidden` | ECDSA over SHA-256(`challenge_hidden`) |
/// | gpg | Ed25519 over `challenge_hidden` | ECDSA over `challenge_hidden` as prehashed 32-byte digest (must be 32 bytes) |
///
/// Choices:
/// - ECDSA: both low-S and high-S signatures are accepted. trezor-crypto's
///   `nist256p1.sign` is not guaranteed to normalize S, and OpenSSH, APK and X.509
///   verifiers accept either. `r`/`s` equal to 0 or `>= n` are rejected
///   (`Error::InvalidSignature`). The returned [`Signature`] carries `s` exactly as the
///   device produced it.
/// - Ed25519: strict verification (`verify_strict`: canonical `s`, no small-order `R`
///   or key).
/// - The device signature format is the same for both curves; the curve is taken from
///   `public_key`, so a signature produced with the other curve fails verification.
/// - gpg/nist256p1 with a `challenge_hidden` that is not exactly 32 bytes is
///   `Error::InvalidSignature` (the firmware would not sign it).
pub fn verify_identity_signature(
    proto: Proto,
    public_key: &PublicKey,
    challenge_hidden: &[u8],
    device_signature: &[u8],
) -> Result<Signature, Error> {
    let raw: [u8; DEVICE_SIG_LEN] = device_signature.try_into().map_err(|_| {
        Error::InvalidSignature(format!(
            "expected {DEVICE_SIG_LEN} bytes, got {}",
            device_signature.len()
        ))
    })?;
    let [prefix, body @ ..] = raw;
    if prefix != 0x00 {
        return Err(Error::InvalidSignature("must start with 0x00".into()));
    }
    match &public_key.0 {
        KeyRepr::Ed25519(vk) => {
            let sig = ed25519_dalek::Signature::from_bytes(&body);
            vk.verify_strict(challenge_hidden, &sig)
                .map_err(|_| Error::VerificationFailed)?;
            Ok(Signature(SigRepr::Ed25519(body)))
        }
        KeyRepr::Nist256p1(vk) => {
            let digest: [u8; 32] = match proto {
                Proto::Ssh => Sha256::digest(challenge_hidden).into(),
                Proto::Gpg => challenge_hidden.try_into().map_err(|_| {
                    Error::InvalidSignature(
                        "gpg challenge for nist256p1 must be a 32-byte digest".into(),
                    )
                })?,
            };
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            let (r_bytes, s_bytes) = body.split_at(32);
            r.copy_from_slice(r_bytes);
            s.copy_from_slice(s_bytes);
            let sig = p256::ecdsa::Signature::from_scalars(r, s)
                .map_err(|_| Error::InvalidSignature("r or s out of range".into()))?;
            vk.verify_prehash(&digest, &sig)
                .map_err(|_| Error::VerificationFailed)?;
            Ok(Signature(SigRepr::Nist256p1 { r, s }))
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use proptest::prelude::*;

    // --- helpers: software "device" ---

    fn ed_sk(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn p_sk(seed: u8) -> p256::ecdsa::SigningKey {
        let mut b = [seed; 32];
        b[0] = 0x01; // keep it well below n
        p256::ecdsa::SigningKey::from_slice(&b).unwrap()
    }

    fn ed_device_key(sk: &ed25519_dalek::SigningKey) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(sk.verifying_key().as_bytes());
        v
    }

    fn p_device_key(sk: &p256::ecdsa::SigningKey) -> Vec<u8> {
        sk.verifying_key().to_sec1_point(true).as_bytes().to_vec()
    }

    /// What the firmware returns for ed25519 (both protos): 0x00 || sig(challenge).
    fn ed_device_sig(sk: &ed25519_dalek::SigningKey, challenge: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(&sk.sign(challenge).to_bytes());
        v
    }

    /// What the firmware returns for nist256p1: 0x00 || r || s over `digest`.
    fn p_device_sig_digest(sk: &p256::ecdsa::SigningKey, digest: &[u8; 32]) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).unwrap();
        let mut v = vec![0x00];
        v.extend_from_slice(&sig.to_bytes());
        v
    }

    fn p_device_sig(sk: &p256::ecdsa::SigningKey, proto: Proto, challenge: &[u8]) -> Vec<u8> {
        let digest: [u8; 32] = match proto {
            Proto::Ssh => Sha256::digest(challenge).into(),
            Proto::Gpg => challenge.try_into().unwrap(),
        };
        p_device_sig_digest(sk, &digest)
    }

    /// Flip s to n - s.
    fn flip_s(dev_sig: &[u8]) -> Vec<u8> {
        let sig = p256::ecdsa::Signature::from_slice(&dev_sig[1..]).unwrap();
        let (r, s) = sig.split_scalars();
        let neg_s = -*s;
        let flipped = p256::ecdsa::Signature::from_scalars(r.to_bytes(), neg_s.to_bytes()).unwrap();
        let mut v = vec![0x00];
        v.extend_from_slice(&flipped.to_bytes());
        v
    }

    fn ed_pk(seed: u8) -> PublicKey {
        PublicKey::from_device(Curve::Ed25519, &ed_device_key(&ed_sk(seed))).unwrap()
    }

    fn p_pk(seed: u8) -> PublicKey {
        PublicKey::from_device(Curve::Nist256p1, &p_device_key(&p_sk(seed))).unwrap()
    }

    #[test]
    fn p256_uncompressed_round_trip() {
        let pk = p_pk(3);
        let point = pk.p256_uncompressed().unwrap();
        assert_eq!(
            &point[..],
            p_sk(3).verifying_key().to_sec1_point(false).as_bytes()
        );
        assert_eq!(PublicKey::from_p256_uncompressed(&point).unwrap(), pk);
        assert_eq!(ed_pk(3).p256_uncompressed(), None);
        let mut off = point;
        off[64] ^= 1;
        assert!(PublicKey::from_p256_uncompressed(&off).is_err());
        let mut tag = point;
        tag[0] = 0x02;
        assert!(PublicKey::from_p256_uncompressed(&tag).is_err());
        assert!(PublicKey::from_p256_uncompressed(&[0u8; 65]).is_err());
    }

    /// The device encoding of a validated key (inverse of `from_device`).
    fn device_bytes(pk: &PublicKey) -> Vec<u8> {
        match &pk.0 {
            KeyRepr::Ed25519(vk) => [&[0u8][..], vk.as_bytes()].concat(),
            KeyRepr::Nist256p1(vk) => vk.to_sec1_point(true).as_bytes().to_vec(),
        }
    }

    /// Only for the DER encoder tests: scalars that never went through verification.
    fn p_sig(r: [u8; 32], s: [u8; 32]) -> Signature {
        Signature(SigRepr::Nist256p1 { r, s })
    }

    fn fp(s: &str) -> Fingerprint {
        Fingerprint::parse(s).unwrap()
    }

    /// P-256 group order n, big-endian.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    // --- public keys ---

    #[test]
    fn from_device_ed25519() {
        let dev = ed_device_key(&ed_sk(7));
        let pk = PublicKey::from_device(Curve::Ed25519, &dev).unwrap();
        assert_eq!(pk.curve(), Curve::Ed25519);
        assert_eq!(device_bytes(&pk), dev);

        // wrong prefix
        let mut bad = dev.clone();
        bad[0] = 0x01;
        assert!(matches!(
            PublicKey::from_device(Curve::Ed25519, &bad),
            Err(Error::InvalidPublicKey(_))
        ));
        // wrong lengths
        for len in [0, 1, 32, 34, 65] {
            let v = vec![0u8; len];
            assert!(
                PublicKey::from_device(Curve::Ed25519, &v).is_err(),
                "len {len}"
            );
        }
        assert!(PublicKey::from_device(Curve::Ed25519, &dev[1..]).is_err());
        // small-order points: identity (y = 1) and y = 0 (order 4)
        let mut identity = [0u8; 33];
        identity[1] = 1;
        assert!(PublicKey::from_device(Curve::Ed25519, &identity).is_err());
        assert!(PublicKey::from_device(Curve::Ed25519, &[0u8; 33]).is_err());
        // y = p + 1: a non-canonical encoding of the identity point
        let mut noncanon = [0xFFu8; 33];
        noncanon[0] = 0x00;
        noncanon[1] = 0xEE; // p + 1 = 2^255 - 18, little-endian
        noncanon[32] = 0x7F;
        assert!(PublicKey::from_device(Curve::Ed25519, &noncanon).is_err());
    }

    #[test]
    fn from_device_ed25519_rejects_noncanonical_nonweak() {
        // Find y < 19 such that y is a valid, non-small-order point; then y + p is a
        // non-canonical encoding of the same point.
        let p_minus: [u8; 32] = {
            let mut b = [0xFFu8; 32];
            b[0] = 0xED;
            b[31] = 0x7F;
            b
        }; // p = 2^255 - 19, little-endian
        let mut found = false;
        for y in 2u8..19 {
            let mut canon = [0u8; 32];
            canon[0] = y;
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&canon) else {
                continue;
            };
            if vk.is_weak() {
                continue;
            }
            // y + p, little-endian (no carry: p's low byte 0xED + y < 0x100 for y < 19)
            let mut nc = p_minus;
            nc[0] = 0xED + y;
            let mut dev = vec![0x00];
            dev.extend_from_slice(&nc);
            if ed25519_dalek::VerifyingKey::from_bytes(&nc).is_ok() {
                found = true;
                assert!(matches!(
                    PublicKey::from_device(Curve::Ed25519, &dev),
                    Err(Error::InvalidPublicKey(_))
                ));
            }
        }
        assert!(found, "no non-canonical test point found");
    }

    #[test]
    fn from_device_p256() {
        let dev = p_device_key(&p_sk(3));
        let pk = PublicKey::from_device(Curve::Nist256p1, &dev).unwrap();
        assert_eq!(pk.curve(), Curve::Nist256p1);
        assert_eq!(device_bytes(&pk), dev);

        // uncompressed form (65 bytes) is not the device format
        let unc = p_sk(3)
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        assert!(PublicKey::from_device(Curve::Nist256p1, &unc).is_err());
        // wrong prefixes
        for prefix in [0x00, 0x01, 0x04, 0x05, 0xFF] {
            let mut bad = dev.clone();
            bad[0] = prefix;
            assert!(PublicKey::from_device(Curve::Nist256p1, &bad).is_err());
        }
        // x not on curve: try a few x values, at least one must be rejected
        let mut rejected = 0;
        for i in 0u8..16 {
            let mut bad = [0u8; 33];
            bad[0] = 0x02;
            bad[32] = i;
            if PublicKey::from_device(Curve::Nist256p1, &bad).is_err() {
                rejected += 1;
            }
        }
        assert!(rejected > 0);
        // x >= p
        let mut bad = [0xFFu8; 33];
        bad[0] = 0x02;
        assert!(PublicKey::from_device(Curve::Nist256p1, &bad).is_err());
        // curve mismatch: an ed25519 device key is not a P-256 key and vice versa
        assert!(PublicKey::from_device(Curve::Nist256p1, &ed_device_key(&ed_sk(3))).is_err());
        assert!(PublicKey::from_device(Curve::Ed25519, &dev).is_err());
    }

    // --- OpenSSH encoding ---

    /// Vectors cross-checked with OpenSSH: each expected line was written to a `.pub`
    /// file and `ssh-keygen -l -E sha256 -f <file>` printed exactly the expected
    /// fingerprint (keys: ed25519 seed [1; 32]; P-256 scalar 0x01 || [1; 31]).
    #[test]
    fn openssh_ed25519_vector() {
        let pk = ed_pk(1);
        let blob = pk.openssh_blob();
        assert_eq!(&blob[..4], &[0, 0, 0, 11]);
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &[0, 0, 0, 32]);
        assert_eq!(blob.len(), 19 + 32);
        let line = pk.openssh_line("test");
        assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(line.ends_with(" test"));
        assert_eq!(line, ED25519_SEED1_LINE);
        assert_eq!(pk.fingerprint(), fp(ED25519_SEED1_FP));
    }

    #[test]
    fn openssh_p256_vector() {
        let pk = p_pk(1);
        let blob = pk.openssh_blob();
        assert_eq!(&blob[..4], &[0, 0, 0, 19]);
        assert_eq!(&blob[4..23], b"ecdsa-sha2-nistp256");
        assert_eq!(&blob[23..27], &[0, 0, 0, 8]);
        assert_eq!(&blob[27..35], b"nistp256");
        assert_eq!(&blob[35..39], &[0, 0, 0, 65]);
        assert_eq!(blob[39], 0x04);
        assert_eq!(blob.len(), 39 + 65);
        assert_eq!(pk.openssh_line("test"), P256_SEED1_LINE);
        assert_eq!(pk.fingerprint(), fp(P256_SEED1_FP));
    }

    const ED25519_SEED1_LINE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c test";
    const ED25519_SEED1_FP: &str = "SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8";
    const P256_SEED1_LINE: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG/wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW/AdxT9sCwx+7ni0DG/30lqW4igrmJzvccFEo= test";
    const P256_SEED1_FP: &str = "SHA256:YFOSdoomjG1xcemA0K3GSPzvPVj4ITkrIJNQ90HNBQA";

    #[test]
    fn openssh_line_comment() {
        let pk = ed_pk(1);
        let bare = pk.openssh_line("");
        assert_eq!(bare.split(' ').count(), 2);
        assert_eq!(pk.openssh_line("a\nb\r\tc"), format!("{bare} abc"));
        assert_eq!(pk.openssh_line("\n"), bare);
        assert_eq!(pk.openssh_line("user@mac x"), format!("{bare} user@mac x"));
    }

    // --- OpenSSH parsing ---

    #[test]
    fn openssh_line_parses_vectors() {
        for (line, pk) in [(ED25519_SEED1_LINE, ed_pk(1)), (P256_SEED1_LINE, p_pk(1))] {
            assert_eq!(PublicKey::from_openssh_line(line).unwrap(), pk);
            let bare = pk.openssh_line("");
            assert_eq!(PublicKey::from_openssh_line(&bare).unwrap(), pk);
            assert_eq!(
                PublicKey::from_openssh_blob(&pk.openssh_blob()).unwrap(),
                pk
            );
        }
    }

    #[test]
    fn openssh_line_rejects() {
        let ed = ed_pk(1).openssh_line("");
        let (_, b64) = ed.split_once(' ').unwrap();
        let p = p_pk(1);
        let p_b64 = STANDARD.encode(p.openssh_blob());
        // compressed P-256 point
        let mut compressed = Vec::new();
        put_string(&mut compressed, SSH_ECDSA_P256.as_bytes());
        put_string(&mut compressed, SSH_P256_CURVE_ID.as_bytes());
        put_string(&mut compressed, &device_bytes(&p));
        // ed25519 key of small order (identity point)
        let mut weak = Vec::new();
        put_string(&mut weak, SSH_ED25519.as_bytes());
        let mut id_point = [0u8; 32];
        id_point[0] = 1;
        put_string(&mut weak, &id_point);
        let mut trailing = ed_pk(1).openssh_blob();
        trailing.push(0);
        let mut rsa = Vec::new();
        put_string(&mut rsa, b"ssh-rsa");
        put_string(&mut rsa, &[1, 0, 1]);
        put_string(&mut rsa, &[0xff; 64]);
        let cases = [
            String::new(),
            "ssh-ed25519".into(),
            format!("ssh-ed25519  {b64}"),
            format!(" ssh-ed25519 {b64}"),
            format!("ssh-ed25519 {b64}\n"),
            format!("ssh-ed25519 {b64} a\tb"),
            format!("ecdsa-sha2-nistp256 {b64}"),
            format!("ssh-ed25519 {p_b64}"),
            format!("ecdsa-sha2-nistp256 {}", p_b64.trim_end_matches('=')),
            format!("ssh-ed25519 {b64}{}", "x".repeat(PublicKey::MAX_LINE_LEN)),
            format!("ecdsa-sha2-nistp256 {}", STANDARD.encode(&compressed)),
            format!("ssh-ed25519 {}", STANDARD.encode(&weak)),
            format!("ssh-ed25519 {}", STANDARD.encode(&trailing)),
            format!("ssh-rsa {}", STANDARD.encode(&rsa)),
            format!("sk-ssh-ed25519@openssh.com {b64}"),
        ];
        for c in cases {
            assert!(
                matches!(
                    PublicKey::from_openssh_line(&c),
                    Err(Error::InvalidKeyLine(_))
                ),
                "accepted {c:?}"
            );
        }
        // non-canonical base64: the P-256 blob (104 bytes) ends in one '=' with two
        // unused low bits; setting one of them must be rejected.
        assert!(p_b64.ends_with('=') && !p_b64.ends_with("=="));
        let mut chars: Vec<u8> = p_b64.clone().into_bytes();
        let last = chars.len() - 2;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let v = alphabet.iter().position(|&c| c == chars[last]).unwrap();
        chars[last] = alphabet[v ^ 1];
        let tweaked = String::from_utf8(chars).unwrap();
        assert!(matches!(
            PublicKey::from_openssh_line(&format!("ecdsa-sha2-nistp256 {tweaked}")),
            Err(Error::InvalidKeyLine(_))
        ));
        assert!(PublicKey::from_openssh_line(&format!("ecdsa-sha2-nistp256 {p_b64}")).is_ok());
    }

    // --- fingerprints ---

    #[test]
    fn fingerprint_syntax() {
        let pk = ed_pk(2);
        let fp = pk.fingerprint().as_str().to_owned();
        assert!(is_valid_fingerprint(&fp));
        assert_eq!(Fingerprint::parse(&fp).unwrap().as_str(), fp);
        assert_eq!(fp.parse::<Fingerprint>().unwrap(), pk.fingerprint());
        assert_eq!(pk.fingerprint().to_string(), fp);
        assert_eq!(fp.len(), 7 + 43);
        assert!(!fp.ends_with('='));

        let body = &fp[7..];
        let bad = [
            String::new(),
            "SHA256:".into(),
            body.into(),
            format!("sha256:{body}"),
            format!("SHA256: {body}"),
            format!("SHA256:{body}="),
            format!("SHA256:{body} "),
            format!("SHA256:{}", &body[..42]),
            format!("SHA256:{body}A"),
            format!("SHA256:{}-", &body[..42]),
            format!("SHA256:{}_", &body[..42]),
            format!("MD5:{body}"),
            // valid alphabet and length, but non-zero trailing bits (last char must be
            // one of A, E, I, ..., i.e. index divisible by 4)
            format!("SHA256:{}B", &body[..42]),
        ];
        for s in &bad {
            assert!(!is_valid_fingerprint(s), "accepted {s:?}");
            assert!(
                matches!(Fingerprint::parse(s), Err(Error::InvalidConfig(_))),
                "accepted {s:?}"
            );
        }
    }

    #[test]
    fn check_fingerprint_cases() {
        let pk = ed_pk(2);
        let fp = pk.fingerprint();
        assert_eq!(pk.check_fingerprint(&fp), Ok(()));

        let other = ed_pk(3).fingerprint();
        assert_eq!(
            pk.check_fingerprint(&other),
            Err(Error::FingerprintMismatch {
                expected: other.clone(),
                actual: fp.clone()
            })
        );
        // case changes are a mismatch, not a match
        let swapped: String = fp.as_str()[7..]
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        if let Ok(swapped) = Fingerprint::parse(&format!("SHA256:{swapped}"))
            && swapped != fp
        {
            assert!(matches!(
                pk.check_fingerprint(&swapped),
                Err(Error::FingerprintMismatch { .. })
            ));
        }
        // P-256 key vs. its own fingerprint and an ed25519 one
        let p = p_pk(2);
        assert_eq!(p.check_fingerprint(&p.fingerprint()), Ok(()));
        assert!(p.check_fingerprint(&fp).is_err());
        // the mismatch message names both fingerprints and nothing else
        let msg = pk.check_fingerprint(&other).unwrap_err().to_string();
        assert_eq!(
            msg,
            format!("fingerprint mismatch: expected {other}, device returned {fp}")
        );
    }

    // --- DER ---

    fn der_roundtrip(r: [u8; 32], s: [u8; 32]) {
        let der = p_sig(r, s).to_der().unwrap();
        let parsed = p256::ecdsa::Signature::from_der(&der).unwrap();
        let (pr, ps) = parsed.split_bytes();
        assert_eq!(pr.as_slice(), &r);
        assert_eq!(ps.as_slice(), &s);
        // and the library's own encoder agrees byte for byte
        assert_eq!(parsed.to_der().as_bytes(), der.as_slice());
    }

    #[test]
    fn der_encoding() {
        assert_eq!(Signature(SigRepr::Ed25519([0; 64])).to_der(), None);

        // small values: INTEGER 1, INTEGER 0x7f, minimal encoding
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut x7f = [0u8; 32];
        x7f[31] = 0x7F;
        assert_eq!(
            p_sig(one, x7f).to_der().unwrap(),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x7F]
        );
        // high bit set -> leading 0x00
        let mut x80 = [0u8; 32];
        x80[31] = 0x80;
        assert_eq!(
            p_sig(x80, one).to_der().unwrap(),
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]
        );
        // zero encodes as INTEGER 0 (never produced by verification, but well-formed)
        assert_eq!(
            p_sig([0; 32], one).to_der().unwrap(),
            vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]
        );
        // full-width values with high bit set: 33-byte integers, 72 bytes total
        let mut n1 = N;
        n1[31] -= 1;
        let der = p_sig(n1, n1).to_der().unwrap();
        assert_eq!(der.len(), 72);
        assert_eq!(&der[..5], &[0x30, 70, 0x02, 33, 0x00]);
        der_roundtrip(n1, n1);
        der_roundtrip(one, n1);
        der_roundtrip(x80, x7f);
        // a leading zero byte inside the value is stripped
        let mut mid = [0u8; 32];
        mid[1] = 0x01;
        der_roundtrip(mid, one);
    }

    // --- verification ---

    const CHALLENGE: &[u8] = b"petschaft test challenge \x00\x01\x02 with arbitrary bytes";

    #[test]
    fn verify_ed25519_ok_both_protos() {
        let sk = ed_sk(5);
        let pk = ed_pk(5);
        for proto in [Proto::Ssh, Proto::Gpg] {
            for challenge in [CHALLENGE, b"" as &[u8], &[0u8; 32], &[0xAB; 512]] {
                let dev = ed_device_sig(&sk, challenge);
                let sig = verify_identity_signature(proto, &pk, challenge, &dev).unwrap();
                assert_eq!(sig.curve(), Curve::Ed25519);
                assert_eq!(
                    sig.parts(),
                    SignatureParts::Ed25519(dev[1..].try_into().unwrap())
                );
                assert_eq!(sig.to_der(), None);
            }
        }
    }

    #[test]
    fn verify_p256_ssh_ok() {
        let sk = p_sk(5);
        let pk = p_pk(5);
        for challenge in [CHALLENGE, b"" as &[u8], &[0xAB; 512]] {
            let dev = p_device_sig(&sk, Proto::Ssh, challenge);
            let sig = verify_identity_signature(Proto::Ssh, &pk, challenge, &dev).unwrap();
            assert_eq!(sig.curve(), Curve::Nist256p1);
            assert_eq!(
                sig.parts(),
                SignatureParts::Nist256p1 {
                    r: dev[1..33].try_into().unwrap(),
                    s: dev[33..].try_into().unwrap()
                }
            );
            // Independent check: it is an ordinary SHA256withECDSA signature over the
            // challenge, verifiable with the library's message-level verifier from DER.
            use p256::ecdsa::signature::Verifier;
            let der =
                p256::ecdsa::DerSignature::try_from(sig.to_der().unwrap().as_slice()).unwrap();
            sk.verifying_key().verify(challenge, &der).unwrap();
            // ssh signs SHA-256(challenge), not the challenge as a digest
            if challenge.len() == 32 {
                assert!(verify_identity_signature(Proto::Gpg, &pk, challenge, &dev).is_err());
            }
        }
    }

    #[test]
    fn verify_p256_gpg_ok_and_digest_len() {
        let sk = p_sk(6);
        let pk = p_pk(6);
        let digest: [u8; 32] = Sha256::digest(CHALLENGE).into();
        let dev = p_device_sig(&sk, Proto::Gpg, &digest);
        verify_identity_signature(Proto::Gpg, &pk, &digest, &dev).unwrap();
        // gpg: the 32-byte challenge is the digest, so it equals ssh over the pre-image
        verify_identity_signature(Proto::Ssh, &pk, CHALLENGE, &dev).unwrap();
        // gpg/nist256p1 challenge must be exactly 32 bytes
        for len in [0usize, 1, 31, 33, 48, 64] {
            let c = vec![0x11u8; len];
            assert!(
                matches!(
                    verify_identity_signature(Proto::Gpg, &pk, &c, &dev),
                    Err(Error::InvalidSignature(_))
                ),
                "len {len}"
            );
        }
        // a 33-byte challenge whose prefix is the digest must not verify (no truncation)
        let mut longer = digest.to_vec();
        longer.push(0);
        assert!(verify_identity_signature(Proto::Gpg, &pk, &longer, &dev).is_err());
    }

    #[test]
    fn verify_p256_high_and_low_s() {
        let sk = p_sk(8);
        let pk = p_pk(8);
        let dev = p_device_sig(&sk, Proto::Ssh, CHALLENGE);
        let flipped = flip_s(&dev);
        assert_ne!(dev, flipped);
        for d in [&dev, &flipped] {
            let sig = verify_identity_signature(Proto::Ssh, &pk, CHALLENGE, d).unwrap();
            // s is returned exactly as the device produced it
            let SignatureParts::Nist256p1 { s, .. } = sig.parts() else {
                panic!()
            };
            assert_eq!(&s[..], &d[33..]);
        }
    }

    #[test]
    fn verify_p256_scalar_range() {
        let sk = p_sk(9);
        let pk = p_pk(9);
        let dev = p_device_sig(&sk, Proto::Ssh, CHALLENGE);
        let mut cases = Vec::new();
        for (off, val) in [
            (1usize, [0u8; 32]),
            (1, N),
            (1, [0xFF; 32]),
            (33, [0u8; 32]),
            (33, N),
            (33, [0xFF; 32]),
        ] {
            let mut d = dev.clone();
            d[off..off + 32].copy_from_slice(&val);
            cases.push(d);
        }
        for d in cases {
            assert!(matches!(
                verify_identity_signature(Proto::Ssh, &pk, CHALLENGE, &d),
                Err(Error::InvalidSignature(_))
            ));
        }
    }

    #[test]
    fn verify_rejects_format_errors() {
        let ed = ed_pk(10);
        let p = p_pk(10);
        let ed_dev = ed_device_sig(&ed_sk(10), CHALLENGE);
        let p_dev = p_device_sig(&p_sk(10), Proto::Ssh, CHALLENGE);
        for (pk, dev) in [(&ed, &ed_dev), (&p, &p_dev)] {
            // wrong prefix
            for prefix in [0x01u8, 0x1B, 0x1F, 0x30, 0xFF] {
                let mut d = dev.clone();
                d[0] = prefix;
                assert!(matches!(
                    verify_identity_signature(Proto::Ssh, pk, CHALLENGE, &d),
                    Err(Error::InvalidSignature(_))
                ));
            }
            // wrong lengths: without prefix, truncated, extended
            for d in [
                &dev[1..],
                &dev[..64],
                &[dev.as_slice(), &[0]].concat()[..],
                &[][..],
            ] {
                assert!(matches!(
                    verify_identity_signature(Proto::Ssh, pk, CHALLENGE, d),
                    Err(Error::InvalidSignature(_))
                ));
            }
        }
        // DER instead of raw
        let der = p256::ecdsa::Signature::from_slice(&p_dev[1..])
            .unwrap()
            .to_der();
        assert!(verify_identity_signature(Proto::Ssh, &p, CHALLENGE, der.as_bytes()).is_err());
    }

    #[test]
    fn verify_rejects_bit_flips() {
        let cases: Vec<(PublicKey, Vec<u8>, Proto, Vec<u8>)> = vec![
            (
                ed_pk(11),
                ed_device_key(&ed_sk(11)),
                Proto::Ssh,
                CHALLENGE.to_vec(),
            ),
            (
                p_pk(11),
                p_device_key(&p_sk(11)),
                Proto::Ssh,
                CHALLENGE.to_vec(),
            ),
            (
                p_pk(11),
                p_device_key(&p_sk(11)),
                Proto::Gpg,
                Sha256::digest(CHALLENGE).to_vec(),
            ),
        ];
        for (pk, dev_key, proto, challenge) in cases {
            let dev = match pk.curve() {
                Curve::Ed25519 => ed_device_sig(&ed_sk(11), &challenge),
                Curve::Nist256p1 => p_device_sig(&p_sk(11), proto, &challenge),
            };
            verify_identity_signature(proto, &pk, &challenge, &dev).unwrap();
            // signature bits (after the prefix)
            for i in 8..dev.len() * 8 {
                let mut d = dev.clone();
                d[i / 8] ^= 1 << (i % 8);
                assert!(
                    verify_identity_signature(proto, &pk, &challenge, &d).is_err(),
                    "sig bit {i}"
                );
            }
            // challenge bits
            for i in 0..challenge.len() * 8 {
                let mut c = challenge.clone();
                c[i / 8] ^= 1 << (i % 8);
                assert!(
                    verify_identity_signature(proto, &pk, &c, &dev).is_err(),
                    "challenge bit {i}"
                );
            }
            // key bits: either the key no longer parses or the signature fails
            for i in 0..dev_key.len() * 8 {
                let mut k = dev_key.clone();
                k[i / 8] ^= 1 << (i % 8);
                if let Ok(pk2) = PublicKey::from_device(pk.curve(), &k) {
                    assert!(
                        verify_identity_signature(proto, &pk2, &challenge, &dev).is_err(),
                        "key bit {i}"
                    );
                }
            }
        }
    }

    #[test]
    fn verify_rejects_wrong_key_and_curve_mismatch() {
        let ed_dev = ed_device_sig(&ed_sk(12), CHALLENGE);
        let p_dev = p_device_sig(&p_sk(12), Proto::Ssh, CHALLENGE);
        // other key, same curve
        assert_eq!(
            verify_identity_signature(Proto::Ssh, &ed_pk(13), CHALLENGE, &ed_dev),
            Err(Error::VerificationFailed)
        );
        assert_eq!(
            verify_identity_signature(Proto::Ssh, &p_pk(13), CHALLENGE, &p_dev),
            Err(Error::VerificationFailed)
        );
        // curve mismatch: ed25519 signature checked against a P-256 key and vice versa
        for proto in [Proto::Ssh, Proto::Gpg] {
            assert!(verify_identity_signature(proto, &p_pk(12), CHALLENGE, &ed_dev).is_err());
            assert!(verify_identity_signature(proto, &ed_pk(12), CHALLENGE, &p_dev).is_err());
        }
        // non-canonical ed25519 s (s + L) is rejected by strict verification
        let mut d = ed_dev.clone();
        let l: [u8; 32] = [
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9,
            0xDE, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(d[33 + i]) + u16::from(l[i]) + carry;
            d[33 + i] = v as u8;
            carry = v >> 8;
        }
        if carry == 0 {
            assert!(verify_identity_signature(Proto::Ssh, &ed_pk(12), CHALLENGE, &d).is_err());
        }
    }

    proptest! {
        /// Random device signatures never panic and never verify, for both curves and protos.
        #[test]
        fn random_signatures_never_verify(
            sig in proptest::collection::vec(any::<u8>(), 0..=80),
            sig65 in proptest::collection::vec(any::<u8>(), 64),
            challenge in proptest::collection::vec(any::<u8>(), 0..=64),
            gpg in any::<bool>(),
        ) {
            let proto = if gpg { Proto::Gpg } else { Proto::Ssh };
            let mut prefixed = vec![0x00];
            prefixed.extend_from_slice(&sig65);
            for pk in [ed_pk(20), p_pk(20)] {
                for s in [&sig, &prefixed] {
                    prop_assert!(verify_identity_signature(proto, &pk, &challenge, s).is_err());
                }
            }
        }

        /// Random device public keys never panic; accepted keys re-encode identically.
        #[test]
        fn random_public_keys(bytes in proptest::collection::vec(any::<u8>(), 0..=40), first in 0u8..=4) {
            let mut b = bytes;
            if let Some(x) = b.first_mut() { *x = first; }
            for curve in [Curve::Ed25519, Curve::Nist256p1] {
                if let Ok(pk) = PublicKey::from_device(curve, &b) {
                    prop_assert_eq!(pk.curve(), curve);
                    prop_assert!(is_valid_fingerprint(pk.fingerprint().as_str()));
                    prop_assert_eq!(device_bytes(&pk), b.clone());
                    // equality is equality of the encoding
                    prop_assert_eq!(PublicKey::from_device(curve, &b), Ok(pk));
                }
            }
        }

        /// Signatures from the software device verify for any challenge (ed25519 and
        /// ssh/nist256p1) and any 32-byte digest (gpg/nist256p1).
        #[test]
        fn software_device_verifies(seed in 1u8..=255, challenge in proptest::collection::vec(any::<u8>(), 0..=512), digest in any::<[u8; 32]>()) {
            let ed = ed_pk(seed);
            let d = ed_device_sig(&ed_sk(seed), &challenge);
            prop_assert!(verify_identity_signature(Proto::Ssh, &ed, &challenge, &d).is_ok());
            let p = p_pk(seed);
            let d = p_device_sig(&p_sk(seed), Proto::Ssh, &challenge);
            prop_assert!(verify_identity_signature(Proto::Ssh, &p, &challenge, &d).is_ok());
            let d = p_device_sig_digest(&p_sk(seed), &digest);
            prop_assert!(verify_identity_signature(Proto::Gpg, &p, &digest, &d).is_ok());
        }

        /// DER encoding round-trips through p256's DER parser for all in-range scalars.
        #[test]
        fn der_roundtrip_prop(r in any::<[u8; 32]>(), s in any::<[u8; 32]>()) {
            if p256::ecdsa::Signature::from_scalars(r, s).is_ok() {
                der_roundtrip(r, s);
            }
        }

        /// OpenSSH key lines: arbitrary input never panics; every printed line parses
        /// back to the same key; any single-byte change of a blob is either rejected or
        /// yields a key that re-encodes to exactly that blob.
        #[test]
        fn openssh_line_round_trip(
            s in any::<String>(),
            seed in 1u8..=255,
            comment in "[ -~]{0,40}",
            pos in any::<usize>(),
            xor in 1u8..=255,
        ) {
            let _ = PublicKey::from_openssh_line(&s);
            for pk in [ed_pk(seed), p_pk(seed)] {
                prop_assert_eq!(PublicKey::from_openssh_line(&pk.openssh_line(&comment)), Ok(pk.clone()));
                let mut blob = pk.openssh_blob();
                let i = pos % blob.len();
                blob[i] ^= xor;
                if let Ok(k) = PublicKey::from_openssh_blob(&blob) {
                    prop_assert_eq!(k.openssh_blob(), blob);
                }
            }
        }

        /// Fingerprint validator never panics on arbitrary strings, and accepts every
        /// generated fingerprint.
        #[test]
        fn fingerprint_validator(
            s in any::<String>(),
            digest in any::<[u8; 32]>(),
            blob in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            // every computed fingerprint is a valid one
            let of_blob = Fingerprint::of_openssh_blob(&blob);
            prop_assert_eq!(Fingerprint::parse(of_blob.as_str()), Ok(of_blob.clone()));
            // accepted strings are kept verbatim
            if let Ok(f) = Fingerprint::parse(&s) {
                prop_assert_eq!(f.as_str(), s.as_str());
            }
            let fp = format!("SHA256:{}", STANDARD_NO_PAD.encode(digest));
            prop_assert_eq!(Fingerprint::parse(&fp).map(|f| f.to_string()), Ok(fp));
        }
    }
}
