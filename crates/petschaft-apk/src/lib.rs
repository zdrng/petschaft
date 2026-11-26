//! APK Signature Scheme v2/v3 and the X.509 certificate builder. See `docs/apk.md`.
//!
//! Pure format code, no device access:
//!
//! - [`Apk::parse`]: strict ZIP parsing (`docs/apk.md` step 1),
//! - [`Apk::align`]: 4-byte / 16 KiB alignment of stored entries (step 2),
//! - [`Apk::content_digest`]: the v2/v3 chunked SHA-256 content digest (step 3),
//! - [`sign`]: v2/v3 signed data, signature callback, local verification, APK Signing Block
//!   (steps 4-6),
//! - [`Certificate`]: the minimal self-signed X.509 v3 certificate for the signing key.
//!
//! Specifications: "APK Signature Scheme v2" and "APK Signature Scheme v3"
//! (source.android.com/docs/security/features/apksigning/v2 and …/v3), cited as
//! `[v2 §…]` / `[v3 §…]`; PKZIP APPNOTE 6.3.x cited as `[APPNOTE §…]`; RFC 5280 / RFC 5480 /
//! RFC 5758 for the certificate.

#![forbid(unsafe_code)]

mod cert;
mod der;
mod digest;
mod signing;
mod zip;

pub use cert::{Certificate, TbsCertificate};
pub use der::ecdsa_der_from_scalars;
pub use signing::{SchemeVersion, V3_MAX_SDK, V3_MIN_SDK, sign};
pub use zip::Apk;

/// Errors of this crate. Messages never contain key material (there is none here).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not a well-formed ZIP archive in the strict subset accepted here.
    #[error("malformed APK: {0}")]
    Malformed(&'static str),
    /// A valid ZIP feature that is deliberately not supported (ZIP64, multi-disk, encryption, …).
    #[error("unsupported APK: {0}")]
    Unsupported(&'static str),
    /// The input already carries an APK Signing Block and `remove_signing_block` was not called.
    #[error("the APK already has an APK Signing Block (replace it explicitly)")]
    SigningBlockPresent,
    /// The (re-)laid-out archive does not fit the 32-bit ZIP offsets.
    #[error("APK too large for a non-ZIP64 archive")]
    TooLarge,
    /// Stored entries are not aligned; call `Apk::align` before signing.
    #[error("the APK is not aligned (call align before signing)")]
    NotAligned,
    /// The certificate subject CN is not 1-64 printable ASCII characters.
    #[error("invalid certificate subject CN: {0}")]
    InvalidSubject(&'static str),
    /// The public key is not an uncompressed SEC1 point on P-256.
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
    /// A signature is not a strict DER ECDSA signature with r, s in [1, n-1].
    #[error("malformed ECDSA signature: {0}")]
    MalformedSignature(&'static str),
    /// A signature does not verify against the certificate's public key.
    #[error("signature does not verify against the certificate's public key")]
    SignatureMismatch,
    /// A certificate is not exactly one this crate builds for the expected key.
    #[error("invalid certificate: {0}")]
    InvalidCertificate(&'static str),
    /// The signing callback failed.
    #[error("signing failed: {0}")]
    Signer(Box<dyn std::error::Error + Send + Sync>),
    /// Internal consistency check of the produced APK failed (a bug, never ignored).
    #[error("internal check failed: {0}")]
    Internal(&'static str),
}

/// Result alias of this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
