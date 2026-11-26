//! Device-independent core of petschaft: SLIP-0013 identities, curves, configuration,
//! public keys and verification of signatures returned by the Trezor.
//!
//! # Parse, don't validate
//!
//! Every type that carries an invariant has private fields and is only produced by a
//! parsing or validating constructor, so a value of the type is the proof that the
//! check happened:
//!
//! - [`Name`], [`Owner`], [`Comment`], [`Fingerprint`], [`SkApplication`], [`Identity`]:
//!   `parse` (or a total constructor such as [`Fingerprint::of_openssh_blob`] or
//!   [`Comment::default_for`]).
//! - [`Slip13Identity`], [`Fido2Identity`], [`IdentityConfig`], [`Config`]: only
//!   [`Config::from_toml_str`] / [`Config::load`].
//! - [`PublicKey`]: only [`PublicKey::from_device`], [`PublicKey::from_openssh_blob`] /
//!   [`PublicKey::from_openssh_line`] or [`PublicKey::from_p256_uncompressed`] (all fully
//!   validate the point); [`Signature`]: only
//!   [`verify_identity_signature`].
//!
//! ```compile_fail
//! // A public key cannot be built from unchecked bytes.
//! let _ = petschaft_core::PublicKey::Ed25519([0u8; 32]);
//! ```
//! ```compile_fail
//! // Nor a signature that was never verified.
//! let _ = petschaft_core::Signature::Ed25519([0u8; 64]);
//! ```
//! ```compile_fail
//! // Nor an identity that did not come from the config parser.
//! let _ = petschaft_core::Slip13Identity { name: todo!(), identity: todo!(), curve: todo!(),
//!     passphrase: todo!(), fingerprint: None, comment: todo!() };
//! ```
//!
//! API CONTRACT: the public items in this crate are used by `petschaft-device`, `petschaft-sshsig`
//! and `petschaft`. Do not change signatures without updating those crates.

#![forbid(unsafe_code)]

pub mod config;
pub mod identity;
pub mod key;
pub mod sk;

pub use config::{
    Comment, Config, Fido2Identity, IdentityConfig, IdentityKind, Name, Owner, PassphrasePolicy,
    SYSTEM_CONFIG_PATH, Slip13Identity, Transport,
};
pub use identity::{Curve, Identity, Proto};
pub use key::{Fingerprint, PublicKey, Signature, SignatureParts, verify_identity_signature};
pub use sk::{SkAlgorithm, SkApplication};

/// Errors of this crate. Messages must never contain secret material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid public key from device: {0}")]
    InvalidPublicKey(String),
    /// An OpenSSH public key line or blob (e.g. `public_key` in the config) is invalid.
    /// The text never quotes the input.
    #[error("invalid OpenSSH public key: {0}")]
    InvalidKeyLine(&'static str),
    #[error("invalid signature from device: {0}")]
    InvalidSignature(String),
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("fingerprint mismatch: expected {expected}, device returned {actual}")]
    FingerprintMismatch {
        expected: Fingerprint,
        actual: Fingerprint,
    },
    /// No identity of that name in the config. The name is user input: printed with
    /// `{:?}`, so control characters are escaped.
    #[error("no identity named {0:?} in the config (see `pets list`)")]
    UnknownIdentity(String),
    /// The identity exists but is of another kind than the operation needs.
    #[error("identity \"{name}\" is a {kind} identity; {}", kind.usage())]
    WrongIdentityKind { name: Name, kind: IdentityKind },
    #[error("io error: {0}")]
    Io(String),
    /// No config path was given and none of the default locations exists.
    #[error("no config file: {0}")]
    ConfigNotFound(String),
}
