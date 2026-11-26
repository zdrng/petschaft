//! Errors of `petschaft-device`. No variant ever carries the THP credential, the pairing code
//! or challenge bytes; texts received from the helper are sanitized before they are
//! stored in an error.

use petschaft_helper_proto::{ErrorCode, ErrorResponse};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The user rejected the action on the device (helper code `cancelled`).
    #[error("cancelled on the Trezor")]
    Cancelled,
    /// `passphrase = "ask"` but passphrase protection is disabled on the device.
    #[error(
        "passphrase entry is unavailable: passphrase protection is disabled on the Trezor; \
         set passphrase = \"standard\" for this identity or enable passphrase protection on the device"
    )]
    PassphraseUnavailable,
    #[error("no Trezor found: {0}")]
    DeviceNotFound(String),
    #[error("the Trezor is not initialized (no seed)")]
    DeviceNotInitialized,
    #[error("pairing with the Trezor failed: {0}")]
    PairingFailed(String),
    /// Helper code `device_error`.
    #[error("Trezor error: {0}")]
    Device(String),
    /// Helper code `bad_request`: the helper considered our request malformed.
    #[error("the helper rejected the request: {0}")]
    HelperBadRequest(String),
    /// Helper code `internal`.
    #[error("internal helper error: {0}")]
    HelperInternal(String),
    /// The helper violated `docs/helper-protocol.md`; it has been killed.
    #[error("helper protocol violation: {0}")]
    Protocol(String),
    /// A deadline of the spec expired; the helper has been killed.
    #[error("timed out waiting for the helper ({0})")]
    Timeout(&'static str),
    /// The helper closed its stdout (exited) before the final response.
    #[error("the helper exited unexpectedly")]
    HelperExited,
    /// Neither compile-time nor runtime helper paths are usable.
    #[error("helper not configured: {0}")]
    HelperNotConfigured(String),
    #[error("failed to start the helper: {0}")]
    Spawn(String),
    #[error("i/o error talking to the helper: {0}")]
    Io(String),
    /// The request violates the protocol rules (e.g. challenge too long); nothing was
    /// sent and the signer stays usable.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The pairing code from [`crate::Ui::pairing_code`] is not exactly 6 digits.
    #[error("invalid pairing code: must be exactly 6 digits")]
    InvalidPairingCode,
    /// Failure inside a [`crate::Ui`] implementation (e.g. the terminal is closed).
    #[error("user interaction failed: {0}")]
    Ui(String),
    /// The signer was closed after an earlier fatal error, timeout or violation.
    #[error("the helper connection is closed")]
    Closed,
    /// Local verification of the device's answer failed (bad key or signature,
    /// fingerprint mismatch).
    #[error(transparent)]
    Verification(#[from] petschaft_core::Error),
}

/// Replace characters that could manipulate a terminal (controls, bidi overrides,
/// zero-width characters) with U+FFFD. Length is already bounded by the protocol
/// (≤ 256 characters).
pub(crate) fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if petschaft_helper_proto::validate::is_forbidden_display_char(c) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

impl From<&ErrorResponse> for Error {
    fn from(e: &ErrorResponse) -> Self {
        let msg = sanitize(&e.message);
        match e.code {
            ErrorCode::Cancelled => Error::Cancelled,
            ErrorCode::PassphraseUnavailable => Error::PassphraseUnavailable,
            ErrorCode::DeviceNotFound => Error::DeviceNotFound(msg),
            ErrorCode::DeviceNotInitialized => Error::DeviceNotInitialized,
            ErrorCode::PairingFailed => Error::PairingFailed(msg),
            ErrorCode::DeviceError => Error::Device(msg),
            ErrorCode::BadRequest => Error::HelperBadRequest(msg),
            ErrorCode::Internal => Error::HelperInternal(msg),
        }
    }
}
