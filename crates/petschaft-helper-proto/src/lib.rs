//! Frame codec and message types of `docs/helper-protocol.md` (protocol version 1).
//!
//! This crate knows nothing about the device or about `petschaft-core`; it only implements
//! the wire contract between `petschaft-device` (the host) and the Python helper.
//!
//! - [`frame`]: 4-byte big-endian length prefix, `1..=65536` bytes of UTF-8 JSON holding
//!   exactly one object. Lengths are checked before anything is allocated.
//! - [`message`]: typed messages for both directions ([`HostMessage`], [`HelperMessage`]).
//! - [`validate`]: every field rule of the spec. Validation runs on every decode
//!   ([`decode_host_message`], [`decode_helper_message`]) and before every encode
//!   ([`encode_host_message`], [`encode_helper_message`]), so neither side can send or
//!   accept a message that violates the contract.
//!
//! Error values never contain peer-supplied bytes: no credential, no challenge, no JSON
//! fragments (see [`Error`]).
//!
//! Interpretations of points the spec leaves open (documented in [`validate`]):
//! - all fields are required on the wire, `null` included (a missing `credential` is an
//!   error, not `null`);
//! - "printable ASCII" for `app_name`/`host_name`/`path` is 0x21-0x7E (no space), the
//!   definition given for tokens; the `device` strings allow space (0x20-0x7E) because
//!   trezorlib model names contain one ("Safe 7");
//! - `credential` must be 1-4096 bytes (empty is rejected);
//! - `ready.device` strings are 1-64 printable ASCII characters;
//! - `signed.public_key` must be 33 bytes and `signed.signature` 65 bytes (both curves);
//! - "printable" for `challenge_visual` approximates Python's `str.isprintable` (used by
//!   the helper): controls, format/bidi characters, non-ASCII separators, private use
//!   and noncharacters are rejected; unassigned code points are not detected;
//! - `error.message` is only length-checked (≤ 256 characters), as specified; consumers
//!   must sanitize it before showing it on a terminal.

#![forbid(unsafe_code)]

pub mod frame;
pub mod message;
pub mod validate;

mod b64;

pub use frame::{MAX_FRAME_LEN, read_frame, write_frame};
pub use message::{
    Credential, Curve, DeviceInfo, ErrorCode, ErrorResponse, Event, EventKind, Hello,
    HelperMessage, HostMessage, Identity, PairingCode, Passphrase, Proto, Ready, SignIdentity,
    Signed, Transport, decode_helper_message, decode_host_message, encode_helper_message,
    encode_host_message, read_helper_message, read_host_message, write_helper_message,
    write_host_message,
};
pub use validate::Validate;

/// The only protocol version this crate speaks (`hello.version`).
pub const PROTOCOL_VERSION: u32 = 1;

/// Errors of the codec. Messages never contain peer-supplied data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The stream ended inside a frame (after at least one byte of it).
    #[error("stream ended in the middle of a frame")]
    Truncated,
    #[error("invalid frame length {0} (must be 1..=65536)")]
    InvalidLength(u64),
    #[error("frame is not valid UTF-8")]
    InvalidUtf8,
    #[error("frame is not a single JSON object")]
    NotAnObject,
    /// JSON syntax error or a mismatch with the message schema (unknown field, unknown
    /// `type`, wrong value type, duplicate field, ...). Only the position is reported.
    #[error("frame does not match the protocol ({category} error at line {line}, column {column})")]
    Json {
        category: &'static str,
        line: usize,
        column: usize,
    },
    /// A field violates a rule of the spec.
    #[error("invalid field `{field}`: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

impl Error {
    pub(crate) fn field(field: &'static str, reason: &'static str) -> Self {
        Error::InvalidField { field, reason }
    }

    pub(crate) fn from_json(e: &serde_json::Error) -> Self {
        use serde_json::error::Category;
        let category = match e.classify() {
            Category::Io => "i/o",
            Category::Syntax => "syntax",
            Category::Data => "schema",
            Category::Eof => "unexpected end",
        };
        Error::Json {
            category,
            line: e.line(),
            column: e.column(),
        }
    }
}

#[cfg(test)]
mod tests;
