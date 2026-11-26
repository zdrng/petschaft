//! Field rules of `docs/helper-protocol.md`.
//!
//! Every rule of the spec is implemented here; where the spec is open, the stricter
//! reading is taken (see the crate docs for the list). The `encode_*`/`decode_*`
//! functions call [`Validate::validate`] unconditionally.

use crate::message::{
    Credential, Curve, DeviceInfo, ErrorResponse, Event, Hello, HelperMessage, HostMessage,
    Identity, PairingCode, Proto, Ready, SignIdentity, Signed,
};
use crate::{Error, PROTOCOL_VERSION};

/// Implemented by every message and sub-object.
pub trait Validate {
    fn validate(&self) -> Result<(), Error>;
}

/// Maximum decoded length of `challenge_hidden`.
pub const MAX_CHALLENGE_HIDDEN: usize = 512;
/// Maximum number of characters of `challenge_visual`.
pub const MAX_CHALLENGE_VISUAL_CHARS: usize = 128;
/// Maximum number of characters of `error.message`.
pub const MAX_ERROR_MESSAGE_CHARS: usize = 256;
/// Length of the device-format public key (both curves).
pub const DEVICE_PUBLIC_KEY_LEN: usize = 33;
/// Length of the device-format signature (both curves).
pub const DEVICE_SIGNATURE_LEN: usize = 65;

fn ensure(cond: bool, field: &'static str, reason: &'static str) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::field(field, reason))
    }
}

/// "token": 1-128 printable ASCII characters (0x21-0x7E) without `/`, `@`, `:`.
pub fn is_token(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| (0x21..=0x7E).contains(&b) && !matches!(b, b'/' | b'@' | b':'))
}

/// `port`: 1-5 ASCII digits.
pub fn is_port(s: &str) -> bool {
    (1..=5).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// `path`: 1-128 printable ASCII characters (0x21-0x7E) starting with `/`, no `@`.
pub fn is_path(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.starts_with('/')
        && s.bytes().all(|b| (0x21..=0x7E).contains(&b) && b != b'@')
}

/// 1-`max` printable ASCII characters including space (0x20-0x7E). Used for the
/// `device` strings (trezorlib model names such as "Safe 7" contain a space).
fn is_printable_ascii(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// `app_name`, `host_name`: 1-64 printable ASCII characters, read as 0x21-0x7E (the
/// definition the spec gives for tokens; no space), as the helper does.
pub fn is_name(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

/// `pairing_code.code`: exactly 6 ASCII digits.
pub fn is_pairing_code(s: &str) -> bool {
    s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Characters that must not appear in text shown on the device. An approximation of
/// "not printable" (Python's `str.isprintable`, which the helper applies) without
/// Unicode tables: C0/C1 controls and DEL (Cc), format characters (Cf: soft hyphen,
/// bidi marks/overrides/isolates, zero-width characters, BOM, tags, ...), separators
/// other than ASCII space (Zs, Zl, Zp), surrogates (impossible in `char`), private use
/// (Co) and noncharacters. Unassigned code points (Cn) are not detected here; the
/// helper rejects them with `bad_request`.
pub fn is_forbidden_display_char(c: char) -> bool {
    let cp = u32::from(c);
    c.is_control()
        || matches!(c,
            // Cf
            '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
            // Zs (except U+0020), Zl, Zp
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            // Co
            | '\u{E000}'..='\u{F8FF}'
            | '\u{F0000}'..='\u{10FFFF}'
            // Noncharacters
            | '\u{FDD0}'..='\u{FDEF}')
        || (cp & 0xFFFE) == 0xFFFE
}

/// `challenge_visual`: 0-128 printable characters (Unicode allowed, no control
/// characters).
pub fn is_challenge_visual(s: &str) -> bool {
    s.chars().count() <= MAX_CHALLENGE_VISUAL_CHARS && !s.chars().any(is_forbidden_display_char)
}

impl Validate for Credential {
    fn validate(&self) -> Result<(), Error> {
        let n = self.as_bytes().len();
        ensure(n >= 1, "credential", "must not be empty")?;
        ensure(
            n <= Credential::MAX_LEN,
            "credential",
            "longer than 4096 bytes",
        )
    }
}

impl Validate for Identity {
    fn validate(&self) -> Result<(), Error> {
        if let Some(user) = &self.user {
            ensure(is_token(user), "identity.user", "must be a token or null")?;
        }
        ensure(is_token(&self.host), "identity.host", "must be a token")?;
        if let Some(port) = &self.port {
            ensure(
                is_port(port),
                "identity.port",
                "must be 1-5 ASCII digits or null",
            )?;
        }
        if let Some(path) = &self.path {
            ensure(
                is_path(path),
                "identity.path",
                "must be 1-128 printable ASCII characters starting with '/', without '@'",
            )?;
        }
        // `index` is a u32 by type: 0 ..= 2^32-1.
        Ok(())
    }
}

impl Validate for DeviceInfo {
    fn validate(&self) -> Result<(), Error> {
        let reason = "must be 1-64 printable ASCII characters";
        ensure(is_printable_ascii(&self.model, 64), "device.model", reason)?;
        ensure(
            is_printable_ascii(&self.internal_model, 64),
            "device.internal_model",
            reason,
        )?;
        ensure(
            is_printable_ascii(&self.firmware, 64),
            "device.firmware",
            reason,
        )
    }
}

impl Validate for Hello {
    fn validate(&self) -> Result<(), Error> {
        ensure(
            self.version == PROTOCOL_VERSION,
            "version",
            "unsupported protocol version",
        )?;
        ensure(
            is_name(&self.app_name),
            "app_name",
            "must be 1-64 printable ASCII characters",
        )?;
        ensure(
            is_name(&self.host_name),
            "host_name",
            "must be 1-64 printable ASCII characters",
        )?;
        if let Some(c) = &self.credential {
            c.validate()?;
        }
        Ok(())
    }
}

impl Validate for PairingCode {
    fn validate(&self) -> Result<(), Error> {
        ensure(
            is_pairing_code(&self.code),
            "code",
            "must be exactly 6 ASCII digits",
        )
    }
}

impl Validate for SignIdentity {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.id >= 1, "id", "must be 1 ..= 2^32-1")?;
        self.identity.validate()?;
        ensure(
            self.challenge_hidden.len() <= MAX_CHALLENGE_HIDDEN,
            "challenge_hidden",
            "longer than 512 bytes",
        )?;
        if self.identity.proto == Proto::Gpg && self.curve == Curve::Nist256p1 {
            ensure(
                self.challenge_hidden.len() == 32,
                "challenge_hidden",
                "must be exactly 32 bytes for gpg with nist256p1",
            )?;
        }
        ensure(
            is_challenge_visual(&self.challenge_visual),
            "challenge_visual",
            "must be at most 128 printable characters",
        )
    }
}

impl Validate for HostMessage {
    fn validate(&self) -> Result<(), Error> {
        match self {
            HostMessage::Hello(m) => m.validate(),
            HostMessage::PairingCode(m) => m.validate(),
            HostMessage::SignIdentity(m) => m.validate(),
        }
    }
}

impl Validate for Event {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Validate for Ready {
    fn validate(&self) -> Result<(), Error> {
        self.device.validate()?;
        if let Some(c) = &self.credential {
            c.validate()?;
        }
        Ok(())
    }
}

impl Validate for Signed {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.id >= 1, "id", "must be 1 ..= 2^32-1")?;
        ensure(
            self.public_key.len() == DEVICE_PUBLIC_KEY_LEN,
            "public_key",
            "must be 33 bytes",
        )?;
        ensure(
            self.signature.len() == DEVICE_SIGNATURE_LEN,
            "signature",
            "must be 65 bytes",
        )
    }
}

impl Validate for ErrorResponse {
    fn validate(&self) -> Result<(), Error> {
        if let Some(id) = self.id {
            ensure(id >= 1, "id", "must be 1 ..= 2^32-1 or null")?;
        }
        ensure(
            self.message.chars().count() <= MAX_ERROR_MESSAGE_CHARS,
            "message",
            "longer than 256 characters",
        )?;
        ensure(
            self.fatal || !self.code.always_fatal(),
            "fatal",
            "must be true for this error code",
        )
    }
}

impl Validate for HelperMessage {
    fn validate(&self) -> Result<(), Error> {
        match self {
            HelperMessage::Event(m) => m.validate(),
            HelperMessage::Ready(m) => m.validate(),
            HelperMessage::Signed(m) => m.validate(),
            HelperMessage::Error(m) => m.validate(),
        }
    }
}
