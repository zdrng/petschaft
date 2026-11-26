//! Typed messages of `docs/helper-protocol.md`, both directions.
//!
//! Structs only describe the shape; the field rules live in [`crate::validate`] and are
//! enforced by the `encode_*`/`decode_*`/`read_*`/`write_*` functions of this module.

use std::fmt;
use std::io::{Read, Write};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::validate::Validate;
use crate::{Error, b64, frame};

// ---------------------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------------------

/// `hello.transport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Usb,
    Ble,
    Auto,
}

/// `identity.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Ssh,
    Gpg,
}

/// `sign_identity.curve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Curve {
    Ed25519,
    Nist256p1,
}

/// `sign_identity.passphrase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Passphrase {
    Standard,
    Ask,
}

/// `event.event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Button,
    PairingCodeRequired,
}

/// `error.code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    DeviceNotFound,
    DeviceNotInitialized,
    PairingFailed,
    Cancelled,
    PassphraseUnavailable,
    DeviceError,
    Internal,
}

impl ErrorCode {
    /// Codes the spec declares "always fatal".
    pub fn always_fatal(self) -> bool {
        matches!(
            self,
            ErrorCode::BadRequest
                | ErrorCode::DeviceNotFound
                | ErrorCode::DeviceNotInitialized
                | ErrorCode::PairingFailed
                | ErrorCode::Internal
        )
    }

    /// Wire name, e.g. `"cancelled"`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::DeviceNotFound => "device_not_found",
            ErrorCode::DeviceNotInitialized => "device_not_initialized",
            ErrorCode::PairingFailed => "pairing_failed",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::PassphraseUnavailable => "passphrase_unavailable",
            ErrorCode::DeviceError => "device_error",
            ErrorCode::Internal => "internal",
        }
    }
}

// ---------------------------------------------------------------------------------------
// Secret-bearing values
// ---------------------------------------------------------------------------------------

/// Opaque THP pairing credential (`hello.credential`, `ready.credential`).
///
/// `Debug` is redacted; the bytes are only reachable through [`Credential::as_bytes`].
/// Valid credentials are 1..=4096 bytes ([`Credential::MAX_LEN`]); this is checked by
/// [`Credential::new`] and by validation of every message carrying one.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(Vec<u8>);

impl Credential {
    /// Maximum decoded size (spec: 4096 bytes).
    pub const MAX_LEN: usize = 4096;

    /// Validating constructor.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        let c = Credential(bytes);
        c.validate()?;
        Ok(c)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential(<redacted, {} bytes>)", self.0.len())
    }
}

impl Serialize for Credential {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        b64::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        b64::deserialize(d).map(Credential)
    }
}

// ---------------------------------------------------------------------------------------
// Common objects
// ---------------------------------------------------------------------------------------

/// The `identity` object (maps 1:1 onto trezorlib `messages.IdentityType`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub proto: Proto,
    #[serde(deserialize_with = "b64::required_option")]
    pub user: Option<String>,
    pub host: String,
    #[serde(deserialize_with = "b64::required_option")]
    pub port: Option<String>,
    #[serde(deserialize_with = "b64::required_option")]
    pub path: Option<String>,
    pub index: u32,
}

/// `ready.device`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub model: String,
    pub internal_model: String,
    pub firmware: String,
    pub passphrase_protection: bool,
}

// ---------------------------------------------------------------------------------------
// Host -> helper
// ---------------------------------------------------------------------------------------

/// `hello`: first message, exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub version: u32,
    pub app_name: String,
    pub host_name: String,
    pub transport: Transport,
    #[serde(deserialize_with = "b64::required_option")]
    pub credential: Option<Credential>,
}

/// `pairing_code`: only in reply to event `pairing_code_required`. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingCode {
    pub code: String,
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

/// `sign_identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignIdentity {
    pub id: u32,
    pub identity: Identity,
    pub curve: Curve,
    #[serde(with = "b64")]
    pub challenge_hidden: Vec<u8>,
    pub challenge_visual: String,
    pub passphrase: Passphrase,
}

/// Every message the host may send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    Hello(Hello),
    PairingCode(PairingCode),
    SignIdentity(SignIdentity),
}

// ---------------------------------------------------------------------------------------
// Helper -> host
// ---------------------------------------------------------------------------------------

/// `event`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub event: EventKind,
}

/// `ready`: final response to `hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub device: DeviceInfo,
    #[serde(deserialize_with = "b64::required_option")]
    pub credential: Option<Credential>,
}

/// `signed`: final response to `sign_identity`. Raw device bytes, not interpreted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub id: u32,
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

/// `error`: final response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    #[serde(deserialize_with = "b64::required_option")]
    pub id: Option<u32>,
    pub code: ErrorCode,
    pub message: String,
    pub fatal: bool,
}

/// Every message the helper may send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperMessage {
    Event(Event),
    Ready(Ready),
    Signed(Signed),
    Error(ErrorResponse),
}

// ---------------------------------------------------------------------------------------
// Encoding / decoding
// ---------------------------------------------------------------------------------------

/// Parse a frame payload as exactly one JSON object of type `T`, then validate it.
fn decode<T: for<'de> Deserialize<'de> + Validate>(payload: &[u8]) -> Result<T, Error> {
    let text = std::str::from_utf8(payload).map_err(|_| Error::InvalidUtf8)?;
    // Internally tagged enums would also accept a JSON array; require an object.
    // `from_str` rejects trailing non-whitespace, so this is exactly one value.
    if !text
        .trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
    {
        return Err(Error::NotAnObject);
    }
    let msg: T = serde_json::from_str(text).map_err(|e| Error::from_json(&e))?;
    msg.validate()?;
    Ok(msg)
}

fn encode<T: Serialize + Validate>(msg: &T) -> Result<Vec<u8>, Error> {
    msg.validate()?;
    let bytes = serde_json::to_vec(msg).map_err(|e| Error::from_json(&e))?;
    if bytes.is_empty() || bytes.len() > frame::MAX_FRAME_LEN {
        return Err(Error::InvalidLength(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        ));
    }
    Ok(bytes)
}

/// Validate and serialize a host message into a frame payload.
pub fn encode_host_message(msg: &HostMessage) -> Result<Vec<u8>, Error> {
    encode(msg)
}

/// Parse and validate a frame payload sent by the host.
pub fn decode_host_message(payload: &[u8]) -> Result<HostMessage, Error> {
    decode(payload)
}

/// Validate and serialize a helper message into a frame payload.
pub fn encode_helper_message(msg: &HelperMessage) -> Result<Vec<u8>, Error> {
    encode(msg)
}

/// Parse and validate a frame payload sent by the helper.
pub fn decode_helper_message(payload: &[u8]) -> Result<HelperMessage, Error> {
    decode(payload)
}

/// Read, parse and validate one host message. `Ok(None)` on clean EOF.
pub fn read_host_message<R: Read + ?Sized>(r: &mut R) -> Result<Option<HostMessage>, Error> {
    frame::read_frame(r)?
        .map(|p| decode_host_message(&p))
        .transpose()
}

/// Validate and write one host message as a frame.
pub fn write_host_message<W: Write + ?Sized>(w: &mut W, msg: &HostMessage) -> Result<(), Error> {
    frame::write_frame(w, &encode_host_message(msg)?)
}

/// Read, parse and validate one helper message. `Ok(None)` on clean EOF.
pub fn read_helper_message<R: Read + ?Sized>(r: &mut R) -> Result<Option<HelperMessage>, Error> {
    frame::read_frame(r)?
        .map(|p| decode_helper_message(&p))
        .transpose()
}

/// Validate and write one helper message as a frame.
pub fn write_helper_message<W: Write + ?Sized>(
    w: &mut W,
    msg: &HelperMessage,
) -> Result<(), Error> {
    frame::write_frame(w, &encode_helper_message(msg)?)
}
