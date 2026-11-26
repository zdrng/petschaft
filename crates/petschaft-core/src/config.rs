//! `config.toml` schema and validation. See `docs/architecture.md` ("Configuration").
//!
//! ```toml
//! transport = "auto"            # auto | usb | ble (default auto); slip13 identities only
//! owner = "user"                # optional, [a-z0-9_-], 1-32 chars; used in default comments
//!
//! [defaults]
//! passphrase = "ask"            # ask | standard (default ask); slip13 identities only
//!
//! [[identity]]
//! name = "git"                  # [a-z0-9-], 1-32 chars, unique across all kinds
//! kind = "slip13"               # optional, default slip13
//! uri = "ssh://user@git-signing" # SLIP-0013 identity; proto ssh or gpg
//! curve = "ed25519"             # ed25519 | nist256p1
//! index = 0                     # optional, default 0
//! passphrase = "standard"       # optional, overrides [defaults]
//! fingerprint = "SHA256:…"      # optional pin
//! public_key = "ssh-ed25519 …"  # optional; OpenSSH key line of the curve, pins the key
//! host_keys = ["SHA256:…"]      # optional; server host keys `pets agent` may log in to
//! certificate = "MIIB…"         # optional; base64 DER X.509 certificate for APK signing,
//!                               # written by `pets apk init`; only gpg:// + nist256p1
//! comment = "user git signing"  # optional (both kinds), default <owner>@hwkey:<name>
//!
//! [[identity]]
//! name = "homelab"
//! kind = "fido2"                # OpenSSH security key, USB only
//! algorithm = "ed25519-sk"      # ed25519-sk | ecdsa-sk (required)
//! application = "ssh:homelab"  # optional, default ssh:<name>
//! user_verification = true      # optional, default true (PIN on every use)
//! resident = false              # optional, default false
//! fingerprint = "SHA256:…"      # optional pin
//! ```
//!
//! Two slip13 identities must not have the same effective pin (`fingerprint`, or the
//! fingerprint of `public_key`).
//!
//! Unknown keys anywhere are errors, and so are keys of the other kind (`uri` in a
//! fido2 identity, `algorithm` in a slip13 one): a typo or a misplaced setting must not
//! silently become a default. Error messages carry the line and column of the problem
//! or the identity's name, but never values or other contents of the file.
//!
//! The parsed types have private fields and no public constructors: a
//! [`Slip13Identity`] or [`Fido2Identity`] exists only if it came out of
//! [`Config::from_toml_str`]. Code that needs a slip13 identity (the device API) takes a
//! `&Slip13Identity`, so a fido2 identity cannot reach it.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use petschaft_apk::Certificate;
use serde::Deserialize;

use crate::{Curve, Error, Fingerprint, Identity, Proto, PublicKey, SkAlgorithm, SkApplication};

/// System-wide config file, used when there is no per-user one (see [`Config::locate`]).
/// Written by the NixOS / nix-darwin module: owned by root and usually a symlink chain
/// into `/nix/store`, which [`Config::load`] follows (it checks the final file).
pub const SYSTEM_CONFIG_PATH: &str = "/etc/petschaft/config.toml";

/// File name of the config inside the per-user directory.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Upper bound for the size of a config file (a typo'd path to a huge file must not
/// exhaust memory).
const MAX_CONFIG_SIZE: u64 = 1024 * 1024;
/// Longest user-supplied name echoed in an [`Error::UnknownIdentity`].
const MAX_ECHOED_NAME: usize = 64;

/// How to reach the device for slip13 identities (fido2 identities are always USB,
/// through OpenSSH).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    #[default]
    Auto,
    Usb,
    Ble,
}

impl Transport {
    /// `"auto"` / `"usb"` / `"ble"` (wire value of `hello.transport`).
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Auto => "auto",
            Transport::Usb => "usb",
            Transport::Ble => "ble",
        }
    }

    fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "auto" => Ok(Transport::Auto),
            "usb" => Ok(Transport::Usb),
            "ble" => Ok(Transport::Ble),
            _ => Err(Error::InvalidConfig(
                "transport must be auto, usb or ble".into(),
            )),
        }
    }
}

/// Passphrase policy of a slip13 identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PassphrasePolicy {
    /// New session, passphrase entered on the device, for every signature. Default.
    #[default]
    Ask,
    /// Standard wallet (empty passphrase), no prompt.
    Standard,
}

impl PassphrasePolicy {
    /// `"ask"` / `"standard"` (wire value of `sign_identity.passphrase`).
    pub fn as_str(self) -> &'static str {
        match self {
            PassphrasePolicy::Ask => "ask",
            PassphrasePolicy::Standard => "standard",
        }
    }

    fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "ask" => Ok(PassphrasePolicy::Ask),
            "standard" => Ok(PassphrasePolicy::Standard),
            _ => Err(Error::InvalidConfig(
                "passphrase must be ask or standard".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------------------

/// Name of a configured identity: 1-32 characters of `[a-z0-9-]`.
///
/// Safe to print, to put into an SSH key comment (`hwkey:<name>`) and into a FIDO
/// application string (`ssh:<name>`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    pub const MAX_LEN: usize = 32;

    pub fn parse(s: &str) -> Result<Self, Error> {
        // No leading '-': such names could not be passed on the command line.
        let valid = (1..=Self::MAX_LEN).contains(&s.len())
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if valid {
            Ok(Name(s.to_owned()))
        } else {
            Err(Error::InvalidConfig(format!(
                "name must be 1-{} characters of [a-z0-9-]",
                Self::MAX_LEN
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({})", self.0)
    }
}

impl FromStr for Name {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Name::parse(s)
    }
}

// ---------------------------------------------------------------------------------------
// Owner and key comments
// ---------------------------------------------------------------------------------------

/// Top-level `owner`: 1-32 characters of `[a-z0-9_-]`, not starting with `-`. Only
/// used to build default key comments (`<owner>@hwkey:<name>`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Owner(String);

impl Owner {
    pub const MAX_LEN: usize = 32;

    pub fn parse(s: &str) -> Result<Self, Error> {
        let valid = (1..=Self::MAX_LEN).contains(&s.len())
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if valid {
            Ok(Owner(s.to_owned()))
        } else {
            Err(Error::InvalidConfig(format!(
                "owner must be 1-{} characters of [a-z0-9_-], not starting with -",
                Self::MAX_LEN
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Owner({})", self.0)
    }
}

/// Middle part of default comments: `<owner>@hwkey:<name>` / `hwkey:<name>`.
const DEFAULT_COMMENT_TAG: &str = "hwkey:";

/// Comment of an identity's OpenSSH public key line (`<algorithm> <base64> <comment>`).
///
/// 1-128 characters; each one a space, an ASCII graphic character, or a letter or digit
/// of any script (`char::is_alphanumeric`). Not allowed: control characters (newline,
/// escape sequences), format characters (bidi overrides, zero-width), other symbols
/// (emoji) and leading or trailing spaces. So a comment always stays on one line, shows
/// the same on every terminal and in `authorized_keys`, survives OpenSSH unchanged and
/// is at most 512 bytes long.
///
/// The comment is metadata only: it is not part of the key, nothing is selected by it
/// (git signing finds the identity by fingerprint), and it can be changed in the config
/// at any time without creating a new key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Comment(String);

/// See [`Comment`].
fn is_comment_char(c: char) -> bool {
    c == ' ' || c.is_ascii_graphic() || c.is_alphanumeric()
}

impl Comment {
    /// Maximum number of characters (not bytes).
    pub const MAX_CHARS: usize = 128;

    pub fn parse(s: &str) -> Result<Self, Error> {
        let valid = !s.is_empty()
            && s.chars().count() <= Self::MAX_CHARS
            && !s.starts_with(' ')
            && !s.ends_with(' ')
            && s.chars().all(is_comment_char);
        if valid {
            Ok(Comment(s.to_owned()))
        } else {
            Err(Error::InvalidConfig(format!(
                "comment must be 1-{} characters (letters, digits, ASCII punctuation, \
                 inner spaces; no control characters or leading/trailing spaces)",
                Self::MAX_CHARS
            )))
        }
    }

    /// The default comment of identity `name`: `<owner>@hwkey:<name>` with an owner,
    /// else `hwkey:<name>`.
    ///
    /// Always valid: owner and name are ASCII graphic, at most 32 characters each, so
    /// the result has at most 71 characters (checked by a test).
    pub fn default_for(owner: Option<&Owner>, name: &Name) -> Self {
        Comment(match owner {
            Some(o) => format!("{}@{DEFAULT_COMMENT_TAG}{}", o.as_str(), name.as_str()),
            None => format!("{DEFAULT_COMMENT_TAG}{}", name.as_str()),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

impl fmt::Debug for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Comment({:?})", self.0)
    }
}

// ---------------------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------------------

/// Kind of a configured identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityKind {
    /// SLIP-0013 key derived on the Trezor, used through the petschaft helper (USB or BLE).
    Slip13,
    /// OpenSSH security key (FIDO2), used by OpenSSH itself, over USB only.
    Fido2,
}

impl IdentityKind {
    /// `"slip13"` / `"fido2"` (config value of `kind`).
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityKind::Slip13 => "slip13",
            IdentityKind::Fido2 => "fido2",
        }
    }

    /// How identities of this kind are used (completes "identity X is a K identity; …").
    pub fn usage(self) -> &'static str {
        match self {
            IdentityKind::Slip13 => {
                "it signs through the petschaft helper (USB or Bluetooth), not as a FIDO2 key"
            }
            IdentityKind::Fido2 => {
                "it can only be used over USB via OpenSSH (fido2 support: see `pets fido2`)"
            }
        }
    }

    fn parse(s: Option<&str>) -> Result<Self, Error> {
        match s {
            None | Some("slip13") => Ok(IdentityKind::Slip13),
            Some("fido2") => Ok(IdentityKind::Fido2),
            Some(_) => Err(Error::InvalidConfig("kind must be slip13 or fido2".into())),
        }
    }
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// A SLIP-0013 identity with all defaults resolved. Only produced by the config parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slip13Identity {
    name: Name,
    identity: Identity,
    curve: Curve,
    passphrase: PassphrasePolicy,
    /// Effective pin: `fingerprint`, else the fingerprint of `public_key`.
    fingerprint: Option<Fingerprint>,
    /// Boxed: a P-256 key is large, and identities are moved around in enums.
    public_key: Option<Box<PublicKey>>,
    /// Empty if not configured (the config rejects an empty list).
    host_keys: Vec<Fingerprint>,
    /// APK signing certificate; boxed for the same reason as `public_key`.
    certificate: Option<Box<Certificate>>,
    comment: Comment,
}

impl Slip13Identity {
    pub fn name(&self) -> &Name {
        &self.name
    }
    /// The SLIP-0013 URI and index.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn curve(&self) -> Curve {
        self.curve
    }
    pub fn passphrase(&self) -> PassphrasePolicy {
        self.passphrase
    }
    /// Pinned fingerprint; a device key that does not match it is rejected. The
    /// configured `fingerprint`, else the fingerprint of the configured `public_key`
    /// (if both are set, the parser has checked that they agree).
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.fingerprint.as_ref()
    }
    /// The configured public key (`public_key`), of this identity's curve. Its
    /// fingerprint is the pin (see [`Slip13Identity::fingerprint`]), so the device can
    /// only ever sign with exactly this key.
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_deref()
    }
    /// Host key fingerprints of the servers `pets agent` may log in to with this
    /// identity (`host_keys`). Empty if not configured; the agent only offers identities
    /// with a `public_key` and at least one host key. Non-empty only for `ssh://`
    /// identities with a `public_key`; never contains duplicates.
    pub fn host_keys(&self) -> &[Fingerprint] {
        &self.host_keys
    }
    /// The APK signing certificate (`certificate`, written by `pets apk init`), fully
    /// validated at load: exactly the self-signed certificate petschaft builds, with a
    /// valid self-signature. Only on `gpg://` identities with curve nist256p1. If the
    /// identity is pinned ([`Slip13Identity::fingerprint`]), the certificate's key is the
    /// pinned key; without a pin nothing ties it to the device yet (`pets apk sign`
    /// requires a pin).
    pub fn certificate(&self) -> Option<&Certificate> {
        self.certificate.as_deref()
    }
    /// Effective key comment (configured, else the default; see [`Comment`]).
    pub fn comment(&self) -> &Comment {
        &self.comment
    }
}

/// An OpenSSH security-key (FIDO2) identity with all defaults resolved. Only produced
/// by the config parser. It is used by OpenSSH over USB and never by the petschaft helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Identity {
    name: Name,
    algorithm: SkAlgorithm,
    application: SkApplication,
    user_verification: bool,
    resident: bool,
    fingerprint: Option<Fingerprint>,
    comment: Comment,
}

impl Fido2Identity {
    pub fn name(&self) -> &Name {
        &self.name
    }
    pub fn algorithm(&self) -> SkAlgorithm {
        self.algorithm
    }
    /// The configured application, or `ssh:<name>`.
    pub fn application(&self) -> &SkApplication {
        &self.application
    }
    /// `true` (default): PIN on every use (`ssh-keygen -O verify-required`).
    pub fn user_verification(&self) -> bool {
        self.user_verification
    }
    /// `true`: discoverable credential stored on the device (`ssh-keygen -O resident`).
    /// Default `false`.
    pub fn resident(&self) -> bool {
        self.resident
    }
    /// Pinned fingerprint of the OpenSSH public key.
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.fingerprint.as_ref()
    }
    /// Effective key comment (configured, else the default; see [`Comment`]). Replaces
    /// the comment of the `.pub` file wherever petschaft prints the key.
    pub fn comment(&self) -> &Comment {
        &self.comment
    }
}

/// One configured identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityConfig {
    Slip13(Slip13Identity),
    Fido2(Fido2Identity),
}

impl IdentityConfig {
    pub fn name(&self) -> &Name {
        match self {
            IdentityConfig::Slip13(i) => i.name(),
            IdentityConfig::Fido2(i) => i.name(),
        }
    }

    pub fn kind(&self) -> IdentityKind {
        match self {
            IdentityConfig::Slip13(_) => IdentityKind::Slip13,
            IdentityConfig::Fido2(_) => IdentityKind::Fido2,
        }
    }

    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        match self {
            IdentityConfig::Slip13(i) => i.fingerprint(),
            IdentityConfig::Fido2(i) => i.fingerprint(),
        }
    }

    /// Effective key comment.
    pub fn comment(&self) -> &Comment {
        match self {
            IdentityConfig::Slip13(i) => i.comment(),
            IdentityConfig::Fido2(i) => i.comment(),
        }
    }
}

/// Parsed and validated configuration. Only produced by [`Config::from_toml_str`] /
/// [`Config::load`] (or `Default`, the empty config).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    transport: Transport,
    identities: Vec<IdentityConfig>,
}

// --- raw TOML schema (private) ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    transport: Option<String>,
    owner: Option<String>,
    #[serde(default)]
    defaults: RawDefaults,
    #[serde(default)]
    identity: Vec<RawIdentity>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawDefaults {
    passphrase: Option<String>,
}

/// Union of the keys of both kinds; which ones are allowed depends on `kind`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    name: String,
    kind: Option<String>,
    fingerprint: Option<String>,
    comment: Option<String>,
    // slip13
    uri: Option<String>,
    curve: Option<String>,
    index: Option<u32>,
    passphrase: Option<String>,
    public_key: Option<String>,
    host_keys: Option<Vec<String>>,
    certificate: Option<String>,
    /// Never valid inside an identity; accepted by the schema (any type) only to give a
    /// clear error.
    transport: Option<toml::Value>,
    // fido2
    algorithm: Option<String>,
    application: Option<String>,
    user_verification: Option<bool>,
    resident: Option<bool>,
}

impl RawIdentity {
    /// Present keys that only a slip13 identity may have.
    fn slip13_keys(&self) -> Vec<&'static str> {
        [
            ("uri", self.uri.is_some()),
            ("curve", self.curve.is_some()),
            ("index", self.index.is_some()),
            ("passphrase", self.passphrase.is_some()),
            ("public_key", self.public_key.is_some()),
            ("host_keys", self.host_keys.is_some()),
            ("certificate", self.certificate.is_some()),
            ("transport", self.transport.is_some()),
        ]
        .into_iter()
        .filter_map(|(k, present)| present.then_some(k))
        .collect()
    }

    /// Present keys that only a fido2 identity may have.
    fn fido2_keys(&self) -> Vec<&'static str> {
        [
            ("algorithm", self.algorithm.is_some()),
            ("application", self.application.is_some()),
            ("user_verification", self.user_verification.is_some()),
            ("resident", self.resident.is_some()),
        ]
        .into_iter()
        .filter_map(|(k, present)| present.then_some(k))
        .collect()
    }
}

/// Longest parser message passed on (serde messages may quote a single value).
const MAX_PARSER_MESSAGE: usize = 200;

/// At most `max` characters of `s`, with an ellipsis if cut.
fn truncate(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if s.chars().nth(max).is_some() {
        out.push('…');
    }
    out
}

/// 1-based line and column of byte offset `pos` in `s`.
fn line_col(s: &str, pos: usize) -> (usize, usize) {
    let before = s.get(..pos).unwrap_or(s);
    let line = before
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        .saturating_add(1);
    let col = before
        .rsplit('\n')
        .next()
        .map_or(0, |l| l.chars().count())
        .saturating_add(1);
    (line, col)
}

/// Prefix an error of a field of identity `name` with the identity.
fn in_identity(name: &Name, e: Error) -> Error {
    match e {
        Error::InvalidConfig(m) => Error::InvalidConfig(format!("identity \"{name}\": {m}")),
        other => Error::InvalidConfig(format!("identity \"{name}\": {other}")),
    }
}

fn invalid(name: &Name, msg: impl fmt::Display) -> Error {
    Error::InvalidConfig(format!("identity \"{name}\": {msg}"))
}

/// The configured comment of identity `name`, else its default.
fn parse_comment(name: &Name, raw: Option<&str>, owner: Option<&Owner>) -> Result<Comment, Error> {
    match raw {
        Some(c) => Comment::parse(c).map_err(|e| in_identity(name, e)),
        None => Ok(Comment::default_for(owner, name)),
    }
}

fn parse_slip13(
    name: Name,
    ri: RawIdentity,
    default_passphrase: PassphrasePolicy,
    owner: Option<&Owner>,
) -> Result<Slip13Identity, Error> {
    if ri.transport.is_some() {
        return Err(invalid(
            &name,
            "transport is not allowed in an identity; set it at the top of the file",
        ));
    }
    let foreign = ri.fido2_keys();
    if !foreign.is_empty() {
        return Err(invalid(
            &name,
            format_args!(
                "{} not allowed for a slip13 identity (for a FIDO2 key set kind = \"fido2\")",
                foreign.join(", ")
            ),
        ));
    }
    let uri = ri.uri.ok_or_else(|| invalid(&name, "missing uri"))?;
    let curve = ri.curve.ok_or_else(|| invalid(&name, "missing curve"))?;
    let identity =
        Identity::parse(&uri, ri.index.unwrap_or(0)).map_err(|e| in_identity(&name, e))?;
    let curve =
        Curve::parse(&curve).map_err(|_| invalid(&name, "curve must be ed25519 or nist256p1"))?;
    let passphrase = match &ri.passphrase {
        Some(p) => PassphrasePolicy::parse(p).map_err(|e| in_identity(&name, e))?,
        None => default_passphrase,
    };
    let fingerprint = ri
        .fingerprint
        .as_deref()
        .map(Fingerprint::parse)
        .transpose()
        .map_err(|e| in_identity(&name, e))?;
    let public_key = ri
        .public_key
        .as_deref()
        .map(|line| parse_public_key(&name, line, curve).map(Box::new))
        .transpose()?;
    // Effective pin: both set → they must agree; only the key → its fingerprint.
    let fingerprint = match (fingerprint, &public_key) {
        (Some(f), Some(k)) if k.fingerprint() != f => {
            return Err(invalid(&name, "fingerprint does not match public_key"));
        }
        (Some(f), _) => Some(f),
        (None, Some(k)) => Some(k.fingerprint()),
        (None, None) => None,
    };
    let host_keys = match ri.host_keys {
        None => Vec::new(),
        Some(raw) => {
            if public_key.is_none() {
                return Err(invalid(
                    &name,
                    "host_keys requires public_key (printed by `pets pubkey`)",
                ));
            }
            if identity.proto() != Proto::Ssh {
                return Err(invalid(&name, "host_keys requires an ssh:// uri"));
            }
            parse_host_keys(&name, &raw)?
        }
    };
    let certificate = ri
        .certificate
        .as_deref()
        .map(|c| parse_certificate(&name, c, &identity, curve, fingerprint.as_ref()).map(Box::new))
        .transpose()?;
    let comment = parse_comment(&name, ri.comment.as_deref(), owner)?;
    Ok(Slip13Identity {
        name,
        identity,
        curve,
        passphrase,
        fingerprint,
        public_key,
        host_keys,
        certificate,
        comment,
    })
}

/// Longest accepted `certificate` value (base64). The certificate petschaft builds is
/// about 400 characters; this only bounds work on a wrong value.
const MAX_CERTIFICATE_B64: usize = 4096;

/// `certificate`: base64 of exactly the DER certificate `pets apk init` builds (see
/// [`Certificate::parse`]), for a `gpg://` nist256p1 identity; its key must be the
/// pinned key if there is a pin (`pin` is the effective one, so `public_key` is covered).
fn parse_certificate(
    name: &Name,
    b64: &str,
    identity: &Identity,
    curve: Curve,
    pin: Option<&Fingerprint>,
) -> Result<Certificate, Error> {
    if identity.proto() != Proto::Gpg || curve != Curve::Nist256p1 {
        return Err(invalid(
            name,
            "certificate (APK signing) requires a gpg:// uri and curve = \"nist256p1\"",
        ));
    }
    if b64.len() > MAX_CERTIFICATE_B64 {
        return Err(invalid(name, "certificate is too long"));
    }
    let der = STANDARD
        .decode(b64)
        .map_err(|_| invalid(name, "certificate is not valid base64 (standard, padded)"))?;
    let cert = Certificate::parse(&der).map_err(|e| {
        invalid(
            name,
            format_args!("certificate is not one written by `pets apk init` ({e})"),
        )
    })?;
    if let Some(pin) = pin {
        let key = PublicKey::from_p256_uncompressed(cert.public_key())
            .map_err(|e| in_identity(name, e))?;
        if key.fingerprint() != *pin {
            return Err(invalid(
                name,
                "certificate is for a different key than fingerprint / public_key",
            ));
        }
    }
    Ok(cert)
}

/// `public_key`: an OpenSSH key line of the identity's curve.
fn parse_public_key(name: &Name, line: &str, curve: Curve) -> Result<PublicKey, Error> {
    let key = PublicKey::from_openssh_line(line).map_err(|e| match e {
        Error::InvalidKeyLine(m) => invalid(
            name,
            format_args!("public_key must be an OpenSSH public key line ({m})"),
        ),
        other => in_identity(name, other),
    })?;
    if key.curve() != curve {
        return Err(invalid(
            name,
            format_args!(
                "public_key is a {} key, but curve is {}",
                key.openssh_algorithm(),
                curve.as_str()
            ),
        ));
    }
    Ok(key)
}

/// Most entries accepted in `host_keys` (a bound for memory and log output; real
/// configurations have a handful).
const MAX_HOST_KEYS: usize = 64;

/// `host_keys`: 1-[`MAX_HOST_KEYS`] distinct fingerprints.
fn parse_host_keys(name: &Name, raw: &[String]) -> Result<Vec<Fingerprint>, Error> {
    if raw.is_empty() {
        return Err(invalid(
            name,
            "host_keys must not be empty (remove it to keep the identity out of `pets agent`)",
        ));
    }
    if raw.len() > MAX_HOST_KEYS {
        return Err(invalid(
            name,
            format_args!("host_keys has more than {MAX_HOST_KEYS} entries"),
        ));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for (i, s) in raw.iter().enumerate() {
        let pos = i.saturating_add(1);
        let fp = Fingerprint::parse(s).map_err(|e| match e {
            Error::InvalidConfig(m) => invalid(name, format_args!("host_keys #{pos}: {m}")),
            other => in_identity(name, other),
        })?;
        if !seen.insert(fp.clone()) {
            return Err(invalid(name, format_args!("host_keys #{pos}: duplicate")));
        }
        out.push(fp);
    }
    Ok(out)
}

fn parse_fido2(name: Name, ri: RawIdentity, owner: Option<&Owner>) -> Result<Fido2Identity, Error> {
    let foreign = ri.slip13_keys();
    if !foreign.is_empty() {
        return Err(invalid(
            &name,
            format_args!(
                "{} not allowed for a fido2 identity (fido2 identities are only used over USB via OpenSSH)",
                foreign.join(", ")
            ),
        ));
    }
    let algorithm = ri
        .algorithm
        .ok_or_else(|| invalid(&name, "missing algorithm (ed25519-sk or ecdsa-sk)"))?;
    let algorithm = SkAlgorithm::parse(&algorithm).map_err(|e| in_identity(&name, e))?;
    let application = match &ri.application {
        Some(a) => SkApplication::parse(a).map_err(|e| in_identity(&name, e))?,
        None => SkApplication::default_for(&name),
    };
    let fingerprint = ri
        .fingerprint
        .as_deref()
        .map(Fingerprint::parse)
        .transpose()
        .map_err(|e| in_identity(&name, e))?;
    let comment = parse_comment(&name, ri.comment.as_deref(), owner)?;
    Ok(Fido2Identity {
        name,
        algorithm,
        application,
        // Secure defaults: PIN on every use, no credential stored on the device.
        user_verification: ri.user_verification.unwrap_or(true),
        resident: ri.resident.unwrap_or(false),
        fingerprint,
        comment,
    })
}

impl Config {
    /// Parse and validate. Unknown keys and keys of the other kind are errors.
    pub fn from_toml_str(s: &str) -> Result<Self, Error> {
        let raw: RawConfig = toml::from_str(s).map_err(|e| {
            // Only the parser's message and position; `Display` of the toml error would
            // quote the offending line of the file.
            let msg = truncate(e.message().trim(), MAX_PARSER_MESSAGE);
            match e.span() {
                Some(span) => {
                    let (line, col) = line_col(s, span.start);
                    Error::InvalidConfig(format!("line {line}, column {col}: {msg}"))
                }
                None => Error::InvalidConfig(msg),
            }
        })?;

        let transport = match &raw.transport {
            Some(t) => Transport::parse(t)?,
            None => Transport::default(),
        };
        let default_passphrase = match &raw.defaults.passphrase {
            Some(p) => PassphrasePolicy::parse(p).map_err(|e| match e {
                Error::InvalidConfig(m) => Error::InvalidConfig(format!("defaults: {m}")),
                other => other,
            })?,
            None => PassphrasePolicy::default(),
        };
        let owner = raw.owner.as_deref().map(Owner::parse).transpose()?;

        let mut names = HashSet::new();
        let mut applications: HashMap<SkApplication, Name> = HashMap::new();
        let mut pins: HashMap<Fingerprint, Name> = HashMap::new();
        let mut identities = Vec::with_capacity(raw.identity.len());
        for (n, ri) in raw.identity.into_iter().enumerate() {
            let pos = n.saturating_add(1);
            let name = Name::parse(&ri.name).map_err(|e| match e {
                Error::InvalidConfig(m) => Error::InvalidConfig(format!("identity #{pos}: {m}")),
                other => other,
            })?;
            if !names.insert(name.clone()) {
                return Err(Error::InvalidConfig(format!(
                    "identity #{pos}: duplicate name \"{name}\""
                )));
            }
            let kind =
                IdentityKind::parse(ri.kind.as_deref()).map_err(|e| in_identity(&name, e))?;
            let parsed = match kind {
                IdentityKind::Slip13 => {
                    let id = parse_slip13(name, ri, default_passphrase, owner.as_ref())?;
                    // One key, one identity: the agent finds the identity by its key,
                    // and two pins on the same key mean a copy-paste mistake.
                    if let Some(fp) = &id.fingerprint
                        && let Some(other) = pins.insert(fp.clone(), id.name.clone())
                    {
                        return Err(invalid(
                            &id.name,
                            format_args!(
                                "same key (public_key / fingerprint) as identity \"{other}\""
                            ),
                        ));
                    }
                    IdentityConfig::Slip13(id)
                }
                IdentityKind::Fido2 => {
                    let id = parse_fido2(name, ri, owner.as_ref())?;
                    // Two keys with the same application are indistinguishable for
                    // `ssh-keygen -K`, and a resident one would overwrite the other.
                    if let Some(other) =
                        applications.insert(id.application.clone(), id.name.clone())
                    {
                        return Err(invalid(
                            &id.name,
                            format_args!("application is already used by identity \"{other}\""),
                        ));
                    }
                    IdentityConfig::Fido2(id)
                }
            };
            identities.push(parsed);
        }

        Ok(Config {
            transport,
            identities,
        })
    }

    /// Read and parse `path`.
    ///
    /// Rejects anything that is not a regular file (after following symlinks) and files
    /// larger than 1 MiB. On Unix, only the current user or root may be able to write
    /// the config: the file must be owned by one of them and not be writable by group
    /// or others, and so must the directory holding it (after following symlinks),
    /// except that a sticky directory may be group/other-writable (others cannot replace
    /// a file they do not own there; `/nix/store` is root-owned with mode 1775). The
    /// file checks use the metadata of the opened file, so they apply to exactly the
    /// bytes that are read.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let shown = path.display();
        let io_err = |e: std::io::Error| Error::Io(format!("cannot read {shown}: {e}"));
        // The directory to check is the one holding the file the symlinks lead to.
        let real = std::fs::canonicalize(path).map_err(io_err)?;
        let file = std::fs::File::open(&real).map_err(io_err)?;
        let meta = file.metadata().map_err(io_err)?;
        if !meta.is_file() {
            return Err(Error::Io(format!("{shown} is not a regular file")));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let me = current_uid()
                .map_err(|e| Error::Io(format!("cannot determine the current user: {e}")))?;
            let mode = meta.mode() & 0o7777;
            match untrusted(meta.uid(), mode, me, false) {
                Some(Untrusted::Owner) => {
                    return Err(Error::InvalidConfig(format!(
                        "{shown} is owned by uid {}, not by the current user (uid {me}) or root",
                        meta.uid()
                    )));
                }
                Some(Untrusted::Writable) => {
                    return Err(Error::InvalidConfig(format!(
                        "{shown} is writable by group or others (mode {mode:o}); run: chmod go-w {shown}"
                    )));
                }
                None => {}
            }
            let dir = real.parent().unwrap_or(Path::new("/"));
            let dir_meta = std::fs::metadata(dir)
                .map_err(|e| Error::Io(format!("cannot check {}: {e}", dir.display())))?;
            let dir_mode = dir_meta.mode() & 0o7777;
            match untrusted(dir_meta.uid(), dir_mode, me, true) {
                Some(Untrusted::Owner) => {
                    return Err(Error::InvalidConfig(format!(
                        "{} (the directory of {shown}) is owned by uid {}, not by the current \
                         user (uid {me}) or root",
                        dir.display(),
                        dir_meta.uid()
                    )));
                }
                Some(Untrusted::Writable) => {
                    return Err(Error::InvalidConfig(format!(
                        "{} (the directory of {shown}) is writable by group or others (mode \
                         {dir_mode:o}); run: chmod go-w {}",
                        dir.display(),
                        dir.display()
                    )));
                }
                None => {}
            }
        }
        if meta.len() > MAX_CONFIG_SIZE {
            return Err(Error::InvalidConfig(format!(
                "{shown} is larger than {MAX_CONFIG_SIZE} bytes"
            )));
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_SIZE.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io_err)?;
        if u64::try_from(bytes.len()).map_or(true, |l| l > MAX_CONFIG_SIZE) {
            return Err(Error::InvalidConfig(format!(
                "{shown} is larger than {MAX_CONFIG_SIZE} bytes"
            )));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| Error::InvalidConfig(format!("{shown} is not valid UTF-8")))?;
        Self::from_toml_str(&text).map_err(|e| match e {
            Error::InvalidConfig(m) => Error::InvalidConfig(format!("{shown}: {m}")),
            other => other,
        })
    }

    /// Per-user petschaft directory: `$XDG_CONFIG_HOME/petschaft`, else
    /// `$HOME/.config/petschaft` (same on macOS and Linux). `None` if neither variable is
    /// set to an absolute path.
    ///
    /// Per-user files (the FIDO2 key handles in `fido2/`) always live here, whichever
    /// config file was loaded.
    pub fn user_dir() -> Option<PathBuf> {
        user_dir_from(
            std::env::var_os("XDG_CONFIG_HOME"),
            std::env::var_os("HOME"),
        )
    }

    /// Per-user config file: [`Config::user_dir`]`/config.toml`.
    pub fn user_path() -> Option<PathBuf> {
        Self::user_dir().map(|d| d.join(CONFIG_FILE_NAME))
    }

    /// The config file to use when none is given explicitly: the per-user file
    /// ([`Config::user_path`]) if anything exists at that path, otherwise
    /// [`SYSTEM_CONFIG_PATH`] if that exists. The two are never merged.
    ///
    /// "Exists" includes a dangling symlink or an unreadable file: a broken per-user
    /// config is reported by [`Config::load`] instead of silently falling back to the
    /// system one. Neither present → [`Error::ConfigNotFound`] naming both paths.
    pub fn locate() -> Result<PathBuf, Error> {
        locate_in(Self::user_path(), Path::new(SYSTEM_CONFIG_PATH))
    }

    /// Transport for slip13 identities.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// All identities, in file order.
    pub fn identities(&self) -> &[IdentityConfig] {
        &self.identities
    }

    pub fn find(&self, name: &str) -> Option<&IdentityConfig> {
        self.identities.iter().find(|i| i.name().as_str() == name)
    }

    /// The slip13 identity `name`; an error if there is none or it is of another kind.
    pub fn slip13(&self, name: &str) -> Result<&Slip13Identity, Error> {
        match self.find(name) {
            Some(IdentityConfig::Slip13(id)) => Ok(id),
            Some(other) => Err(wrong_kind(other)),
            None => Err(unknown(name)),
        }
    }

    /// The fido2 identity `name`; an error if there is none or it is of another kind.
    pub fn fido2(&self, name: &str) -> Result<&Fido2Identity, Error> {
        match self.find(name) {
            Some(IdentityConfig::Fido2(id)) => Ok(id),
            Some(other) => Err(wrong_kind(other)),
            None => Err(unknown(name)),
        }
    }
}

/// Why someone other than the current user or root could change a config file.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum Untrusted {
    Owner,
    Writable,
}

/// The problem with a config file (or, with `dir`, the directory holding it) with
/// owner `uid` and `mode` for the user `me`; `None` if only `me` or root can change it.
#[cfg(unix)]
fn untrusted(uid: u32, mode: u32, me: u32, dir: bool) -> Option<Untrusted> {
    if uid != me && uid != 0 {
        return Some(Untrusted::Owner);
    }
    let sticky = dir && mode & 0o1000 != 0;
    (mode & 0o022 != 0 && !sticky).then_some(Untrusted::Writable)
}

/// The effective uid of this process: the owner of a socket we just created. std has
/// no `getuid` and the workspace forbids `unsafe`; unlike the agent's temporary socket
/// file, a socket pair touches no file system.
#[cfg(unix)]
fn current_uid() -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let (ours, _peer) = std::os::unix::net::UnixStream::pair()?;
    Ok(std::fs::File::from(std::os::fd::OwnedFd::from(ours))
        .metadata()?
        .uid())
}

fn wrong_kind(id: &IdentityConfig) -> Error {
    Error::WrongIdentityKind {
        name: id.name().clone(),
        kind: id.kind(),
    }
}

fn unknown(name: &str) -> Error {
    Error::UnknownIdentity(truncate(name, MAX_ECHOED_NAME))
}

/// [`Config::user_dir`] with the environment passed in (testable without mutating
/// the process environment). Relative or empty values are ignored, as the XDG Base
/// Directory spec requires.
fn user_dir_from(xdg_config_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(base) = absolute(xdg_config_home) {
        return Some(base.join("petschaft"));
    }
    absolute(home).map(|h| h.join(".config").join("petschaft"))
}

/// [`Config::locate`] with the candidate paths passed in (tests never touch `/etc`).
fn locate_in(user: Option<PathBuf>, system: &Path) -> Result<PathBuf, Error> {
    if let Some(user) = &user
        && present(user)?
    {
        return Ok(user.clone());
    }
    if present(system)? {
        return Ok(system.to_owned());
    }
    Err(Error::ConfigNotFound(match user {
        Some(u) => format!(
            "neither {} (per user) nor {} (system) exists",
            u.display(),
            system.display()
        ),
        None => format!(
            "{} (system) does not exist, and there is no per-user path \
             (neither XDG_CONFIG_HOME nor HOME is an absolute path)",
            system.display()
        ),
    }))
}

/// Whether anything (including a dangling symlink) is at `path`. Errors other than
/// "not found" (e.g. permission denied on a parent) are errors, not "absent".
fn present(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(format!("cannot check {}: {e}", path.display()))),
    }
}

#[cfg(test)]
mod tests;
