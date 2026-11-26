//! SLIP-0013 identities as understood by the Trezor `SignIdentity` message.
//!
//! Reference: trezor-firmware `core/src/apps/misc/sign_identity.py`
//! (`serialize_identity`, `get_identity_path`) and SLIP-0013.
//!
//! Field rules (`docs/helper-protocol.md`, "identity"):
//! - "token": 1-128 printable ASCII characters (0x21-0x7E) without `/`, `@`, `:`.
//! - `user`: token or absent; `host`: token (required).
//! - `port`: 1-5 ASCII digits or absent (no numeric range check: the firmware treats it
//!   as an opaque string, and so do we, to keep the URI and hence the key unchanged).
//! - `path`: absent, or 1-128 printable ASCII characters (0x21-0x7E) starting with `/`,
//!   without `@`.
//!
//! With these rules the serialization of [`Identity::to_uri`] is injective and
//! [`Identity::parse`] is its exact inverse: the authority (`[user@]host[:port]`) cannot
//! contain `/`, so the first `/` starts the path; the user cannot contain `@`, so the
//! first `@` ends it; the host cannot contain `:`, so the first `:` after it starts the
//! port. Empty user/port/path are rejected because the firmware treats empty strings as
//! absent, which would make two different identities derive the same key.

use sha2::{Digest, Sha256};

use crate::Error;

/// Hardened BIP-32 index bit.
const HARDENED: u32 = 0x8000_0000;
/// SLIP-0013 purpose (`13'`).
const SLIP13_PURPOSE: u32 = 13;
/// Maximum length of a token (user, host) and of a path.
const MAX_FIELD_LEN: usize = 128;
/// Maximum number of digits of a port.
const MAX_PORT_LEN: usize = 5;

/// Protocol of an identity. Selects how the device prepares the data it signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// `ssh://`: ed25519 signs `challenge_hidden` raw; nist256p1 signs SHA-256(`challenge_hidden`).
    Ssh,
    /// `gpg://`: the device signs `challenge_hidden` as given (for nist256p1: a 32-byte digest).
    Gpg,
}

impl Proto {
    /// `"ssh"` / `"gpg"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Ssh => "ssh",
            Proto::Gpg => "gpg",
        }
    }

    /// Parse `"ssh"` / `"gpg"` (exact, lowercase); anything else is an error.
    /// Inverse of [`Proto::as_str`].
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "ssh" => Ok(Proto::Ssh),
            "gpg" => Ok(Proto::Gpg),
            _ => Err(Error::InvalidIdentity(
                "unsupported protocol (expected ssh or gpg)".into(),
            )),
        }
    }
}

/// Curve name as used by the Trezor (`ecdsa_curve_name`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    Ed25519,
    Nist256p1,
}

impl Curve {
    /// `"ed25519"` / `"nist256p1"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Curve::Ed25519 => "ed25519",
            Curve::Nist256p1 => "nist256p1",
        }
    }

    /// Parse `"ed25519"` / `"nist256p1"`; anything else is an error.
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "ed25519" => Ok(Curve::Ed25519),
            "nist256p1" => Ok(Curve::Nist256p1),
            _ => Err(Error::InvalidIdentity(
                "unsupported curve (expected ed25519 or nist256p1)".into(),
            )),
        }
    }
}

/// A SLIP-0013 identity. Field rules are those of `docs/helper-protocol.md` ("identity").
/// Construct only through [`Identity::parse`] or [`Identity::new`], which validate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    proto: Proto,
    user: Option<String>,
    host: String,
    port: Option<String>,
    path: Option<String>,
    index: u32,
}

/// Printable ASCII as defined by the helper protocol: 0x21-0x7E (no space).
fn is_printable(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}

fn validate_token(field: &str, s: &str) -> Result<(), Error> {
    let len_ok = (1..=MAX_FIELD_LEN).contains(&s.len());
    let chars_ok = s
        .bytes()
        .all(|b| is_printable(b) && b != b'/' && b != b'@' && b != b':');
    if len_ok && chars_ok {
        Ok(())
    } else {
        Err(Error::InvalidIdentity(format!(
            "{field} must be 1-{MAX_FIELD_LEN} printable ASCII characters without '/', '@', ':'"
        )))
    }
}

fn validate_port(s: &str) -> Result<(), Error> {
    if (1..=MAX_PORT_LEN).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(Error::InvalidIdentity(format!(
            "port must be 1-{MAX_PORT_LEN} ASCII digits"
        )))
    }
}

fn validate_path(s: &str) -> Result<(), Error> {
    let len_ok = (1..=MAX_FIELD_LEN).contains(&s.len());
    let chars_ok = s.bytes().all(|b| is_printable(b) && b != b'@');
    if len_ok && chars_ok && s.starts_with('/') {
        Ok(())
    } else {
        Err(Error::InvalidIdentity(format!(
            "path must be 1-{MAX_FIELD_LEN} printable ASCII characters starting with '/', without '@'"
        )))
    }
}

impl Identity {
    /// Validating constructor.
    pub fn new(
        proto: Proto,
        user: Option<String>,
        host: String,
        port: Option<String>,
        path: Option<String>,
        index: u32,
    ) -> Result<Self, Error> {
        if let Some(u) = &user {
            validate_token("user", u)?;
        }
        validate_token("host", &host)?;
        if let Some(p) = &port {
            validate_port(p)?;
        }
        if let Some(p) = &path {
            validate_path(p)?;
        }
        Ok(Identity {
            proto,
            user,
            host,
            port,
            path,
            index,
        })
    }

    /// Parse `proto://[user@]host[:port][/path]` (proto `ssh` or `gpg`).
    pub fn parse(uri: &str, index: u32) -> Result<Self, Error> {
        let (proto, rest) = uri.split_once("://").ok_or_else(|| {
            Error::InvalidIdentity("expected proto://[user@]host[:port][/path]".into())
        })?;
        let proto = Proto::parse(proto)?;
        // The authority contains no '/', so the first '/' (if any) starts the path.
        let (authority, path) = match rest.find('/') {
            Some(i) => {
                let (a, p) = rest.split_at(i);
                (a, Some(p))
            }
            None => (rest, None),
        };
        // The user contains no '@', so the first '@' (if any) ends it.
        let (user, host_port) = match authority.split_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, authority),
        };
        // The host contains no ':', so the first ':' (if any) starts the port.
        let (host, port) = match host_port.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (host_port, None),
        };
        Identity::new(
            proto,
            user.map(str::to_owned),
            host.to_owned(),
            port.map(str::to_owned),
            path.map(str::to_owned),
            index,
        )
    }

    /// The URI exactly as the firmware serializes it (`serialize_identity`). This string
    /// determines the key; `parse(to_uri())` must round-trip.
    pub fn to_uri(&self) -> String {
        let mut s = String::new();
        s.push_str(self.proto.as_str());
        s.push_str("://");
        if let Some(user) = &self.user {
            s.push_str(user);
            s.push('@');
        }
        s.push_str(&self.host);
        if let Some(port) = &self.port {
            s.push(':');
            s.push_str(port);
        }
        if let Some(path) = &self.path {
            s.push_str(path);
        }
        s
    }

    /// SLIP-0013 BIP-32 path: `[13', a', b', c', d']` from
    /// SHA-256(index as u32 little-endian || to_uri()), first 16 bytes as four u32 LE,
    /// each hardened (| 0x8000_0000).
    pub fn slip13_path(&self) -> [u32; 5] {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.to_uri().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut words = [0u32; 4];
        for (word, chunk) in words.iter_mut().zip(digest.chunks_exact(4)) {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            *word = u32::from_le_bytes(b) | HARDENED;
        }
        let [a, b, c, d] = words;
        [SLIP13_PURPOSE | HARDENED, a, b, c, d]
    }

    pub fn proto(&self) -> Proto {
        self.proto
    }
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> Option<&str> {
        self.port.as_deref()
    }
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
    pub fn index(&self) -> u32 {
        self.index
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
    use proptest::prelude::*;

    fn id(uri: &str, index: u32) -> Identity {
        Identity::parse(uri, index).unwrap()
    }

    /// Fixed SLIP-0013 vectors, computed independently of this code with
    /// `python3 -I -c` using `hashlib.sha256(struct.pack("<I", index) + uri.encode())`
    /// and `struct.unpack("<IIII", digest[:16])`, each OR'ed with 0x80000000, prefixed
    /// by 13', i.e. exactly `get_identity_path` from trezor-firmware
    /// `core/src/apps/misc/sign_identity.py`.
    #[test]
    fn slip13_vectors() {
        let cases: &[(&str, u32, [u32; 5])] = &[
            (
                "ssh://user@homelab",
                0,
                [
                    0x8000_000D,
                    0xD2D5_3F5E,
                    0xC60D_916C,
                    0x9580_1333,
                    0xEBD8_EE46,
                ],
            ),
            (
                "ssh://user@homelab",
                1,
                [
                    0x8000_000D,
                    0xF3C2_5A99,
                    0xD42B_364D,
                    0xF17A_4422,
                    0x8509_5E07,
                ],
            ),
            (
                "gpg://alice@example.org",
                0,
                [
                    0x8000_000D,
                    0x8CAB_76D6,
                    0xD7C8_FAAB,
                    0x9316_48B4,
                    0xF222_7E3E,
                ],
            ),
            (
                "ssh://git@github.com:22/repo",
                u32::MAX,
                [
                    0x8000_000D,
                    0xED05_A3FA,
                    0xB09A_B7AF,
                    0xEA94_2542,
                    0xD235_D666,
                ],
            ),
            (
                "ssh://host",
                7,
                [
                    0x8000_000D,
                    0xA0DD_356C,
                    0x8E40_AB32,
                    0x927C_AEC3,
                    0xAA84_1696,
                ],
            ),
        ];
        for (uri, index, expected) in cases {
            let identity = id(uri, *index);
            assert_eq!(identity.to_uri(), *uri);
            assert_eq!(identity.slip13_path(), *expected, "{uri} index {index}");
        }
    }

    #[test]
    fn parse_fields() {
        let i = id("ssh://git@github.com:2222/a/b:c", 3);
        assert_eq!(i.proto(), Proto::Ssh);
        assert_eq!(i.user(), Some("git"));
        assert_eq!(i.host(), "github.com");
        assert_eq!(i.port(), Some("2222"));
        assert_eq!(i.path(), Some("/a/b:c"));
        assert_eq!(i.index(), 3);

        let i = id("gpg://host", 0);
        assert_eq!(i.proto(), Proto::Gpg);
        assert_eq!(i.user(), None);
        assert_eq!(i.port(), None);
        assert_eq!(i.path(), None);

        let i = id("ssh://host/", 0);
        assert_eq!(i.path(), Some("/"));
    }

    #[test]
    fn parse_rejects() {
        let max = "a".repeat(128);
        let too_long = "a".repeat(129);
        let long_path = format!("/{}", "a".repeat(128));
        let bad: Vec<String> = vec![
            "".into(),
            "ssh:/host".into(),
            "ssh//host".into(),
            "host".into(),
            "SSH://host".into(),
            "https://host".into(),
            "signify://host".into(),
            "ssh://".into(),
            "ssh://@host".into(),
            "ssh://user@".into(),
            "ssh://user@@host".into(),
            "ssh://a@b@host".into(),
            "ssh://us:er@host".into(),
            "ssh://host:".into(),
            "ssh://host:123456".into(),
            "ssh://host:12a".into(),
            "ssh://host:-1".into(),
            "ssh://host:1:2".into(),
            "ssh://:22".into(),
            "ssh:///path".into(),
            "ssh://host/pa@th".into(),
            "ssh://host/pa th".into(),
            "ssh://ho st".into(),
            "ssh://host\n".into(),
            "ssh://h\u{00e4}st".into(),
            "ssh://host/\u{7f}".into(),
            format!("ssh://{too_long}"),
            format!("ssh://{too_long}@host"),
            format!("ssh://host{long_path}"),
        ];
        for uri in &bad {
            assert!(
                matches!(Identity::parse(uri, 0), Err(Error::InvalidIdentity(_))),
                "accepted {uri:?}"
            );
        }
        // Boundaries that must be accepted.
        let max_path = format!("/{}", "a".repeat(127));
        for uri in [
            format!("ssh://{max}@{max}:65535{max_path}"),
            "ssh://h:0".into(),
            "ssh://h:00000".into(),
            "ssh://!~#$%^&*()[]{}<>?;,.=+-_|\\\"'`".into(),
        ] {
            let i = id(&uri, 0);
            assert_eq!(i.to_uri(), uri);
        }
    }

    #[test]
    fn new_validates() {
        assert!(Identity::new(Proto::Ssh, Some(String::new()), "h".into(), None, None, 0).is_err());
        assert!(Identity::new(Proto::Ssh, None, String::new(), None, None, 0).is_err());
        assert!(Identity::new(Proto::Ssh, None, "h".into(), Some(String::new()), None, 0).is_err());
        assert!(Identity::new(Proto::Ssh, None, "h".into(), None, Some(String::new()), 0).is_err());
        assert!(Identity::new(Proto::Ssh, None, "h".into(), None, Some("x".into()), 0).is_err());
        assert!(Identity::new(Proto::Ssh, None, "h/x".into(), None, None, 0).is_err());
        let i = Identity::new(
            Proto::Gpg,
            Some("u".into()),
            "h".into(),
            Some("1".into()),
            Some("/p".into()),
            9,
        )
        .unwrap();
        assert_eq!(i.to_uri(), "gpg://u@h:1/p");
    }

    #[test]
    fn proto_and_curve_strings() {
        for p in [Proto::Ssh, Proto::Gpg] {
            assert_eq!(Proto::parse(p.as_str()).unwrap(), p);
        }
        for c in [Curve::Ed25519, Curve::Nist256p1] {
            assert_eq!(Curve::parse(c.as_str()).unwrap(), c);
        }
        for bad in ["", "SSH", "ssh ", "https", "signify"] {
            assert!(Proto::parse(bad).is_err());
        }
        for bad in ["", "Ed25519", "secp256k1", "nist256p1 ", "curve25519"] {
            assert!(Curve::parse(bad).is_err());
        }
    }

    #[test]
    fn index_changes_path_not_uri() {
        let a = id("ssh://user@homelab", 0);
        let b = id("ssh://user@homelab", 1);
        assert_eq!(a.to_uri(), b.to_uri());
        assert_ne!(a.slip13_path(), b.slip13_path());
    }

    // --- property tests ---

    /// Printable ASCII 0x21-0x7E without the given excluded characters.
    fn printable_except(excluded: &'static [u8]) -> impl Strategy<Value = char> {
        (0x21u8..=0x7E)
            .prop_filter("excluded", move |b| !excluded.contains(b))
            .prop_map(char::from)
    }

    fn token() -> impl Strategy<Value = String> {
        proptest::collection::vec(printable_except(b"/@:"), 1..=128)
            .prop_map(|v| v.into_iter().collect())
    }

    fn port() -> impl Strategy<Value = String> {
        "[0-9]{1,5}"
    }

    fn path() -> impl Strategy<Value = String> {
        proptest::collection::vec(printable_except(b"@"), 0..=127)
            .prop_map(|v| std::iter::once('/').chain(v).collect())
    }

    fn proto() -> impl Strategy<Value = Proto> {
        prop_oneof![Just(Proto::Ssh), Just(Proto::Gpg)]
    }

    prop_compose! {
        fn identity()(
            proto in proto(),
            user in proptest::option::of(token()),
            host in token(),
            port in proptest::option::of(port()),
            path in proptest::option::of(path()),
            index in any::<u32>(),
        ) -> Identity {
            Identity::new(proto, user, host, port, path, index).unwrap()
        }
    }

    proptest! {
        #[test]
        fn roundtrip(x in identity()) {
            let uri = x.to_uri();
            let parsed = Identity::parse(&uri, x.index()).unwrap();
            prop_assert_eq!(&parsed, &x);
            prop_assert_eq!(parsed.to_uri(), uri);
        }

        /// Arbitrary strings never panic; anything accepted re-serializes to the input
        /// (parse is injective on its domain, so no two URIs share a key).
        #[test]
        fn parse_arbitrary(s in any::<String>(), index in any::<u32>()) {
            if let Ok(i) = Identity::parse(&s, index) {
                prop_assert_eq!(i.to_uri(), s);
            }
        }

        /// Same, with strings biased towards the URI alphabet so that the accept path
        /// and near-misses are exercised.
        #[test]
        fn parse_uri_like(s in "(ssh|gpg|sh|SSH)?(:|://|//)?[a-z@:/ \\x7f.0-9]{0,24}") {
            if let Ok(i) = Identity::parse(&s, 0) {
                prop_assert_eq!(i.to_uri(), s);
            }
        }

        #[test]
        fn slip13_path_hardened(x in identity()) {
            let p = x.slip13_path();
            prop_assert_eq!(p[0], 13 | HARDENED);
            prop_assert!(p.iter().all(|w| w & HARDENED != 0));
        }
    }
}
