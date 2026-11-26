//! Parsing of OpenSSH security-key public key lines (`<key>.pub`).
//!
//! Wire formats (OpenSSH `PROTOCOL.u2f`, "SSH U2F/FIDO public key format"; strings
//! per RFC 4251 §5: `uint32` big-endian length, then the bytes):
//!
//! ```text
//! string  "sk-ssh-ed25519@openssh.com"
//! string  public key (32 bytes)
//! string  application
//!
//! string  "sk-ecdsa-sha2-nistp256@openssh.com"
//! string  "nistp256"
//! string  Q (SEC1 uncompressed point, 65 bytes, 0x04 || x || y)
//! string  application
//! ```
//!
//! The parser accepts exactly these two layouts with no trailing bytes. It checks
//! lengths and the SEC1 prefix but does not decode curve points (no curve arithmetic
//! in this crate); the private key lives on the authenticator and `sshd` validates
//! the point when it verifies a signature.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use sha2::{Digest as _, Sha256};

use crate::Error;

/// Largest `.pub` file [`read_public`] reads. Real lines are ~150-250 bytes.
pub const MAX_PUB_FILE_LEN: u64 = 8 * 1024;

/// Longest accepted comment (bytes). 512 = 128 characters of up to 4 bytes each, the
/// longest comment a petschaft config allows.
pub const MAX_COMMENT_LEN: usize = 512;

/// Longest accepted application string (bytes), including the `ssh:` prefix.
pub const MAX_APPLICATION_LEN: usize = 128;

/// Application strings of OpenSSH security keys must start with this.
pub const APPLICATION_PREFIX: &str = "ssh:";

const ED25519_KEY_LEN: usize = 32;
const P256_POINT_LEN: usize = 65;
const SEC1_UNCOMPRESSED: u8 = 0x04;
const P256_CURVE_ID: &[u8] = b"nistp256";

/// The two supported OpenSSH security-key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkAlgorithm {
    /// `sk-ssh-ed25519@openssh.com` (`ssh-keygen -t ed25519-sk`).
    Ed25519,
    /// `sk-ecdsa-sha2-nistp256@openssh.com` (`ssh-keygen -t ecdsa-sk`).
    EcdsaP256,
}

impl SkAlgorithm {
    /// All supported algorithms, in the order recommended for `PubkeyAcceptedAlgorithms`.
    pub const ALL: [SkAlgorithm; 2] = [SkAlgorithm::Ed25519, SkAlgorithm::EcdsaP256];

    /// The OpenSSH algorithm name (first token of a `.pub` line, first string of the blob).
    pub fn ssh_name(self) -> &'static str {
        match self {
            SkAlgorithm::Ed25519 => "sk-ssh-ed25519@openssh.com",
            SkAlgorithm::EcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    /// The `ssh-keygen -t` argument that creates a key of this algorithm.
    pub fn keygen_type(self) -> &'static str {
        match self {
            SkAlgorithm::Ed25519 => "ed25519-sk",
            SkAlgorithm::EcdsaP256 => "ecdsa-sk",
        }
    }

    /// Inverse of [`SkAlgorithm::ssh_name`].
    pub fn from_ssh_name(name: &str) -> Option<Self> {
        SkAlgorithm::ALL.into_iter().find(|a| a.ssh_name() == name)
    }

    /// Inverse of [`SkAlgorithm::keygen_type`].
    pub fn from_keygen_type(t: &str) -> Option<Self> {
        SkAlgorithm::ALL.into_iter().find(|a| a.keygen_type() == t)
    }
}

/// A validated security-key public key line (`<algorithm> <base64 blob> [comment]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyLine {
    algorithm: SkAlgorithm,
    blob: Vec<u8>,
    application: String,
    comment: Option<String>,
    fingerprint: String,
}

impl PublicKeyLine {
    /// Parse one line as written by `ssh-keygen` into `<key>.pub`. A single trailing
    /// `\n` (or `\r\n`) is allowed; anything else after the line is rejected.
    pub fn parse(line: &str) -> Result<Self, Error> {
        let line = line
            .strip_suffix('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .unwrap_or(line);
        if line.contains(['\n', '\r']) {
            return Err(Error::InvalidPublicKey("more than one line"));
        }
        let (alg_name, rest) = line
            .split_once(' ')
            .ok_or(Error::InvalidPublicKey("missing key data"))?;
        let algorithm = SkAlgorithm::from_ssh_name(alg_name)
            .ok_or(Error::InvalidPublicKey("not a supported security-key type"))?;
        let (b64, comment) = match rest.split_once(' ') {
            Some((b, c)) => (b, Some(c)),
            None => (rest, None),
        };
        let blob = STANDARD
            .decode(b64)
            .map_err(|_| Error::InvalidPublicKey("key data is not canonical base64"))?;
        let application = parse_blob(algorithm, &blob)?;
        let comment = match comment {
            None => None,
            Some(c) => {
                validate_comment(c).map_err(Error::InvalidPublicKey)?;
                Some(c.to_owned())
            }
        };
        let fingerprint = fingerprint(&blob);
        Ok(PublicKeyLine {
            algorithm,
            blob,
            application,
            comment,
            fingerprint,
        })
    }

    pub fn algorithm(&self) -> SkAlgorithm {
        self.algorithm
    }

    /// The SSH wire-format public key blob.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The FIDO application (relying party id) bound into the key, e.g. `ssh:homelab`.
    pub fn application(&self) -> &str {
        &self.application
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// The same key with `comment` instead of the one from the file (the comment is
    /// not part of the key: blob, application and fingerprint are unchanged). `comment`
    /// must follow the same rules as a parsed comment, else [`Error::InvalidInput`].
    pub fn with_comment(&self, comment: &str) -> Result<Self, Error> {
        validate_comment(comment).map_err(|reason| Error::InvalidInput {
            field: "comment",
            reason,
        })?;
        Ok(PublicKeyLine {
            comment: Some(comment.to_owned()),
            ..self.clone()
        })
    }

    /// OpenSSH fingerprint: `SHA256:` + unpadded standard base64 of SHA-256(blob), as
    /// printed by `ssh-keygen -l`.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The canonical line `<algorithm> <base64 blob>[ <comment>]` (no newline).
    pub fn to_line(&self) -> String {
        let mut s = format!(
            "{} {}",
            self.algorithm.ssh_name(),
            STANDARD.encode(&self.blob)
        );
        if let Some(c) = &self.comment {
            s.push(' ');
            s.push_str(c);
        }
        s
    }
}

/// `SHA256:` + unpadded standard base64 of SHA-256(`blob`).
pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// Read and parse `<key_path>.pub` (at most [`MAX_PUB_FILE_LEN`] bytes, UTF-8, one
/// line). The key handle file itself is never read.
pub fn read_public(key_path: &Path) -> Result<PublicKeyLine, Error> {
    let pub_path = pub_path(key_path);
    let file = File::open(&pub_path).map_err(|e| Error::io("cannot open", &pub_path, e))?;
    let mut buf = Vec::new();
    file.take(MAX_PUB_FILE_LEN.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| Error::io("cannot read", &pub_path, e))?;
    if u64::try_from(buf.len()).map_or(true, |n| n > MAX_PUB_FILE_LEN) {
        return Err(Error::TooLarge {
            path: pub_path,
            limit: MAX_PUB_FILE_LEN,
        });
    }
    let text =
        std::str::from_utf8(&buf).map_err(|_| Error::InvalidPublicKey("file is not UTF-8"))?;
    PublicKeyLine::parse(text)
}

/// `<key_path>.pub`, built like OpenSSH does (append, do not replace an extension).
pub fn pub_path(key_path: &Path) -> PathBuf {
    let mut s = key_path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

/// Comment rules shared by parsing and [`crate::CreateOptions`]: 1..=[`MAX_COMMENT_LEN`]
/// bytes, no control characters (so it stays on one line in `authorized_keys`), no
/// leading/trailing whitespace (OpenSSH would not round-trip it).
pub(crate) fn validate_comment(c: &str) -> Result<(), &'static str> {
    if c.is_empty() || c.len() > MAX_COMMENT_LEN {
        return Err("comment must be 1-512 bytes");
    }
    if c.chars().any(char::is_control) {
        return Err("comment contains control characters");
    }
    if c.trim() != c {
        return Err("comment has leading or trailing whitespace");
    }
    Ok(())
}

/// Application rules shared by parsing and [`crate::CreateOptions`]: `ssh:` followed by
/// printable ASCII without spaces, at most [`MAX_APPLICATION_LEN`] bytes. OpenSSH itself
/// requires the `ssh:` prefix when creating keys.
pub(crate) fn validate_application(a: &str) -> Result<(), &'static str> {
    if !a.starts_with(APPLICATION_PREFIX) {
        return Err("application must start with \"ssh:\"");
    }
    if a.len() > MAX_APPLICATION_LEN {
        return Err("application is longer than 128 bytes");
    }
    if !a.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("application must be printable ASCII without spaces");
    }
    Ok(())
}

/// Validate the blob layout of `algorithm`; returns the application string.
fn parse_blob(algorithm: SkAlgorithm, blob: &[u8]) -> Result<String, Error> {
    let mut r = Reader(blob);
    if r.string()? != algorithm.ssh_name().as_bytes() {
        return Err(Error::InvalidPublicKey(
            "key data does not match the algorithm name",
        ));
    }
    match algorithm {
        SkAlgorithm::Ed25519 => {
            if r.string()?.len() != ED25519_KEY_LEN {
                return Err(Error::InvalidPublicKey("ed25519 key is not 32 bytes"));
            }
        }
        SkAlgorithm::EcdsaP256 => {
            if r.string()? != P256_CURVE_ID {
                return Err(Error::InvalidPublicKey("ecdsa curve is not nistp256"));
            }
            let q = r.string()?;
            if q.len() != P256_POINT_LEN || q.first() != Some(&SEC1_UNCOMPRESSED) {
                return Err(Error::InvalidPublicKey(
                    "ecdsa point is not 65-byte uncompressed SEC1",
                ));
            }
        }
    }
    let application = std::str::from_utf8(r.string()?)
        .map_err(|_| Error::InvalidPublicKey("application is not UTF-8"))?;
    validate_application(application).map_err(Error::InvalidPublicKey)?;
    if !r.0.is_empty() {
        return Err(Error::InvalidPublicKey("trailing bytes after key data"));
    }
    Ok(application.to_owned())
}

/// Minimal RFC 4251 reader over a byte slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Result<&'a [u8], Error> {
        let (len, rest) = self
            .0
            .split_first_chunk::<4>()
            .ok_or(Error::InvalidPublicKey("truncated key data"))?;
        let len = usize::try_from(u32::from_be_bytes(*len))
            .map_err(|_| Error::InvalidPublicKey("truncated key data"))?;
        let (s, rest) = rest
            .split_at_checked(len)
            .ok_or(Error::InvalidPublicKey("truncated key data"))?;
        self.0 = rest;
        Ok(s)
    }
}
