//! Error type of the crate.
//!
//! Messages never contain key material or file contents: only paths, option names,
//! static reasons and exit statuses.

use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

/// Everything that can go wrong in `petschaft-fido2`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `PETSCHAFT_OPENSSH_BIN` is unset (at build time and at run time) or not absolute.
    #[error("FIDO-capable OpenSSH is not configured: {0}")]
    NotConfigured(String),

    /// A [`crate::CreateOptions`] field (or other caller input) violates its contract.
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },

    /// The key handle file or its `.pub` already exists; nothing was overwritten.
    #[error("refusing to overwrite existing file {0}")]
    KeyExists(PathBuf),

    /// A directory that would hold the key handle is writable by group/others or is
    /// owned by someone else.
    #[error("insecure permissions on {path}: {reason}")]
    InsecurePermissions { path: PathBuf, reason: &'static str },

    /// A filesystem operation failed.
    #[error("{context} {path}: {source}")]
    Io {
        context: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// A `.pub` file is larger than [`crate::MAX_PUB_FILE_LEN`].
    #[error("{path} is larger than {limit} bytes")]
    TooLarge { path: PathBuf, limit: u64 },

    /// `ssh-keygen` could not be started.
    #[error("cannot run {program}: {source}")]
    Spawn {
        program: PathBuf,
        #[source]
        source: io::Error,
    },

    /// `ssh-keygen` exited unsuccessfully (no authenticator, touch timeout, wrong PIN,
    /// unsupported option, ...). Its own diagnostics went to the inherited stderr.
    #[error("ssh-keygen failed ({status})")]
    KeygenFailed { status: ExitStatus },

    /// `ssh-keygen` reported success but its output does not match the request.
    #[error("ssh-keygen output is unexpected: {0}")]
    UnexpectedOutput(&'static str),

    /// A public key line is malformed or not a supported security-key type.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(&'static str),
}

impl Error {
    pub(crate) fn io(context: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Error::Io {
            context,
            path: path.into(),
            source,
        }
    }
}
