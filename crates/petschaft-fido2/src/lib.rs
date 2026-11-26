//! FIDO2 ("hardware-only") SSH keys on the Trezor, used through OpenSSH.
//!
//! The Trezor acts as a FIDO2 authenticator over USB. OpenSSH (built with libfido2)
//! creates `sk-ssh-ed25519@openssh.com` / `sk-ecdsa-sha2-nistp256@openssh.com` keys:
//! the private key never leaves the device; the local file is only a *key handle*
//! that is useless without it. A server can then accept only such keys with
//! `PubkeyAcceptedAlgorithms sk-…` ([`sshd_snippet`]).
//!
//! This crate does not talk to the device itself; it drives the FIDO-capable `ssh`
//! and `ssh-keygen` located by [`OpenSsh::resolve`] (never via `PATH`: macOS's own
//! OpenSSH has no FIDO support). It depends on no other petschaft crate; callers pass
//! already validated names and paths, and the functions re-check the syntactic rules
//! documented on each item.

#![forbid(unsafe_code)]

mod create;
mod error;
mod openssh;
mod pubkey;
mod snippet;

#[cfg(test)]
mod tests;

pub use create::{CreateOptions, KEY_DIR_MODE, KEY_FILE_MODE, create};
pub use error::Error;
pub use openssh::{
    OPENSSH_BIN_VAR, OpenSsh, REMOVED_ENV, handle_public_key, sign_command, ssh_command,
};
pub use pubkey::{
    APPLICATION_PREFIX, MAX_APPLICATION_LEN, MAX_COMMENT_LEN, MAX_PUB_FILE_LEN, PublicKeyLine,
    SkAlgorithm, fingerprint, pub_path, read_public,
};
pub use snippet::{SSHD_DROPIN_PATH, authorized_keys_line, sshd_snippet};
