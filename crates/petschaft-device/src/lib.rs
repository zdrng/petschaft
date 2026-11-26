//! Device access for petschaft: the [`Signer`] trait, the helper-backed implementation
//! [`HelperSigner`] and storage of the THP pairing credential. See
//! `docs/architecture.md` and `docs/helper-protocol.md`.
//!
//! # API overview
//!
//! ```text
//! SignRequest::for_identity(&Slip13Identity, challenge, visual)   (the only constructor)
//! trait Signer { fn sign_identity(&mut self, &SignRequest) -> Result<SignedIdentity, Error> }
//! trait Ui     { fn confirm_on_device(&self); fn pairing_code(&self) -> Result<String, Error> }
//! trait CredentialStore { load / store / delete }    KeyringStore, NoStore
//!
//! HelperSigner::spawn(&HelperPaths::resolve()?, &ConnectOptions::new(host, transport), ui, &store)?
//!     .device()            -> &DeviceInfo   (from `ready.device`)
//!     .store_warning()     -> Option<&StoreError>  (credential could not be loaded/stored)
//!     .is_open()           -> bool          (false after a fatal error, timeout or violation)
//!     .sign_identity(&req) -> Result<SignedIdentity, Error>
//! ```
//!
//! # Fail closed
//!
//! A [`SignedIdentity`] can only be constructed by [`SignedIdentity::from_device`], which
//! parses the device public key, verifies the signature with
//! [`petschaft_core::verify_identity_signature`] over exactly the data the firmware signs and,
//! if the request's identity has a pinned fingerprint, checks the pin with
//! [`petschaft_core::PublicKey::check_fingerprint`]. There is no other constructor and no
//! switch to skip either check, so every [`Signer`] implementation (including software
//! signers used in tests of other crates) returns only verified signatures.
//!
//! # Only slip13 identities
//!
//! A [`SignRequest`] is built only by [`SignRequest::for_identity`] from a
//! [`petschaft_core::Slip13Identity`], which only the config parser produces. FIDO2
//! identities ([`petschaft_core::Fido2Identity`]) are used by OpenSSH over USB and have no
//! way into this crate: passing one is a type error, not a runtime check.
//!
//! # Helper process
//!
//! [`HelperSigner`] runs `<python> -I -B <script>` (paths from [`HelperPaths::resolve`]):
//! compile-time `PETSCHAFT_HELPER_PYTHON`/`PETSCHAFT_HELPER_SCRIPT` take precedence over the
//! runtime environment variables of the same names; both must be absolute paths. The
//! child gets a cleared environment plus only [`PASSED_ENV`] (no `PYTHON*`, no
//! `TREZOR_PATH`; transport selection happens through `hello.transport`), runs in `/`,
//! has stdin/stdout piped and stderr inherited.
//!
//! Timeouts (spec "Timeouts"): `hello` must produce its first event or `ready` within
//! 120 s, and every request (`hello` included) must finish within 180 s overall. A reader
//! thread decodes frames from the helper's stdout into a bounded channel; the protocol
//! state machine waits with `recv_timeout` against the deadline. Time spent inside
//! [`Ui`] callbacks counts towards the 180 s (the callbacks themselves cannot be
//! interrupted). On a timeout, a protocol violation, an I/O error or unexpected EOF the
//! helper is killed and the signer is closed ([`Error::Closed`] afterwards). Dropping a
//! [`HelperSigner`] closes the helper's stdin (the spec's orderly shutdown), waits
//! briefly and then kills and reaps the child.
//!
//! # Credentials
//!
//! The THP credential is loaded from the [`CredentialStore`] before `hello` and a new
//! one returned in `ready` is stored. Store failures never abort the connection: the
//! credential is simply not persisted (the next run pairs again) and the failure is
//! reported by [`HelperSigner::store_warning`]. A stored credential that fails
//! validation is ignored. Credentials never appear in errors or `Debug` output.

#![forbid(unsafe_code)]

mod error;
mod helper;
mod signer;
mod store;

pub use error::Error;
pub use helper::{
    APP_NAME, ConnectOptions, HelperPaths, HelperSigner, PASSED_ENV, REQUEST_TIMEOUT,
};
pub use petschaft_helper_proto::{Credential, DeviceInfo};
pub use signer::{SignRequest, SignedIdentity, Signer, Ui};
pub use store::{CredentialStore, KeyringStore, NoStore, StoreError};

#[cfg(test)]
mod tests;
