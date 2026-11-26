//! The device-independent signing interface.

use petschaft_core::{PublicKey, Signature, Slip13Identity};

use crate::Error;

/// One `SignIdentity` request for a configured slip13 identity.
///
/// The only constructor is [`SignRequest::for_identity`], which takes a
/// [`Slip13Identity`]: SLIP-0013 path, curve, passphrase policy and the pinned
/// fingerprint all come from the config, so a caller can neither forget the pin nor
/// mix the curve of one identity with the path of another. A FIDO2 identity
/// ([`petschaft_core::Fido2Identity`]) is a different type and cannot be passed:
///
/// ```compile_fail
/// fn f(config: &petschaft_core::Config) -> Result<(), petschaft_core::Error> {
///     let id = config.fido2("homelab")?;
///     let _ = petschaft_device::SignRequest::for_identity(id, Vec::new(), String::new());
///     Ok(())
/// }
/// ```
/// ```
/// fn f(config: &petschaft_core::Config) -> Result<(), petschaft_core::Error> {
///     let id = config.slip13("homelab")?;
///     let _ = petschaft_device::SignRequest::for_identity(id, Vec::new(), String::new());
///     Ok(())
/// }
/// ```
/// ```compile_fail
/// // No struct literal: the fields are private.
/// let _ = petschaft_device::SignRequest { identity: todo!(), challenge_hidden: Vec::new(),
///     challenge_visual: String::new() };
/// ```
///
/// The challenge and the display text are checked against the protocol rules when the
/// request is sent ([`Error::InvalidRequest`]; nothing reaches the helper).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    identity: Slip13Identity,
    /// Data the device signs (0-512 bytes; exactly 32 for gpg with nist256p1).
    challenge_hidden: Vec<u8>,
    /// Text shown on the device (≤ 128 printable characters).
    challenge_visual: String,
}

impl SignRequest {
    /// Request a signature by `identity` over `challenge_hidden`, showing
    /// `challenge_visual` on the device.
    pub fn for_identity(
        identity: &Slip13Identity,
        challenge_hidden: Vec<u8>,
        challenge_visual: String,
    ) -> Self {
        SignRequest {
            identity: identity.clone(),
            challenge_hidden,
            challenge_visual,
        }
    }

    /// The identity (path, curve, passphrase policy, pin) this request is for.
    pub fn identity(&self) -> &Slip13Identity {
        &self.identity
    }

    pub fn challenge_hidden(&self) -> &[u8] {
        &self.challenge_hidden
    }

    pub fn challenge_visual(&self) -> &str {
        &self.challenge_visual
    }
}

/// A signature that has been verified locally against the returned public key and, if
/// requested, against the pinned fingerprint.
///
/// Fields are private: the only constructor is [`SignedIdentity::from_device`], which
/// performs all checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIdentity {
    public_key: PublicKey,
    signature: Signature,
}

impl SignedIdentity {
    /// Validate raw device output (`SignedIdentity.public_key` / `.signature`) for `req`.
    ///
    /// 1. parse `public_key` for the identity's curve ([`PublicKey::from_device`]);
    /// 2. verify `signature` over the data the firmware signs for the identity's proto
    ///    ([`petschaft_core::verify_identity_signature`]);
    /// 3. if the identity has a pinned fingerprint, require it to match
    ///    ([`PublicKey::check_fingerprint`]).
    ///
    /// Any failure is an error; there is no way to skip a step.
    pub fn from_device(
        req: &SignRequest,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<Self, Error> {
        let id = req.identity();
        let public_key = PublicKey::from_device(id.curve(), public_key)?;
        let signature = petschaft_core::verify_identity_signature(
            id.identity().proto(),
            &public_key,
            req.challenge_hidden(),
            signature,
        )?;
        if let Some(expected) = id.fingerprint() {
            public_key.check_fingerprint(expected)?;
        }
        Ok(SignedIdentity {
            public_key,
            signature,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn into_parts(self) -> (PublicKey, Signature) {
        (self.public_key, self.signature)
    }
}

/// Something that can produce identity signatures. Implementations must return only
/// values built by [`SignedIdentity::from_device`] (enforced by its private fields).
pub trait Signer {
    fn sign_identity(&mut self, req: &SignRequest) -> Result<SignedIdentity, Error>;
}

/// User interaction needed while talking to the device (implemented by the CLI).
pub trait Ui {
    /// The Trezor waits for a confirmation on its display. Called once per `button`
    /// event; must return promptly (it should only inform the user).
    fn confirm_on_device(&self);

    /// The Trezor shows a pairing code; return what the user typed. Surrounding
    /// whitespace is ignored; anything but exactly 6 ASCII digits aborts the connection
    /// with [`Error::InvalidPairingCode`]. Return an error (e.g. [`Error::Cancelled`]) to
    /// abort pairing.
    fn pairing_code(&self) -> Result<String, Error>;
}

impl<T: Ui + ?Sized> Ui for &T {
    fn confirm_on_device(&self) {
        (**self).confirm_on_device()
    }
    fn pairing_code(&self) -> Result<String, Error> {
        (**self).pairing_code()
    }
}
