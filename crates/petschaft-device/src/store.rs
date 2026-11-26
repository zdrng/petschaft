//! Storage of the THP pairing credential.
//!
//! Only the OS secret store is used, with no plaintext fallback: [`KeyringStore`] wraps
//! `keyring` 4 with its `v1` feature, which compiles in exactly one backend per
//! platform and never falls back to anything else:
//!
//! - macOS: Keychain Services, the user's login keychain (generic password, service
//!   `petschaft`, account `thp-credential`). Access may prompt the user; a rebuilt binary is
//!   a different application for the keychain ACL and may prompt again.
//! - Linux / *BSD: the freedesktop Secret Service over the D-Bus session bus (GNOME
//!   Keyring, KWallet, KeePassXC, ...), via `zbus` with encrypted transfer
//!   (`crypto-rust`). No session bus or no Secret Service provider means
//!   [`StoreError::Unavailable`] or a backend error at first use.
//! - Windows: Credential Manager (not a target platform of petschaft).
//!
//! The `keyring` feature `cli` is not enabled; it would add the `keyring-core` sample
//! store (a plaintext file), the Linux kernel keyutils store (lost on reboot) and an
//! SQLite store. `keyring-core` always contains an in-memory mock store, but it is only
//! used if some code installs it with `keyring_core::set_default_store`, which nothing
//! in petschaft does; `v1` installs the platform store on first use.
//!
//! If no secure store is usable, callers continue without storing (the next run pairs
//! again). Errors never contain credential bytes: `keyring` errors that carry secret
//! data (`BadEncoding`, `BadDataFormat`) are mapped to [`StoreError::Corrupt`] without
//! their payload.

use petschaft_helper_proto::Credential;

/// Failures of a [`CredentialStore`]. Never contains credential bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// No secure backend exists on this system (nothing is stored, pair each time).
    #[error("no secure credential store available: {0}")]
    Unavailable(String),
    /// The backend exists but refused access (locked, denied by the user, ...).
    #[error("access to the secure credential store was denied: {0}")]
    AccessDenied(String),
    #[error("secure credential store error: {0}")]
    Backend(String),
    /// The stored value is not a valid credential (it is ignored).
    #[error("the stored pairing credential is malformed")]
    Corrupt,
}

/// Persistent storage for one THP credential.
pub trait CredentialStore {
    /// `Ok(None)` if nothing is stored.
    fn load(&self) -> Result<Option<Credential>, StoreError>;
    /// Store, replacing any previous credential.
    fn store(&self, credential: &Credential) -> Result<(), StoreError>;
    /// Remove the stored credential; `Ok(())` if there was none.
    fn delete(&self) -> Result<(), StoreError>;
}

impl<T: CredentialStore + ?Sized> CredentialStore for &T {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        (**self).load()
    }
    fn store(&self, credential: &Credential) -> Result<(), StoreError> {
        (**self).store(credential)
    }
    fn delete(&self) -> Result<(), StoreError> {
        (**self).delete()
    }
}

/// Stores nothing: `load` returns `None`, `store` and `delete` succeed without effect.
/// Use when no secure store is available or the user opted out; every connection then
/// pairs anew.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStore;

impl CredentialStore for NoStore {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        Ok(None)
    }
    fn store(&self, _credential: &Credential) -> Result<(), StoreError> {
        Ok(())
    }
    fn delete(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// The OS secret store (see module docs).
pub struct KeyringStore {
    entry: keyring::Entry,
}

impl std::fmt::Debug for KeyringStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringStore")
            .field("service", &Self::SERVICE)
            .field("account", &Self::ACCOUNT)
            .finish()
    }
}

impl KeyringStore {
    pub const SERVICE: &'static str = "petschaft";
    pub const ACCOUNT: &'static str = "thp-credential";

    /// Open the platform store. [`StoreError::Unavailable`] if this platform has no
    /// usable secure store (e.g. Linux without a D-Bus session bus); the caller should
    /// then use [`NoStore`] and tell the user that pairing will be required each time.
    pub fn new() -> Result<Self, StoreError> {
        if let Err(e) = keyring::Entry::store_status() {
            return Err(StoreError::Unavailable(describe(e)));
        }
        let entry = keyring::Entry::new(Self::SERVICE, Self::ACCOUNT).map_err(map_err)?;
        Ok(KeyringStore { entry })
    }
}

impl CredentialStore for KeyringStore {
    fn load(&self) -> Result<Option<Credential>, StoreError> {
        match self.entry.get_secret() {
            Ok(bytes) => Credential::new(bytes)
                .map(Some)
                .map_err(|_| StoreError::Corrupt),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    fn store(&self, credential: &Credential) -> Result<(), StoreError> {
        self.entry
            .set_secret(credential.as_bytes())
            .map_err(map_err)
    }

    fn delete(&self) -> Result<(), StoreError> {
        match self.entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}

/// Description of a keyring error that never includes secret payloads.
fn describe(e: &keyring::Error) -> String {
    use keyring::Error as K;
    match e {
        K::PlatformFailure(p) | K::NoStorageAccess(p) => p.to_string(),
        K::NoEntry => "no entry".into(),
        K::BadEncoding(_) | K::BadDataFormat(..) => "malformed stored data".into(),
        K::BadStoreFormat(s) => format!("store data malformed: {s}"),
        K::TooLong(attr, limit) => format!("{attr} longer than {limit}"),
        K::Invalid(attr, reason) => format!("invalid {attr}: {reason}"),
        K::Ambiguous(items) => format!("{} matching entries", items.len()),
        K::NoDefaultStore => "no platform credential store".into(),
        K::NotSupportedByStore(s) => format!("not supported: {s}"),
        _ => "unknown keyring error".into(),
    }
}

fn map_err(e: keyring::Error) -> StoreError {
    use keyring::Error as K;
    match &e {
        K::NoStorageAccess(_) => StoreError::AccessDenied(describe(&e)),
        K::BadEncoding(_) | K::BadDataFormat(..) => StoreError::Corrupt,
        K::NoDefaultStore => StoreError::Unavailable(describe(&e)),
        _ => StoreError::Backend(describe(&e)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn no_store_stores_nothing() {
        let c = Credential::new(vec![1, 2, 3]).unwrap();
        NoStore.store(&c).unwrap();
        assert!(NoStore.load().unwrap().is_none());
        NoStore.delete().unwrap();
    }

    #[test]
    fn keyring_errors_do_not_leak_payload() {
        let secret = b"SUPERSECRETCREDENTIAL".to_vec();
        let as_text = String::from_utf8_lossy(&secret).to_string();
        for e in [
            keyring::Error::BadEncoding(secret.clone()),
            keyring::Error::BadDataFormat(secret.clone(), "x".into()),
        ] {
            let mapped = map_err(e);
            assert_eq!(mapped, StoreError::Corrupt);
            assert!(!format!("{mapped} {mapped:?}").contains(&as_text));
        }
    }

    #[test]
    fn keyring_error_classes() {
        assert!(matches!(
            map_err(keyring::Error::NoDefaultStore),
            StoreError::Unavailable(_)
        ));
        assert!(matches!(
            map_err(keyring::Error::NoStorageAccess("locked".into())),
            StoreError::AccessDenied(_)
        ));
        assert!(matches!(
            map_err(keyring::Error::PlatformFailure("boom".into())),
            StoreError::Backend(_)
        ));
    }

    /// Touches the real OS secret store (may prompt). Run manually:
    /// `cargo nextest run -p petschaft-device --run-ignored only keyring_roundtrip`.
    /// Uses a separate account so the real credential is not affected.
    #[test]
    #[ignore = "uses the real OS secret store"]
    fn keyring_roundtrip() {
        let store = KeyringStore {
            entry: keyring::Entry::new(KeyringStore::SERVICE, "thp-credential-test").unwrap(),
        };
        let c = Credential::new(vec![0, 255, 7, 42]).unwrap();
        store.store(&c).unwrap();
        assert_eq!(store.load().unwrap(), Some(c));
        store.delete().unwrap();
        assert_eq!(store.load().unwrap(), None);
        store.delete().unwrap();
    }
}
