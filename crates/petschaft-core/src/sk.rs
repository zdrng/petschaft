//! Types of FIDO2 ("security key", OpenSSH `sk-*`) identities.
//!
//! FIDO2 identities are created and used by OpenSSH itself over USB (`ssh-keygen -t
//! ed25519-sk`, `ssh` with the resulting key file). They never go through the petschaft
//! helper; the types here only describe them.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Name};

/// Prefix OpenSSH requires for a FIDO application string.
const APPLICATION_PREFIX: &str = "ssh:";
/// Maximum number of characters after [`APPLICATION_PREFIX`].
const MAX_APPLICATION_SUFFIX: usize = 60;

/// OpenSSH security-key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkAlgorithm {
    /// `ed25519-sk`: `sk-ssh-ed25519@openssh.com`.
    Ed25519Sk,
    /// `ecdsa-sk`: `sk-ecdsa-sha2-nistp256@openssh.com`.
    EcdsaSk,
}

impl SkAlgorithm {
    /// Config value: `"ed25519-sk"` / `"ecdsa-sk"`.
    pub fn as_str(self) -> &'static str {
        match self {
            SkAlgorithm::Ed25519Sk => "ed25519-sk",
            SkAlgorithm::EcdsaSk => "ecdsa-sk",
        }
    }

    /// Value of `ssh-keygen -t` (identical to the config value).
    pub fn ssh_keygen_type(self) -> &'static str {
        self.as_str()
    }

    /// OpenSSH key type as it appears in public key lines and key blobs.
    pub fn openssh_key_type(self) -> &'static str {
        match self {
            SkAlgorithm::Ed25519Sk => "sk-ssh-ed25519@openssh.com",
            SkAlgorithm::EcdsaSk => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    /// Parse the config value (exact, lowercase). Inverse of [`SkAlgorithm::as_str`].
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "ed25519-sk" => Ok(SkAlgorithm::Ed25519Sk),
            "ecdsa-sk" => Ok(SkAlgorithm::EcdsaSk),
            _ => Err(Error::InvalidConfig(
                "algorithm must be ed25519-sk or ecdsa-sk".into(),
            )),
        }
    }
}

impl fmt::Display for SkAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// FIDO application string of an OpenSSH security key (`ssh-keygen -O application=`):
/// `ssh:` followed by 1-60 characters of `[a-z0-9.-]`.
///
/// The character set keeps the value safe to pass as a single `ssh-keygen` argument
/// and to show on a terminal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SkApplication(String);

fn is_application_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
}

impl SkApplication {
    /// Validate an application string.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let valid = s.strip_prefix(APPLICATION_PREFIX).is_some_and(|rest| {
            (1..=MAX_APPLICATION_SUFFIX).contains(&rest.len())
                && rest.bytes().all(is_application_char)
        });
        if valid {
            Ok(SkApplication(s.to_owned()))
        } else {
            Err(Error::InvalidConfig(format!(
                "application must be {APPLICATION_PREFIX} followed by 1-{MAX_APPLICATION_SUFFIX} characters of [a-z0-9.-]"
            )))
        }
    }

    /// The default application of identity `name`: `ssh:<name>`.
    ///
    /// Always valid: a [`Name`] is 1-32 characters of `[a-z0-9-]`, so the part after
    /// `ssh:` is 1-32 characters of `[a-z0-9.-]` (checked by a test).
    pub fn default_for(name: &Name) -> Self {
        SkApplication(format!("{APPLICATION_PREFIX}{}", name.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SkApplication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

impl FromStr for SkApplication {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        SkApplication::parse(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn algorithm_strings() {
        assert_eq!(SkAlgorithm::parse("ed25519-sk"), Ok(SkAlgorithm::Ed25519Sk));
        assert_eq!(SkAlgorithm::parse("ecdsa-sk"), Ok(SkAlgorithm::EcdsaSk));
        for (a, keygen, openssh) in [
            (
                SkAlgorithm::Ed25519Sk,
                "ed25519-sk",
                "sk-ssh-ed25519@openssh.com",
            ),
            (
                SkAlgorithm::EcdsaSk,
                "ecdsa-sk",
                "sk-ecdsa-sha2-nistp256@openssh.com",
            ),
        ] {
            assert_eq!(SkAlgorithm::parse(a.as_str()), Ok(a));
            assert_eq!(a.ssh_keygen_type(), keygen);
            assert_eq!(a.openssh_key_type(), openssh);
            assert_eq!(a.to_string(), a.as_str());
        }
        for bad in [
            "",
            "ed25519",
            "ecdsa",
            "ED25519-SK",
            "ed25519-sk ",
            "sk-ssh-ed25519@openssh.com",
            "rsa-sk",
        ] {
            assert!(SkAlgorithm::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn application_rules() {
        for ok in [
            "ssh:a",
            "ssh:homelab",
            "ssh:my.host-1",
            &format!("ssh:{}", "a".repeat(60)),
        ] {
            assert_eq!(SkApplication::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            "ssh:",
            "ssh",
            "a",
            "SSH:a",
            "ssh:A",
            "ssh:a b",
            "ssh:a_b",
            "ssh:a/b",
            "ssh:a:b",
            "ssh:\u{e4}",
            "http:a",
            " ssh:a",
            &format!("ssh:{}", "a".repeat(61)),
        ] {
            assert!(SkApplication::parse(bad).is_err(), "{bad:?}");
        }
    }

    proptest! {
        /// Accepted exactly when the documented rule holds; accepted values are kept
        /// verbatim.
        #[test]
        fn application_parse_matches_rule(
            s in prop_oneof![any::<String>(), "(ssh|SSH|sh):[a-z0-9.:_A-Z -]{0,62}"],
        ) {
            let rule = s.strip_prefix("ssh:").is_some_and(|r| {
                (1..=60).contains(&r.len())
                    && r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
            });
            match SkApplication::parse(&s) {
                Ok(a) => {
                    prop_assert!(rule);
                    prop_assert_eq!(a.as_str(), s.as_str());
                }
                Err(_) => prop_assert!(!rule),
            }
        }

        /// The default application of every valid name is itself valid.
        #[test]
        fn default_application_is_valid(name in "[a-z0-9][a-z0-9-]{0,31}") {
            let name = Name::parse(&name).unwrap();
            let app = SkApplication::default_for(&name);
            prop_assert_eq!(SkApplication::parse(app.as_str()), Ok(app.clone()));
            prop_assert_eq!(app.as_str(), format!("ssh:{}", name.as_str()));
        }
    }
}
