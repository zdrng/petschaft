//! FIDO2 ("hardware-only") identities: keys are created and used by the FIDO-capable
//! OpenSSH baked into the build, over USB. They never go through the petschaft helper or
//! Bluetooth; the types (`Fido2Identity` vs `Slip13Identity`) keep the two apart.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use petschaft_core::{Config, Fido2Identity, Fingerprint, IdentityConfig, SkAlgorithm};
use petschaft_fido2::{CreateOptions, OpenSsh, PublicKeyLine};

/// Per-user directory of FIDO2 key handles: `$XDG_CONFIG_HOME/petschaft/fido2` (or
/// `~/.config/petschaft/fido2`).
///
/// Deliberately independent of where the config was loaded from: with the system
/// config (`/etc/petschaft/config.toml`) or `--config`, key handles still belong to the
/// user running `pets`, never next to a shared or foreign config file.
pub fn key_dir() -> Result<PathBuf> {
    Config::user_dir().map(|d| d.join("fido2")).ok_or_else(|| {
        anyhow!("cannot determine the FIDO2 key directory: set HOME or XDG_CONFIG_HOME")
    })
}

/// `<key dir>/<name>` (key handle; the public key is `<name>.pub`).
fn key_path(key_dir: &Path, id: &Fido2Identity) -> PathBuf {
    key_dir.join(id.name().as_str())
}

fn algorithm(a: SkAlgorithm) -> petschaft_fido2::SkAlgorithm {
    match a {
        SkAlgorithm::Ed25519Sk => petschaft_fido2::SkAlgorithm::Ed25519,
        SkAlgorithm::EcdsaSk => petschaft_fido2::SkAlgorithm::EcdsaP256,
    }
}

/// The public key of `id`, checked against the config: algorithm, application and,
/// if `require_pin`, the pinned fingerprint. The `.pub` file and the key handle itself
/// (`ssh-keygen -y`, which needs no device) must hold the same key, so the pin applies
/// to the key OpenSSH actually uses. Fails closed on any mismatch. The returned line
/// carries the identity's configured comment, not the one in the `.pub` file.
fn checked_key(
    openssh: &OpenSsh,
    key_dir: &Path,
    id: &Fido2Identity,
    require_pin: bool,
) -> Result<PublicKeyLine> {
    let path = key_path(key_dir, id);
    let key = petschaft_fido2::read_public(&path).map_err(|e| {
        anyhow!(
            "{e} (create the key first: pets fido2 create {})",
            id.name()
        )
    })?;
    if key.algorithm() != algorithm(id.algorithm())
        || key.application() != id.application().as_str()
    {
        bail!(
            "{} does not match identity \"{}\" (algorithm/application differ from the config)",
            petschaft_fido2::pub_path(&path).display(),
            id.name()
        );
    }
    let handle = petschaft_fido2::handle_public_key(openssh, &path)
        .map_err(|e| anyhow!("cannot read the public key of {}: {e}", path.display()))?;
    if handle.blob() != key.blob() {
        bail!(
            "the key handle {} holds another key ({}) than {} ({}); not using either",
            path.display(),
            handle.fingerprint(),
            petschaft_fido2::pub_path(&path).display(),
            key.fingerprint()
        );
    }
    let key = key.with_comment(id.comment().as_str())?;
    let actual = Fingerprint::parse(key.fingerprint())?;
    match id.fingerprint() {
        Some(pin) if *pin != actual => bail!(
            "key of identity \"{}\" does not match the pinned fingerprint (expected {pin}, found {actual})",
            id.name()
        ),
        None if require_pin => bail!(
            "identity \"{}\" has no pinned fingerprint; add  fingerprint = \"{actual}\"  to the config first",
            id.name()
        ),
        _ => Ok(key),
    }
}

pub fn create(config: &Config, key_dir: &Path, name: &str, device: Option<PathBuf>) -> Result<()> {
    let id = config.fido2(name)?;
    if let Some(pin) = id.fingerprint() {
        bail!(
            "identity \"{}\" already has a pinned key ({pin}); refusing to create another. \
             To restore a resident key on a new computer use `ssh-keygen -K`; to replace the \
             key, remove the pin and the old key files deliberately first",
            id.name()
        );
    }
    let openssh = OpenSsh::resolve()?;
    let path = key_path(key_dir, id);
    let opts = CreateOptions {
        algorithm: algorithm(id.algorithm()),
        application: id.application().as_str().to_owned(),
        comment: id.comment().as_str().to_owned(),
        user_verification: id.user_verification(),
        resident: id.resident(),
        device,
    };
    crate::say(&format!(
        "creating {} key \"{}\" on the Trezor (USB); confirm on the device{}",
        id.algorithm(),
        id.application(),
        if id.user_verification() {
            " and enter the PIN when asked"
        } else {
            ""
        }
    ));
    if id.resident() {
        crate::say(
            "note: if ssh-keygen asks to overwrite an existing resident key in the token, \
             answer n unless you really want to destroy that key",
        );
    }
    let key = petschaft_fido2::create(&openssh, &opts, &path).map_err(|e| {
        if id.user_verification() && matches!(e, petschaft_fido2::Error::KeygenFailed { .. }) {
            anyhow!(
                "{e}\nhint: if ssh-keygen said \"requested feature not supported\", the Trezor rejected \
                 PIN verification for this key (-O verify-required). Set  user_verification = false  \
                 for identity \"{}\" (every login then needs a touch on the Trezor) and run this again",
                id.name()
            )
        } else {
            e.into()
        }
    })?;
    println!("{}", key.to_line());
    eprintln!("key handle: {}", path.display());
    eprintln!("fingerprint: {}", key.fingerprint());
    eprintln!(
        "next: add  fingerprint = \"{}\"  to [[identity]] \"{}\", then run: pets sshd-config {}",
        key.fingerprint(),
        id.name(),
        id.name()
    );
    Ok(())
}

/// `pets pubkey` for a fido2 identity: read from disk (and the key handle), no device
/// needed.
pub fn pubkey(key_dir: &Path, id: &Fido2Identity) -> Result<()> {
    let key = checked_key(&OpenSsh::resolve()?, key_dir, id, false)?;
    println!("{}", key.to_line());
    eprintln!("fingerprint: {}", key.fingerprint());
    if id.fingerprint().is_some() {
        eprintln!("matches the pinned fingerprint");
    } else {
        eprintln!(
            "not pinned yet: add  fingerprint = \"{}\"  to [[identity]] \"{}\" in the config",
            key.fingerprint(),
            id.name()
        );
    }
    Ok(())
}

/// Replace this process with the FIDO-capable `ssh` using the identity's key.
pub fn ssh(config: &Config, key_dir: &Path, name: &str, args: &[OsString]) -> Result<()> {
    let id = config.fido2(name)?;
    let openssh = OpenSsh::resolve()?;
    checked_key(&openssh, key_dir, id, true)?;
    let err = petschaft_fido2::ssh_command(&openssh, &key_path(key_dir, id), args)?.exec();
    Err(anyhow!("cannot run ssh: {err}"))
}

/// Print `authorized_keys` lines and the sshd drop-in for the given (or all) fido2 identities.
pub fn sshd_config(config: &Config, key_dir: &Path, names: &[String]) -> Result<()> {
    let ids: Vec<&Fido2Identity> = if names.is_empty() {
        config
            .identities()
            .iter()
            .filter_map(|i| match i {
                IdentityConfig::Fido2(f) => Some(f),
                IdentityConfig::Slip13(_) => None,
            })
            .collect()
    } else {
        names
            .iter()
            .map(|n| config.fido2(n))
            .collect::<Result<_, _>>()?
    };
    if ids.is_empty() {
        bail!("no fido2 identities in the config");
    }
    // Only pinned keys: what goes into authorized_keys must be exactly the key you checked.
    let openssh = OpenSsh::resolve()?;
    let keys = ids
        .iter()
        .map(|id| checked_key(&openssh, key_dir, id, true).map(|k| (k, id.user_verification())))
        .collect::<Result<Vec<_>>>()?;
    let refs: Vec<(&PublicKeyLine, bool)> = keys.iter().map(|(k, uv)| (k, *uv)).collect();
    print!("{}", petschaft_fido2::sshd_snippet(&refs));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// From `petschaft-fido2`'s tests: a hand-built `ed25519-sk` key line.
    const KEY: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIP7QI5opSkI2I3vshL+xE9lqgkLxI+M057dTGorIOu3sAAAADHNzaDpkZW1vdGVzdA== demo:test";
    const KEY_FP: &str = "SHA256:Nt05kVT0IEull0Lo/ESwkF/2mnBZEkraW73v6ppVyFg";
    /// Same algorithm and application, another public key.
    const OTHER: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAADHNzaDpkZW1vdGVzdA== demo:test";

    /// `key_dir` with `test.pub` = [`KEY`] and a handle `test`, and a fake ssh-keygen
    /// that prints `handle_line` for `-y -f <dir>/test` with stdin at EOF, else fails.
    fn setup(handle_line: &str) -> (tempfile::TempDir, OpenSsh, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let key_dir = root.path().join("fido2");
        std::fs::create_dir(&key_dir).unwrap();
        std::fs::write(key_dir.join("test"), "handle").unwrap();
        std::fs::write(key_dir.join("test.pub"), format!("{KEY}\n")).unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let keygen = bin.join("ssh-keygen");
        std::fs::write(
            &keygen,
            format!(
                "#!/bin/sh\n[ \"$*\" = '-y -f {}' ] || exit 2\n\
                 if read -r x; then exit 3; fi\nprintf '%s\\n' '{handle_line}'\n",
                key_dir.join("test").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&keygen, std::fs::Permissions::from_mode(0o755)).unwrap();
        (root, OpenSsh::from_bin_dir(&bin).unwrap(), key_dir)
    }

    fn config(pin: &str) -> Config {
        Config::from_toml_str(&format!(
            "[[identity]]\nname = \"test\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n\
             application = \"ssh:demotest\"\nfingerprint = \"{pin}\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn pin_is_checked_against_handle_and_pub() {
        let c = config(KEY_FP);
        let id = c.fido2("test").unwrap();
        let (_root, openssh, key_dir) = setup(KEY);
        let key = checked_key(&openssh, &key_dir, id, true).unwrap();
        assert_eq!(key.fingerprint(), KEY_FP);

        // The handle holds another key than the .pub (which matches the pin): refused.
        let (_root, openssh, key_dir) = setup(OTHER);
        let e = checked_key(&openssh, &key_dir, id, true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("holds another key"), "{e}");
        // ... also without a pin (pets pubkey).
        assert!(checked_key(&openssh, &key_dir, id, false).is_err());

        // Both agree but the pin is another key: refused as before.
        let other_fp = petschaft_fido2::PublicKeyLine::parse(OTHER)
            .unwrap()
            .fingerprint()
            .to_owned();
        let c = config(&other_fp);
        let (_root, openssh, key_dir) = setup(KEY);
        let e = checked_key(&openssh, &key_dir, c.fido2("test").unwrap(), true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not match the pinned fingerprint"), "{e}");
    }

    #[test]
    fn failing_ssh_keygen_is_refused() {
        let c = config(KEY_FP);
        let id = c.fido2("test").unwrap();
        // The fake checks its arguments: another path makes it exit 2.
        let (root, openssh, key_dir) = setup(KEY);
        let moved = root.path().join("moved");
        std::fs::rename(&key_dir, &moved).unwrap();
        let e = checked_key(&openssh, &moved, id, true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("cannot read the public key of"), "{e}");
        assert!(e.contains("ssh-keygen failed"), "{e}");
    }
}
