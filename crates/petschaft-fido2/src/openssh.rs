//! Locating the FIDO-capable OpenSSH and building `ssh` / `ssh-keygen -Y sign` commands.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{Error, MAX_PUB_FILE_LEN, PublicKeyLine};

/// Name of the build-time and run-time variable holding OpenSSH's `bin` directory.
pub const OPENSSH_BIN_VAR: &str = "PETSCHAFT_OPENSSH_BIN";

/// Environment variables removed from every OpenSSH child.
///
/// - `SSH_SK_HELPER`: path of the `ssh-sk-helper` that talks to the authenticator;
///   unset, OpenSSH uses the helper of its own installation (the one linked against
///   libfido2).
/// - `SSH_SK_PROVIDER`: a shared library loaded *into* `ssh-keygen`/`ssh` as security
///   key middleware; unset, the built-in libfido2 middleware (`internal`) is used.
pub const REMOVED_ENV: &[&str] = &["SSH_SK_HELPER", "SSH_SK_PROVIDER"];

/// Absolute paths of the FIDO-capable `ssh` and `ssh-keygen`.
///
/// macOS's system OpenSSH is built without security-key support, so petschaft never uses
/// `PATH`; release builds embed the Nix store path of nixpkgs' OpenSSH (built with
/// libfido2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSsh {
    ssh: PathBuf,
    ssh_keygen: PathBuf,
}

impl OpenSsh {
    /// The compile-time `PETSCHAFT_OPENSSH_BIN` (fixed Nix store path of release builds)
    /// takes precedence; otherwise the run-time variable of the same name; otherwise
    /// [`Error::NotConfigured`]. The directory must be absolute (no `PATH` lookup). An
    /// empty value counts as unset. Existence is not checked here; spawning reports it.
    pub fn resolve() -> Result<Self, Error> {
        resolve_from(
            option_env!("PETSCHAFT_OPENSSH_BIN"),
            std::env::var_os(OPENSSH_BIN_VAR),
        )
    }

    /// Use the OpenSSH in `bin_dir` (must be absolute).
    pub fn from_bin_dir(bin_dir: &Path) -> Result<Self, Error> {
        if !bin_dir.is_absolute() {
            return Err(Error::NotConfigured(format!(
                "{OPENSSH_BIN_VAR} must be an absolute path"
            )));
        }
        Ok(OpenSsh {
            ssh: bin_dir.join("ssh"),
            ssh_keygen: bin_dir.join("ssh-keygen"),
        })
    }

    pub fn ssh(&self) -> &Path {
        &self.ssh
    }

    pub fn ssh_keygen(&self) -> &Path {
        &self.ssh_keygen
    }

    /// A `Command` for `program` with [`REMOVED_ENV`] removed.
    pub(crate) fn command(program: &Path) -> Command {
        let mut cmd = Command::new(program);
        for var in REMOVED_ENV {
            cmd.env_remove(var);
        }
        // PIN prompts go to the terminal, never to an (inherited) SSH_ASKPASS program.
        cmd.env("SSH_ASKPASS_REQUIRE", "never");
        cmd
    }
}

pub(crate) fn resolve_from(
    compile_time: Option<&str>,
    runtime: Option<OsString>,
) -> Result<OpenSsh, Error> {
    let chosen = match compile_time.filter(|s| !s.is_empty()) {
        Some(s) => PathBuf::from(s),
        None => match runtime.filter(|s| !s.is_empty()) {
            Some(s) => PathBuf::from(s),
            None => {
                return Err(Error::NotConfigured(format!(
                    "{OPENSSH_BIN_VAR} is not set (neither at build time nor in the environment)"
                )));
            }
        },
    };
    OpenSsh::from_bin_dir(&chosen)
}

/// Arguments placed before the user's arguments in [`ssh_command`].
pub(crate) fn ssh_args(key_path: &Path) -> Vec<OsString> {
    vec![
        "-i".into(),
        key_path.into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "IdentityAgent=none".into(),
        // Overrides a SecurityKeyProvider from ssh_config: always the built-in libfido2.
        "-o".into(),
        "SecurityKeyProvider=internal".into(),
        // Hardware-only: never fall back to other keys (IdentityFile in ssh_config or
        // `-i` in user args accumulate), PKCS#11 tokens, passwords, or an existing
        // multiplexed connection that was authenticated some other way.
        "-o".into(),
        "PubkeyAcceptedAlgorithms=sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"
            .into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "KbdInteractiveAuthentication=no".into(),
        "-o".into(),
        "PKCS11Provider=none".into(),
        "-o".into(),
        "ControlMaster=no".into(),
        "-o".into(),
        "ControlPath=none".into(),
    ]
}

/// The FIDO-capable `ssh` logging in with the security key handle `key_path`:
///
/// `ssh -i <key_path> -o IdentitiesOnly=yes -o IdentityAgent=none
///  -o SecurityKeyProvider=internal <user_args...>`
///
/// Fails with [`Error::Io`] if `key_path` is not an existing regular file: `ssh` only
/// warns about an inaccessible `-i` file and then falls back to the default
/// `~/.ssh/id_*` keys, which must not happen silently.
///
/// No shell is involved; `user_args` (destination, further options, remote command)
/// are passed verbatim. OpenSSH uses the first value it obtains for an option, so the
/// options above win over later `-o` in `user_args` and over `ssh_config`. Identities
/// still accumulate (an `-i` in `user_args` or an `IdentityFile` in `ssh_config` adds
/// one), but `PubkeyAcceptedAlgorithms` restricted to sk-* keys, no password/keyboard-
/// interactive and no connection multiplexing mean only a security key can log in. stdio is inherited (the default for `Command::status`), so `ssh` can prompt
/// for touch/PIN.
pub fn ssh_command(
    openssh: &OpenSsh,
    key_path: &Path,
    user_args: &[OsString],
) -> Result<Command, Error> {
    let meta = std::fs::metadata(key_path).map_err(|e| Error::io("cannot use key", key_path, e))?;
    if !meta.is_file() {
        return Err(Error::InvalidInput {
            field: "key path",
            reason: "is not a regular file",
        });
    }
    let mut cmd = OpenSsh::command(openssh.ssh());
    cmd.args(ssh_args(key_path)).args(user_args);
    Ok(cmd)
}

/// Arguments of [`sign_command`].
pub(crate) fn sign_args(key_path: &Path, namespace: &str, file: &Path) -> Vec<OsString> {
    vec![
        "-Y".into(),
        "sign".into(),
        "-n".into(),
        namespace.into(),
        "-f".into(),
        key_path.into(),
        // A file name starting with '-' must not be parsed as an option.
        "--".into(),
        file.into(),
    ]
}

/// The FIDO-capable `ssh-keygen -Y sign -n <namespace> -f <key_path> -- <file>`, which
/// writes `<file>.sig` (SSHSIG). Contract: `namespace` is a non-empty, caller-validated
/// constant such as `git` or `file`. Requires touch (and PIN for `verify-required`
/// keys) on the authenticator.
pub fn sign_command(openssh: &OpenSsh, key_path: &Path, namespace: &str, file: &Path) -> Command {
    let mut cmd = OpenSsh::command(openssh.ssh_keygen());
    cmd.args(sign_args(key_path, namespace, file));
    cmd
}

/// The public key stored in the key handle `key_path`, as printed by the FIDO-capable
/// `ssh-keygen -y -f <key_path>`. For security keys this only reads the handle file;
/// the authenticator is not involved. stdin is `/dev/null`, so a passphrase-protected
/// handle fails instead of prompting. Output longer than [`MAX_PUB_FILE_LEN`] or not a
/// single valid security-key line is an error.
pub fn handle_public_key(openssh: &OpenSsh, key_path: &Path) -> Result<PublicKeyLine, Error> {
    let out = OpenSsh::command(openssh.ssh_keygen())
        .arg("-y")
        .arg("-f")
        .arg(key_path)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|source| Error::Spawn {
            program: openssh.ssh_keygen().to_owned(),
            source,
        })?;
    if !out.status.success() {
        return Err(Error::KeygenFailed { status: out.status });
    }
    if u64::try_from(out.stdout.len()).map_or(true, |n| n > MAX_PUB_FILE_LEN) {
        return Err(Error::UnexpectedOutput("ssh-keygen -y printed too much"));
    }
    let text = std::str::from_utf8(&out.stdout)
        .map_err(|_| Error::UnexpectedOutput("ssh-keygen -y printed no UTF-8"))?;
    PublicKeyLine::parse(text)
}
