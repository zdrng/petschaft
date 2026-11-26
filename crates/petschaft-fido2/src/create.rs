//! Creating a security-key SSH key with the FIDO-capable `ssh-keygen`.
//!
//! `ssh-keygen` would ask "Overwrite (y/n)?" on the inherited terminal if the output
//! file exists. To rule that out (also against a file appearing after our check),
//! `ssh-keygen` writes into a fresh private staging directory next to the target, and
//! the results are published with `hard_link`, which fails instead of replacing an
//! existing file.

use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pubkey::{pub_path, read_public, validate_application, validate_comment};
use crate::{Error, OpenSsh, PublicKeyLine, SkAlgorithm};

/// Mode of directories created for key handles.
pub const KEY_DIR_MODE: u32 = 0o700;
/// Mode of the key handle file.
pub const KEY_FILE_MODE: u32 = 0o600;

/// Name of the key file inside the staging directory.
const STAGED_NAME: &str = "key";
/// Attempts at finding an unused staging directory name.
const STAGING_ATTEMPTS: u32 = 16;

/// Parameters of [`create`].
///
/// Contract: the caller passes values it has already validated against its own naming
/// rules (e.g. petschaft identity names); [`create`] re-checks the syntactic rules below and
/// returns [`Error::InvalidInput`] instead of passing anything questionable to
/// `ssh-keygen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOptions {
    /// `ssh-keygen -t ed25519-sk` or `-t ecdsa-sk`.
    pub algorithm: SkAlgorithm,
    /// FIDO application, `ssh:` + printable ASCII without spaces, at most 128 bytes,
    /// e.g. `ssh:homelab`. Keys with different applications are unrelated.
    pub application: String,
    /// Key comment, e.g. `hwkey:homelab`: 1-512 bytes, no control characters, no
    /// leading/trailing whitespace.
    pub comment: String,
    /// `-O verify-required`: the authenticator must verify the user (PIN) for every
    /// signature, not only presence (touch).
    pub user_verification: bool,
    /// `-O resident`: store the credential on the authenticator (discoverable).
    pub resident: bool,
    /// `-O device=<path>`: use this authenticator instead of letting libfido2 choose.
    /// Must be absolute. `None` for the usual single-device case.
    pub device: Option<PathBuf>,
}

impl CreateOptions {
    fn validate(&self) -> Result<(), Error> {
        validate_application(&self.application).map_err(|reason| Error::InvalidInput {
            field: "application",
            reason,
        })?;
        validate_comment(&self.comment).map_err(|reason| Error::InvalidInput {
            field: "comment",
            reason,
        })?;
        if let Some(d) = &self.device
            && !d.is_absolute()
        {
            return Err(Error::InvalidInput {
                field: "device",
                reason: "must be an absolute path",
            });
        }
        Ok(())
    }
}

/// Arguments of `ssh-keygen` for creating a key with handle file `out`:
///
/// `-t <type> -O application=<app> [-O verify-required] [-O resident]
///  [-O device=<dev>] -C <comment> -N "" -f <out>`
///
/// `-N ""`: the handle file is not passphrase-protected; it is useless without the
/// authenticator, which enforces touch (and PIN with `verify-required`).
pub(crate) fn keygen_create_args(opts: &CreateOptions, out: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "-t".into(),
        opts.algorithm.keygen_type().into(),
        "-O".into(),
        format!("application={}", opts.application).into(),
    ];
    if opts.user_verification {
        args.extend(["-O".into(), "verify-required".into()]);
    }
    if opts.resident {
        args.extend(["-O".into(), "resident".into()]);
    }
    if let Some(dev) = &opts.device {
        let mut o = OsString::from("device=");
        o.push(dev);
        args.extend(["-O".into(), o]);
    }
    args.extend([
        "-C".into(),
        opts.comment.as_str().into(),
        "-N".into(),
        "".into(),
        "-f".into(),
        out.into(),
    ]);
    args
}

/// Create a new security key with `ssh-keygen`, writing the key handle to `key_path`
/// (mode 0600) and the public key to `<key_path>.pub`.
///
/// - Refuses with [`Error::KeyExists`] if either file exists (checked before running
///   `ssh-keygen`, and again atomically when publishing); never overwrites.
/// - Creates missing parent directories with mode 0700. An existing parent must not be
///   group/other-writable and must be owned by the current user
///   ([`Error::InsecurePermissions`]); its mode is not changed.
/// - stdio is inherited: `ssh-keygen` itself asks for the PIN and to touch the device.
/// - Returns the parsed public key after checking it matches `opts` (algorithm,
///   application, comment).
pub fn create(
    openssh: &OpenSsh,
    opts: &CreateOptions,
    key_path: &Path,
) -> Result<PublicKeyLine, Error> {
    create_with_stdin(openssh, opts, key_path, Stdio::inherit())
}

pub(crate) fn create_with_stdin(
    openssh: &OpenSsh,
    opts: &CreateOptions,
    key_path: &Path,
    stdin: Stdio,
) -> Result<PublicKeyLine, Error> {
    opts.validate()?;
    if key_path.file_name().is_none() {
        return Err(Error::InvalidInput {
            field: "key path",
            reason: "has no file name",
        });
    }
    let pub_final = pub_path(key_path);
    refuse_existing(key_path)?;
    refuse_existing(&pub_final)?;

    let parent = match key_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    ensure_private_dir(parent)?;
    let staging = Staging::new(parent)?;
    check_same_owner(parent, &staging.dir)?;

    let staged_key = staging.key();
    let staged_pub = pub_path(&staged_key);
    let status = OpenSsh::command(openssh.ssh_keygen())
        .args(keygen_create_args(opts, &staged_key))
        .stdin(stdin)
        .status()
        .map_err(|source| Error::Spawn {
            program: openssh.ssh_keygen().to_owned(),
            source,
        })?;
    if !status.success() {
        return Err(Error::KeygenFailed { status });
    }

    for p in [&staged_key, &staged_pub] {
        let meta = fs::symlink_metadata(p).map_err(|e| Error::io("missing output", p, e))?;
        if !meta.is_file() {
            return Err(Error::UnexpectedOutput("output is not a regular file"));
        }
    }
    fs::set_permissions(&staged_key, fs::Permissions::from_mode(KEY_FILE_MODE))
        .map_err(|e| Error::io("cannot set mode of", &staged_key, e))?;

    let line = read_public(&staged_key)?;
    if line.algorithm() != opts.algorithm {
        return Err(Error::UnexpectedOutput(
            "key algorithm differs from request",
        ));
    }
    if line.application() != opts.application {
        return Err(Error::UnexpectedOutput("application differs from request"));
    }
    if line.comment() != Some(opts.comment.as_str()) {
        return Err(Error::UnexpectedOutput("comment differs from request"));
    }

    publish(&staged_key, key_path)?;
    if let Err(e) = publish(&staged_pub, &pub_final) {
        // We created key_path a moment ago in a directory only we can write.
        let _ = fs::remove_file(key_path);
        return Err(e);
    }
    Ok(line)
}

/// [`Error::KeyExists`] if anything (including a dangling symlink) is at `path`.
fn refuse_existing(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::KeyExists(path.to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io("cannot check", path, e)),
    }
}

/// Create `dir` (and missing ancestors) with mode 0700 if missing; then require it to
/// be a directory that is not group/other-writable.
fn ensure_private_dir(dir: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => DirBuilder::new()
            .recursive(true)
            .mode(KEY_DIR_MODE)
            .create(dir)
            .map_err(|e| Error::io("cannot create directory", dir, e))?,
        Err(e) => return Err(Error::io("cannot check", dir, e)),
    }
    let meta = fs::metadata(dir).map_err(|e| Error::io("cannot check", dir, e))?;
    if !meta.is_dir() {
        return Err(Error::InvalidInput {
            field: "key path",
            reason: "parent is not a directory",
        });
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(Error::InsecurePermissions {
            path: dir.to_owned(),
            reason: "directory is writable by group or others",
        });
    }
    Ok(())
}

/// `dir` must be owned by the user we run as, i.e. the owner of `ours` (a directory
/// we just created; avoids needing `getuid`).
fn check_same_owner(dir: &Path, ours: &Path) -> Result<(), Error> {
    let theirs = fs::metadata(dir).map_err(|e| Error::io("cannot check", dir, e))?;
    let mine = fs::metadata(ours).map_err(|e| Error::io("cannot check", ours, e))?;
    if theirs.uid() != mine.uid() {
        return Err(Error::InsecurePermissions {
            path: dir.to_owned(),
            reason: "directory is owned by another user",
        });
    }
    Ok(())
}

/// Link `from` to the new name `to`; fails if `to` exists (no replacement).
fn publish(from: &Path, to: &Path) -> Result<(), Error> {
    fs::hard_link(from, to).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::KeyExists(to.to_owned())
        } else {
            Error::io("cannot create", to, e)
        }
    })
}

/// A fresh mode-0700 directory; its two possible files and itself are removed on drop.
struct Staging {
    dir: PathBuf,
}

impl Staging {
    fn new(parent: &Path) -> Result<Self, Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        let mut last_err = None;
        for attempt in 0..STAGING_ATTEMPTS {
            let dir = parent.join(format!(
                ".petschaft-fido2-tmp-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match DirBuilder::new().mode(KEY_DIR_MODE).create(&dir) {
                Ok(()) => return Ok(Staging { dir }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(Error::io("cannot create directory", &dir, e)),
            }
        }
        Err(Error::io(
            "cannot create staging directory in",
            parent,
            last_err.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)),
        ))
    }

    fn key(&self) -> PathBuf {
        self.dir.join(STAGED_NAME)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let key = self.key();
        let _ = fs::remove_file(pub_path(&key));
        let _ = fs::remove_file(&key);
        let _ = fs::remove_dir(&self.dir);
    }
}
