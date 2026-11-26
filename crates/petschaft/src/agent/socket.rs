//! Location and creation of the agent socket.
//!
//! - The socket lives in a private directory (mode 0700, owned by us; created if
//!   missing, refused if it is a symlink, not ours or group/other-accessible). Other
//!   users cannot reach the socket because of that directory, like OpenSSH's agent.
//! - The socket is first bound under a temporary name in that directory, which also
//!   tells us our own uid (std has no `getuid` and the workspace forbids `unsafe`):
//!   a socket we just created is owned by us. The directory must have the same owner.
//! - An existing `agent.sock` is replaced only if it is a socket owned by us that
//!   nobody listens on (a stale socket of an agent that was killed: std cannot catch
//!   SIGTERM/SIGINT without `unsafe`, so the socket stays behind on termination and is
//!   cleaned up here on the next start). Anything else there is an error.
//! - The new socket gets mode 0600 and is renamed into place atomically.

use std::ffi::OsString;
use std::fs::DirBuilder;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

const DIR_NAME: &str = "petschaft";
const SOCKET_NAME: &str = "agent.sock";

/// The default socket path: Linux (and other non-macOS Unix)
/// `$XDG_RUNTIME_DIR/petschaft/agent.sock`, macOS
/// `~/Library/Application Support/petschaft/agent.sock`.
pub(crate) fn default_socket_path() -> Result<PathBuf> {
    socket_path_from(
        cfg!(target_os = "macos"),
        std::env::var_os("XDG_RUNTIME_DIR"),
        std::env::var_os("HOME"),
    )
}

/// [`default_socket_path`] with the environment passed in (testable).
pub(crate) fn socket_path_from(
    macos: bool,
    xdg_runtime_dir: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    if macos {
        let home = absolute(home)
            .ok_or_else(|| anyhow!("HOME is not set to an absolute path; pass --socket <path>"))?;
        return Ok(home
            .join("Library")
            .join("Application Support")
            .join(DIR_NAME)
            .join(SOCKET_NAME));
    }
    let runtime = absolute(xdg_runtime_dir).ok_or_else(|| {
        anyhow!(
            "XDG_RUNTIME_DIR is not set to an absolute path (it is set in a normal login \
             session and for systemd user services); pass --socket <path> in a private directory"
        )
    })?;
    Ok(runtime.join(DIR_NAME).join(SOCKET_NAME))
}

/// Check (and create if missing) the socket directory; returns its owner's uid.
fn private_dir(dir: &Path) -> Result<u32> {
    let shown = dir.display();
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Not recursive: the parent ($XDG_RUNTIME_DIR, ~/Library/Application Support)
            // must exist.
            DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("cannot create {shown}"))?;
            std::fs::symlink_metadata(dir).with_context(|| format!("cannot check {shown}"))?
        }
        Err(e) => return Err(anyhow!("cannot check {shown}: {e}")),
    };
    if !meta.file_type().is_dir() {
        bail!("{shown} is not a directory (symlinks are not accepted)");
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        bail!(
            "{shown} is accessible by group or others (mode {mode:o}); other users could \
             reach the agent. Run: chmod 700 {shown}"
        );
    }
    Ok(meta.uid())
}

/// Removes the temporary socket unless disarmed.
struct TempSocket<'a>(Option<&'a Path>);

impl Drop for TempSocket<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Bind the agent socket at `path` (see the module docs for every check).
pub(crate) fn bind(path: &Path) -> Result<UnixListener> {
    if !path.is_absolute() {
        bail!("socket path {} must be absolute", path.display());
    }
    let (Some(dir), Some(file_name)) = (path.parent(), path.file_name()) else {
        bail!("socket path {} has no directory", path.display());
    };
    let dir_uid = private_dir(dir)?;

    let mut temp_name = OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp = dir.join(temp_name);
    // A leftover of an earlier process with the same pid (only removed if a socket).
    if std::fs::symlink_metadata(&temp).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = std::fs::remove_file(&temp);
    }
    let listener =
        UnixListener::bind(&temp).with_context(|| format!("cannot bind {}", temp.display()))?;
    let mut guard = TempSocket(Some(&temp));

    // We just created it, so its owner is us.
    let our_uid = std::fs::symlink_metadata(&temp)
        .with_context(|| format!("cannot check {}", temp.display()))?
        .uid();
    if our_uid != dir_uid {
        bail!(
            "{} is owned by uid {dir_uid}, not by us (uid {our_uid})",
            dir.display()
        );
    }
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set the mode of {}", temp.display()))?;

    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => bail!("cannot check {}: {e}", path.display()),
        Ok(m) => {
            if !m.file_type().is_socket() {
                bail!(
                    "{} exists and is not a socket; not touching it",
                    path.display()
                );
            }
            if m.uid() != our_uid {
                bail!(
                    "{} is owned by uid {}, not by us; not touching it",
                    path.display(),
                    m.uid()
                );
            }
            match UnixStream::connect(path) {
                Ok(_) => bail!("another agent is already listening on {}", path.display()),
                // Stale: replaced by the rename below.
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => {}
                Err(e) => bail!("cannot check {}: {e}", path.display()),
            }
        }
    }
    std::fs::rename(&temp, path)
        .with_context(|| format!("cannot move the socket to {}", path.display()))?;
    guard.0 = None;
    Ok(listener)
}
