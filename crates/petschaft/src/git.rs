//! `ssh-keygen -Y` compatible entry point, so git can use petschaft as `gpg.ssh.program`.
//!
//! git calls `<program> -Y sign -n git -f <key file> [-U] <payload file>` and reads
//! `<payload file>.sig`. Signing goes to the Trezor; every other `-Y` operation
//! (`verify`, `find-principals`, `check-novalidate`) is handed to the baked OpenSSH
//! `ssh-keygen` (`PETSCHAFT_OPENSSH_BIN`, never a `PATH` lookup), so verification is
//! done by OpenSSH, independently of petschaft.

use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use petschaft_core::{Config, Fingerprint, IdentityConfig, Proto, Slip13Identity};
use petschaft_device::{SignRequest, Signer};
use petschaft_sshsig::{KeyLine, armor, message_hash, signed_data};

const NAMESPACE: &str = "git";
/// Commit and tag objects are small; this only bounds memory for a wrong path.
const MAX_MESSAGE: u64 = 64 * 1024 * 1024;
const MAX_KEY_FILE: u64 = 16 * 1024;
/// Longest text sent to the device display (protocol limit: 128 characters).
const MAX_VISUAL_CHARS: usize = 100;
/// Set when delegating to ssh-keygen, to detect the baked `ssh-keygen` being pets itself.
const DELEGATED_ENV: &str = "PETSCHAFT_DELEGATED_TO_SSH_KEYGEN";

/// `args` starts with `-Y`.
pub fn ssh_keygen_compat(args: &[OsString]) -> ExitCode {
    match args.get(1).and_then(|a| a.to_str()) {
        Some("sign") => match sign(args.get(2..).unwrap_or_default()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                // git only shows the program's stderr when signing fails.
                eprintln!("pets: {e:#}");
                ExitCode::FAILURE
            }
        },
        _ => delegate(args),
    }
}

fn delegate(args: &[OsString]) -> ExitCode {
    if std::env::var_os(DELEGATED_ENV).is_some() {
        eprintln!("pets: the configured ssh-keygen is pets itself; refusing to recurse");
        return ExitCode::FAILURE;
    }
    match petschaft_fido2::OpenSsh::resolve() {
        Ok(openssh) => run_ssh_keygen(openssh.ssh_keygen(), args),
        Err(e) => {
            eprintln!("pets: cannot run ssh-keygen for verification: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs `ssh_keygen` (an absolute path) with `args`; its exit code is ours.
fn run_ssh_keygen(ssh_keygen: &Path, args: &[OsString]) -> ExitCode {
    match Command::new(ssh_keygen)
        .args(args)
        .env(DELEGATED_ENV, "1")
        .status()
    {
        Ok(status) => status
            .code()
            .and_then(|c| u8::try_from(c).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from),
        Err(e) => {
            eprintln!(
                "pets: cannot run {} for verification: {e}",
                ssh_keygen.display()
            );
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SignArgs {
    namespace: String,
    key_file: PathBuf,
    file: PathBuf,
}

fn parse_sign_args(args: &[OsString]) -> Result<SignArgs> {
    let mut namespace = None;
    let mut key_file = None;
    let mut files = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("-n") => {
                let v = it
                    .next()
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| anyhow!("-n needs a namespace"))?;
                namespace = Some(v.to_owned());
            }
            Some("-f") => {
                let v = it.next().ok_or_else(|| anyhow!("-f needs a key file"))?;
                key_file = Some(PathBuf::from(v));
            }
            // Use an agent: petschaft always uses the Trezor, so this changes nothing.
            Some("-U") => {}
            Some(opt) if opt.starts_with('-') => bail!("unsupported ssh-keygen option {opt:?}"),
            _ => files.push(PathBuf::from(arg)),
        }
    }
    let [file] = <[PathBuf; 1]>::try_from(files)
        .map_err(|_| anyhow!("expected exactly one file to sign"))?;
    Ok(SignArgs {
        namespace: namespace.ok_or_else(|| anyhow!("missing -n <namespace>"))?,
        key_file: key_file.ok_or_else(|| anyhow!("missing -f <key file>"))?,
        file,
    })
}

pub(crate) fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .with_context(|| format!("read {}", path.display()))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > limit {
        bail!("{} is larger than {limit} bytes", path.display());
    }
    Ok(buf)
}

/// Display-safe copy: ASCII graphics and space are kept; other whitespace becomes a
/// space, everything else (non-ASCII letters, controls, format/bidi characters, emoji)
/// becomes `?`. ASCII only, so the helper's display rule (Python's `isprintable`) can
/// never disagree with Rust about it, whatever Unicode version either side has.
pub(crate) fn display_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c
            } else if c.is_whitespace() {
                ' '
            } else {
                '?'
            }
        })
        .collect()
}

pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// What the Trezor shows for a git object: its kind and the first non-empty message
/// line (`commit: Fix login`, `tag v1.0: Release`, `git object: ...`).
fn describe(object: &[u8]) -> String {
    let text = String::from_utf8_lossy(object);
    let (headers, body) = text.split_once("\n\n").unwrap_or((&text, ""));
    let first_line = body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("(no message)");
    let kind = if headers.starts_with("tree ") {
        "commit".to_owned()
    } else if headers.starts_with("object ") {
        let name = headers
            .lines()
            .find_map(|l| l.strip_prefix("tag "))
            .unwrap_or("?");
        format!("tag {}", truncate_chars(name, 40))
    } else {
        "git object".to_owned()
    };
    truncate_chars(
        &display_safe(&format!("{kind}: {first_line}")),
        MAX_VISUAL_CHARS,
    )
}

/// The identity git may sign with for the key with fingerprint `fp` (from git's key
/// file): the one identity whose *pinned* fingerprint is `fp`, which must be a slip13
/// identity with an `ssh://` URI.
///
/// Selected by fingerprint only, never by the key comment: the comment is free text
/// that anyone can edit and that may change without a new key. Unpinned identities
/// never match, so signing always requires a pin. Several identities pinning the same
/// key are ambiguous and rejected. FIDO2 identities are rejected (OpenSSH signs with
/// those itself, over USB).
fn signing_identity<'a>(config: &'a Config, fp: &Fingerprint) -> Result<&'a Slip13Identity> {
    let mut pinned = config
        .identities()
        .iter()
        .filter(|i| i.fingerprint() == Some(fp));
    let id = pinned.next().ok_or_else(|| {
        anyhow!(
            "no pinned slip13 identity with fingerprint {fp}; run `pets pubkey <name>` and pin \
             it (fingerprint = \"...\" in the config), then use that key as user.signingkey"
        )
    })?;
    if let Some(other) = pinned.next() {
        bail!(
            "identities \"{}\" and \"{}\" both pin fingerprint {fp}; keep the pin on one of them",
            id.name(),
            other.name()
        );
    }
    let id = match id {
        IdentityConfig::Slip13(s) => s,
        IdentityConfig::Fido2(f) => bail!(
            "identity \"{}\" is a fido2 identity; petschaft signs git objects only with slip13 \
             identities (fido2 support: see `pets fido2`)",
            f.name()
        ),
    };
    if id.identity().proto() != Proto::Ssh {
        bail!(
            "identity \"{}\" must use an ssh:// URI for git signatures",
            id.name()
        );
    }
    Ok(id)
}

fn sign(args: &[OsString]) -> Result<()> {
    let args = parse_sign_args(args)?;
    if args.namespace != NAMESPACE {
        bail!("only the {NAMESPACE:?} namespace is supported");
    }
    let config = crate::load_config(None)?;

    // The key git was told to use must be the pinned key of a slip13 identity; it is
    // found by its fingerprint (the comment in the key line is ignored).
    let key_text = String::from_utf8(read_limited(&args.key_file, MAX_KEY_FILE)?)
        .map_err(|_| anyhow!("signing key file is not UTF-8"))?;
    let key = KeyLine::parse(key_text.lines().next().unwrap_or(""))
        .context("user.signingkey must be a key line printed by `pets pubkey <name>`")?;
    let id = signing_identity(&config, &key.fingerprint())?;
    let name = id.name();

    let object = read_limited(&args.file, MAX_MESSAGE)?;
    let data = signed_data(NAMESPACE, &message_hash(&object))?;
    let what = describe(&object);

    let mut signer = crate::connect(&config)?;
    crate::say(&format!("pets: signing {what} (identity {name})"));
    let req = SignRequest::for_identity(id, data, what);
    // Verified against the returned key and the pin inside sign_identity.
    let signed = signer.sign_identity(&req)?;
    if signed.public_key().openssh_blob() != key.blob {
        bail!("the Trezor returned a different key than user.signingkey");
    }
    let armored = armor(signed.public_key(), NAMESPACE, signed.signature())?;

    let mut sig_path: OsString = args.file.into_os_string();
    sig_path.push(OsStr::new(".sig"));
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sig_path)
        .with_context(|| format!("create {}", Path::new(&sig_path).display()))?;
    out.write_all(armored.as_bytes())?;
    crate::say("pets: signature created");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    /// Verification runs the given (baked) ssh-keygen with git's arguments and the
    /// recursion guard set, and passes its exit code through.
    #[test]
    fn verification_runs_the_given_ssh_keygen() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("ssh-keygen");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\n[ \"${DELEGATED_ENV}\" = 1 ] || exit 90\n\
                 [ \"$*\" = '-Y verify -n git' ] || exit 91\nexit 7\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let code = run_ssh_keygen(&fake, &os(&["-Y", "verify", "-n", "git"]));
        assert_eq!(code, ExitCode::from(7));
        let missing = run_ssh_keygen(&dir.path().join("nope"), &os(&["-Y", "verify"]));
        assert_eq!(missing, ExitCode::FAILURE);
    }

    /// The program delegated to is the baked FIDO-capable OpenSSH, never a PATH lookup.
    #[test]
    fn verification_uses_the_baked_openssh() {
        let o = petschaft_fido2::OpenSsh::resolve().unwrap();
        assert!(o.ssh_keygen().is_absolute());
        assert!(o.ssh_keygen().ends_with("ssh-keygen"));
    }

    #[test]
    fn parses_git_invocations() {
        let expected = SignArgs {
            namespace: "git".into(),
            key_file: "/tmp/k".into(),
            file: "/tmp/buf".into(),
        };
        assert_eq!(
            parse_sign_args(&os(&["-n", "git", "-f", "/tmp/k", "/tmp/buf"])).unwrap(),
            expected
        );
        assert_eq!(
            parse_sign_args(&os(&["-n", "git", "-f", "/tmp/k", "-U", "/tmp/buf"])).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_bad_invocations() {
        for bad in [
            &["-n", "git", "-f", "/k"][..],
            &["-n", "git", "/buf"],
            &["-f", "/k", "/buf"],
            &["-n", "git", "-f", "/k", "/a", "/b"],
            &["-n", "git", "-f", "/k", "-O", "x", "/buf"],
            &["-n"],
        ] {
            assert!(parse_sign_args(&os(bad)).is_err(), "{bad:?}");
        }
    }

    /// An `ssh-ed25519` key line with 32 bytes of `seed` as the "public key". The bytes
    /// are not a real key; only the fingerprint matters for selecting the identity.
    fn key_line(seed: u8, comment: Option<&str>) -> KeyLine {
        let mut blob = Vec::new();
        for part in [&b"ssh-ed25519"[..], &[seed; 32]] {
            blob.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
            blob.extend_from_slice(part);
        }
        KeyLine {
            algorithm: "ssh-ed25519".into(),
            blob,
            comment: comment.map(str::to_owned),
        }
    }

    fn fp(seed: u8) -> Fingerprint {
        key_line(seed, None).fingerprint()
    }

    /// Identities: `git` (seed 1, pinned), `nopin` (unpinned), `apk` (gpg://, pinned
    /// seed 2), `sk` (fido2, pinned seed 3), `dup-a` / `dup-b` (both pin seed 4;
    /// `dup-b` is fido2, since the config rejects two slip13 identities with one pin).
    fn config() -> Config {
        Config::from_toml_str(&format!(
            "owner = \"user\"\n\
             [[identity]]\nname = \"git\"\nuri = \"ssh://user@git-signing\"\ncurve = \"ed25519\"\n\
             fingerprint = \"{}\"\ncomment = \"my signing key\"\n\
             [[identity]]\nname = \"nopin\"\nuri = \"ssh://user@x\"\ncurve = \"ed25519\"\n\
             [[identity]]\nname = \"apk\"\nuri = \"gpg://apk@release\"\ncurve = \"ed25519\"\n\
             fingerprint = \"{}\"\n\
             [[identity]]\nname = \"sk\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n\
             fingerprint = \"{}\"\n\
             [[identity]]\nname = \"dup-a\"\nuri = \"ssh://a@x\"\ncurve = \"ed25519\"\n\
             fingerprint = \"{}\"\n\
             [[identity]]\nname = \"dup-b\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n\
             fingerprint = \"{}\"\n",
            fp(1),
            fp(2),
            fp(3),
            fp(4),
            fp(4)
        ))
        .unwrap()
    }

    #[test]
    fn identity_selected_by_pinned_fingerprint() {
        let config = config();
        let id = signing_identity(&config, &fp(1)).unwrap();
        assert_eq!(id.name().as_str(), "git");
        assert_eq!(id.fingerprint(), Some(&fp(1)));
    }

    /// The comment of the key line never matters: any comment (including none, the
    /// `hwkey:<name>` form naming another identity, or the configured comment of
    /// another identity) selects the identity pinning the key's fingerprint.
    #[test]
    fn comment_is_ignored() {
        let config = config();
        for comment in [
            None,
            Some("my signing key"),
            Some("anything at all"),
            Some("hwkey:nopin"),
            Some("hwkey:sk"),
            Some("user@hwkey:apk"),
        ] {
            let key = key_line(1, comment);
            let id = signing_identity(&config, &key.fingerprint()).unwrap();
            assert_eq!(id.name().as_str(), "git", "{comment:?}");
        }
        // A key nobody pinned is rejected, even if its comment names a pinned identity.
        for comment in ["hwkey:git", "my signing key", "user@hwkey:git"] {
            let key = key_line(9, Some(comment));
            let e = signing_identity(&config, &key.fingerprint())
                .unwrap_err()
                .to_string();
            assert!(
                e.starts_with(&format!(
                    "no pinned slip13 identity with fingerprint {}; run `pets pubkey <name>`",
                    key.fingerprint()
                )),
                "{e}"
            );
        }
    }

    #[test]
    fn only_pinned_ssh_slip13_identities_sign() {
        let config = config();
        let err = |seed: u8| {
            signing_identity(&config, &fp(seed))
                .unwrap_err()
                .to_string()
        };
        assert!(
            err(2).contains("\"apk\" must use an ssh:// URI"),
            "{}",
            err(2)
        );
        assert!(err(3).contains("\"sk\" is a fido2 identity"), "{}", err(3));
        assert!(
            err(4).contains("\"dup-a\" and \"dup-b\" both pin fingerprint"),
            "{}",
            err(4)
        );
        // `nopin` is never selected: unpinned identities do not match any key.
        assert!(
            err(5).starts_with("no pinned slip13 identity"),
            "{}",
            err(5)
        );
        let empty = Config::default();
        assert!(signing_identity(&empty, &fp(1)).is_err());
    }

    #[test]
    fn describes_commits_and_tags() {
        let commit = b"tree abc\nauthor A <a@b> 1 +0000\n\nFix login\n\nlonger body\n";
        assert_eq!(describe(commit), "commit: Fix login");
        let tag = b"object abc\ntype commit\ntag v1.0\ntagger A <a@b> 1 +0000\n\nRelease\n";
        assert_eq!(describe(tag), "tag v1.0: Release");
        assert_eq!(
            describe(b"certificate version 0.1\n\nold new ref\n"),
            "git object: old new ref"
        );
        // Leading blank lines (git commit --cleanup=verbatim) are skipped like git does.
        assert_eq!(describe(b"tree abc\n\n\n\nreal\n"), "commit: real");
        assert_eq!(describe(b"tree abc\n\n"), "commit: (no message)");
    }

    #[test]
    fn display_text_is_always_safe() {
        let d = describe(
            "tree a\n\nFix \u{1F468}\u{200D}\u{1F4BB} caf\u{e9}\u{a0}\u{202E}evil\u{F8FF}\x1b[31m"
                .as_bytes(),
        );
        assert_eq!(d, "commit: Fix ??? caf? ?evil??[31m");
        // Letters of other scripts are not kept either (Unicode versions differ).
        assert_eq!(
            describe("tree a\n\nFix \u{444}\u{438}\u{43a}\u{0663}".as_bytes()),
            "commit: Fix ????"
        );
        let long = describe(format!("tree a\n\n{}", "x".repeat(300)).as_bytes());
        assert_eq!(long.chars().count(), MAX_VISUAL_CHARS);
        assert!(long.ends_with('\u{2026}'));
        for c in d.chars().chain(long.chars()) {
            assert!(c == ' ' || c.is_ascii_graphic() || c == '\u{2026}', "{c:?}");
        }
    }
}
