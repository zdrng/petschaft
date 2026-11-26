#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use proptest::prelude::*;

use crate::create::{create_with_stdin, keygen_create_args};
use crate::openssh::resolve_from;
use crate::*;

// ---------------------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------------------

const ED: &str = "sk-ssh-ed25519@openssh.com";
const EC: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// Hand-built test vector in the layout `ssh-keygen -t ed25519-sk -O application=ssh:demotest
/// -C hwkey:test` writes (public key = SHA-256 of a fixed string; no authenticator involved).
const SAMPLE_ED25519: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIP7QI5opSkI2I3vshL+xE9lqgkLxI+M057dTGorIOu3sAAAADHNzaDpkZW1vdGVzdA== hwkey:test\n";
const SAMPLE_ED25519_FP: &str = "SHA256:Nt05kVT0IEull0Lo/ESwkF/2mnBZEkraW73v6ppVyFg";
/// Same for `-t ecdsa-sk` (default application `ssh:`), public key 7·G on P-256.
const SAMPLE_ECDSA: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBI5TO2+gv3tGJbswZnwB+2B++fi4qA/vWzAGKHAxh7Kjc+sdveAzGDZtBp+DpvWQAFPHNjPLBBshxV4ahsH0ALQAAAAEc3NoOg== hwkey:test-ecdsa\n";
const SAMPLE_ECDSA_FP: &str = "SHA256:WnDqNlCkEEb1SapijyDLJ7AHPFmno9LoH91wEO3Uz00";

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

/// `string "sk-ssh-ed25519@openssh.com", string pk(32), string application`
fn ed_blob(pk: &[u8], app: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, ED.as_bytes());
    put_string(&mut b, pk);
    put_string(&mut b, app);
    b
}

/// `string "sk-ecdsa-sha2-nistp256@openssh.com", string "nistp256", string Q(65), string application`
fn ec_blob(q: &[u8], app: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, EC.as_bytes());
    put_string(&mut b, b"nistp256");
    put_string(&mut b, q);
    put_string(&mut b, app);
    b
}

/// SEC1 uncompressed P-256 base point G (on the curve, so `ssh-keygen` accepts it).
fn p256_generator() -> Vec<u8> {
    let mut q = vec![0x04];
    for hex in [
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    ] {
        q.extend(
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()),
        );
    }
    q
}

/// A syntactically valid (65 bytes, 0x04 prefix) but generally off-curve point; the
/// parser checks only the layout.
fn p256_point(seed: u8) -> Vec<u8> {
    let mut q = vec![0x04];
    q.extend((0..64u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)));
    q
}

fn line(alg: &str, blob: &[u8], comment: Option<&str>) -> String {
    match comment {
        Some(c) => format!("{alg} {} {c}", STANDARD.encode(blob)),
        None => format!("{alg} {}", STANDARD.encode(blob)),
    }
}

fn invalid(l: &str) -> &'static str {
    match PublicKeyLine::parse(l) {
        Err(Error::InvalidPublicKey(r)) => r,
        other => panic!("expected InvalidPublicKey for {l:?}, got {other:?}"),
    }
}

fn openssh() -> OpenSsh {
    OpenSsh::resolve().expect("PETSCHAFT_OPENSSH_BIN must be set (run via the flake)")
}

fn opts(app: &str) -> CreateOptions {
    CreateOptions {
        algorithm: SkAlgorithm::Ed25519,
        application: app.to_owned(),
        comment: "hwkey:test".to_owned(),
        user_verification: false,
        resident: false,
        device: None,
    }
}

fn args_of(cmd: &Command) -> Vec<&OsStr> {
    cmd.get_args().collect()
}

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

fn dir_entries(p: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

// ---------------------------------------------------------------------------------------
// OpenSsh resolution
// ---------------------------------------------------------------------------------------

#[test]
fn resolve_compile_time_wins_over_runtime() {
    let o = resolve_from(Some("/nix/store/x/bin"), Some("/other/bin".into())).unwrap();
    assert_eq!(o.ssh(), Path::new("/nix/store/x/bin/ssh"));
    assert_eq!(o.ssh_keygen(), Path::new("/nix/store/x/bin/ssh-keygen"));
}

#[test]
fn resolve_runtime_fallback_and_empty_is_unset() {
    let o = resolve_from(Some(""), Some("/opt/ssh/bin".into())).unwrap();
    assert_eq!(o.ssh(), Path::new("/opt/ssh/bin/ssh"));
    assert!(matches!(
        resolve_from(None, Some("".into())),
        Err(Error::NotConfigured(_))
    ));
    assert!(matches!(
        resolve_from(None, None),
        Err(Error::NotConfigured(_))
    ));
}

#[test]
fn resolve_rejects_relative_paths() {
    assert!(matches!(
        resolve_from(Some("bin"), None),
        Err(Error::NotConfigured(_))
    ));
    assert!(matches!(
        resolve_from(None, Some("./bin".into())),
        Err(Error::NotConfigured(_))
    ));
}

#[test]
fn baked_openssh_is_absolute() {
    let o = openssh();
    assert!(o.ssh().is_absolute());
    assert!(o.ssh_keygen().is_file(), "{}", o.ssh_keygen().display());
}

// ---------------------------------------------------------------------------------------
// Argument construction
// ---------------------------------------------------------------------------------------

#[test]
fn ssh_command_argv() {
    let o = OpenSsh::from_bin_dir(Path::new("/nix/store/o/bin")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_homelab");
    fs::write(&key, b"handle").unwrap();
    let cmd = ssh_command(&o, &key, &os(&["-p", "2222", "user@homelab", "uname -a"])).unwrap();
    assert_eq!(cmd.get_program(), "/nix/store/o/bin/ssh");
    assert_eq!(
        args_of(&cmd),
        [
            "-i",
            key.to_str().unwrap(),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "SecurityKeyProvider=internal",
            "-o",
            "PubkeyAcceptedAlgorithms=sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PKCS11Provider=none",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-p",
            "2222",
            "user@homelab",
            "uname -a",
        ]
    );
}

#[test]
fn commands_remove_sk_env() {
    let o = OpenSsh::from_bin_dir(Path::new("/b")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k");
    fs::write(&key, b"handle").unwrap();
    for cmd in [
        ssh_command(&o, &key, &[]).unwrap(),
        sign_command(&o, Path::new("/k"), "git", Path::new("/f")),
    ] {
        let removed: Vec<&OsStr> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k)
            .collect();
        for var in REMOVED_ENV {
            assert!(removed.contains(&OsStr::new(var)), "{var}");
        }
    }
}

#[test]
fn ssh_command_requires_existing_key_file() {
    // ssh would silently fall back to ~/.ssh/id_* for an inaccessible -i file.
    let o = OpenSsh::from_bin_dir(Path::new("/b")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let r = ssh_command(&o, &dir.path().join("missing"), &[]);
    assert!(matches!(r, Err(Error::Io { .. })), "{r:?}");
    let r = ssh_command(&o, dir.path(), &[]);
    assert!(matches!(r, Err(Error::InvalidInput { .. })), "{r:?}");
}

#[test]
fn sign_command_argv() {
    let o = OpenSsh::from_bin_dir(Path::new("/nix/store/o/bin")).unwrap();
    let cmd = sign_command(&o, Path::new("/k/id_git"), "git", Path::new("-msg"));
    assert_eq!(cmd.get_program(), "/nix/store/o/bin/ssh-keygen");
    assert_eq!(
        args_of(&cmd),
        ["-Y", "sign", "-n", "git", "-f", "/k/id_git", "--", "-msg"]
    );
}

#[test]
fn keygen_args_minimal() {
    let args = keygen_create_args(&opts("ssh:homelab"), Path::new("/d/key"));
    assert_eq!(
        args,
        os(&[
            "-t",
            "ed25519-sk",
            "-O",
            "application=ssh:homelab",
            "-C",
            "hwkey:test",
            "-N",
            "",
            "-f",
            "/d/key",
        ])
    );
}

#[test]
fn keygen_args_all_options() {
    let o = CreateOptions {
        algorithm: SkAlgorithm::EcdsaP256,
        user_verification: true,
        resident: true,
        device: Some("/dev/hidraw3".into()),
        ..opts("ssh:x")
    };
    assert_eq!(
        keygen_create_args(&o, Path::new("/d/key")),
        os(&[
            "-t",
            "ecdsa-sk",
            "-O",
            "application=ssh:x",
            "-O",
            "verify-required",
            "-O",
            "resident",
            "-O",
            "device=/dev/hidraw3",
            "-C",
            "hwkey:test",
            "-N",
            "",
            "-f",
            "/d/key",
        ])
    );
}

#[test]
fn algorithm_names_round_trip() {
    for a in SkAlgorithm::ALL {
        assert_eq!(SkAlgorithm::from_ssh_name(a.ssh_name()), Some(a));
        assert_eq!(SkAlgorithm::from_keygen_type(a.keygen_type()), Some(a));
    }
    assert_eq!(SkAlgorithm::from_ssh_name("ssh-ed25519"), None);
    assert_eq!(SkAlgorithm::from_keygen_type("ed25519"), None);
}

// ---------------------------------------------------------------------------------------
// .pub parsing
// ---------------------------------------------------------------------------------------

#[test]
fn parse_sample_key_lines() {
    let ed = PublicKeyLine::parse(SAMPLE_ED25519).unwrap();
    assert_eq!(ed.algorithm(), SkAlgorithm::Ed25519);
    assert_eq!(ed.application(), "ssh:demotest");
    assert_eq!(ed.comment(), Some("hwkey:test"));
    assert_eq!(ed.fingerprint(), SAMPLE_ED25519_FP);
    assert_eq!(ed.to_line(), SAMPLE_ED25519.trim_end());

    let ec = PublicKeyLine::parse(SAMPLE_ECDSA).unwrap();
    assert_eq!(ec.algorithm(), SkAlgorithm::EcdsaP256);
    assert_eq!(ec.application(), "ssh:");
    assert_eq!(ec.fingerprint(), SAMPLE_ECDSA_FP);
    assert_eq!(ec.to_line(), SAMPLE_ECDSA.trim_end());
}

#[test]
fn parse_hand_built_lines() {
    let blob = ed_blob(&[7u8; 32], b"ssh:homelab");
    let l = PublicKeyLine::parse(&line(ED, &blob, Some("hwkey:homelab"))).unwrap();
    assert_eq!(l.blob(), &blob[..]);
    assert_eq!(l.application(), "ssh:homelab");
    assert_eq!(l.fingerprint(), fingerprint(&blob));

    let blob = ec_blob(&p256_point(1), b"ssh:");
    let l = PublicKeyLine::parse(&format!("{}\r\n", line(EC, &blob, None))).unwrap();
    assert_eq!(l.algorithm(), SkAlgorithm::EcdsaP256);
    assert_eq!(l.comment(), None);
}

/// Replacing the comment changes only the comment: same key, application, fingerprint.
#[test]
fn with_comment_keeps_the_key() {
    let blob = ed_blob(&[7u8; 32], b"ssh:homelab");
    for original in [None, Some("hwkey:homelab")] {
        let l = PublicKeyLine::parse(&line(ED, &blob, original)).unwrap();
        for c in [
            "user@hwkey:homelab",
            "Demo - Trezör homelab",
            "a",
            &"\u{20000}".repeat(128),
        ] {
            let r = l.with_comment(c).unwrap();
            assert_eq!(r.comment(), Some(c));
            assert_eq!(r.blob(), l.blob());
            assert_eq!(r.application(), l.application());
            assert_eq!(r.fingerprint(), l.fingerprint());
            assert_eq!(r.algorithm(), l.algorithm());
            assert_eq!(PublicKeyLine::parse(&r.to_line()).unwrap(), r);
        }
        for bad in ["", " a", "a ", "a\nb", "a\u{1b}b", &"a".repeat(513)] {
            assert!(
                matches!(
                    l.with_comment(bad),
                    Err(Error::InvalidInput {
                        field: "comment",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
    }
}

#[test]
fn parse_comment_with_spaces() {
    let blob = ed_blob(&[1u8; 32], b"ssh:a");
    let l = PublicKeyLine::parse(&line(ED, &blob, Some("hwkey: two words"))).unwrap();
    assert_eq!(l.comment(), Some("hwkey: two words"));
}

#[test]
fn parse_rejections() {
    let ed = ed_blob(&[7u8; 32], b"ssh:a");
    let ec = ec_blob(&p256_point(0), b"ssh:a");
    let mut trailing = ed.clone();
    trailing.push(0);
    let mut short_len = ed.clone();
    short_len.truncate(short_len.len() - 1);
    let mut compressed = p256_point(0);
    compressed[0] = 0x02;
    let b64 = STANDARD.encode(&ed);

    // Not security keys / unknown.
    invalid(&line("ssh-ed25519", &ed, None));
    invalid(&line("sk-ssh-ed25519-cert-v01@openssh.com", &ed, None));
    invalid("");
    invalid("sk-ssh-ed25519@openssh.com");
    // Token and blob disagree.
    invalid(&line(EC, &ed, None));
    invalid(&line(ED, &ec, None));
    // Base64.
    let padded = STANDARD.encode(ed_blob(&[7u8; 32], b"ssh:ab"));
    assert!(padded.ends_with("=="));
    invalid(&format!("{ED} {}", padded.trim_end_matches('=')));
    invalid(&format!("{ED} {}=", padded.trim_end_matches('=')));
    invalid(&format!("{ED} {b64}x"));
    invalid(&format!("{ED} !{b64}"));
    // Non-canonical trailing bits: last char 'A' -> 'B' keeps the length.
    let mut nc = STANDARD.encode(ed_blob(&[7u8; 32], b"ssh:ab"));
    let pos = nc.trim_end_matches('=').len() - 1;
    nc.replace_range(pos..=pos, "B");
    assert!(
        STANDARD.decode(&nc).is_err(),
        "test vector must be non-canonical"
    );
    invalid(&format!("{ED} {nc}"));
    // Layout.
    invalid(&line(ED, &trailing, None));
    invalid(&line(ED, &short_len, None));
    invalid(&line(ED, &ed_blob(&[7u8; 31], b"ssh:a"), None));
    invalid(&line(ED, &ed_blob(&[7u8; 33], b"ssh:a"), None));
    invalid(&line(EC, &ec_blob(&compressed, b"ssh:a"), None));
    invalid(&line(EC, &ec_blob(&p256_point(0)[..64], b"ssh:a"), None));
    let mut wrong_curve = Vec::new();
    put_string(&mut wrong_curve, EC.as_bytes());
    put_string(&mut wrong_curve, b"nistp384");
    put_string(&mut wrong_curve, &p256_point(0));
    put_string(&mut wrong_curve, b"ssh:a");
    invalid(&line(EC, &wrong_curve, None));
    let mut huge_len = Vec::new();
    put_string(&mut huge_len, ED.as_bytes());
    huge_len.extend_from_slice(&u32::MAX.to_be_bytes());
    invalid(&line(ED, &huge_len, None));
    // Application.
    invalid(&line(ED, &ed_blob(&[7u8; 32], b"webauthn:x"), None));
    invalid(&line(ED, &ed_blob(&[7u8; 32], b"ssh:a b"), None));
    invalid(&line(ED, &ed_blob(&[7u8; 32], b"ssh:\xff"), None));
    invalid(&line(ED, &ed_blob(&[7u8; 32], &[b'a'; 200]), None));
    // Comment / lines.
    invalid(&format!("{} ", line(ED, &ed, None)));
    invalid(&line(ED, &ed, Some("a\u{7}b")));
    invalid(&line(ED, &ed, Some("x ")));
    invalid(&format!(
        "{}\n{}\n",
        line(ED, &ed, None),
        line(ED, &ed, None)
    ));
    invalid(&format!("{}\n\n", line(ED, &ed, None)));
    invalid(&format!("{ED}  {b64}"));
}

#[test]
fn read_public_reads_pub_file() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_test");
    fs::write(pub_path(&key), SAMPLE_ED25519).unwrap();
    let l = read_public(&key).unwrap();
    assert_eq!(l.fingerprint(), SAMPLE_ED25519_FP);
    assert_eq!(pub_path(&key), dir.path().join("id_test.pub"));
    assert_eq!(pub_path(Path::new("a.b")), Path::new("a.b.pub"));
}

#[test]
fn read_public_limits() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k");
    assert!(matches!(read_public(&key), Err(Error::Io { .. })));

    let big = vec![b'a'; usize::try_from(MAX_PUB_FILE_LEN).unwrap() + 1];
    fs::write(pub_path(&key), &big).unwrap();
    assert!(matches!(read_public(&key), Err(Error::TooLarge { .. })));

    fs::write(pub_path(&key), b"sk-ssh-ed25519@openssh.com \xff\xfe").unwrap();
    assert!(matches!(
        read_public(&key),
        Err(Error::InvalidPublicKey("file is not UTF-8"))
    ));
}

/// Our fingerprint and parse result must agree with OpenSSH's own `ssh-keygen -l`.
#[test]
fn fingerprint_matches_ssh_keygen() {
    let o = openssh();
    let dir = tempfile::tempdir().unwrap();
    let lines = [
        SAMPLE_ED25519.to_owned(),
        SAMPLE_ECDSA.to_owned(),
        line(ED, &ed_blob(&[0u8; 32], b"ssh:"), Some("hwkey:zero")),
        line(
            ED,
            &ed_blob(&[0xa5; 32], b"ssh:homelab"),
            Some("hwkey:homelab"),
        ),
        line(
            EC,
            &ec_blob(&p256_generator(), b"ssh:git"),
            Some("hwkey:git"),
        ),
        line(EC, &ec_blob(&p256_generator(), b"ssh:x.y-z@q"), None),
    ];
    for (i, l) in lines.iter().enumerate() {
        let path = dir.path().join(format!("k{i}.pub"));
        fs::write(&path, format!("{}\n", l.trim_end())).unwrap();
        let out = Command::new(o.ssh_keygen())
            .args([OsStr::new("-l"), OsStr::new("-f"), path.as_os_str()])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "{l}: {out:?}");
        let stdout = String::from_utf8(out.stdout).unwrap();
        let theirs = stdout.split(' ').nth(1).unwrap();
        let ours = PublicKeyLine::parse(l).unwrap();
        assert_eq!(ours.fingerprint(), theirs, "{l}");
        let kind = match ours.algorithm() {
            SkAlgorithm::Ed25519 => "(ED25519-SK)",
            SkAlgorithm::EcdsaP256 => "(ECDSA-SK)",
        };
        assert!(stdout.trim_end().ends_with(kind), "{stdout}");
    }
}

fn arb_comment() -> impl Strategy<Value = Option<String>> {
    proptest::option::of("[!-~]([ -~]{0,30}[!-~])?")
}

fn arb_app() -> impl Strategy<Value = String> {
    "[!-~]{0,40}".prop_map(|s| format!("ssh:{s}"))
}

proptest! {
    #[test]
    fn parse_never_panics(s in "\\PC*") {
        let _ = PublicKeyLine::parse(&s);
    }

    #[test]
    fn parse_never_panics_on_arbitrary_blobs(
        alg in prop_oneof![Just(ED), Just(EC)],
        blob in proptest::collection::vec(any::<u8>(), 0..200),
        comment in arb_comment(),
    ) {
        let _ = PublicKeyLine::parse(&line(alg, &blob, comment.as_deref()));
    }

    #[test]
    fn parse_never_panics_on_mutated_valid_blobs(
        idx in any::<prop::sample::Index>(),
        byte in any::<u8>(),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut blob = ec_blob(&p256_point(3), b"ssh:prop");
        let i = idx.index(blob.len());
        blob[i] = byte;
        blob.truncate(cut.index(blob.len() + 1));
        let _ = PublicKeyLine::parse(&line(EC, &blob, None));
    }

    #[test]
    fn valid_lines_round_trip(
        ed in any::<bool>(),
        key in proptest::collection::vec(any::<u8>(), 64),
        app in arb_app(),
        comment in arb_comment(),
    ) {
        let (alg, blob) = if ed {
            (ED, ed_blob(&key[..32], app.as_bytes()))
        } else {
            let mut q = vec![0x04];
            q.extend_from_slice(&key);
            (EC, ec_blob(&q, app.as_bytes()))
        };
        let text = line(alg, &blob, comment.as_deref());
        let l = PublicKeyLine::parse(&text).unwrap();
        prop_assert_eq!(l.algorithm().ssh_name(), alg);
        prop_assert_eq!(l.application(), app.as_str());
        prop_assert_eq!(l.comment(), comment.as_deref());
        prop_assert_eq!(l.blob(), &blob[..]);
        prop_assert_eq!(l.to_line(), text);
    }
}

// ---------------------------------------------------------------------------------------
// sshd snippet
// ---------------------------------------------------------------------------------------

#[test]
fn snippet_contents() {
    let a = PublicKeyLine::parse(SAMPLE_ED25519).unwrap();
    let b = PublicKeyLine::parse(SAMPLE_ECDSA).unwrap();
    let s = sshd_snippet(&[(&a, true), (&b, false)]);
    let lines: Vec<&str> = s.lines().collect();
    assert!(lines.contains(&format!("verify-required {}", a.to_line()).as_str()));
    assert!(lines.contains(&b.to_line().as_str()));
    assert!(!s.contains(&format!("verify-required {}", b.to_line())));
    assert!(!s.contains("no-touch-required"));
    for required in [
        "PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "AuthenticationMethods publickey",
        "# PermitRootLogin no",
    ] {
        assert!(lines.contains(&required), "{required}");
    }
    assert!(s.contains(SSHD_DROPIN_PATH));
    assert!(s.contains("sshd -t"));
    assert!(s.contains("SECOND session"));
    assert!(s.contains("FIRST value"));
    // Every non-comment, non-empty line is either a key or a directive we emitted.
    let directives = lines
        .iter()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();
    // 2 keys + 4 directives (PermitRootLogin is an optional, commented-out line).
    assert_eq!(directives, 2 + 4);
}

#[test]
fn authorized_keys_line_without_options() {
    let a = PublicKeyLine::parse(SAMPLE_ED25519).unwrap();
    assert_eq!(authorized_keys_line(&a, false), SAMPLE_ED25519.trim_end());
}

// ---------------------------------------------------------------------------------------
// create: refusal, validation and permissions (no ssh-keygen run)
// ---------------------------------------------------------------------------------------

/// An OpenSsh whose binaries do not exist: reaching ssh-keygen yields `Error::Spawn`.
fn missing_openssh() -> OpenSsh {
    OpenSsh::from_bin_dir(Path::new("/nonexistent/petschaft-test/bin")).unwrap()
}

#[test]
fn create_refuses_existing_key_without_running_keygen() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id");
    fs::write(&key, b"keep").unwrap();
    let r = create(&missing_openssh(), &opts("ssh:a"), &key);
    assert!(matches!(&r, Err(Error::KeyExists(p)) if p == &key), "{r:?}");
    assert_eq!(fs::read(&key).unwrap(), b"keep");
    assert_eq!(dir_entries(dir.path()), ["id"]);
}

#[test]
fn create_refuses_existing_pub_and_dangling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id");
    fs::write(pub_path(&key), b"keep").unwrap();
    let r = create(&missing_openssh(), &opts("ssh:a"), &key);
    assert!(matches!(r, Err(Error::KeyExists(_))), "{r:?}");

    let key2 = dir.path().join("id2");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &key2).unwrap();
    let r = create(&missing_openssh(), &opts("ssh:a"), &key2);
    assert!(matches!(r, Err(Error::KeyExists(_))), "{r:?}");
}

#[test]
fn create_validates_options() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id");
    let cases = [
        (opts("homelab"), "application"),
        (opts("ssh:a b"), "application"),
        (
            CreateOptions {
                comment: "a\nb".into(),
                ..opts("ssh:a")
            },
            "comment",
        ),
        (
            CreateOptions {
                comment: String::new(),
                ..opts("ssh:a")
            },
            "comment",
        ),
        (
            CreateOptions {
                device: Some("hidraw0".into()),
                ..opts("ssh:a")
            },
            "device",
        ),
    ];
    for (o, field) in cases {
        let r = create(&missing_openssh(), &o, &key);
        assert!(
            matches!(&r, Err(Error::InvalidInput { field: f, .. }) if *f == field),
            "{field}: {r:?}"
        );
    }
    assert!(dir_entries(dir.path()).is_empty());
}

#[test]
fn create_makes_missing_parent_0700() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("a/b");
    let key = parent.join("id");
    let r = create(&missing_openssh(), &opts("ssh:a"), &key);
    assert!(matches!(r, Err(Error::Spawn { .. })), "{r:?}");
    assert_eq!(mode(&dir.path().join("a")) & 0o777, 0o700);
    assert_eq!(mode(&parent) & 0o777, 0o700);
    // Staging directory was cleaned up.
    assert!(dir_entries(&parent).is_empty());
}

#[test]
fn create_refuses_group_writable_parent() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("shared");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o775)).unwrap();
    let r = create(&missing_openssh(), &opts("ssh:a"), &parent.join("id"));
    assert!(matches!(r, Err(Error::InsecurePermissions { .. })), "{r:?}");
    assert!(dir_entries(&parent).is_empty());
    // An existing mode is never changed by create.
    assert_eq!(mode(&parent) & 0o777, 0o775);
}

#[test]
fn create_rejects_path_without_file_name() {
    let r = create(&missing_openssh(), &opts("ssh:a"), Path::new("/"));
    assert!(matches!(r, Err(Error::InvalidInput { .. })), "{r:?}");
}

// ---------------------------------------------------------------------------------------
// create with a fake ssh-keygen (full flow without a device)
// ---------------------------------------------------------------------------------------

/// A bin dir with a shell-script `ssh-keygen` that logs its argv, writes the key
/// handle (mode 0644 on purpose) and `pub_line` to `-f <out>`, then runs `extra`.
fn fake_openssh(root: &Path, pub_line: &str, extra: &str, exit: i32) -> OpenSsh {
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let script = format!(
        "#!/bin/sh\n\
         log='{log}'\n\
         for a in \"$@\"; do printf '%s\\n' \"$a\" >> \"$log\"; done\n\
         out=''\n\
         while [ $# -gt 0 ]; do if [ \"$1\" = -f ]; then out=\"$2\"; fi; shift; done\n\
         printf 'handle' > \"$out\"\n\
         chmod 644 \"$out\"\n\
         printf '%s\\n' '{pub_line}' > \"$out.pub\"\n\
         {extra}\n\
         exit {exit}\n",
        log = root.join("argv.log").display(),
    );
    let path = bin.join("ssh-keygen");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    OpenSsh::from_bin_dir(&bin).unwrap()
}

#[test]
fn create_full_flow_with_fake_keygen() {
    let root = tempfile::tempdir().unwrap();
    let pub_line = SAMPLE_ED25519.trim_end();
    let o = fake_openssh(root.path(), pub_line, "", 0);
    let keys = root.path().join("keys");
    let key = keys.join("id_homelab");
    let options = CreateOptions {
        user_verification: true,
        ..opts("ssh:demotest")
    };

    let l = create_with_stdin(&o, &options, &key, Stdio::null()).unwrap();
    assert_eq!(l.fingerprint(), SAMPLE_ED25519_FP);
    assert_eq!(fs::read(&key).unwrap(), b"handle");
    assert_eq!(mode(&key), KEY_FILE_MODE);
    assert_eq!(mode(&keys) & 0o777, KEY_DIR_MODE);
    assert_eq!(read_public(&key).unwrap(), l);
    assert_eq!(dir_entries(&keys), ["id_homelab", "id_homelab.pub"]);

    let argv = fs::read_to_string(root.path().join("argv.log")).unwrap();
    let argv: Vec<&str> = argv.lines().collect();
    let staged = argv.last().unwrap();
    assert!(
        Path::new(staged).starts_with(&keys) && staged.ends_with("/key"),
        "{staged}"
    );
    assert_eq!(
        argv,
        [
            "-t",
            "ed25519-sk",
            "-O",
            "application=ssh:demotest",
            "-O",
            "verify-required",
            "-C",
            "hwkey:test",
            "-N",
            "",
            "-f",
            staged,
        ]
    );

    // A second create on the same path refuses before running the fake again.
    let r = create_with_stdin(&o, &options, &key, Stdio::null());
    assert!(matches!(r, Err(Error::KeyExists(_))), "{r:?}");
    let runs = fs::read_to_string(root.path().join("argv.log"))
        .unwrap()
        .lines()
        .filter(|l| *l == "-t")
        .count();
    assert_eq!(runs, 1);
}

#[test]
fn create_never_replaces_file_appearing_during_keygen() {
    let root = tempfile::tempdir().unwrap();
    let keys = root.path().join("keys");
    let key = keys.join("id");
    let racer = format!("printf 'other' > '{}'", key.display());
    let o = fake_openssh(root.path(), SAMPLE_ED25519.trim_end(), &racer, 0);
    let r = create_with_stdin(&o, &opts("ssh:demotest"), &key, Stdio::null());
    assert!(matches!(&r, Err(Error::KeyExists(p)) if p == &key), "{r:?}");
    assert_eq!(fs::read(&key).unwrap(), b"other");
    assert_eq!(dir_entries(&keys), ["id"]);
}

#[test]
fn create_reports_keygen_failure_and_cleans_up() {
    let root = tempfile::tempdir().unwrap();
    let o = fake_openssh(root.path(), SAMPLE_ED25519.trim_end(), "", 3);
    let keys = root.path().join("keys");
    let r = create_with_stdin(&o, &opts("ssh:demotest"), &keys.join("id"), Stdio::null());
    match r {
        Err(e @ Error::KeygenFailed { status }) => {
            assert_eq!(status.code(), Some(3));
            assert!(e.to_string().contains('3'), "{e}");
        }
        other => panic!("{other:?}"),
    }
    assert!(dir_entries(&keys).is_empty());
}

#[test]
fn create_rejects_output_not_matching_request() {
    for (options, why) in [
        (opts("ssh:other"), "application"),
        (
            CreateOptions {
                algorithm: SkAlgorithm::EcdsaP256,
                ..opts("ssh:demotest")
            },
            "algorithm",
        ),
        (
            CreateOptions {
                comment: "hwkey:else".into(),
                ..opts("ssh:demotest")
            },
            "comment",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let o = fake_openssh(root.path(), SAMPLE_ED25519.trim_end(), "", 0);
        let keys = root.path().join("keys");
        let r = create_with_stdin(&o, &options, &keys.join("id"), Stdio::null());
        assert!(matches!(r, Err(Error::UnexpectedOutput(_))), "{why}: {r:?}");
        assert!(dir_entries(&keys).is_empty(), "{why}");
    }
}

// ---------------------------------------------------------------------------------------
// Real OpenSSH processes (no authenticator needed)
// ---------------------------------------------------------------------------------------

/// Path of an authenticator that cannot exist, so libfido2 fails fast even when a real
/// security key is plugged in.
const NO_DEVICE: &str = "/nonexistent/petschaft-test-fido-device";

/// The baked ssh-keygen knows both sk key types: with no usable authenticator it fails
/// at enrollment, not with "unknown key type".
#[test]
fn baked_keygen_supports_sk_types() {
    let o = openssh();
    let dir = tempfile::tempdir().unwrap();
    for t in ["ed25519-sk", "ecdsa-sk"] {
        let out = Command::new(o.ssh_keygen())
            .args([
                "-t",
                t,
                "-O",
                &format!("device={NO_DEVICE}"),
                "-N",
                "",
                "-f",
            ])
            .arg(dir.path().join(t))
            .env_remove("SSH_SK_HELPER")
            .env_remove("SSH_SK_PROVIDER")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{t}: {stderr}");
        assert!(!stderr.contains("unknown key type"), "{t}: {stderr}");
        assert!(stderr.contains("enrollment failed"), "{t}: {stderr}");
    }
    assert!(dir_entries(dir.path()).is_empty());
}

#[test]
fn real_create_without_authenticator_fails_cleanly() {
    let o = openssh();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("keys/id");
    let options = CreateOptions {
        device: Some(NO_DEVICE.into()),
        ..opts("ssh:demotest")
    };
    let (tx, rx) = mpsc::channel();
    let key2 = key.clone();
    std::thread::spawn(move || {
        let _ = tx.send(create_with_stdin(&o, &options, &key2, Stdio::null()));
    });
    let r = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("ssh-keygen must not block");
    assert!(
        matches!(&r, Err(Error::KeygenFailed { status }) if !status.success()),
        "{r:?}"
    );
    assert!(dir_entries(&dir.path().join("keys")).is_empty());
}

#[test]
fn real_sign_command_with_software_key() {
    // sign_command's argv (incl. "--" before a file starting with '-') works with the
    // real ssh-keygen; a plain ed25519 key stands in for the security key.
    let o = openssh();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("soft");
    let st = Command::new(o.ssh_keygen())
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"])
        .arg(&key)
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    fs::write(dir.path().join("-msg"), b"hello").unwrap();
    let out = sign_command(&o, &key, "file", Path::new("-msg"))
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let sig = fs::read_to_string(dir.path().join("-msg.sig")).unwrap();
    assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"));
}

#[test]
fn real_ssh_command_effective_options() {
    // `ssh -G` prints the effective configuration without connecting; `-F /dev/null`
    // keeps the user's and the system ssh_config out of it.
    let o = openssh();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id");
    fs::write(&key, b"handle").unwrap();
    let out = ssh_command(
        &o,
        &key,
        &os(&[
            "-F",
            "/dev/null",
            "-G",
            "-o",
            "IdentitiesOnly=no",
            "example.invalid",
        ]),
    )
    .unwrap()
    .stdin(Stdio::null())
    .output()
    .unwrap();
    assert!(out.status.success(), "{out:?}");
    let cfg = String::from_utf8(out.stdout).unwrap();
    let cfg: Vec<&str> = cfg.lines().collect();
    for expected in [
        "identitiesonly yes",
        "identityagent none",
        "securitykeyprovider internal",
        "pubkeyacceptedalgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com",
        "preferredauthentications publickey",
        "passwordauthentication no",
        "kbdinteractiveauthentication no",
        "controlmaster false",
    ] {
        assert!(cfg.contains(&expected), "{expected}");
    }
    let files: Vec<&&str> = cfg
        .iter()
        .filter(|l| l.starts_with("identityfile "))
        .collect();
    assert_eq!(files, [&format!("identityfile {}", key.display()).as_str()]);
}
