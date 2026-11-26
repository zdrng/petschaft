//! Format tests plus round-trips through the real `ssh-keygen -Y verify`.

use std::io::Write;
use std::process::{Command, Stdio};

use ed25519_dalek::Signer as _;
use petschaft_core::{Curve, Proto, verify_identity_signature};

use super::*;

fn ed25519_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

fn p256_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap()
}

/// Software stand-in for the Trezor: signs `signed_data` exactly as the firmware does
/// for an `ssh://` identity (ed25519 raw, nist256p1 ECDSA over SHA-256) and returns the
/// device formats; the key and signature then go through the same validating API as
/// real device output (`PublicKey::from_device`, `verify_identity_signature`).
fn sign(curve: &str, data: &[u8]) -> (PublicKey, Signature) {
    let (curve, device_key, device_sig) = match curve {
        "ed25519" => {
            let k = ed25519_key();
            let key = [&[0u8][..], k.verifying_key().as_bytes()].concat();
            let sig = [&[0u8][..], &k.sign(data).to_bytes()].concat();
            (Curve::Ed25519, key, sig)
        }
        _ => {
            let k = p256_key();
            let s: p256::ecdsa::Signature = k.sign(data);
            let key = k.verifying_key().to_sec1_point(true).as_bytes().to_vec();
            let sig = [&[0u8][..], &s.to_bytes()].concat();
            (Curve::Nist256p1, key, sig)
        }
    };
    let key = PublicKey::from_device(curve, &device_key).unwrap();
    let sig = verify_identity_signature(Proto::Ssh, &key, data, &device_sig).unwrap();
    (key, sig)
}

fn ssh_keygen() -> Command {
    // Present in `nix develop` and in the Nix build (nativeCheckInputs). No skipping:
    // a missing ssh-keygen must fail the test.
    Command::new("ssh-keygen")
}

/// Run `ssh-keygen -Y verify` for `message` with an allowed_signers file.
fn openssh_verifies(key: &PublicKey, armored: &str, message: &[u8]) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let sig = dir.path().join("msg.sig");
    std::fs::write(&sig, armored).unwrap();
    let allowed = dir.path().join("allowed_signers");
    let line = key.openssh_line("");
    std::fs::write(
        &allowed,
        format!("demo@petschaft namespaces=\"git\" {line}\n"),
    )
    .unwrap();
    let mut child = ssh_keygen()
        .args(["-Y", "verify", "-n", "git", "-I", "demo@petschaft", "-f"])
        .arg(&allowed)
        .arg("-s")
        .arg(&sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("ssh-keygen must be on PATH for these tests");
    child.stdin.take().unwrap().write_all(message).unwrap();
    child.wait().unwrap().success()
}

#[test]
fn signed_data_layout() {
    let h = [0xABu8; 64];
    let d = signed_data("git", &h).unwrap();
    let mut expected = b"SSHSIG".to_vec();
    expected.extend_from_slice(&[0, 0, 0, 3]);
    expected.extend_from_slice(b"git");
    expected.extend_from_slice(&[0, 0, 0, 0]);
    expected.extend_from_slice(&[0, 0, 0, 6]);
    expected.extend_from_slice(b"sha512");
    expected.extend_from_slice(&[0, 0, 0, 64]);
    expected.extend_from_slice(&h);
    assert_eq!(d, expected);
    // Fits the Trezor's 512-byte challenge limit with room to spare.
    assert!(d.len() <= 512);
}

#[test]
fn namespace_rules() {
    let h = [0u8; 64];
    assert!(signed_data("", &h).is_err());
    assert!(signed_data("g it", &h).is_err());
    assert!(signed_data(&"a".repeat(65), &h).is_err());
    assert!(signed_data("file", &h).is_ok());
}

#[test]
fn mpint_encoding() {
    let enc = |x: &[u8]| {
        let mut v = Vec::new();
        put_mpint(&mut v, x);
        v
    };
    assert_eq!(enc(&[0, 0]), [0, 0, 0, 0]);
    assert_eq!(enc(&[0, 0x7f]), [0, 0, 0, 1, 0x7f]);
    assert_eq!(enc(&[0, 0x80]), [0, 0, 0, 2, 0, 0x80]);
    assert_eq!(enc(&[0x12, 0x34]), [0, 0, 0, 2, 0x12, 0x34]);
}

#[test]
fn openssh_accepts_our_signatures() {
    for curve in ["ed25519", "nist256p1"] {
        let message = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nhello petschaft\n";
        let data = signed_data("git", &message_hash(message)).unwrap();
        let (key, sig) = sign(curve, &data);
        let armored = armor(&key, "git", &sig).unwrap();
        assert!(armored.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
        assert!(
            armored
                .lines()
                .all(|l| l.len() <= 70 || l.starts_with("-----"))
        );
        assert!(
            openssh_verifies(&key, &armored, message),
            "{curve}: OpenSSH rejected a valid signature"
        );
        // Negative controls: other message, other namespace in the signed data.
        assert!(
            !openssh_verifies(&key, &armored, b"tampered"),
            "{curve}: tampered message accepted"
        );
        let other = signed_data("file", &message_hash(message)).unwrap();
        let (_, sig2) = sign(curve, &other);
        let armored2 = armor(&key, "git", &sig2).unwrap();
        assert!(
            !openssh_verifies(&key, &armored2, message),
            "{curve}: wrong namespace accepted"
        );
    }
}

#[test]
fn armor_rejects_mismatched_key_and_signature() {
    let (ed, ed_sig) = sign("ed25519", b"x");
    let (p, p_sig) = sign("nist256p1", b"x");
    assert_eq!(armor(&ed, "git", &p_sig), Err(Error::KeyMismatch));
    assert_eq!(armor(&p, "git", &ed_sig), Err(Error::KeyMismatch));
    // matching pairs and namespace rules
    assert!(armor(&ed, "git", &ed_sig).is_ok());
    assert!(armor(&p, "git", &p_sig).is_ok());
    assert_eq!(armor(&ed, "", &ed_sig), Err(Error::InvalidNamespace));
    assert_eq!(armor(&ed, "g it", &ed_sig), Err(Error::InvalidNamespace));
}

#[test]
fn armor_layout() {
    // Decode the armored body and check every field of PROTOCOL.sshsig.
    for curve in ["ed25519", "nist256p1"] {
        let data = signed_data("git", &message_hash(b"m")).unwrap();
        let (key, sig) = sign(curve, &data);
        let armored = armor(&key, "git", &sig).unwrap();
        let b64: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let body = STANDARD.decode(b64).unwrap();
        let mut expected = b"SSHSIG".to_vec();
        expected.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut expected, &key.openssh_blob());
        put_string(&mut expected, b"git");
        put_string(&mut expected, b"");
        put_string(&mut expected, b"sha512");
        assert!(body.starts_with(&expected), "{curve}");
        let mut sig_blob = Vec::new();
        put_string(&mut sig_blob, key.openssh_algorithm().as_bytes());
        match sig.parts() {
            SignatureParts::Ed25519(s) => put_string(&mut sig_blob, s),
            SignatureParts::Nist256p1 { r, s } => {
                let mut rs = Vec::new();
                put_mpint(&mut rs, r);
                put_mpint(&mut rs, s);
                put_string(&mut sig_blob, &rs);
            }
        }
        let mut tail = Vec::new();
        put_string(&mut tail, &sig_blob);
        assert_eq!(&body[expected.len()..], &tail[..], "{curve}");
    }
}

#[test]
fn key_line_parsing() {
    let (key, _) = sign("ed25519", b"x");
    let line = key.openssh_line("user@hwkey:git");
    let parsed = KeyLine::parse(&line).unwrap();
    assert_eq!(parsed.algorithm, "ssh-ed25519");
    assert_eq!(parsed.blob, key.openssh_blob());
    assert_eq!(parsed.comment.as_deref(), Some("user@hwkey:git"));
    assert_eq!(parsed.fingerprint(), key.fingerprint());
    for curve in ["ed25519", "nist256p1"] {
        let (k, _) = sign(curve, b"x");
        let parsed = KeyLine::parse(&k.openssh_line("c")).unwrap();
        assert_eq!(parsed.algorithm, k.openssh_algorithm());
        assert_eq!(parsed.fingerprint(), k.fingerprint());
    }

    assert!(KeyLine::parse("").is_err());
    assert!(KeyLine::parse("ssh-rsa AAAA x").is_err());
    assert!(KeyLine::parse("ssh-ed25519 !!!").is_err());
    // Algorithm field and blob disagree.
    let (p, _) = sign("nist256p1", b"x");
    let p_b64 = p.openssh_line("").split(' ').nth(1).unwrap().to_owned();
    assert!(KeyLine::parse(&format!("ssh-ed25519 {p_b64}")).is_err());
}

#[test]
fn openssh_accepts_many_p256_signatures() {
    // Different messages give r/s with and without the high bit and with leading zero
    // bytes, covering both mpint branches.
    for i in 0..64u32 {
        let message = format!("tree x\n\nmessage {i}\n");
        let data = signed_data("git", &message_hash(message.as_bytes())).unwrap();
        let (key, sig) = sign("nist256p1", &data);
        let armored = armor(&key, "git", &sig).unwrap();
        assert!(
            openssh_verifies(&key, &armored, message.as_bytes()),
            "message {i}"
        );
    }
}

proptest::proptest! {
    #[test]
    fn key_line_never_panics(s in "\\PC{0,200}") {
        let _ = KeyLine::parse(&s);
    }
}
