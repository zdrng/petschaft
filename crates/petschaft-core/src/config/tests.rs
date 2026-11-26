#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use super::*;
use crate::Proto;
use proptest::prelude::*;

const FP: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

fn err(s: &str) -> String {
    match Config::from_toml_str(s) {
        Err(Error::InvalidConfig(m)) => m,
        other => panic!("expected InvalidConfig for {s:?}, got {other:?}"),
    }
}

fn fp(s: &str) -> Fingerprint {
    Fingerprint::parse(s).unwrap()
}

/// Fingerprints used in config fixtures. They belong to throw-away TEST keys whose
/// Ed25519 seeds are public (`0x11` * 32 and `0x22` * 32, see `docs/testing.md`);
/// `fixture_fingerprints_belong_to_test_keys` checks that, so no real key is referenced.
const TEST_FP_HOMELAB: &str = "SHA256:2HS8bJpYBy7bDfWIQN304coFKT0s6CVPABFLYq+IX5E";
const TEST_FP_GIT: &str = "SHA256:sijgBpZVy7erVIEPkg1iFzd6kBJm7+kWQS9wf+ge734";

#[test]
fn fixture_fingerprints_belong_to_test_keys() {
    for (seed, fp) in [(0x11u8, TEST_FP_HOMELAB), (0x22u8, TEST_FP_GIT)] {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        let mut device = vec![0u8];
        device.extend_from_slice(vk.as_bytes());
        let key = crate::PublicKey::from_device(crate::Curve::Ed25519, &device).unwrap();
        assert_eq!(key.fingerprint().as_str(), fp);
    }
}

/// An existing config from before identity kinds existed must load unchanged.
#[test]
fn existing_user_config_loads_unchanged() {
    let s = r#"
transport = "ble"
[defaults]
passphrase = "ask"
[[identity]]
name = "homelab"
uri = "ssh://user@homelab"
curve = "ed25519"
passphrase = "standard"
fingerprint = "SHA256:2HS8bJpYBy7bDfWIQN304coFKT0s6CVPABFLYq+IX5E"
[[identity]]
name = "git"
uri = "ssh://user@git-signing"
curve = "ed25519"
passphrase = "standard"
fingerprint = "SHA256:sijgBpZVy7erVIEPkg1iFzd6kBJm7+kWQS9wf+ge734"
"#;
    let c = Config::from_toml_str(s).unwrap();
    assert_eq!(c.transport(), Transport::Ble);
    assert_eq!(c.identities().len(), 2);
    for (name, uri, pin) in [
        (
            "homelab",
            "ssh://user@homelab",
            "SHA256:2HS8bJpYBy7bDfWIQN304coFKT0s6CVPABFLYq+IX5E",
        ),
        (
            "git",
            "ssh://user@git-signing",
            "SHA256:sijgBpZVy7erVIEPkg1iFzd6kBJm7+kWQS9wf+ge734",
        ),
    ] {
        let id = c.slip13(name).unwrap();
        assert_eq!(id.name().as_str(), name);
        assert_eq!(id.identity(), &Identity::parse(uri, 0).unwrap());
        assert_eq!(id.curve(), Curve::Ed25519);
        assert_eq!(id.passphrase(), PassphrasePolicy::Standard);
        assert_eq!(id.fingerprint(), Some(&fp(pin)));
        assert_eq!(c.find(name).unwrap().kind(), IdentityKind::Slip13);
    }
}

#[test]
fn empty_config() {
    let c = Config::from_toml_str("").unwrap();
    assert_eq!(c, Config::default());
    assert_eq!(c.transport(), Transport::Auto);
    assert!(c.identities().is_empty());
    assert_eq!(
        Config::from_toml_str("# only a comment\n\n").unwrap(),
        Config::default()
    );
    assert_eq!(
        Config::from_toml_str("[defaults]\n").unwrap(),
        Config::default()
    );
}

#[test]
fn full_example() {
    let s = format!(
        r#"
transport = "ble"

[defaults]
passphrase = "standard"

[[identity]]
name = "homelab"
uri = "ssh://user@homelab"
curve = "ed25519"
index = 0
passphrase = "ask"
fingerprint = "{FP}"

[[identity]]
name = "git-1"
kind = "slip13"
uri = "ssh://git@github.com:22/me"
curve = "nist256p1"
index = 4294967295

[[identity]]
name = "gpg"
uri = "gpg://alice@example.org"
curve = "ed25519"

[[identity]]
name = "sk"
kind = "fido2"
algorithm = "ed25519-sk"
application = "ssh:homelab"
user_verification = false
resident = true
fingerprint = "{FP}"

[[identity]]
name = "sk2"
kind = "fido2"
algorithm = "ecdsa-sk"
"#
    );
    let c = Config::from_toml_str(&s).unwrap();
    assert_eq!(c.transport(), Transport::Ble);
    assert_eq!(c.identities().len(), 5);

    let h = c.slip13("homelab").unwrap();
    assert_eq!(
        h.identity(),
        &Identity::parse("ssh://user@homelab", 0).unwrap()
    );
    assert_eq!(h.curve(), Curve::Ed25519);
    assert_eq!(h.passphrase(), PassphrasePolicy::Ask);
    assert_eq!(h.fingerprint(), Some(&fp(FP)));

    let g = c.slip13("git-1").unwrap();
    assert_eq!(g.identity().index(), u32::MAX);
    assert_eq!(g.identity().port(), Some("22"));
    assert_eq!(g.curve(), Curve::Nist256p1);
    assert_eq!(g.passphrase(), PassphrasePolicy::Standard); // from [defaults]
    assert_eq!(g.fingerprint(), None);

    let p = c.slip13("gpg").unwrap();
    assert_eq!(p.identity().proto(), Proto::Gpg);
    assert_eq!(p.identity().index(), 0);

    let sk = c.fido2("sk").unwrap();
    assert_eq!(sk.algorithm(), SkAlgorithm::Ed25519Sk);
    assert_eq!(sk.application().as_str(), "ssh:homelab");
    assert!(!sk.user_verification());
    assert!(sk.resident());
    assert_eq!(sk.fingerprint(), Some(&fp(FP)));

    // fido2 defaults: derived application, PIN on every use, not resident, no pin
    let sk2 = c.fido2("sk2").unwrap();
    assert_eq!(sk2.algorithm(), SkAlgorithm::EcdsaSk);
    assert_eq!(sk2.application().as_str(), "ssh:sk2");
    assert!(sk2.user_verification());
    assert!(!sk2.resident());
    assert_eq!(sk2.fingerprint(), None);

    assert!(c.find("nope").is_none());
    // order is preserved
    let names: Vec<_> = c.identities().iter().map(|i| i.name().as_str()).collect();
    assert_eq!(names, ["homelab", "git-1", "gpg", "sk", "sk2"]);
    let kinds: Vec<_> = c.identities().iter().map(IdentityConfig::kind).collect();
    assert_eq!(
        kinds,
        [
            IdentityKind::Slip13,
            IdentityKind::Slip13,
            IdentityKind::Slip13,
            IdentityKind::Fido2,
            IdentityKind::Fido2
        ]
    );
}

#[test]
fn kind_accessors_and_errors() {
    let c = Config::from_toml_str(
        "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n\
         [[identity]]\nname = \"b\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n",
    )
    .unwrap();
    assert!(c.slip13("a").is_ok());
    assert!(c.fido2("b").is_ok());
    assert_eq!(
        c.slip13("b"),
        Err(Error::WrongIdentityKind {
            name: Name::parse("b").unwrap(),
            kind: IdentityKind::Fido2
        })
    );
    let msg = c.slip13("b").unwrap_err().to_string();
    assert_eq!(
        msg,
        "identity \"b\" is a fido2 identity; it can only be used over USB via OpenSSH \
         (fido2 support: see `pets fido2`)"
    );
    let msg = c.fido2("a").unwrap_err().to_string();
    assert!(
        msg.starts_with("identity \"a\" is a slip13 identity; "),
        "{msg}"
    );
    for missing in ["c", ""] {
        assert_eq!(
            c.slip13(missing),
            Err(Error::UnknownIdentity(missing.into()))
        );
        assert_eq!(
            c.fido2(missing),
            Err(Error::UnknownIdentity(missing.into()))
        );
    }
    // user input in the message is escaped and bounded
    let msg = c
        .slip13(&format!("x\n\u{1b}[31m{}", "y".repeat(500)))
        .unwrap_err()
        .to_string();
    assert!(!msg.contains('\n') && !msg.contains('\u{1b}'), "{msg}");
    assert!(msg.len() < 200, "{msg}");
}

#[test]
fn defaults_are_secure() {
    let c = Config::from_toml_str(
        "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n\
         [[identity]]\nname = \"b\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n",
    )
    .unwrap();
    assert_eq!(c.transport(), Transport::Auto);
    let a = c.slip13("a").unwrap();
    assert_eq!(a.passphrase(), PassphrasePolicy::Ask);
    assert_eq!(a.identity().index(), 0);
    let b = c.fido2("b").unwrap();
    assert!(b.user_verification());
    assert!(!b.resident());
}

#[test]
fn enum_strings() {
    for (t, s) in [
        (Transport::Auto, "auto"),
        (Transport::Usb, "usb"),
        (Transport::Ble, "ble"),
    ] {
        assert_eq!(t.as_str(), s);
        let c = Config::from_toml_str(&format!("transport = \"{s}\"")).unwrap();
        assert_eq!(c.transport(), t);
    }
    for (p, s) in [
        (PassphrasePolicy::Ask, "ask"),
        (PassphrasePolicy::Standard, "standard"),
    ] {
        assert_eq!(p.as_str(), s);
        let c = Config::from_toml_str(&format!("[defaults]\npassphrase = \"{s}\"\n[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n")).unwrap();
        assert_eq!(c.slip13("a").unwrap().passphrase(), p);
    }
    for (k, s) in [
        (IdentityKind::Slip13, "slip13"),
        (IdentityKind::Fido2, "fido2"),
    ] {
        assert_eq!(k.as_str(), s);
        assert_eq!(k.to_string(), s);
    }
}

/// Deeply nested values must not overflow the stack (the parser has a nesting limit).
#[test]
fn deep_nesting_is_an_error() {
    for depth in [1_000usize, 100_000] {
        let arrays = format!("transport = {}{}", "[".repeat(depth), "]".repeat(depth));
        let _ = err(&arrays);
        let tables = format!("transport = {}1{}", "{a=".repeat(depth), "}".repeat(depth));
        let _ = err(&tables);
        // `transport` inside an identity accepts any value type: still bounded
        let nested = format!(
            "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\ntransport = {}{}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let _ = err(&nested);
    }
}

#[test]
fn truncate_messages() {
    assert_eq!(truncate("abc", 3), "abc");
    assert_eq!(truncate("abcd", 3), "abc…");
    assert_eq!(truncate("\u{e4}\u{e4}\u{e4}", 2), "\u{e4}\u{e4}…");
    let long = format!("index = \"{}\"", "x".repeat(1000));
    let s = format!("[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n{long}");
    assert!(err(&s).chars().count() < 260);
    // the unknown-field message lists all expected keys and is still bounded
    let s = "[[identity]]\nname = \"a\"\nbogus = 1\n";
    assert!(err(s).chars().count() < 260);
}

#[test]
fn rejects() {
    let id = |extra: &str| {
        format!("[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n{extra}")
    };
    let sk = |extra: &str| {
        format!("[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n{extra}")
    };
    let cases: Vec<String> = vec![
        // unknown keys at every level
        "transprot = \"usb\"".into(),
        "[defaults]\npassphrase = \"ask\"\nextra = 1".into(),
        "[default]\npassphrase = \"ask\"".into(),
        id("fingerprnt = \"x\""),
        sk("aplication = \"ssh:x\""),
        "[identity]\nname = \"a\"".into(), // table instead of array of tables
        // bad enum values / types
        "transport = \"USB\"".into(),
        "transport = \"wifi\"".into(),
        "transport = 1".into(),
        "[defaults]\npassphrase = \"none\"".into(),
        "[defaults]\npassphrase = \"\"".into(),
        id("passphrase = \"Standard\""),
        id("index = -1"),
        id("index = 4294967296"),
        id("index = \"0\""),
        id("index = 1.0"),
        id("kind = \"SLIP13\""),
        id("kind = \"\""),
        id("kind = \"fido\""),
        id("kind = 1"),
        sk("user_verification = \"yes\""),
        sk("user_verification = 1"),
        sk("resident = \"false\""),
        // missing required fields
        "[[identity]]\nuri = \"ssh://h\"\ncurve = \"ed25519\"".into(),
        "[[identity]]\nname = \"a\"\ncurve = \"ed25519\"".into(),
        "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"".into(),
        "[[identity]]\nname = \"a\"\nkind = \"fido2\"".into(),
        "[[identity]]\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"".into(),
        // invalid values
        "[[identity]]\nname = \"a\"\nuri = \"https://h\"\ncurve = \"ed25519\"".into(),
        "[[identity]]\nname = \"a\"\nuri = \"ssh://@h\"\ncurve = \"ed25519\"".into(),
        "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"secp256k1\"".into(),
        id("fingerprint = \"SHA256:abc\""),
        id(&format!("fingerprint = \"{FP}=\"")),
        id(&format!("fingerprint = \"{}\"", FP.to_lowercase())),
        sk(&format!("fingerprint = \"{FP} \"")),
        "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519\"".into(),
        "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"rsa-sk\"".into(),
        sk("application = \"petschaft\""),
        sk("application = \"ssh:\""),
        sk("application = \"ssh:A\""),
        sk(&format!("application = \"ssh:{}\"", "a".repeat(61))),
        // transport is never per identity
        id("transport = \"usb\""),
        sk("transport = \"usb\""),
        // syntax error
        "transport = ".into(),
    ];
    for c in &cases {
        let _ = err(c);
    }
}

// --- public_key / host_keys (agent) ---

/// Throw-away test key: ed25519 from seed `[seed; 32]`, or P-256 from scalar
/// `0x01 || [seed; 31]` (see `docs/testing.md`).
fn test_key(curve: crate::Curve, seed: u8) -> crate::PublicKey {
    let device = match curve {
        crate::Curve::Ed25519 => {
            let vk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
            [&[0u8][..], vk.as_bytes()].concat()
        }
        crate::Curve::Nist256p1 => {
            let mut b = [seed; 32];
            b[0] = 0x01;
            let sk = p256::ecdsa::SigningKey::from_slice(&b).unwrap();
            sk.verifying_key().to_sec1_point(true).as_bytes().to_vec()
        }
    };
    crate::PublicKey::from_device(curve, &device).unwrap()
}

fn agent_identity(extra: &str) -> String {
    format!("[[identity]]\nname = \"a\"\nuri = \"ssh://user@h\"\ncurve = \"ed25519\"\n{extra}")
}

#[test]
fn public_key_and_host_keys() {
    let key = test_key(crate::Curve::Ed25519, 0x11);
    let line = key.openssh_line("any comment");
    let host = fp(TEST_FP_GIT);
    let c = Config::from_toml_str(&agent_identity(&format!(
        "public_key = \"{line}\"\nhost_keys = [\"{TEST_FP_GIT}\", \"{FP}\"]\n"
    )))
    .unwrap();
    let id = c.slip13("a").unwrap();
    assert_eq!(id.public_key(), Some(&key));
    // the pin is derived from public_key
    assert_eq!(id.fingerprint(), Some(&fp(TEST_FP_HOMELAB)));
    assert_eq!(id.host_keys(), &[host, fp(FP)]);
    // the config comment, not the key line's, stays the effective comment
    assert_eq!(id.comment().as_str(), "hwkey:a");

    // matching fingerprint is accepted
    let c = Config::from_toml_str(&agent_identity(&format!(
        "public_key = \"{line}\"\nfingerprint = \"{TEST_FP_HOMELAB}\"\n"
    )))
    .unwrap();
    let id = c.slip13("a").unwrap();
    assert_eq!(id.fingerprint(), Some(&fp(TEST_FP_HOMELAB)));
    assert!(id.host_keys().is_empty());

    // nothing configured: no key, no host keys
    let c = Config::from_toml_str(&agent_identity("")).unwrap();
    let id = c.slip13("a").unwrap();
    assert_eq!(id.public_key(), None);
    assert!(id.host_keys().is_empty());

    // a nist256p1 identity takes an ecdsa key
    let p = test_key(crate::Curve::Nist256p1, 3);
    let s = format!(
        "[[identity]]\nname = \"p\"\nuri = \"ssh://h\"\ncurve = \"nist256p1\"\npublic_key = \"{}\"\n",
        p.openssh_line("")
    );
    let c = Config::from_toml_str(&s).unwrap();
    assert_eq!(c.slip13("p").unwrap().public_key(), Some(&p));
}

/// Software key `test_key(Nist256p1, seed)` and the APK certificate `pets apk init`
/// would write for it (base64 DER).
fn test_certificate(seed: u8, cn: &str) -> (petschaft_apk::Certificate, String) {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    let mut b = [seed; 32];
    b[0] = 0x01;
    let sk = p256::ecdsa::SigningKey::from_slice(&b).unwrap();
    let point: [u8; 65] = sk
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let tbs = petschaft_apk::Certificate::build(&point, cn).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign_prehash(&tbs.digest()).unwrap();
    let cert = tbs.finish(&sig.to_der().to_bytes()).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(cert.der());
    (cert, b64)
}

fn apk_identity(uri: &str, curve: &str, extra: &str) -> String {
    format!("[[identity]]\nname = \"apk\"\nuri = \"{uri}\"\ncurve = \"{curve}\"\n{extra}")
}

#[test]
fn certificate() {
    let (cert, b64) = test_certificate(5, "Release");
    let key = test_key(crate::Curve::Nist256p1, 5);
    let ok = |extra: &str| {
        Config::from_toml_str(&apk_identity("gpg://apk@release", "nist256p1", extra)).unwrap()
    };
    // Without a pin (the certificate is validated on its own) ...
    let c = ok(&format!("certificate = \"{b64}\"\n"));
    let id = c.slip13("apk").unwrap();
    assert_eq!(id.certificate(), Some(&cert));
    assert_eq!(id.certificate().unwrap().subject_cn(), "Release");
    assert_eq!(id.fingerprint(), None);
    // ... with a matching fingerprint, or a matching public_key.
    let c = ok(&format!(
        "certificate = \"{b64}\"\nfingerprint = \"{}\"\n",
        key.fingerprint()
    ));
    assert_eq!(c.slip13("apk").unwrap().certificate(), Some(&cert));
    let c = ok(&format!(
        "certificate = \"{b64}\"\npublic_key = \"{}\"\n",
        key.openssh_line("")
    ));
    assert_eq!(c.slip13("apk").unwrap().certificate(), Some(&cert));
    // No certificate configured.
    assert_eq!(ok("").slip13("apk").unwrap().certificate(), None);
}

#[test]
fn certificate_rejects() {
    let (_, b64) = test_certificate(5, "Release");
    let other = test_key(crate::Curve::Nist256p1, 6);
    let cert = format!("certificate = \"{b64}\"\n");
    let gpg = |extra: &str| err(&apk_identity("gpg://apk@release", "nist256p1", extra));

    for (uri, curve) in [
        ("ssh://apk@release", "nist256p1"),
        ("gpg://apk@release", "ed25519"),
        ("ssh://apk@release", "ed25519"),
    ] {
        let m = err(&apk_identity(uri, curve, &cert));
        assert_eq!(
            m,
            "identity \"apk\": certificate (APK signing) requires a gpg:// uri and curve = \"nist256p1\"",
            "{uri} {curve}"
        );
    }
    // A pin or public_key of another key.
    let m = gpg(&format!(
        "{cert}fingerprint = \"{}\"\n",
        other.fingerprint()
    ));
    assert_eq!(
        m,
        "identity \"apk\": certificate is for a different key than fingerprint / public_key"
    );
    let m = gpg(&format!(
        "{cert}public_key = \"{}\"\n",
        other.openssh_line("")
    ));
    assert!(m.contains("certificate is for a different key"), "{m}");
    // Not base64, non-canonical base64, not a petschaft certificate, too long.
    let m = gpg("certificate = \"not base64!\"\n");
    assert!(m.contains("certificate is not valid base64"), "{m}");
    let m = gpg(&format!(
        "certificate = \"{}\"\n",
        b64.trim_end_matches('=')
    ));
    assert!(m.contains("certificate is not valid base64"), "{m}");
    let m = gpg("certificate = \"MAA=\"\n");
    assert!(
        m.starts_with("identity \"apk\": certificate is not one written by `pets apk init` (invalid certificate"),
        "{m}"
    );
    let mut der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .unwrap();
    let last = der.len() - 1;
    der[last] ^= 1;
    let m = gpg(&format!(
        "certificate = \"{}\"\n",
        base64::engine::general_purpose::STANDARD.encode(&der)
    ));
    assert!(
        m.contains("certificate is not one written by `pets apk init`"),
        "{m}"
    );
    let m = gpg(&format!("certificate = \"{}\"\n", "A".repeat(4100)));
    assert_eq!(m, "identity \"apk\": certificate is too long");
    // Wrong type, and not allowed in a fido2 identity.
    let m = gpg("certificate = 1\n");
    assert!(m.contains("invalid type"), "{m}");
    let m = err(&format!(
        "[[identity]]\nname = \"sk\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n{cert}"
    ));
    assert!(
        m.contains("certificate not allowed for a fido2 identity"),
        "{m}"
    );
    // The message never quotes the value.
    assert!(!gpg("certificate = \"QUJD\"\n").contains("QUJD"));
}

#[test]
fn public_key_and_host_keys_rejects() {
    let line = test_key(crate::Curve::Ed25519, 0x11).openssh_line("");
    let p_line = test_key(crate::Curve::Nist256p1, 3).openssh_line("");
    let pk = format!("public_key = \"{line}\"\n");
    let cases: Vec<(String, &str)> = vec![
        (
            agent_identity("public_key = \"ssh-ed25519 AAAA\""),
            "public_key must be an OpenSSH",
        ),
        (
            agent_identity("public_key = \"\""),
            "public_key must be an OpenSSH",
        ),
        (agent_identity("public_key = 1"), "invalid type"),
        (
            agent_identity(&format!("public_key = \"{p_line}\"")),
            "but curve is ed25519",
        ),
        (
            agent_identity(&format!("{pk}fingerprint = \"{TEST_FP_GIT}\"")),
            "fingerprint does not match public_key",
        ),
        (
            agent_identity(&format!("{pk}host_keys = []")),
            "host_keys must not be empty",
        ),
        (
            agent_identity(&format!("{pk}host_keys = \"{FP}\"")),
            "invalid type",
        ),
        (
            agent_identity(&format!("{pk}host_keys = [1]")),
            "invalid type",
        ),
        (
            agent_identity(&format!("{pk}host_keys = [\"SHA256:x\"]")),
            "host_keys #1: fingerprint must be",
        ),
        (
            agent_identity(&format!(
                "{pk}host_keys = [\"{FP}\", \"{TEST_FP_GIT}\", \"{FP}\"]"
            )),
            "host_keys #3: duplicate",
        ),
        (
            agent_identity(&format!(
                "{pk}host_keys = [{}]",
                vec![format!("\"{FP}\""); 65].join(", ")
            )),
            "more than 64",
        ),
        (
            agent_identity(&format!("host_keys = [\"{FP}\"]")),
            "host_keys requires public_key",
        ),
        (
            format!(
                "[[identity]]\nname = \"a\"\nuri = \"gpg://h\"\ncurve = \"ed25519\"\n{pk}host_keys = [\"{FP}\"]\n"
            ),
            "host_keys requires an ssh:// uri",
        ),
        (
            format!(
                "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n{pk}"
            ),
            "public_key not allowed for a fido2 identity",
        ),
        (
            format!(
                "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\nhost_keys = [\"{FP}\"]\n"
            ),
            "host_keys not allowed for a fido2 identity",
        ),
    ];
    for (c, want) in &cases {
        let m = err(c);
        assert!(m.contains(want), "{m:?} lacks {want:?} for\n{c}");
        // errors never quote the key material
        assert!(!m.contains("AAAA"), "{m}");
    }
}

#[test]
fn duplicate_slip13_keys() {
    let line = test_key(crate::Curve::Ed25519, 0x11).openssh_line("");
    let ident = |name: &str, extra: &str| {
        format!(
            "[[identity]]\nname = \"{name}\"\nuri = \"ssh://user@{name}\"\ncurve = \"ed25519\"\n{extra}\n"
        )
    };
    let pk = format!("public_key = \"{line}\"");
    let pin = format!("fingerprint = \"{TEST_FP_HOMELAB}\"");
    // same public_key, same fingerprint, or one of each for the same key
    for (a, b) in [(&pk, &pk), (&pin, &pin), (&pk, &pin), (&pin, &pk)] {
        let m = err(&format!("{}{}", ident("first", a), ident("second", b)));
        assert!(
            m.contains("identity \"second\"") && m.contains("identity \"first\""),
            "{m}"
        );
        assert!(m.contains("same key"), "{m}");
        assert!(!m.contains("AAAA") && !m.contains("SHA256"), "{m}");
    }
    // different keys, unpinned identities and a fido2 pin on the same fingerprint are fine
    let other = format!("fingerprint = \"{TEST_FP_GIT}\"");
    let fido = format!(
        "[[identity]]\nname = \"f\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n{pin}\n"
    );
    let ok = format!(
        "{}{}{}{}{fido}",
        ident("a", &pk),
        ident("b", &other),
        ident("c", ""),
        ident("d", "")
    );
    assert_eq!(Config::from_toml_str(&ok).unwrap().identities().len(), 5);
}

#[test]
fn kind_mismatch_messages() {
    let m = err(
        "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n",
    );
    assert_eq!(
        m,
        "identity \"a\": uri, curve not allowed for a fido2 identity \
         (fido2 identities are only used over USB via OpenSSH)"
    );
    let m = err(
        "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\nalgorithm = \"ed25519-sk\"\n",
    );
    assert_eq!(
        m,
        "identity \"a\": algorithm not allowed for a slip13 identity \
         (for a FIDO2 key set kind = \"fido2\")"
    );
    let m = err(
        "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\ntransport = \"ble\"\n",
    );
    assert!(m.contains("transport is not allowed"), "{m}");
    let m = err(
        "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\ntransport = \"usb\"\n",
    );
    assert!(
        m.contains("transport not allowed for a fido2 identity"),
        "{m}"
    );
    // missing required keys are named
    assert!(err("[[identity]]\nname = \"a\"\nkind = \"fido2\"\n").contains("missing algorithm"));
    assert!(err("[[identity]]\nname = \"a\"\ncurve = \"ed25519\"\n").contains("missing uri"));
}

#[test]
fn names() {
    let with_name =
        |n: &str| format!("[[identity]]\nname = \"{n}\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n");
    for ok in ["a", "0", "a-", "a-b-1", &"z".repeat(32)] {
        Config::from_toml_str(&with_name(ok)).unwrap();
        assert_eq!(Name::parse(ok).unwrap().as_str(), ok);
    }
    for bad in [
        "",
        "A",
        "a_b",
        "a b",
        "a.b",
        "\u{e4}",
        &"a".repeat(33),
        "a\\n",
        "-",
        "-a",
    ] {
        let _ = err(&with_name(bad));
    }
    // duplicates, also across kinds
    let dup = format!("{}{}", with_name("x"), with_name("x"));
    assert!(err(&dup).contains("duplicate"));
    let fido = "[[identity]]\nname = \"x\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n";
    assert!(err(&format!("{}{fido}", with_name("x"))).contains("duplicate"));
    assert!(err(&format!("{fido}{}", with_name("x"))).contains("duplicate"));
}

#[test]
fn duplicate_applications() {
    // explicit vs. derived default
    let s = "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n\
             [[identity]]\nname = \"b\"\nkind = \"fido2\"\nalgorithm = \"ecdsa-sk\"\napplication = \"ssh:a\"\n";
    assert_eq!(
        err(s),
        "identity \"b\": application is already used by identity \"a\""
    );
    // the same application string in a slip13 context does not exist; different ones are fine
    let s = "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n\
             [[identity]]\nname = \"b\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\napplication = \"ssh:c\"\n";
    Config::from_toml_str(s).unwrap();
}

#[test]
fn error_does_not_echo_contents() {
    let marker = "SECRETMARKER-ZZZ";
    let slip = "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n";
    let fido = "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n";
    for (s, line) in [
        (format!("# {marker}\ntransport = \"{marker}\""), None),
        (format!("# {marker}\n{slip}passphrase = \"{marker}\""), None),
        (format!("# {marker}\n{slip}kind = \"{marker}\""), None),
        (
            format!("# {marker}\n{slip}fingerprint = \"{marker}\""),
            None,
        ),
        (
            format!("# {marker}\n{fido}application = \"{marker}\""),
            None,
        ),
        (
            format!("# {marker}\n{fido}fingerprint = \"{marker}\""),
            None,
        ),
        (format!("# {marker}\n{fido}uri = \"{marker}\""), None),
        (format!("# {marker}\n{slip}algorithm = \"{marker}\""), None),
        (format!("# {marker}\n{slip}transport = \"{marker}\""), None),
        (
            format!(
                "# {marker}\n[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"{marker}\""
            ),
            None,
        ),
        (format!("# {marker}\nunknown_{marker} = 1"), Some(2)),
        (format!("# {marker}\n{slip}bogus = \"{marker}\""), Some(6)),
    ] {
        let m = err(&s);
        // the offending *key* may be named, never a value, comment or source line
        assert!(!m.contains(&format!("\"{marker}\"")), "{m}");
        assert!(!m.contains(&format!("`{marker}`")), "{m}");
        assert!(!m.contains(&format!("# {marker}")), "{m}");
        assert!(!m.contains(&format!("{marker}\n")), "{m}");
        assert!(!m.contains('\n'), "{m}");
        if line.is_none() {
            assert!(!m.contains(marker), "{m}");
        }
        if let Some(line) = line {
            assert!(m.starts_with(&format!("line {line}, column 1: ")), "{m}");
        }
    }
}

#[test]
fn user_dir_rules() {
    let os = |s: &str| Some(OsString::from(s));
    assert_eq!(
        user_dir_from(os("/xdg"), os("/home/u")),
        Some(PathBuf::from("/xdg/petschaft"))
    );
    assert_eq!(
        user_dir_from(None, os("/home/u")),
        Some(PathBuf::from("/home/u/.config/petschaft"))
    );
    // relative / empty XDG falls back to HOME
    assert_eq!(
        user_dir_from(os("rel/xdg"), os("/home/u")),
        Some(PathBuf::from("/home/u/.config/petschaft"))
    );
    assert_eq!(
        user_dir_from(os(""), os("/home/u")),
        Some(PathBuf::from("/home/u/.config/petschaft"))
    );
    assert_eq!(user_dir_from(None, os("relative")), None);
    assert_eq!(user_dir_from(os(""), os("")), None);
    assert_eq!(user_dir_from(None, None), None);
    // the real ones are either None or absolute (computed only, never read)
    if let Some(d) = Config::user_dir() {
        assert!(d.is_absolute());
        assert!(d.ends_with("petschaft"));
        assert_eq!(Config::user_path(), Some(d.join("config.toml")));
    }
    assert_eq!(SYSTEM_CONFIG_PATH, "/etc/petschaft/config.toml");
    assert!(Path::new(SYSTEM_CONFIG_PATH).is_absolute());
}

#[test]
fn owner_and_comments() {
    let s = r#"
owner = "user_1"
[[identity]]
name = "git"
uri = "ssh://user@git-signing"
curve = "ed25519"
[[identity]]
name = "work"
uri = "ssh://user@work"
curve = "ed25519"
comment = "Demo - Büro (Trezör) #2"
[[identity]]
name = "homelab"
kind = "fido2"
algorithm = "ed25519-sk"
[[identity]]
name = "sk"
kind = "fido2"
algorithm = "ecdsa-sk"
comment = "a"
"#;
    let c = Config::from_toml_str(s).unwrap();
    let comment = |n: &str| c.find(n).unwrap().comment().as_str().to_owned();
    assert_eq!(comment("git"), "user_1@hwkey:git");
    assert_eq!(
        c.slip13("git").unwrap().comment().as_str(),
        "user_1@hwkey:git"
    );
    assert_eq!(comment("work"), "Demo - Büro (Trezör) #2");
    assert_eq!(comment("homelab"), "user_1@hwkey:homelab");
    assert_eq!(
        c.fido2("homelab").unwrap().comment().as_str(),
        "user_1@hwkey:homelab"
    );
    assert_eq!(comment("sk"), "a");

    // without owner
    let c = Config::from_toml_str(
        "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\n\
         [[identity]]\nname = \"b\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\n",
    )
    .unwrap();
    assert_eq!(c.find("a").unwrap().comment().as_str(), "hwkey:a");
    assert_eq!(c.find("b").unwrap().comment().as_str(), "hwkey:b");
    // an owner alone is a valid config
    assert_eq!(
        Config::from_toml_str("owner = \"x\"").unwrap().identities(),
        &[]
    );
}

#[test]
fn owner_and_comment_rejects() {
    let slip = |c: &str| {
        format!(
            "[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\ncomment = {c}\n"
        )
    };
    let fido = |c: &str| {
        format!(
            "[[identity]]\nname = \"a\"\nkind = \"fido2\"\nalgorithm = \"ed25519-sk\"\ncomment = {c}\n"
        )
    };
    for bad in [
        "\"\"",
        "\" a\"",
        "\"a \"",
        "\" \"",
        "\"a\\nb\"",
        "\"a\\tb\"",
        "\"a\\u001b[31mb\"",
        "\"a\\u202Eb\"",
        "\"a\\u200Bb\"",
        "\"a\\u00A0b\"",
        "\"\\U0001F511 key\"",
        // non-ASCII punctuation and symbols (no Unicode category tables: letters and
        // digits only)
        "\"a \\u2013 b\"",
        "\"5 \\u20AC\"",
        &format!("\"{}\"", "x".repeat(129)),
        "1",
        "true",
        "[]",
    ] {
        for s in [slip(bad), fido(bad)] {
            let m = err(&s);
            if bad.starts_with('"') {
                assert!(
                    m.starts_with("identity \"a\": comment must be"),
                    "{bad}: {m}"
                );
            }
        }
    }
    // the limit is in characters, not bytes
    Config::from_toml_str(&slip(&format!("\"{}\"", "\u{e4}".repeat(128)))).unwrap();
    for bad in [
        "\"\"",
        "\"-demo\"",
        "\"Demo\"",
        "\"a b\"",
        "\"a.b\"",
        "\"a@b\"",
        "\"\u{e4}\"",
        &format!("\"{}\"", "a".repeat(33)),
        "1",
    ] {
        let m = err(&format!("owner = {bad}\n"));
        if bad.starts_with('"') {
            assert!(m.starts_with("owner must be"), "{bad}: {m}");
        }
    }
    // never per identity, never in [defaults]
    let _ =
        err("[[identity]]\nname = \"a\"\nuri = \"ssh://h\"\ncurve = \"ed25519\"\nowner = \"x\"\n");
    let _ = err("[defaults]\nowner = \"x\"\n");
    let _ = err("[defaults]\ncomment = \"x\"\n");
    // values are never echoed
    let m = err(&slip("\"SECRETMARKER\\n\""));
    assert!(!m.contains("SECRETMARKER"), "{m}");
    let m = err("owner = \"SECRETMARKER\"\n");
    assert!(!m.contains("SECRETMARKER"), "{m}");
}

#[test]
fn line_col_positions() {
    assert_eq!(line_col("abc", 0), (1, 1));
    assert_eq!(line_col("abc\ndef", 5), (2, 2));
    assert_eq!(line_col("\u{e4}x\ny", 2), (1, 2));
    assert_eq!(line_col("abc", 100), (1, 4));
    // offset inside a multi-byte char does not panic
    let _ = line_col("\u{e4}", 1);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn write(dir: &tempfile::TempDir, content: &str, mode: u32) -> PathBuf {
        let p = dir.path().join("config.toml");
        // the previous file may be read-only
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    const OK: &str = "transport = \"usb\"\n";

    #[test]
    fn load_ok_modes() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o644, 0o400, 0o755] {
            let p = write(&dir, OK, mode);
            assert_eq!(
                Config::load(&p).unwrap().transport(),
                Transport::Usb,
                "{mode:o}"
            );
        }
    }

    #[test]
    fn load_rejects_writable_by_others() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o620, 0o602, 0o666, 0o622, 0o660, 0o777] {
            let p = write(&dir, OK, mode);
            match Config::load(&p) {
                Err(Error::InvalidConfig(m)) => {
                    assert!(m.contains("writable by group or others"), "{m}");
                    assert!(!m.contains("usb"), "{m}");
                }
                other => panic!("mode {mode:o}: {other:?}"),
            }
        }
    }

    #[test]
    fn current_uid_is_the_owner_of_our_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, OK, 0o600);
        assert_eq!(current_uid().unwrap(), std::fs::metadata(&p).unwrap().uid());
    }

    #[test]
    fn only_the_user_or_root_may_own_the_config() {
        let me = 1000;
        assert_eq!(untrusted(me, 0o644, me, false), None);
        // root-owned, read-only: the NixOS / nix-darwin module's file in /nix/store
        assert_eq!(untrusted(0, 0o444, me, false), None);
        assert_eq!(untrusted(0, 0o555, me, true), None);
        // /nix/store itself: root, group-writable but sticky
        assert_eq!(untrusted(0, 0o1775, me, true), None);
        assert_eq!(untrusted(1001, 0o644, me, false), Some(Untrusted::Owner));
        assert_eq!(untrusted(1001, 0o755, me, true), Some(Untrusted::Owner));
        assert_eq!(untrusted(me, 0o664, me, false), Some(Untrusted::Writable));
        assert_eq!(untrusted(me, 0o775, me, true), Some(Untrusted::Writable));
        assert_eq!(untrusted(me, 0o757, me, true), Some(Untrusted::Writable));
        // sticky helps only a directory
        assert_eq!(untrusted(me, 0o1666, me, false), Some(Untrusted::Writable));
    }

    #[test]
    fn load_checks_the_directory_of_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let p = shared.join("config.toml");
        std::fs::write(&p, OK).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        for mode in [0o775, 0o757, 0o777] {
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).unwrap();
            for path in [&p, &link] {
                match Config::load(path) {
                    Err(Error::InvalidConfig(m)) => {
                        assert!(m.contains("(the directory of"), "{m}");
                        assert!(m.contains("writable by group or others"), "{m}");
                    }
                    other => panic!("mode {mode:o}: {other:?}"),
                }
            }
        }
        // sticky (like /nix/store, 1775) or private: fine
        for mode in [0o1777, 0o1775, 0o755, 0o700] {
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).unwrap();
            for path in [&p, &link] {
                assert_eq!(
                    Config::load(path).unwrap().transport(),
                    Transport::Usb,
                    "{mode:o}"
                );
            }
        }
    }

    #[test]
    fn load_errors() {
        let dir = tempfile::tempdir().unwrap();
        // missing file -> Io
        let missing = dir.path().join("nope.toml");
        assert!(matches!(Config::load(&missing), Err(Error::Io(_))));
        // directory -> Io
        assert!(matches!(Config::load(dir.path()), Err(Error::Io(_))));
        // invalid UTF-8
        let p = dir.path().join("bin.toml");
        std::fs::write(&p, b"transport = \"\xff\"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(Config::load(&p), Err(Error::InvalidConfig(_))));
        // invalid content: message names the file, not its contents
        let p = write(&dir, "transport = \"secretvalue\"\n", 0o600);
        match Config::load(&p) {
            Err(Error::InvalidConfig(m)) => {
                assert!(m.contains("config.toml"), "{m}");
                assert!(!m.contains("secretvalue"), "{m}");
            }
            other => panic!("{other:?}"),
        }
        // too large
        let big = format!("# {}\n", "x".repeat(1024 * 1024));
        let p = write(&dir, &big, 0o600);
        assert!(matches!(Config::load(&p), Err(Error::InvalidConfig(_))));
        // empty file is a valid, empty config
        let p = write(&dir, "", 0o600);
        assert_eq!(Config::load(&p).unwrap(), Config::default());
    }

    /// Like the NixOS module's `/etc/petschaft/config.toml`: a chain of symlinks to a
    /// read-only file. The final file's mode is what counts.
    #[test]
    fn load_follows_symlink_chain() {
        let dir = tempfile::tempdir().unwrap();
        let target = write(&dir, OK, 0o444);
        let mid = dir.path().join("mid.toml");
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &mid).unwrap();
        std::os::unix::fs::symlink(&mid, &link).unwrap();
        assert_eq!(Config::load(&link).unwrap().transport(), Transport::Usb);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(matches!(Config::load(&link), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn locate_prefers_user_then_system() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user").join("config.toml");
        let system = dir.path().join("etc").join("config.toml");
        let none = || match locate_in(Some(user.clone()), &system) {
            Err(Error::ConfigNotFound(m)) => m,
            other => panic!("{other:?}"),
        };
        // neither: the error names both paths
        let m = none();
        assert!(m.contains(&user.display().to_string()), "{m}");
        assert!(m.contains(&system.display().to_string()), "{m}");
        let m = match locate_in(None, &system) {
            Err(Error::ConfigNotFound(m)) => m,
            other => panic!("{other:?}"),
        };
        assert!(m.contains(&system.display().to_string()), "{m}");
        assert!(m.contains("HOME"), "{m}");

        // only the system one (e.g. a symlink into the Nix store)
        std::fs::create_dir_all(system.parent().unwrap()).unwrap();
        let store = dir.path().join("store-config.toml");
        std::fs::write(&store, OK).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::os::unix::fs::symlink(&store, &system).unwrap();
        assert_eq!(locate_in(Some(user.clone()), &system).unwrap(), system);
        assert_eq!(locate_in(None, &system).unwrap(), system);
        assert_eq!(Config::load(&system).unwrap().transport(), Transport::Usb);
        // the user directory existing without a config.toml (e.g. only fido2/) still
        // falls back
        std::fs::create_dir_all(user.parent().unwrap().join("fido2")).unwrap();
        assert_eq!(locate_in(Some(user.clone()), &system).unwrap(), system);

        // a per-user file wins
        std::fs::write(&user, "").unwrap();
        assert_eq!(locate_in(Some(user.clone()), &system).unwrap(), user);
        // ... even when it is broken: no silent fallback to the system config
        std::fs::remove_file(&user).unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing"), &user).unwrap();
        assert_eq!(locate_in(Some(user.clone()), &system).unwrap(), user);
        assert!(matches!(Config::load(&user), Err(Error::Io(_))));
    }

    /// A path that cannot be checked (a parent is a file) is an error, not "absent".
    #[test]
    fn locate_does_not_fall_back_on_errors() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        let system = dir.path().join("system.toml");
        std::fs::write(&system, OK).unwrap();
        assert!(matches!(
            locate_in(Some(file.join("config.toml")), &system),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn load_follows_symlink_and_checks_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = write(&dir, OK, 0o666);
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(Config::load(&link), Err(Error::InvalidConfig(_))));
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(Config::load(&link).unwrap().transport(), Transport::Usb);
    }
}

// ---------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------

/// A valid identity table without its name, as the generator produces it.
#[derive(Debug, Clone)]
enum Spec {
    Slip13 {
        explicit_kind: bool,
        uri: String,
        curve: &'static str,
        index: Option<u32>,
        passphrase: Option<&'static str>,
        fingerprint: Option<String>,
    },
    Fido2 {
        algorithm: &'static str,
        application: Option<String>,
        user_verification: Option<bool>,
        resident: Option<bool>,
        fingerprint: Option<String>,
    },
}

fn fingerprint_strategy() -> impl Strategy<Value = String> {
    any::<[u8; 32]>().prop_map(|d| {
        format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(d)
        )
    })
}

fn slip13_spec() -> impl Strategy<Value = Spec> {
    (
        any::<bool>(),
        "(ssh|gpg)://([a-z0-9]{1,8}@)?[a-z0-9.-]{1,12}(:[0-9]{1,5})?(/[a-z0-9/.-]{0,10})?",
        prop::sample::select(vec!["ed25519", "nist256p1"]),
        prop::option::of(any::<u32>()),
        prop::option::of(prop::sample::select(vec!["ask", "standard"])),
        prop::option::of(fingerprint_strategy()),
    )
        .prop_map(
            |(explicit_kind, uri, curve, index, passphrase, fingerprint)| Spec::Slip13 {
                explicit_kind,
                uri,
                curve,
                index,
                passphrase,
                fingerprint,
            },
        )
}

fn fido2_spec() -> impl Strategy<Value = Spec> {
    (
        prop::sample::select(vec!["ed25519-sk", "ecdsa-sk"]),
        prop::option::of("ssh:[a-z0-9.-]{1,60}"),
        prop::option::of(any::<bool>()),
        prop::option::of(any::<bool>()),
        prop::option::of(fingerprint_strategy()),
    )
        .prop_map(
            |(algorithm, application, user_verification, resident, fingerprint)| Spec::Fido2 {
                algorithm,
                application,
                user_verification,
                resident,
                fingerprint,
            },
        )
}

fn spec() -> impl Strategy<Value = Spec> {
    prop_oneof![slip13_spec(), fido2_spec()]
}

/// The key lines of an identity table (without the `[[identity]]` header).
fn lines(name: &str, spec: &Spec) -> Vec<String> {
    let mut l = vec![format!("name = \"{name}\"")];
    match spec {
        Spec::Slip13 {
            explicit_kind,
            uri,
            curve,
            index,
            passphrase,
            fingerprint,
        } => {
            if *explicit_kind {
                l.push("kind = \"slip13\"".into());
            }
            l.push(format!("uri = \"{uri}\""));
            l.push(format!("curve = \"{curve}\""));
            if let Some(i) = index {
                l.push(format!("index = {i}"));
            }
            if let Some(p) = passphrase {
                l.push(format!("passphrase = \"{p}\""));
            }
            if let Some(f) = fingerprint {
                l.push(format!("fingerprint = \"{f}\""));
            }
        }
        Spec::Fido2 {
            algorithm,
            application,
            user_verification,
            resident,
            fingerprint,
        } => {
            l.push("kind = \"fido2\"".into());
            l.push(format!("algorithm = \"{algorithm}\""));
            if let Some(a) = application {
                l.push(format!("application = \"{a}\""));
            }
            if let Some(v) = user_verification {
                l.push(format!("user_verification = {v}"));
            }
            if let Some(r) = resident {
                l.push(format!("resident = {r}"));
            }
            if let Some(f) = fingerprint {
                l.push(format!("fingerprint = \"{f}\""));
            }
        }
    }
    l
}

/// Render one table; `rot` rotates the key order (TOML tables are unordered).
fn table(lines: &[String], rot: usize) -> String {
    let mut l = lines.to_vec();
    if !l.is_empty() {
        let n = rot % l.len();
        l.rotate_left(n);
    }
    format!("[[identity]]\n{}\n", l.join("\n"))
}

fn expected_application(name: &str, spec: &Spec) -> Option<String> {
    match spec {
        Spec::Fido2 { application, .. } => {
            Some(application.clone().unwrap_or_else(|| format!("ssh:{name}")))
        }
        Spec::Slip13 { .. } => None,
    }
}

/// Assert that `id` carries exactly the fields of `spec` (defaults resolved).
fn assert_matches(
    id: &IdentityConfig,
    name: &str,
    spec: &Spec,
    default_pass: Option<&str>,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(id.name().as_str(), name);
    match (id, spec) {
        (
            IdentityConfig::Slip13(i),
            Spec::Slip13 {
                uri,
                curve,
                index,
                passphrase,
                fingerprint,
                ..
            },
        ) => {
            prop_assert_eq!(i.identity().to_uri(), uri.clone());
            prop_assert_eq!(i.identity().index(), index.unwrap_or(0));
            prop_assert_eq!(i.curve().as_str(), *curve);
            let pass = passphrase.or(default_pass).unwrap_or("ask");
            prop_assert_eq!(i.passphrase().as_str(), pass);
            prop_assert_eq!(
                i.fingerprint().map(Fingerprint::as_str),
                fingerprint.as_deref()
            );
        }
        (
            IdentityConfig::Fido2(i),
            Spec::Fido2 {
                algorithm,
                user_verification,
                resident,
                fingerprint,
                ..
            },
        ) => {
            prop_assert_eq!(i.algorithm().as_str(), *algorithm);
            prop_assert_eq!(
                Some(i.application().as_str().to_owned()),
                expected_application(name, spec)
            );
            prop_assert_eq!(i.user_verification(), user_verification.unwrap_or(true));
            prop_assert_eq!(i.resident(), resident.unwrap_or(false));
            prop_assert_eq!(
                i.fingerprint().map(Fingerprint::as_str),
                fingerprint.as_deref()
            );
        }
        _ => prop_assert!(false, "kind mismatch: {id:?} vs {spec:?}"),
    }
    Ok(())
}

/// Foreign keys (with values that would be valid for their own kind).
const SLIP13_ONLY: &[(&str, &str)] = &[
    ("uri", "uri = \"ssh://user@h\""),
    ("curve", "curve = \"ed25519\""),
    ("index", "index = 0"),
    ("passphrase", "passphrase = \"ask\""),
    ("transport", "transport = \"usb\""),
    ("certificate", "certificate = \"AAAA\""),
    (
        "public_key",
        "public_key = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c\"",
    ),
    (
        "host_keys",
        "host_keys = [\"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\"]",
    ),
];
const FIDO2_ONLY: &[(&str, &str)] = &[
    ("algorithm", "algorithm = \"ed25519-sk\""),
    ("application", "application = \"ssh:x\""),
    ("user_verification", "user_verification = true"),
    ("resident", "resident = false"),
];

proptest! {
    /// Arbitrary input never panics; any error is InvalidConfig.
    #[test]
    fn arbitrary_toml_never_panics(s in any::<String>()) {
        match Config::from_toml_str(&s) {
            Ok(_) | Err(Error::InvalidConfig(_)) => {}
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }

    /// Arbitrary values in identity tables of both kinds: never a panic, only
    /// InvalidConfig errors.
    #[test]
    fn arbitrary_identity_values_never_panic(
        keys in prop::collection::vec(
            prop::sample::select(vec![
                "name", "kind", "uri", "curve", "index", "passphrase", "fingerprint",
                "transport", "algorithm", "application", "user_verification", "resident",
                "comment", "owner", "public_key", "host_keys",
            ]),
            0..8,
        ),
        values in prop::collection::vec(
            prop_oneof![
                "\"[ -~]{0,20}\"".prop_map(|s| s),
                any::<i64>().prop_map(|i| i.to_string()),
                any::<bool>().prop_map(|b| b.to_string()),
                Just("\"fido2\"".to_owned()),
                Just("\"slip13\"".to_owned()),
                Just("[]".to_owned()),
                Just("[\"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\"]".to_owned()),
                any::<u8>().prop_map(|seed| format!("\"{}\"", test_key(crate::Curve::Ed25519, seed.max(1)).openssh_line("c"))),
            ],
            8,
        ),
    ) {
        let mut seen = HashSet::new();
        let mut s = String::from("[[identity]]\n");
        for (k, v) in keys.iter().zip(&values) {
            if seen.insert(*k) {
                s.push_str(&format!("{k} = {v}\n"));
            }
        }
        match Config::from_toml_str(&s) {
            Ok(_) | Err(Error::InvalidConfig(_)) => {}
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }

    /// Valid configs of mixed kinds, in any key order, load into exactly the given
    /// fields (defaults resolved); the only rejection is a duplicate application.
    #[test]
    fn valid_configs_round_trip(
        names in prop::collection::btree_set("[a-z0-9][a-z0-9-]{0,31}", 0..5),
        specs in prop::collection::vec(spec(), 5),
        transport in prop::option::of(prop::sample::select(vec!["auto", "usb", "ble"])),
        default_pass in prop::option::of(prop::sample::select(vec!["ask", "standard"])),
        owner in prop::option::of("[a-z0-9_][a-z0-9_-]{0,31}"),
        comments in prop::collection::vec(
            prop::option::of("[!-~\u{e4}\u{4e2d}]([ -~\u{e4}\u{4e2d}]{0,126}[!-~\u{e4}\u{4e2d}])?"),
            5,
        ),
        rot in any::<usize>(),
    ) {
        let mut s = String::new();
        if let Some(t) = transport { s.push_str(&format!("transport = \"{t}\"\n")); }
        if let Some(o) = &owner { s.push_str(&format!("owner = \"{o}\"\n")); }
        if let Some(p) = default_pass { s.push_str(&format!("[defaults]\npassphrase = \"{p}\"\n")); }
        let pairs: Vec<(&String, &Spec)> = names.iter().zip(&specs).collect();
        for (i, (name, spec)) in pairs.iter().enumerate() {
            let mut l = lines(name, spec);
            if let Some(c) = &comments[i] {
                // TOML literal string: no escapes, so the comment must not contain `'`
                // (replaced; the generator otherwise covers all of printable ASCII).
                l.push(format!("comment = '{}'", c.replace('\'', "\"")));
            }
            s.push_str(&table(&l, rot.wrapping_add(i)));
        }
        let apps: Vec<String> = pairs.iter().filter_map(|(n, sp)| expected_application(n, sp)).collect();
        let unique_apps = apps.iter().collect::<HashSet<_>>().len() == apps.len();

        match Config::from_toml_str(&s) {
            Ok(c) => {
                prop_assert!(unique_apps);
                prop_assert_eq!(c.transport().as_str(), transport.unwrap_or("auto"));
                prop_assert_eq!(c.identities().len(), pairs.len());
                for (i, (id, (name, spec))) in c.identities().iter().zip(&pairs).enumerate() {
                    assert_matches(id, name, spec, default_pass)?;
                    let expected_comment = match (&comments[i], &owner) {
                        (Some(c), _) => c.replace('\'', "\""),
                        (None, Some(o)) => format!("{o}@hwkey:{name}"),
                        (None, None) => format!("hwkey:{name}"),
                    };
                    prop_assert_eq!(id.comment().as_str(), expected_comment);
                    // lookup by name finds the same identity, with the right kind
                    prop_assert_eq!(c.find(name), Some(id));
                    match id {
                        IdentityConfig::Slip13(i) => {
                            prop_assert_eq!(c.slip13(name), Ok(i));
                            let is_wrong_kind = matches!(c.fido2(name), Err(Error::WrongIdentityKind { .. }));
                            prop_assert!(is_wrong_kind);
                        }
                        IdentityConfig::Fido2(i) => {
                            prop_assert_eq!(c.fido2(name), Ok(i));
                            let is_wrong_kind = matches!(c.slip13(name), Err(Error::WrongIdentityKind { .. }));
                            prop_assert!(is_wrong_kind);
                        }
                    }
                }
            }
            Err(Error::InvalidConfig(m)) => {
                prop_assert!(!unique_apps, "rejected a valid config: {m}\n{s}");
                prop_assert!(m.contains("application is already used"), "{m}");
            }
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }

    /// A valid identity plus any non-empty set of keys of the other kind is always
    /// rejected, naming the keys, whatever the order.
    #[test]
    fn kind_mismatched_keys_always_rejected(
        name in "[a-z0-9][a-z0-9-]{0,31}",
        slip in slip13_spec(),
        fido in fido2_spec(),
        as_fido2 in any::<bool>(),
        slip_foreign in prop::sample::subsequence(SLIP13_ONLY.to_vec(), 1..=SLIP13_ONLY.len()),
        fido_foreign in prop::sample::subsequence(FIDO2_ONLY.to_vec(), 1..=FIDO2_ONLY.len()),
        rot in any::<usize>(),
    ) {
        let (spec, foreign) = if as_fido2 { (&fido, &slip_foreign) } else { (&slip, &fido_foreign) };
        let mut l = lines(&name, spec);
        // the valid table on its own loads
        prop_assert!(Config::from_toml_str(&table(&l, rot)).is_ok());
        l.extend(foreign.iter().map(|(_, line)| (*line).to_owned()));
        let s = table(&l, rot);
        match Config::from_toml_str(&s) {
            Err(Error::InvalidConfig(m)) => {
                prop_assert!(m.starts_with(&format!("identity \"{name}\": ")), "{m}");
                prop_assert!(m.contains("not allowed"), "{m}");
                for (key, _) in foreign {
                    prop_assert!(m.contains(key), "{m} lacks {key}");
                }
            }
            other => prop_assert!(false, "accepted mismatched keys: {other:?}\n{s}"),
        }
    }

    /// A slip13 table with `transport` is always rejected (it is a top-level setting).
    #[test]
    fn transport_in_slip13_identity_rejected(name in "[a-z0-9][a-z0-9-]{0,31}", slip in slip13_spec(), rot in any::<usize>()) {
        let mut l = lines(&name, &slip);
        l.push("transport = \"ble\"".into());
        let m = err(&table(&l, rot));
        prop_assert!(m.contains("transport is not allowed"), "{m}");
    }

    /// `public_key` / `fingerprint` / `host_keys` in any combination and key order:
    /// accepted exactly when the documented rules hold, and then the identity carries
    /// the key, the effective pin and the host keys in file order.
    #[test]
    fn agent_keys_round_trip(
        curve_is_ed in any::<bool>(),
        key_curve_is_ed in any::<bool>(),
        seed in 1u8..=255,
        with_key in any::<bool>(),
        pin in prop::option::of(any::<bool>()),
        gpg in any::<bool>(),
        host_keys in prop::option::of(prop::collection::vec(fingerprint_strategy(), 0..6)),
        comment in "[ -~&&[^\"\\\\]]{0,20}",
        rot in any::<usize>(),
    ) {
        let curve = if curve_is_ed { crate::Curve::Ed25519 } else { crate::Curve::Nist256p1 };
        let key_curve = if key_curve_is_ed { crate::Curve::Ed25519 } else { crate::Curve::Nist256p1 };
        let key = test_key(key_curve, seed);
        let other = test_key(key_curve, seed.wrapping_add(1).max(1));
        let mut l = vec![
            "name = \"a\"".to_owned(),
            format!("uri = \"{}://h\"", if gpg { "gpg" } else { "ssh" }),
            format!("curve = \"{}\"", curve.as_str()),
        ];
        if with_key {
            l.push(format!("public_key = \"{}\"", key.openssh_line(&comment)));
        }
        // pin: Some(true) = the key's fingerprint, Some(false) = another key's
        let pin_fp = pin.map(|same| if same { key.fingerprint() } else { other.fingerprint() });
        if let Some(f) = &pin_fp {
            l.push(format!("fingerprint = \"{f}\""));
        }
        if let Some(h) = &host_keys {
            let items: Vec<String> = h.iter().map(|f| format!("\"{f}\"")).collect();
            l.push(format!("host_keys = [{}]", items.join(", ")));
        }
        let unique = host_keys.as_ref().is_none_or(|h| h.iter().collect::<HashSet<_>>().len() == h.len());
        let valid = (!with_key || (key_curve == curve && pin != Some(false)))
            && host_keys.as_ref().is_none_or(|h| with_key && !gpg && !h.is_empty() && unique);
        match Config::from_toml_str(&table(&l, rot)) {
            Ok(c) => {
                prop_assert!(valid, "accepted an invalid identity");
                let id = c.slip13("a").unwrap();
                prop_assert_eq!(id.public_key(), with_key.then_some(&key));
                let expected_pin = pin_fp.or_else(|| with_key.then(|| key.fingerprint()));
                prop_assert_eq!(id.fingerprint(), expected_pin.as_ref());
                let expected_hosts: Vec<Fingerprint> = host_keys
                    .unwrap_or_default()
                    .iter()
                    .map(|f| Fingerprint::parse(f).unwrap())
                    .collect();
                prop_assert_eq!(id.host_keys(), expected_hosts.as_slice());
            }
            Err(Error::InvalidConfig(m)) => {
                prop_assert!(!valid, "rejected a valid identity: {m}");
                prop_assert!(m.starts_with("identity \"a\": "), "{m}");
            }
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }

    /// `Owner::parse` accepts exactly the documented language and keeps the input.
    #[test]
    fn owner_parse_matches_rule(s in prop_oneof![any::<String>(), "[a-z0-9A-Z_. @-]{0,34}"]) {
        let rule = (1..=32).contains(&s.len())
            && !s.starts_with('-')
            && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        match Owner::parse(&s) {
            Ok(o) => {
                prop_assert!(rule);
                prop_assert_eq!(o.as_str(), s.as_str());
                prop_assert_eq!(o.to_string(), s.clone());
            }
            Err(e) => {
                prop_assert!(!rule);
                prop_assert!(matches!(e, Error::InvalidConfig(_)));
            }
        }
    }

    /// `Comment::parse` accepts exactly the documented language (oracle written from
    /// the documentation) and keeps the input; accepted comments are single-line,
    /// trimmed, and fit the 512-byte limit of the FIDO2 key files.
    #[test]
    fn comment_parse_matches_rule(
        s in prop_oneof![
            any::<String>(),
            "[ -~]{0,130}",
            "[a-z \\x00-\\x1f\\x7f\u{a0}\u{e4}\u{200b}\u{202e}\u{2013}\u{1f511}\u{4e2d}\u{20000}]{0,130}",
        ],
    ) {
        let n = s.chars().count();
        let rule = (1..=128).contains(&n)
            && !s.starts_with(' ')
            && !s.ends_with(' ')
            && s.chars().all(|c| c == ' ' || (' '..='~').contains(&c) || c.is_alphanumeric());
        match Comment::parse(&s) {
            Ok(c) => {
                prop_assert!(rule);
                prop_assert_eq!(c.as_str(), s.as_str());
                prop_assert!(!s.chars().any(char::is_control));
                prop_assert_eq!(s.trim(), s.as_str());
                prop_assert!(s.len() <= 512);
            }
            Err(e) => {
                prop_assert!(!rule);
                prop_assert!(matches!(e, Error::InvalidConfig(_)));
            }
        }
    }

    /// Default comments are always valid comments, of the documented form.
    #[test]
    fn default_comment_is_valid(
        name in "[a-z0-9][a-z0-9-]{0,31}",
        owner in prop::option::of("[a-z0-9_][a-z0-9_-]{0,31}"),
    ) {
        let name = Name::parse(&name).unwrap();
        let owner = owner.map(|o| Owner::parse(&o).unwrap());
        let c = Comment::default_for(owner.as_ref(), &name);
        prop_assert_eq!(Comment::parse(c.as_str()), Ok(c.clone()));
        let expected = match &owner {
            Some(o) => format!("{o}@hwkey:{name}"),
            None => format!("hwkey:{name}"),
        };
        prop_assert_eq!(c.as_str(), expected);
    }

    /// `Name::parse` accepts exactly the documented language and keeps the input.
    #[test]
    fn name_parse_matches_rule(s in prop_oneof![any::<String>(), "[a-z0-9A-Z_. -]{0,34}"]) {
        let rule = (1..=32).contains(&s.len())
            && !s.starts_with('-')
            && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        match Name::parse(&s) {
            Ok(n) => {
                prop_assert!(rule);
                prop_assert_eq!(n.as_str(), s.as_str());
                prop_assert_eq!(n.to_string(), s.clone());
                prop_assert_eq!(s.parse::<Name>(), Ok(n));
            }
            Err(e) => {
                prop_assert!(!rule);
                prop_assert!(matches!(e, Error::InvalidConfig(_)));
            }
        }
    }
}
