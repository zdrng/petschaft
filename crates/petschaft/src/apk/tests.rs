//! `pets apk` with a software P-256 "device" (no Trezor, no helper): it signs like the
//! firmware does for gpg/nist256p1 (`0x00 || r || s` over `challenge_hidden` as the
//! digest), and its answers pass through the real `SignedIdentity::from_device`. Every
//! signed APK is checked by the real `apksigner` (`PETSCHAFT_APKSIGNER`, set by the dev
//! shell and the Nix build; the tests fail without it). Test APKs carry a hand-written
//! binary `AndroidManifest.xml` ([`manifest_axml`]) that the real `aapt2`
//! (`PETSCHAFT_AAPT2`, likewise required) reads; only builds marked
//! `PETSCHAFT_NO_AAPT2` (platforms without aapt2 in nixpkgs) skip the tests needing it.
//!
//! Keys: the petschaft-apk test key (`[0x11; 32]`) and another one (`[0x22; 32]`),
//! public fixed seeds (`docs/testing.md`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::rc::Rc;

use proptest::prelude::*;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use petschaft_core::Config;

use super::*;

/// Builders of the petschaft-apk tests (independent ZIP writer, apksigner runner).
#[path = "../../../petschaft-apk/tests/common/mod.rs"]
mod common;

const OTHER_SEED: u8 = 0x22;

fn other_key() -> SigningKey {
    SigningKey::from_slice(&[OTHER_SEED; 32]).unwrap()
}

fn core_key(k: &SigningKey) -> PublicKey {
    PublicKey::from_p256_uncompressed(&common::point(k)).unwrap()
}

/// What the fake device saw.
#[derive(Clone, Default)]
struct Seen(Rc<RefCell<Vec<String>>>);

impl Seen {
    fn visuals(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

struct FakeDevice {
    /// Keys used for successive requests (the last one repeats).
    keys: Vec<SigningKey>,
    seen: Seen,
    fail: bool,
    /// Run before each signature (e.g. to create the output file meanwhile).
    hook: Option<Box<dyn FnMut()>>,
}

impl FakeDevice {
    fn new(key: SigningKey, seen: &Seen) -> Self {
        FakeDevice {
            keys: vec![key],
            seen: seen.clone(),
            fail: false,
            hook: None,
        }
    }
}

impl Signer for FakeDevice {
    fn sign_identity(
        &mut self,
        req: &SignRequest,
    ) -> Result<SignedIdentity, petschaft_device::Error> {
        let n = self.seen.0.borrow().len();
        self.seen
            .0
            .borrow_mut()
            .push(req.challenge_visual().to_owned());
        if let Some(h) = &mut self.hook {
            h();
        }
        if self.fail {
            return Err(petschaft_device::Error::HelperExited);
        }
        let key = &self.keys[n.min(self.keys.len() - 1)];
        // gpg with nist256p1: the 32-byte challenge is the digest.
        let digest: [u8; 32] = req.challenge_hidden().try_into().unwrap();
        let sig: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        let mut dev_sig = vec![0u8];
        dev_sig.extend_from_slice(&sig.to_bytes());
        let pk = key.verifying_key().to_sec1_point(true);
        SignedIdentity::from_device(req, pk.as_bytes(), &dev_sig)
    }
}

fn never() -> Result<FakeDevice> {
    panic!("must not connect to the device")
}

/// Identity `apk` (gpg://, nist256p1) with `extra` lines.
fn config(extra: &str) -> Config {
    Config::from_toml_str(&format!(
        "[[identity]]\nname = \"apk\"\nuri = \"gpg://apk@release\"\ncurve = \"nist256p1\"\n{extra}"
    ))
    .unwrap()
}

fn pin(k: &SigningKey) -> String {
    format!("fingerprint = \"{}\"\n", core_key(k).fingerprint())
}

fn cert_line(c: &Certificate) -> String {
    format!("certificate = \"{}\"\n", STANDARD.encode(c.der()))
}

/// Pinned to the test key, with the petschaft-apk test certificate.
fn signing_config() -> Config {
    let k = common::key();
    config(&format!("{}{}", pin(&k), cert_line(&common::cert(&k))))
}

/// One `ResChunk_header` chunk: type, header size, total size, then header and body.
fn res_chunk(ty: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
    let header_size = 8 + header.len();
    let mut out = Vec::new();
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&(header_size as u16).to_le_bytes());
    out.extend_from_slice(&((header_size + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    out
}

/// `RES_STRING_POOL_TYPE` with UTF-16 strings.
fn string_pool(strings: &[&str]) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut data = Vec::new();
    for s in strings {
        offsets.extend_from_slice(&(data.len() as u32).to_le_bytes());
        let units: Vec<u16> = s.encode_utf16().collect();
        assert!(units.len() < 0x8000, "one-unit length only");
        data.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let n = strings.len() as u32;
    let mut header = Vec::new();
    for v in [n, 0, 0, 28 + 4 * n, 0] {
        // stringCount, styleCount, flags (UTF-16), stringsStart, stylesStart
        header.extend_from_slice(&v.to_le_bytes());
    }
    offsets.extend_from_slice(&data);
    res_chunk(0x0001, &header, &offsets)
}

/// A minimal binary (AXML) manifest, written by hand so the tests need no Android SDK:
/// string pool, resource map (the first three strings are the android attributes
/// versionCode 0x0101021b, versionName 0x0101021c, minSdkVersion 0x0101020c), then
/// `<manifest xmlns:android package android:versionCode android:versionName>` with an
/// optional `<uses-sdk android:minSdkVersion>`.
fn manifest_axml(
    package: &str,
    version_code: u32,
    version_name: &str,
    min_sdk: Option<u32>,
) -> Vec<u8> {
    const NS: &str = "http://schemas.android.com/apk/res/android";
    let strings = [
        "versionCode",
        "versionName",
        "minSdkVersion",
        "android",
        NS,
        "package",
        "manifest",
        "uses-sdk",
        package,
        version_name,
    ];
    let idx = |s: &str| strings.iter().position(|x| *x == s).unwrap() as u32;
    let (ns_prefix, ns_uri) = (idx("android"), idx(NS));
    let none = u32::MAX;
    const TYPE_STRING: u8 = 0x03;
    const TYPE_INT_DEC: u8 = 0x10;
    // ResXMLTree_node: lineNumber, comment.
    let node = |ty: u16, body: &[u8]| {
        let mut header = 1u32.to_le_bytes().to_vec();
        header.extend_from_slice(&none.to_le_bytes());
        res_chunk(ty, &header, body)
    };
    // ResXMLTree_attribute: ns, name, rawValue, Res_value { size 8, 0, type, data }.
    let attr = |ns: u32, name: u32, raw: u32, ty: u8, data: u32| {
        let mut a = Vec::new();
        for v in [ns, name, raw] {
            a.extend_from_slice(&v.to_le_bytes());
        }
        a.extend_from_slice(&8u16.to_le_bytes());
        a.extend_from_slice(&[0, ty]);
        a.extend_from_slice(&data.to_le_bytes());
        a
    };
    let start = |name: &str, attrs: &[Vec<u8>]| {
        let mut b = Vec::new();
        b.extend_from_slice(&none.to_le_bytes());
        b.extend_from_slice(&idx(name).to_le_bytes());
        // attributeStart, attributeSize, attributeCount, idIndex, classIndex, styleIndex
        for v in [20u16, 20, attrs.len() as u16, 0, 0, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for a in attrs {
            b.extend_from_slice(a);
        }
        node(0x0102, &b)
    };
    let end = |name: &str| {
        let mut b = none.to_le_bytes().to_vec();
        b.extend_from_slice(&idx(name).to_le_bytes());
        node(0x0103, &b)
    };
    let mut ns = ns_prefix.to_le_bytes().to_vec();
    ns.extend_from_slice(&ns_uri.to_le_bytes());

    let mut body = string_pool(&strings);
    let mut ids = Vec::new();
    for id in [0x0101_021bu32, 0x0101_021c, 0x0101_020c] {
        ids.extend_from_slice(&id.to_le_bytes());
    }
    body.extend(res_chunk(0x0180, &[], &ids));
    body.extend(node(0x0100, &ns));
    let (pkg, name) = (strings.len() as u32 - 2, strings.len() as u32 - 1);
    body.extend(start(
        "manifest",
        &[
            attr(ns_uri, idx("versionCode"), none, TYPE_INT_DEC, version_code),
            attr(ns_uri, idx("versionName"), name, TYPE_STRING, name),
            attr(none, idx("package"), pkg, TYPE_STRING, pkg),
        ],
    ));
    if let Some(sdk) = min_sdk {
        body.extend(start(
            "uses-sdk",
            &[attr(ns_uri, idx("minSdkVersion"), none, TYPE_INT_DEC, sdk)],
        ));
        body.extend(end("uses-sdk"));
    }
    body.extend(end("manifest"));
    body.extend(node(0x0101, &ns));
    res_chunk(0x0003, &[], &body)
}

/// An empty but valid `resources.arsc` (no packages, empty global string pool).
fn empty_resource_table() -> Vec<u8> {
    let pool = string_pool(&[]);
    let mut out = res_chunk(0x0002, &0u32.to_le_bytes(), &pool);
    assert_eq!(out.len(), 40);
    out.truncate(40);
    out
}

/// The APK entries: `manifest` (if any) plus stored + deflated entries, an odd-length
/// entry before a stored file so alignment matters.
fn apk_entries(manifest: Option<Vec<u8>>) -> Vec<common::ZipEntry> {
    let mut entries = Vec::new();
    if let Some(m) = manifest {
        entries.push(common::stored("AndroidManifest.xml", &m));
    }
    entries.push(common::deflated("classes.dex"));
    entries.push(common::stored("res/odd", b"123"));
    entries.push(common::stored("resources.arsc", &empty_resource_table()));
    entries
}

fn write_apk(dir: &Path, file: &str, manifest: Option<Vec<u8>>) -> PathBuf {
    let p = dir.join(file);
    std::fs::write(&p, common::write_zip(&apk_entries(manifest), b"")).unwrap();
    p
}

/// `org.example.app` 1.4.2 (42), minSdkVersion 24.
fn sample_apk(dir: &Path) -> PathBuf {
    write_apk(
        dir,
        "app-release.apk",
        Some(manifest_axml("org.example.app", 42, "1.4.2", Some(24))),
    )
}

fn sample_app() -> AppInfo {
    AppInfo {
        package: "org.example.app".into(),
        version_code: 42,
        version_name: "1.4.2".into(),
        min_sdk: 24,
    }
}

fn args(input: &Path) -> SignArgs {
    SignArgs {
        input: input.to_owned(),
        output: input.with_file_name("signed.apk"),
        replace: false,
    }
}

fn apksigner() -> PathBuf {
    apksigner_path().expect("PETSCHAFT_APKSIGNER must be set for these tests")
}

/// The real aapt2; `None` (test skipped) only in builds marked `PETSCHAFT_NO_AAPT2`.
fn real_aapt2() -> Option<PathBuf> {
    match aapt2_path() {
        Ok(p) => Some(p),
        Err(_) if option_env!("PETSCHAFT_NO_AAPT2").is_some() => {
            eprintln!("skipped: this build has no aapt2 (PETSCHAFT_NO_AAPT2)");
            None
        }
        Err(e) => panic!("PETSCHAFT_AAPT2 must be set for these tests: {e:#}"),
    }
}

/// apksigner and the real aapt2 (see [`real_aapt2`]).
fn tools() -> Option<Tools> {
    Some(Tools {
        apksigner: apksigner(),
        aapt2: real_aapt2()?,
    })
}

/// An executable `/bin/sh` script in `dir` (runs with an empty environment: builtins
/// only).
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// apksigner and an aapt2 that must never run: for inputs refused before aapt2.
fn early_tools(dir: &Path) -> Tools {
    Tools {
        apksigner: apksigner(),
        aapt2: script(
            dir,
            "aapt2-unused",
            "echo 'fake aapt2 must not run' >&2; exit 99",
        ),
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn err<T: std::fmt::Debug>(r: Result<T>) -> String {
    format!("{:#}", r.unwrap_err())
}

#[test]
fn tool_path_rules() {
    let resolve = |c: Option<&str>, r: Option<OsString>| resolve_tool("PETSCHAFT_X", c, r, "");
    let abs = Some(OsString::from("/run/apksigner"));
    assert_eq!(
        resolve(Some("/nix/store/x/bin/apksigner"), abs.clone()).unwrap(),
        PathBuf::from("/nix/store/x/bin/apksigner")
    );
    assert_eq!(
        resolve(None, abs.clone()).unwrap(),
        PathBuf::from("/run/apksigner")
    );
    assert_eq!(
        resolve(Some(""), abs).unwrap(),
        PathBuf::from("/run/apksigner")
    );
    assert!(err(resolve(None, None)).starts_with("PETSCHAFT_X is not set"));
    assert!(resolve(None, Some(OsString::new())).is_err());
    assert!(resolve(Some("apksigner"), None).is_err());
    assert!(resolve(None, Some(OsString::from("bin/apksigner"))).is_err());
    let e = err(resolve_tool("PETSCHAFT_AAPT2", None, None, " (hint)"));
    assert!(
        e.starts_with("PETSCHAFT_AAPT2 is not set") && e.ends_with(" (hint)"),
        "{e}"
    );
}

#[test]
fn subject_forms() {
    assert_eq!(parse_subject("CN=Release Key").unwrap(), "Release Key");
    assert_eq!(parse_subject("Release Key").unwrap(), "Release Key");
    assert_eq!(parse_subject(&"a".repeat(64)).unwrap().len(), 64);
    for bad in [
        "",
        "CN=",
        "CN=a, O=b",
        "O=b",
        "CN=caf\u{e9}",
        "a\nb",
        &"a".repeat(65),
    ] {
        assert!(parse_subject(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn init_end_to_end_then_sign() {
    let k = common::key();
    let seen = Seen::default();
    let c = config(&pin(&k));
    let id = c.slip13("apk").unwrap();
    let cert = init(id, "CN=Release Key", || {
        Ok(FakeDevice::new(k.clone(), &seen))
    })
    .unwrap();
    assert_eq!(seen.visuals(), ["apk init apk", "apk cert Release Key"]);
    assert_eq!(cert.public_key(), &common::point(&k));
    assert_eq!(cert.subject_cn(), "Release Key");
    assert_eq!(Certificate::parse(cert.der()).unwrap(), cert);
    print_init(id, &cert).unwrap();

    // The printed line loads, and the certificate signs APKs that apksigner accepts.
    let c = config(&format!("{}{}", pin(&k), cert_line(&cert)));
    let id = c.slip13("apk").unwrap();
    assert_eq!(id.certificate(), Some(&cert));
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let a = args(&sample_apk(dir.path()));
    let report = sign(id, &a, &tools, || Ok(FakeDevice::new(k, &seen))).unwrap();
    assert_eq!(report.certificate_sha256, cert.sha256_fingerprint());
    assert_eq!(report.app, sample_app());
    let (ok, out) = common::apksigner_verify(&std::fs::read(&a.output).unwrap(), 24);
    assert!(ok, "{out}");
    assert!(
        out.contains("Signer #1 certificate DN: CN=Release Key"),
        "{out}"
    );

    // A second init for the same identity is refused before the device is asked.
    let e = err(init(id, "CN=Release Key", never));
    assert!(e.contains("already has a certificate"), "{e}");
}

#[test]
fn init_unpinned_identity() {
    let k = common::key();
    let seen = Seen::default();
    let c = config("");
    let id = c.slip13("apk").unwrap();
    let cert = init(id, "petschaft", || Ok(FakeDevice::new(k.clone(), &seen))).unwrap();
    assert_eq!(cert.public_key(), &common::point(&k));
    assert_eq!(seen.visuals(), ["apk init apk", "apk cert petschaft"]);
}

#[test]
fn init_fails_closed() {
    let k = common::key();
    // Wrong kind of identity, bad subject: refused before connecting.
    for (uri, curve) in [
        ("ssh://apk@release", "nist256p1"),
        ("gpg://apk@release", "ed25519"),
    ] {
        let c = Config::from_toml_str(&format!(
            "[[identity]]\nname = \"apk\"\nuri = \"{uri}\"\ncurve = \"{curve}\"\n"
        ))
        .unwrap();
        let e = err(init(c.slip13("apk").unwrap(), "CN=x", never));
        assert!(
            e.contains("needs a gpg:// uri and curve = \"nist256p1\""),
            "{e}"
        );
    }
    let c = config(&pin(&k));
    let id = c.slip13("apk").unwrap();
    assert!(err(init(id, "CN=a,O=b", never)).contains("single CN"));

    // The device answers with another key than the pinned one.
    let seen = Seen::default();
    let e = err(init(id, "CN=x", || Ok(FakeDevice::new(other_key(), &seen))));
    assert!(e.contains("fingerprint mismatch"), "{e}");
    assert_eq!(seen.visuals().len(), 1, "stopped after the first request");

    // Unpinned, but the key changes between the two requests.
    let c = config("");
    let seen = Seen::default();
    let mut dev = FakeDevice::new(k, &seen);
    dev.keys.push(other_key());
    let e = err(init(c.slip13("apk").unwrap(), "CN=x", || Ok(dev)));
    assert!(e.contains("different key"), "{e}");

    // Device errors propagate.
    let seen = Seen::default();
    let mut dev = FakeDevice::new(common::key(), &seen);
    dev.fail = true;
    assert!(init(id, "CN=x", || Ok(dev)).is_err());
}

#[test]
fn sign_v2_and_v3() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let input = sample_apk(dir.path());
    let a = args(&input);
    let seen = Seen::default();
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    let report = sign(id, &a, &tools, || Ok(FakeDevice::new(common::key(), &seen))).unwrap();
    print_sign(&a, &report);
    assert_eq!(report.schemes, [SchemeVersion::V2, SchemeVersion::V3]);
    assert_eq!(report.app, sample_app());
    assert_eq!(report.app.to_string(), "org.example.app:1.4.2(42)");
    let cert = common::cert(&common::key());
    assert_eq!(report.certificate_sha256, cert.sha256_fingerprint());

    // One confirmation per scheme, showing the scheme, package:versionName(versionCode)
    // and the content digest.
    let mut aligned = Apk::parse(&std::fs::read(&input).unwrap()).unwrap();
    aligned.align().unwrap();
    let short = hex(&aligned.content_digest().unwrap()[..4]);
    assert_eq!(
        seen.visuals(),
        [
            format!("apk v2 org.example.app:1.4.2(42) {short}"),
            format!("apk v3 org.example.app:1.4.2(42) {short}")
        ]
    );

    // Only input and output remain; the output verifies independently.
    assert_eq!(files(dir.path()), ["app-release.apk", "signed.apk"]);
    let signed = std::fs::read(&a.output).unwrap();
    let (ok, out) = common::apksigner_verify(&signed, 24);
    assert!(ok, "{out}");
    assert!(
        out.contains("Verified using v2 scheme (APK Signature Scheme v2): true"),
        "{out}"
    );
    assert!(
        out.contains("Verified using v3 scheme (APK Signature Scheme v3): true"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "Signer #1 certificate SHA-256 digest: {}",
            hex(&cert.sha256_fingerprint())
        )),
        "{out}"
    );
    // `pets apk verify` accepts it (without --min-sdk apksigner reads the manifest).
    verify(&apksigner(), &a.output, Some(24)).unwrap();
    verify(&apksigner(), &a.output, None).unwrap();
}

#[test]
fn sign_uses_the_manifest_min_sdk() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let input = write_apk(
        dir.path(),
        "app.apk",
        Some(manifest_axml("com.example.thirty", 7, "2.0-beta", Some(30))),
    );
    let a = args(&input);
    let seen = Seen::default();
    let c = signing_config();
    let report = sign(c.slip13("apk").unwrap(), &a, &tools, || {
        Ok(FakeDevice::new(common::key(), &seen))
    })
    .unwrap();
    assert_eq!(report.app.min_sdk, 30);
    assert_eq!(report.app.to_string(), "com.example.thirty:2.0-beta(7)");
    let v = seen.visuals();
    assert!(
        v[0].starts_with("apk v2 com.example.thirty:2.0-beta(7) "),
        "{v:?}"
    );
    let signed = std::fs::read(&a.output).unwrap();
    let (ok, out) = common::apksigner_verify(&signed, 30);
    assert!(ok, "{out}");
    // apksigner checks only v3 from API 28 on; the v2 signature is valid as well.
    let (ok, out) = common::apksigner_verify(&signed, 24);
    assert!(ok, "{out}");
    assert!(
        out.contains("Verified using v2 scheme (APK Signature Scheme v2): true"),
        "{out}"
    );
}

#[test]
fn sign_refuses_min_sdk_below_24() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    for sdk in [21, 23] {
        let input = write_apk(
            dir.path(),
            "old.apk",
            Some(manifest_axml("org.example.old", 1, "1.0", Some(sdk))),
        );
        let e = err(sign(id, &args(&input), &tools, never));
        assert!(
            e.contains(&format!(
                "(org.example.old:1.0(1)) has minSdkVersion {sdk}; pets signs only apps with \
                 minSdkVersion >= 24"
            )),
            "{e}"
        );
    }
    assert_eq!(files(dir.path()), ["old.apk"]);
}

#[test]
fn sign_refuses_missing_or_broken_manifest() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    let none = write_apk(dir.path(), "none.apk", None);
    let e = err(sign(id, &args(&none), &tools, never));
    assert!(e.contains("aapt2 cannot read the manifest of"), "{e}");
    let junk = write_apk(
        dir.path(),
        "junk.apk",
        Some(b"not a real binary manifest".to_vec()),
    );
    let e = err(sign(id, &args(&junk), &tools, never));
    assert!(e.contains("aapt2 cannot read the manifest of"), "{e}");
    // No <uses-sdk>: aapt2 prints no minSdkVersion (Android would assume 1).
    let nosdk = write_apk(
        dir.path(),
        "nosdk.apk",
        Some(manifest_axml("org.example.app", 1, "1.0", None)),
    );
    let e = err(sign(id, &args(&nosdk), &tools, never));
    assert!(e.contains("no or several minSdkVersion lines"), "{e}");
    // Invalid package name, missing versionName.
    let bad = write_apk(
        dir.path(),
        "bad.apk",
        Some(manifest_axml("noseparator", 1, "1.0", Some(24))),
    );
    let e = err(sign(id, &args(&bad), &tools, never));
    assert!(e.contains("is not a valid Android package name"), "{e}");
    let unnamed = write_apk(
        dir.path(),
        "unnamed.apk",
        Some(manifest_axml("org.example.app", 1, "", Some(24))),
    );
    let e = err(sign(id, &args(&unnamed), &tools, never));
    assert!(e.contains("the manifest has no versionName"), "{e}");
    assert_eq!(
        files(dir.path()),
        [
            "bad.apk",
            "junk.apk",
            "none.apk",
            "nosdk.apk",
            "unnamed.apk"
        ]
    );
}

/// aapt2 prints manifest strings unescaped: a versionName can fake the minSdkVersion
/// line of an app without `<uses-sdk>`. apksigner's own manifest check catches it.
#[test]
fn faked_min_sdk_line_is_caught_by_apksigner() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let input = write_apk(
        dir.path(),
        "fake.apk",
        Some(manifest_axml(
            "org.example.app",
            1,
            "1'\nminSdkVersion:'30",
            None,
        )),
    );
    let a = args(&input);
    let c = signing_config();
    let seen = Seen::default();
    let e = err(sign(c.slip13("apk").unwrap(), &a, &tools, || {
        Ok(FakeDevice::new(common::key(), &seen))
    }));
    assert!(
        e.contains("rejected the signed APK for the minSdkVersion in its manifest"),
        "{e}"
    );
    assert_eq!(files(dir.path()), ["fake.apk"]);
}

#[test]
fn real_aapt2_reads_the_hand_written_manifest() {
    let Some(aapt2) = real_aapt2() else { return };
    let dir = tempfile::tempdir().unwrap();
    for sdk in [24, 30] {
        let apk = write_apk(
            dir.path(),
            "m.apk",
            Some(manifest_axml("org.example.app", 42, "1.4.2", Some(sdk))),
        );
        let out = Command::new(&aapt2)
            .args(["dump", "badging"])
            .arg(&apk)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{text}");
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("package: name='org.example.app' versionCode='42' versionName='1.4.2'")
        );
        assert_eq!(
            lines.next(),
            Some(format!("minSdkVersion:'{sdk}'").as_str())
        );
        assert_eq!(
            read_app_info(&aapt2, &apk, AAPT2_TIMEOUT).unwrap(),
            AppInfo {
                min_sdk: sdk,
                ..sample_app()
            }
        );
    }
}

#[test]
fn sign_requires_certificate_and_pin() {
    let dir = tempfile::tempdir().unwrap();
    let a = args(&sample_apk(dir.path()));
    let tools_dir = tempfile::tempdir().unwrap();
    let tools = early_tools(tools_dir.path());
    let k = common::key();
    let c = config(&pin(&k));
    let e = err(sign(c.slip13("apk").unwrap(), &a, &tools, never));
    assert!(
        e.contains("has no certificate; run `pets apk init apk"),
        "{e}"
    );
    let c = config(&cert_line(&common::cert(&k)));
    let e = err(sign(c.slip13("apk").unwrap(), &a, &tools, never));
    assert!(e.contains("is not pinned"), "{e}");
    assert_eq!(files(dir.path()), ["app-release.apk"]);
}

#[test]
fn sign_never_overwrites() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let a = args(&sample_apk(dir.path()));
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    std::fs::write(&a.output, b"keep me").unwrap();
    let e = err(sign(id, &a, &tools, never));
    assert!(e.contains("already exists"), "{e}");
    // Input and output the same file.
    let mut same = a.clone();
    same.output = same.input.clone();
    assert!(err(sign(id, &same, &tools, never)).contains("already exists"));
    // A dangling symlink counts as existing.
    std::fs::remove_file(&a.output).unwrap();
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &a.output).unwrap();
    assert!(err(sign(id, &a, &tools, never)).contains("already exists"));
    std::fs::remove_file(&a.output).unwrap();

    // The output appears while the device is signing: still not overwritten, and the
    // temporary file is gone.
    let seen = Seen::default();
    let mut dev = FakeDevice::new(common::key(), &seen);
    let out = a.output.clone();
    dev.hook = Some(Box::new(move || {
        if !out.exists() {
            std::fs::write(&out, b"keep me").unwrap();
        }
    }));
    let e = err(sign(id, &a, &tools, || Ok(dev)));
    assert!(e.contains("already exists; not overwriting"), "{e}");
    assert_eq!(std::fs::read(&a.output).unwrap(), b"keep me");
    assert_eq!(files(dir.path()), ["app-release.apk", "signed.apk"]);
}

#[test]
fn sign_fails_closed_on_device_errors() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let a = args(&sample_apk(dir.path()));
    let c = signing_config();
    let id = c.slip13("apk").unwrap();

    // Another key than the pinned (= certificate) key.
    let seen = Seen::default();
    let e = err(sign(id, &a, &tools, || {
        Ok(FakeDevice::new(other_key(), &seen))
    }));
    assert!(e.contains("fingerprint mismatch"), "{e}");
    assert_eq!(seen.visuals().len(), 1);

    // Cancelled / failed on the device.
    let seen = Seen::default();
    let mut dev = FakeDevice::new(common::key(), &seen);
    dev.fail = true;
    let e = err(sign(id, &a, &tools, || Ok(dev)));
    assert!(e.starts_with("signing failed"), "{e}");

    // Connecting fails.
    let e = err(sign(id, &a, &tools, || -> Result<FakeDevice> {
        bail!("no device")
    }));
    assert_eq!(e, "no device");

    assert_eq!(files(dir.path()), ["app-release.apk"]);
}

#[test]
fn apksigner_checked_before_the_device() {
    let dir = tempfile::tempdir().unwrap();
    let a = args(&sample_apk(dir.path()));
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    let tools = tempfile::tempdir().unwrap();
    let not_exec = tools.path().join("not-executable");
    std::fs::write(&not_exec, b"#!/bin/sh\n").unwrap();
    let missing = tools.path().join("missing");
    let good = early_tools(tools.path());
    for bad in [missing.as_path(), tools.path(), not_exec.as_path()] {
        let t = Tools {
            apksigner: bad.to_owned(),
            ..good.clone()
        };
        let e = err(sign(id, &a, &t, never));
        assert!(e.contains(&format!("apksigner {}", bad.display())), "{e}");
        assert!(verify(bad, &a.input, None).is_err());
        // The same for aapt2.
        let t = Tools {
            aapt2: bad.to_owned(),
            ..good.clone()
        };
        let e = err(sign(id, &a, &t, never));
        assert!(e.contains(&format!("aapt2 {}", bad.display())), "{e}");
    }
    check_apksigner(&apksigner()).unwrap();
    assert_eq!(files(dir.path()), ["app-release.apk"]);
}

#[test]
fn apksigner_environment_and_arguments() {
    let cmd = apksigner_command(Path::new("/x/apksigner"));
    let removed: Vec<_> = cmd
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    for var in [
        "JAVA_OPTS",
        "APKSIGNER_OPTS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "CLASSPATH",
    ] {
        assert!(removed.iter().any(|r| r == var), "{var} not removed");
    }
    assert_eq!(path_arg(Path::new("-v.apk")), Path::new("./-v.apk"));
    assert_eq!(path_arg(Path::new("d/a.apk")), Path::new("./d/a.apk"));
    assert_eq!(path_arg(Path::new("/d/-a.apk")), Path::new("/d/-a.apk"));
}

#[test]
fn input_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.apk");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(MAX_APK + 1)
        .unwrap();
    let c = signing_config();
    let e = err(sign(
        c.slip13("apk").unwrap(),
        &args(&big),
        &early_tools(dir.path()),
        never,
    ));
    assert!(e.contains("is larger than 268435456 bytes"), "{e}");
}

#[test]
fn v1_signature_files_refused() {
    let dir = tempfile::tempdir().unwrap();
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    let mut entries = apk_entries(Some(manifest_axml("org.example.app", 1, "1", Some(24))));
    entries.push(common::stored("META-INF/CERT.SF", b"x"));
    entries.push(common::stored("META-INF/CERT.RSA", b"x"));
    let input = dir.path().join("v1.apk");
    std::fs::write(&input, common::write_zip(&entries, b"")).unwrap();
    let tools_dir = tempfile::tempdir().unwrap();
    let tools = early_tools(tools_dir.path());
    for replace in [false, true] {
        let mut a = args(&input);
        a.replace = replace;
        let e = err(sign(id, &a, &tools, never));
        assert!(
            e.contains(
                "v1 (JAR) signature files of a previous signer \
                 (META-INF/CERT.SF, META-INF/CERT.RSA)"
            ),
            "{e}"
        );
    }
    assert_eq!(files(dir.path()), ["v1.apk"]);
}

#[test]
fn sign_rejects_bad_input_before_the_device() {
    let dir = tempfile::tempdir().unwrap();
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    let tools_dir = tempfile::tempdir().unwrap();
    let tools = early_tools(tools_dir.path());
    let junk = dir.path().join("junk.apk");
    std::fs::write(&junk, b"PK\x03\x04 not really").unwrap();
    assert!(err(sign(id, &args(&junk), &tools, never)).contains("junk.apk"));
    let missing = dir.path().join("missing.apk");
    assert!(sign(id, &args(&missing), &tools, never).is_err());
    assert_eq!(files(dir.path()), ["junk.apk"]);
}

#[test]
fn resign_requires_replace() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().unwrap();
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    let seen = Seen::default();
    let first = args(&sample_apk(dir.path()));
    sign(id, &first, &tools, || {
        Ok(FakeDevice::new(common::key(), &seen))
    })
    .unwrap();

    let mut again = args(&first.output);
    again.output = dir.path().join("resigned.apk");
    let e = err(sign(id, &again, &tools, never));
    assert!(e.contains("pass --replace"), "{e}");
    again.replace = true;
    let report = sign(id, &again, &tools, || {
        Ok(FakeDevice::new(common::key(), &seen))
    })
    .unwrap();
    assert_eq!(report.schemes, [SchemeVersion::V2, SchemeVersion::V3]);
    let (ok, out) = common::apksigner_verify(&std::fs::read(&again.output).unwrap(), 24);
    assert!(ok, "{out}");
}

#[test]
fn verify_reports_failure() {
    let dir = tempfile::tempdir().unwrap();
    let unsigned = sample_apk(dir.path());
    assert!(verify(&apksigner(), &unsigned, Some(24)).is_err());
    assert!(verify(&apksigner(), &unsigned, None).is_err());
    assert!(verify(&apksigner(), &dir.path().join("missing.apk"), Some(24)).is_err());
}

#[test]
fn display_text() {
    let d = [0xab; 32];
    let app = sample_app();
    assert_eq!(
        visual(&app, &d, SchemeVersion::V2),
        "apk v2 org.example.app:1.4.2(42) abababab"
    );
    assert_eq!(
        visual(&app, &d, SchemeVersion::V3),
        "apk v3 org.example.app:1.4.2(42) abababab"
    );
    // Longest package name, versionName and versionCode: the package name is truncated.
    let long = AppInfo {
        package: format!("a.{}", "b".repeat(126)),
        version_code: u32::MAX,
        version_name: "v".repeat(MAX_VERSION_NAME),
        min_sdk: 24,
    };
    let shown = visual(&long, &d, SchemeVersion::V3);
    assert_eq!(
        shown.chars().count(),
        128,
        "helper limit for challenge_visual"
    );
    assert!(
        shown.ends_with(&format!(":{}(4294967295) abababab", "v".repeat(32))),
        "{shown}"
    );
    assert!(shown.starts_with("apk v3 a.bbb"), "{shown}");
    assert!(shown.contains("b\u{2026}:"), "{shown}");
    assert_eq!(
        colon_hex(&[0x0a, 0xbc, 0xde]),
        "0A:BC:DE",
        "Play Console style"
    );
}

const BADGING: &str = "package: name='org.example.app' versionCode='42' versionName='1.4.2'\n\
                       minSdkVersion:'24'\n\
                       feature-group: label=''\n";

#[test]
fn badging_parse() {
    assert_eq!(parse_badging(BADGING).unwrap(), sample_app());
    // What AGP builds add to the package line; old aapt's sdkVersion line.
    let agp = "package: name='org.example.app' versionCode='42' versionName='1.4.2' \
               platformBuildVersionName='14' platformBuildVersionCode='34' \
               compileSdkVersion='34' compileSdkVersionCodename='14'\nsdkVersion:'24'\n";
    assert_eq!(parse_badging(agp).unwrap(), sample_app());
    // versionName: display-safe and truncated.
    let long = format!(
        "package: name='a.b' versionCode='0' versionName='{}\u{202e}{}'\nminSdkVersion:'35'\n",
        "x".repeat(10),
        "y".repeat(40)
    );
    let app = parse_badging(&long).unwrap();
    assert_eq!(app.version_name.chars().count(), MAX_VERSION_NAME);
    assert!(app.version_name.starts_with("xxxxxxxxxx?yyy"));
    assert!(app.version_name.ends_with('\u{2026}'));
    assert_eq!((app.version_code, app.min_sdk), (0, 35));
    let max = "package: name='a.b' versionCode='4294967295' versionName='1'\nminSdkVersion:'24'\n";
    assert_eq!(parse_badging(max).unwrap().version_code, u32::MAX);
}

#[test]
fn badging_parse_refuses() {
    let line = |pkg: &str, code: &str, name: &str| {
        format!("package: name='{pkg}' versionCode='{code}' versionName='{name}'")
    };
    let ok = line("org.example.app", "42", "1.4.2");
    for (text, msg) in [
        (String::new(), "no or several \"package:\" lines"),
        (
            "minSdkVersion:'24'\n".to_owned(),
            "no or several \"package:\" lines",
        ),
        (
            format!("{ok}\n{ok}\nminSdkVersion:'24'"),
            "no or several \"package:\" lines",
        ),
        (
            format!("x\n{ok}\nminSdkVersion:'24'"),
            "no well-formed \"package:\" line first",
        ),
        (ok.clone(), "no or several minSdkVersion lines"),
        (
            format!("{ok}\nminSdkVersion:'24'\nminSdkVersion:'30'"),
            "no or several minSdkVersion",
        ),
        (
            format!("{ok}\nsdkVersion:'24'\nminSdkVersion:'24'"),
            "no or several minSdkVersion",
        ),
        (format!("{ok}\nminSdkVersion:'Tiramisu'"), "is not a number"),
        (format!("{ok}\nminSdkVersion:' 24'"), "is not a number"),
        (format!("{ok}\nminSdkVersion:'24"), "is not a number"),
        (
            format!("{ok}\nminSdkVersion:'99999999999'"),
            "is not a number",
        ),
        (
            format!("{} \nminSdkVersion:'24'", ok),
            "unexpected \"package:\" line",
        ),
        (
            format!("{ok} x\nminSdkVersion:'24'"),
            "unexpected \"package:\" line",
        ),
        (
            format!("{ok} a b='c'\nminSdkVersion:'24'"),
            "unexpected \"package:\" line",
        ),
        (format!("{ok} k='v\nminSdkVersion:'24'"), "no well-formed"),
        (
            format!("{}\nminSdkVersion:'24'", line("o.a", "42", "it's")),
            "unexpected \"package:\" line",
        ),
        (
            format!("{}\nminSdkVersion:'24'", line("o.a", "", "1")),
            "no valid versionCode",
        ),
        (
            format!("{}\nminSdkVersion:'24'", line("o.a", "-1", "1")),
            "no valid versionCode",
        ),
        (
            format!("{}\nminSdkVersion:'24'", line("o.a", "+1", "1")),
            "no valid versionCode",
        ),
        (
            format!("{}\nminSdkVersion:'24'", line("o.a", "4294967296", "1")),
            "no valid versionCode",
        ),
        (
            format!("{}\nminSdkVersion:'24'", line("o.a", "1", "")),
            "has no versionName",
        ),
        (
            "package: name='o.a' versionName='1' versionCode='1'\nminSdkVersion:'24'".to_owned(),
            "no well-formed",
        ),
    ] {
        let e = err(parse_badging(&text));
        assert!(e.contains(msg), "{text:?}: {e}");
    }
    for pkg in [
        "app",
        "org..app",
        ".org.app",
        "org.app.",
        "org.1app",
        "org._app",
        "org.ap-p",
        "org.äpp",
        "org.a p",
        &format!("a.{}", "b".repeat(127)),
    ] {
        let text = format!("{}\nminSdkVersion:'24'", line(pkg, "1", "1"));
        let e = err(parse_badging(&text));
        assert!(
            e.contains("not a valid Android package name"),
            "{pkg:?}: {e}"
        );
    }
    assert!(valid_package_name(&format!("a.{}", "b".repeat(126))));
    assert!(valid_package_name("A.b_1.C2"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary aapt2 output never panics the parser; whatever it accepts is valid.
    #[test]
    fn badging_parse_total(text in ".{0,300}", prefix in prop::bool::ANY) {
        let text = if prefix { format!("package: name='{text}") } else { text };
        if let Ok(app) = parse_badging(&text) {
            prop_assert!(valid_package_name(&app.package));
            prop_assert!(app.version_name.chars().count() <= MAX_VERSION_NAME);
            prop_assert_eq!(crate::git::display_safe(&app.version_name), app.version_name.clone());
            prop_assert!(visual(&app, &[0; 32], SchemeVersion::V2).chars().count() <= MAX_VISUAL);
        }
    }

    /// Well-formed output round-trips.
    #[test]
    fn badging_parse_roundtrip(
        package in "[a-zA-Z][a-zA-Z0-9_]{0,20}(\\.[a-zA-Z][a-zA-Z0-9_]{0,20}){1,4}",
        code in any::<u32>(),
        name in "[0-9a-zA-Z.\\- ]{1,32}",
        sdk in any::<u32>(),
        extra in prop::bool::ANY,
    ) {
        let tail = if extra { " compileSdkVersion='34'" } else { "" };
        let text = format!(
            "package: name='{package}' versionCode='{code}' versionName='{name}'{tail}\n\
             minSdkVersion:'{sdk}'\nlocales:\n"
        );
        let app = parse_badging(&text).unwrap();
        prop_assert_eq!(app, AppInfo { package, version_code: code, version_name: name, min_sdk: sdk });
    }
}

#[test]
fn aapt2_output_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let apk = sample_apk(dir.path());
    let t = Duration::from_secs(10);
    // Endless output: stopped at 1 MiB (builtins only, the environment is empty).
    let flood = script(
        dir.path(),
        "flood",
        "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done",
    );
    let e = err(read_app_info(&flood, &apk, t));
    assert!(e.contains("it printed more than 1048576 bytes"), "{e}");
    // Endless stderr is drained (and capped) without blocking.
    let noisy = script(
        dir.path(),
        "noisy",
        "i=0; while [ $i -lt 20000 ]; do echo eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee >&2; i=$((i+1)); done; \
         printf \"package: name='a.b' versionCode='1' versionName='1'\\nminSdkVersion:'24'\\n\"",
    );
    assert_eq!(read_app_info(&noisy, &apk, t).unwrap().package, "a.b");
    // Never finishes: killed at the deadline.
    let hang = script(dir.path(), "hang", "while :; do :; done");
    let e = err(read_app_info(&hang, &apk, Duration::from_millis(300)));
    assert!(e.contains("did not finish within"), "{e}");
    // Fails: its stderr is shown display-safe and truncated.
    let fail = script(
        dir.path(),
        "fail",
        "printf 'bad \\033[31m\\342\\200\\256 thing' >&2; i=0; while [ $i -lt 100 ]; do \
         printf xxxxxxxxxx >&2; i=$((i+1)); done; exit 3",
    );
    let e = err(read_app_info(&fail, &apk, t));
    assert!(e.contains("aapt2 cannot read the manifest of"), "{e}");
    assert!(e.contains("bad ?[31m? thing"), "{e}");
    assert!(!e.contains('\u{1b}') && e.ends_with('\u{2026}'), "{e}");
    // Garbage on stdout, exit 0: refused by the parser.
    let junk = script(dir.path(), "junk", "printf 'package: name=evil\\n'");
    assert!(err(read_app_info(&junk, &apk, t)).contains("no well-formed"));
}

/// apksigner gets the same bounds as aapt2: a deadline and an output cap.
#[test]
fn apksigner_run_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let apk = sample_apk(dir.path());
    let cert = common::cert(&common::key());
    let hang = script(dir.path(), "hang", "while :; do :; done");
    let e = err(verify_with_apksigner(
        &hang,
        &apk,
        &cert,
        24,
        Duration::from_millis(300),
    ));
    assert!(e.contains("did not finish within"), "{e}");
    let flood = script(
        dir.path(),
        "flood",
        "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done",
    );
    let e = err(verify_with_apksigner(
        &flood,
        &apk,
        &cert,
        24,
        Duration::from_secs(10),
    ));
    assert!(e.contains("it printed more than 1048576 bytes"), "{e}");
}

#[test]
fn aapt2_runs_with_an_empty_environment() {
    assert!(
        std::env::var_os("HOME").is_some(),
        "the test needs HOME set"
    );
    let dir = tempfile::tempdir().unwrap();
    let apk = sample_apk(dir.path());
    // Shows $HOME and its first two arguments as the versionName.
    let env = script(
        dir.path(),
        "env",
        "printf \"package: name='a.b' versionCode='1' versionName='%s|%s'\\nminSdkVersion:'24'\\n\" \
         \"${HOME-nohome}\" \"$1 $2\"",
    );
    let app = read_app_info(&env, &apk, AAPT2_TIMEOUT).unwrap();
    assert_eq!(app.version_name, "nohome|dump badging");
}

#[test]
fn aapt2_checked_before_the_device() {
    let dir = tempfile::tempdir().unwrap();
    let a = args(&sample_apk(dir.path()));
    let c = signing_config();
    let id = c.slip13("apk").unwrap();
    // Exits 0 but prints nothing: refused, device never asked.
    let tools = Tools {
        apksigner: apksigner(),
        aapt2: script(dir.path(), "silent", "exit 0"),
    };
    let e = err(sign(id, &a, &tools, never));
    assert!(e.contains("no or several \"package:\" lines"), "{e}");
    // A slow aapt2 is cut off.
    let tools = Tools {
        aapt2: script(dir.path(), "slow", "while :; do :; done"),
        ..tools
    };
    let e = err(sign_with_timeout(
        id,
        &a,
        &tools,
        Duration::from_millis(200),
        never,
    ));
    assert!(e.contains("did not finish within"), "{e}");
    assert_eq!(files(dir.path()), ["app-release.apk", "silent", "slow"]);
}
