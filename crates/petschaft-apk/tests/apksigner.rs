//! End-to-end: sign test APKs with a software P-256 key and verify them with Google's
//! `apksigner` (path in `PETSCHAFT_APKSIGNER`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::*;
use petschaft_apk::{Apk, Error, SchemeVersion};

const V2_LINE: &str = "Verified using v2 scheme (APK Signature Scheme v2): ";
const V3_LINE: &str = "Verified using v3 scheme (APK Signature Scheme v3): ";

/// Verifies with `--min-sdk-version 24`, the lowest supported minSdkVersion (v2 for
/// Android 7.0-8.1, v3 from 9).
fn assert_verifies(apk: &[u8]) -> String {
    let (ok, out) = apksigner_verify(apk, 24);
    assert!(ok, "apksigner rejected the APK:\n{out}");
    assert!(out.contains(&format!("{V2_LINE}true")), "{out}");
    assert!(out.contains(&format!("{V3_LINE}true")), "{out}");
    assert!(!out.contains("WARNING"), "unexpected warning:\n{out}");
    let fp = hex(&cert(&key()).sha256_fingerprint());
    assert!(
        out.contains(&format!("Signer #1 certificate SHA-256 digest: {fp}")),
        "certificate digest not shown:\n{out}"
    );
    assert!(
        out.contains("Signer #1 certificate DN: CN=petschaft test"),
        "{out}"
    );
    assert!(out.contains("Signer #1 key algorithm: EC"), "{out}");
    out
}

#[test]
fn always_v2_and_v3() {
    let (signed, asked) = sign_bytes(&write_zip(&sample_entries(), b""));
    assert_eq!(asked, vec![SchemeVersion::V2, SchemeVersion::V3]);
    let out = assert_verifies(&signed);
    eprintln!("{out}");
    // Note: apksigner 35.0.6 also accepts a v3-only APK with `--min-sdk-version 24` (it
    // does not require v2 coverage for API 24-27), so `sign` itself must always add v2.
    for min_sdk in [28, 35] {
        let (ok, out) = apksigner_verify(&signed, min_sdk);
        assert!(ok, "--min-sdk-version {min_sdk}:\n{out}");
    }
}

#[test]
fn zip_comment() {
    let (signed, _) = sign_bytes(&write_zip(&sample_entries(), b"a ZIP comment PK"));
    assert!(signed.ends_with(b"a ZIP comment PK"));
    assert_verifies(&signed);
}

#[test]
fn deflated_with_data_descriptor() {
    let mut entries = sample_entries();
    let mut d = deflated("assets/described.txt");
    d.descriptor = true;
    entries.push(d);
    let (signed, _) = sign_bytes(&write_zip(&entries, b""));
    assert_verifies(&signed);
}

#[test]
fn native_library_alignment() {
    let mut entries = sample_entries();
    entries.push(stored("x", b"odd"));
    entries.push(stored("lib/arm64-v8a/libfoo.so", &[0x7f; 5000]));
    entries.push(stored("lib/x86_64/libbar.so", &[0x7e; 33]));
    entries.push(deflated("lib/arm64-v8a/libdeflated.so"));
    entries.push(stored("assets/after.bin", b"12345"));
    // A pre-existing malformed (old zipalign) local extra.
    let mut z = stored("assets/zeros", b"z");
    z.local_extra = vec![0, 0, 0];
    entries.push(z);
    let input = write_zip(&entries, b"");
    // Not aligned as written.
    assert!(
        local_entries(&input)
            .iter()
            .any(|(n, off, m)| *m == 0 && n.ends_with(b".so") && off % 16384 != 0)
    );
    let (signed, _) = sign_bytes(&input);
    for (name, off, method) in local_entries(&signed) {
        if method != 0 {
            continue;
        }
        let a = if name.starts_with(b"lib/") && name.ends_with(b".so") {
            16384
        } else {
            4
        };
        assert_eq!(off % a, 0, "{} at {off}", String::from_utf8_lossy(&name));
    }
    assert_verifies(&signed);
}

#[test]
fn align_is_idempotent_and_keeps_aligned_input() {
    let input = write_zip(&sample_entries(), b"");
    let mut apk = Apk::parse(&input).unwrap();
    apk.align().unwrap();
    let d1 = apk.content_digest().unwrap();
    apk.align().unwrap();
    assert_eq!(apk.content_digest().unwrap(), d1);
    // Signed (aligned) output → parse → remove block → align changes nothing.
    let (signed, _) = sign_bytes(&input);
    let mut again = Apk::parse(&signed).unwrap();
    assert!(again.remove_signing_block());
    let before = again.content_digest().unwrap();
    again.align().unwrap();
    assert_eq!(again.content_digest().unwrap(), before);
    assert_eq!(before, d1);
}

#[test]
fn existing_signing_block_requires_explicit_removal() {
    let (signed, _) = sign_bytes(&write_zip(&sample_entries(), b""));
    let mut apk = Apk::parse(&signed).unwrap();
    assert!(apk.has_signing_block());
    assert!(matches!(
        apk.content_digest(),
        Err(Error::SigningBlockPresent)
    ));
    let k = key();
    let r = petschaft_apk::sign(&apk, &cert(&k), |_, _| panic!("must not ask the device"));
    assert!(matches!(r, Err(Error::SigningBlockPresent)));
    assert!(apk.remove_signing_block());
    // Re-signing gives a valid APK again.
    let resigned = petschaft_apk::sign(&apk, &cert(&k), |d, _| {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        let s: p256::ecdsa::Signature = k.sign_prehash(d).unwrap();
        Ok(s.to_der().to_bytes().to_vec())
    })
    .unwrap();
    assert_verifies(&resigned);
}

#[test]
fn bad_device_signature_is_never_embedded() {
    let mut apk = Apk::parse(&write_zip(&sample_entries(), b"")).unwrap();
    let r = petschaft_apk::sign(&apk, &cert(&key()), |_, _| {
        panic!("must not ask the device")
    });
    assert!(matches!(r, Err(Error::NotAligned)));
    apk.align().unwrap();
    assert!(apk.is_aligned().unwrap());
    let k = key();
    let other = p256::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap();
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    // Wrong key.
    let r = petschaft_apk::sign(&apk, &cert(&k), |d, _| {
        let s: p256::ecdsa::Signature = other.sign_prehash(d).unwrap();
        Ok(s.to_der().to_bytes().to_vec())
    });
    assert!(matches!(r, Err(Error::SignatureMismatch)));
    // Right key, wrong digest.
    let r = petschaft_apk::sign(&apk, &cert(&k), |_, _| {
        let s: p256::ecdsa::Signature = k.sign_prehash(&[1u8; 32]).unwrap();
        Ok(s.to_der().to_bytes().to_vec())
    });
    assert!(matches!(r, Err(Error::SignatureMismatch)));
    // Raw r||s instead of DER, and signer errors propagate.
    let r = petschaft_apk::sign(&apk, &cert(&k), |d, _| {
        let s: p256::ecdsa::Signature = k.sign_prehash(d).unwrap();
        Ok(s.to_bytes().to_vec())
    });
    assert!(matches!(r, Err(Error::MalformedSignature(_))));
    let r = petschaft_apk::sign(&apk, &cert(&k), |_, _| {
        Err(Error::Signer("cancelled".into()))
    });
    assert!(matches!(r, Err(Error::Signer(_))));
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).position(|w| w == needle).unwrap()
}

#[test]
fn apksigner_rejects_tampering() {
    let input = write_zip(&sample_entries(), b"comment");
    let (signed, _) = sign_bytes(&input);
    assert_verifies(&signed);

    // 1. Entry data.
    let mut t = signed.clone();
    let at = find(&t, &[0x42; 100]);
    t[at + 50] ^= 1;
    assert!(!apksigner_verify(&t, 24).0, "tampered entry data accepted");

    // 2. Central directory (a file name byte in the CD).
    let mut t = signed.clone();
    let cd = find(&t, &0x0201_4b50u32.to_le_bytes());
    t[cd + 46] ^= 0x20;
    assert!(
        !apksigner_verify(&t, 24).0,
        "tampered central directory accepted"
    );

    // 3. EOCD comment.
    let mut t = signed.clone();
    let last = t.len() - 1;
    t[last] ^= 1;
    assert!(!apksigner_verify(&t, 24).0, "tampered EOCD accepted");

    // 4. The signature bytes of the last signer (v3).
    let mut t = signed.clone();
    let magic = find(&t, b"APK Sig Block 42");
    // The public key (SPKI, 91 bytes) ends the v3 signer; the signature precedes it.
    t[magic - 8 - 91 - 4 - 10] ^= 1;
    assert!(!apksigner_verify(&t, 24).0, "tampered signature accepted");

    // 5. Stripping the v3 block (renaming its ID) must be caught by v2's stripping
    //    protection attribute (0xbeeff00d → 3).
    let mut t = signed.clone();
    let id = find(&t, &0xf053_68c0u32.to_le_bytes());
    t[id..id + 4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let (ok, out) = apksigner_verify(&t, 24);
    assert!(!ok, "stripped v3 block accepted:\n{out}");
    assert!(
        out.contains("signed using APK Signature Scheme v3 but no such signature was found"),
        "expected a stripping-protection error:\n{out}"
    );
}

#[test]
fn certificate_parses_with_openssl_if_available() {
    let Some(openssl) = std::env::var_os("PETSCHAFT_OPENSSL") else {
        eprintln!("PETSCHAFT_OPENSSL not set: openssl check skipped (apksigner covers parsing)");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.der");
    std::fs::write(&path, cert(&key()).der()).unwrap();
    let out = std::process::Command::new(openssl)
        .args(["x509", "-inform", "DER", "-noout", "-text", "-in"])
        .arg(&path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    eprintln!("{text}{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success());
    for needle in [
        "Version: 3 (0x2)",
        "Signature Algorithm: ecdsa-with-SHA256",
        "Issuer: CN=petschaft test",
        "Subject: CN=petschaft test",
        "Not Before: Jan  1 00:00:00 2026 GMT",
        "Not After : Jan  1 00:00:00 2126 GMT",
        "ASN1 OID: prime256v1",
    ] {
        assert!(text.contains(needle), "missing {needle:?}");
    }
}
