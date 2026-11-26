//! Strict-parser rejection cases and property tests (no apksigner needed).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::*;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use petschaft_apk::{Apk, Error};
use proptest::prelude::*;

fn sample() -> Vec<u8> {
    write_zip(&sample_entries(), b"")
}

fn eocd_pos(z: &[u8]) -> usize {
    z.windows(4)
        .rposition(|w| w == 0x0605_4b50u32.to_le_bytes())
        .unwrap()
}

fn cd_pos(z: &[u8]) -> usize {
    let e = eocd_pos(z);
    u32::from_le_bytes(z[e + 16..e + 20].try_into().unwrap()) as usize
}

fn malformed(r: Result<Apk, Error>) -> bool {
    matches!(r, Err(Error::Malformed(_)))
}

fn unsupported(r: Result<Apk, Error>) -> bool {
    matches!(r, Err(Error::Unsupported(_)))
}

#[test]
fn sample_parses() {
    let apk = Apk::parse(&sample()).unwrap();
    assert_eq!(apk.len(), 4);
    assert!(!apk.has_signing_block());
}

#[test]
fn every_truncation_is_rejected() {
    let z = sample();
    for len in 0..z.len() {
        assert!(Apk::parse(&z[..len]).is_err(), "prefix {len} accepted");
    }
    // Leading junk shifts all offsets.
    let mut j = vec![0u8];
    j.extend_from_slice(&z);
    assert!(Apk::parse(&j).is_err());
    // Trailing junk breaks the EOCD comment length.
    let mut t = z.clone();
    t.push(0);
    assert!(malformed(Apk::parse(&t)));
}

#[test]
fn bad_eocd() {
    let z = sample();
    let e = eocd_pos(&z);
    let patch = |off: usize, bytes: &[u8]| {
        let mut t = z.clone();
        t[e + off..e + off + bytes.len()].copy_from_slice(bytes);
        t
    };
    assert!(malformed(Apk::parse(&patch(0, &[0x50, 0x4b, 0x05, 0x07]))));
    assert!(malformed(Apk::parse(&patch(20, &1u16.to_le_bytes())))); // comment length
    let cd = cd_pos(&z) as u32;
    assert!(malformed(Apk::parse(&patch(16, &(cd + 1).to_le_bytes()))));
    assert!(malformed(Apk::parse(&patch(16, &(cd - 1).to_le_bytes()))));
    let size = u32::from_le_bytes(z[e + 12..e + 16].try_into().unwrap());
    assert!(malformed(Apk::parse(&patch(12, &(size - 1).to_le_bytes()))));
    // Entry counts.
    assert!(malformed(Apk::parse(&patch(8, &[3, 0, 3, 0]))));
    assert!(malformed(Apk::parse(&patch(8, &[5, 0, 5, 0]))));
    assert!(malformed(Apk::parse(&patch(8, &[0, 0, 0, 0]))));
    assert!(unsupported(Apk::parse(&patch(8, &[3, 0, 4, 0]))));
    // Multi-disk.
    assert!(unsupported(Apk::parse(&patch(4, &[1, 0]))));
    assert!(unsupported(Apk::parse(&patch(6, &[1, 0]))));
}

#[test]
fn ambiguous_eocd_in_comment() {
    // The comment ends with a complete, self-consistent fake EOCD.
    let mut fake = 0x0605_4b50u32.to_le_bytes().to_vec();
    fake.extend_from_slice(&[0; 18]);
    let z = write_zip(&sample_entries(), &fake);
    assert!(malformed(Apk::parse(&z)));
    // A signature in the comment that is not self-consistent is fine.
    let z = write_zip(&sample_entries(), b"PK\x05\x06 not an EOCD");
    Apk::parse(&z).unwrap();
}

#[test]
fn zip64_markers() {
    let z = sample();
    let e = eocd_pos(&z);
    let mut t = z.clone();
    t[e + 10..e + 12].copy_from_slice(&[0xff, 0xff]);
    t[e + 8..e + 10].copy_from_slice(&[0xff, 0xff]);
    assert!(unsupported(Apk::parse(&t)));
    let mut t = z.clone();
    t[e + 16..e + 20].copy_from_slice(&[0xff; 4]);
    assert!(unsupported(Apk::parse(&t)));
    let mut t = z.clone();
    t[e + 12..e + 16].copy_from_slice(&[0xff; 4]);
    assert!(unsupported(Apk::parse(&t)));
    // ZIP64 EOCD locator signature 20 bytes before the EOCD (here: the end of the
    // last central directory file name).
    let mut entries = sample_entries();
    let mut name = b"assets/".to_vec();
    name.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    name.extend_from_slice(&[b'a'; 16]);
    entries.push(ZipEntry {
        name,
        ..stored("x", b"x")
    });
    assert!(unsupported(Apk::parse(&write_zip(&entries, b""))));
    // ZIP64 extra field in a local header.
    let mut entries = sample_entries();
    entries[0].local_extra = vec![0x01, 0x00, 0x00, 0x00];
    assert!(unsupported(Apk::parse(&write_zip(&entries, b""))));
    // 0xFFFFFFFF sizes in the central directory.
    let mut t = z.clone();
    let cd = cd_pos(&z);
    t[cd + 20..cd + 24].copy_from_slice(&[0xff; 4]);
    assert!(unsupported(Apk::parse(&t)));
}

#[test]
fn overlapping_duplicate_and_gaps() {
    let z = sample();
    let cd = cd_pos(&z);
    // Second CD record (classes.dex) pointing at the first local header.
    let second = cd + 46 + "AndroidManifest.xml".len();
    let mut t = z.clone();
    t[second + 42..second + 46].copy_from_slice(&0u32.to_le_bytes());
    assert!(malformed(Apk::parse(&t)));
    // Two CD records for the same local entry and name.
    let entries = vec![stored("a", b"1"), stored("a", b"1")];
    let mut t = write_zip(&entries, b"");
    let cd = cd_pos(&t);
    let second = cd + 46 + 1;
    t[second + 42..second + 46].copy_from_slice(&0u32.to_le_bytes());
    assert!(malformed(Apk::parse(&t)));
    // Duplicate names in separate entries.
    let entries = vec![stored("a", b"1"), stored("a", b"2")];
    assert!(malformed(Apk::parse(&write_zip(&entries, b""))));
    // Bytes between the last entry and the CD.
    let mut t = z.clone();
    let cd = cd_pos(&z);
    t.splice(cd..cd, [0u8; 8]);
    let e = eocd_pos(&t);
    t[e + 16..e + 20].copy_from_slice(&((cd + 8) as u32).to_le_bytes());
    assert!(malformed(Apk::parse(&t)));
    // Stored size bigger than the data (overlaps the next local header).
    let mut entries = sample_entries();
    entries[0].uncompressed += 4;
    let mut t = write_zip(&entries, b"");
    // Fix the sizes in local + CD to the larger value so they agree with each other.
    let n = entries[0].data.len() as u32 + 4;
    t[18..22].copy_from_slice(&n.to_le_bytes());
    let cd = cd_pos(&t);
    t[cd + 20..cd + 24].copy_from_slice(&n.to_le_bytes());
    assert!(malformed(Apk::parse(&t)));
}

#[test]
fn local_header_consistency() {
    let z = sample();
    // Local name differs from the CD name.
    let mut t = z.clone();
    t[30] ^= 0x20;
    assert!(malformed(Apk::parse(&t)));
    // Local method differs.
    let mut t = z.clone();
    t[8] = 8;
    assert!(malformed(Apk::parse(&t)));
    // Local CRC differs.
    let mut t = z.clone();
    t[14] ^= 1;
    assert!(malformed(Apk::parse(&t)));
    // Bad local signature.
    let mut t = z.clone();
    t[0] = 0;
    assert!(malformed(Apk::parse(&t)));
    // Data descriptor flag without a descriptor.
    let mut entries = sample_entries();
    entries[1].descriptor = true;
    let mut t = write_zip(&entries, b"");
    let dd = t
        .windows(4)
        .position(|w| w == 0x0807_4b50u32.to_le_bytes())
        .unwrap();
    t[dd] = 0;
    assert!(malformed(Apk::parse(&t)));
}

#[test]
fn unsupported_features() {
    // Encryption flag (local and CD).
    let z = sample();
    let mut t = z.clone();
    t[6] |= 1;
    let cd = cd_pos(&z);
    t[cd + 8] |= 1;
    assert!(unsupported(Apk::parse(&t)));
    // bzip2.
    let mut entries = sample_entries();
    entries[1].method = 12;
    assert!(unsupported(Apk::parse(&write_zip(&entries, b""))));
    // Stored with differing sizes.
    let mut entries = sample_entries();
    entries[0].uncompressed += 1;
    assert!(malformed(Apk::parse(&write_zip(&entries, b""))));
}

#[test]
fn signing_block_detection() {
    let (signed, _) = sign_bytes(&sample());
    let apk = Apk::parse(&signed).unwrap();
    assert!(apk.has_signing_block());
    assert!(matches!(
        apk.content_digest(),
        Err(Error::SigningBlockPresent)
    ));
    // Inconsistent size fields.
    let magic = signed
        .windows(16)
        .position(|w| w == b"APK Sig Block 42")
        .unwrap();
    let mut t = signed.clone();
    t[magic - 8] ^= 1;
    assert!(malformed(Apk::parse(&t)));
    let cd = cd_pos(&signed);
    let footer = u64::from_le_bytes(signed[magic - 8..magic].try_into().unwrap()) as usize;
    let start = cd - footer - 8;
    let mut t = signed.clone();
    t[start] ^= 1;
    assert!(malformed(Apk::parse(&t)));
}

#[test]
fn parse_owned_matches_parse() {
    let z = sample();
    let a = Apk::parse(&z).unwrap();
    let b = Apk::parse_owned(z.clone()).unwrap();
    assert_eq!(a.content_digest().unwrap(), b.content_digest().unwrap());
    assert!(malformed(Apk::parse_owned(z[1..].to_vec())));
}

#[test]
fn alignment_never_creates_a_zip64_extra() {
    // Found by `generated_archives_align_and_sign`: a stored entry whose 1-byte local
    // extra `[0x01]` would be zero-padded into a ZIP64 extra record.
    let mut e = stored("lib/aa/a/a.txt", b"");
    e.local_extra = vec![1];
    let mut apk = Apk::parse(&write_zip(&[e], b"")).unwrap();
    assert!(matches!(apk.align(), Err(Error::Unsupported(_))));
}

#[test]
fn v1_signature_files_detected() {
    assert!(
        Apk::parse(&sample())
            .unwrap()
            .v1_signature_files()
            .is_empty()
    );
    let mut entries = sample_entries();
    let v1 = [
        "META-INF/CERT.SF",
        "META-INF/cert.rsa",
        "meta-inf/KEY.Ec",
        "META-INF/X.DSA",
        "META-INF/.SF",
    ];
    let other = [
        "META-INF/MANIFEST.MF",
        "META-INF/sub/A.SF",
        "assets/META-INF/A.SF",
        "META-INF/A.SFX",
        "META-INF/RSA",
        "META-INF/services/x",
    ];
    for n in v1.iter().chain(&other) {
        entries.push(stored(n, b"x"));
    }
    let apk = Apk::parse(&write_zip(&entries, b"")).unwrap();
    assert_eq!(apk.v1_signature_files(), v1);
}

#[test]
fn content_digest_reference() {
    // Independent computation for a small unsigned APK: one chunk per section.
    use sha2::{Digest, Sha256};
    let z = sample();
    let cd = cd_pos(&z);
    let e = eocd_pos(&z);
    let mut apk = Apk::parse(&z).unwrap();
    // Without align the layout is the input itself.
    let mut top = vec![0x5a, 3, 0, 0, 0];
    for s in [&z[..cd], &z[cd..e], &z[e..]] {
        let mut c = vec![0xa5];
        c.extend_from_slice(&(s.len() as u32).to_le_bytes());
        c.extend_from_slice(s);
        top.extend_from_slice(&Sha256::digest(&c));
    }
    let expected: [u8; 32] = Sha256::digest(&top).into();
    assert_eq!(apk.content_digest().unwrap(), expected);
    apk.align().unwrap();
    assert_ne!(
        apk.content_digest().unwrap(),
        expected,
        "sample is not aligned"
    );
}

fn arb_entry() -> impl Strategy<Value = ZipEntry> {
    (
        "[a-z]{1,6}(/[a-z]{1,6}){0,2}(\\.so|\\.txt|)",
        proptest::collection::vec(any::<u8>(), 0..300),
        any::<bool>(),
        any::<bool>(),
        proptest::option::of(proptest::collection::vec(any::<u8>(), 0..8)),
    )
        .prop_map(|(name, data, deflate, descriptor, extra)| {
            let name = if deflate { name } else { format!("lib/{name}") };
            let mut e = stored(&name, &data);
            if deflate {
                // The parser never inflates; arbitrary bytes stand in for deflate data.
                e.method = 8;
                e.uncompressed = data.len() as u32 * 2;
                e.descriptor = descriptor;
            }
            if let Some(x) = extra {
                e.local_extra = x;
            }
            e
        })
}

fn arb_archive() -> impl Strategy<Value = Vec<u8>> {
    (
        proptest::collection::vec(arb_entry(), 1..8),
        proptest::collection::vec(any::<u8>(), 0..40),
    )
        .prop_map(|(mut entries, comment)| {
            let mut seen = std::collections::BTreeSet::new();
            entries.retain(|e| seen.insert(e.name.clone()));
            // Avoid ZIP64 extra ids, also ones that zero padding of a malformed extra
            // would create (`[1]` → `01 00 00 00`), and EOCD signatures in comments
            // (tested separately).
            for e in &mut entries {
                for b in &mut e.local_extra {
                    if *b == 1 {
                        *b = 2;
                    }
                }
            }
            write_zip(
                &entries,
                &comment.iter().map(|b| b & 0x7f).collect::<Vec<_>>(),
            )
        })
}

fn soft_sign(apk: &Apk) -> Result<Vec<u8>, Error> {
    let k = key();
    petschaft_apk::sign(apk, &cert(&k), |d, _| {
        let s: p256::ecdsa::Signature = k.sign_prehash(d).unwrap();
        Ok(s.to_der().to_bytes().to_vec())
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
        if let Ok(mut apk) = Apk::parse(&bytes) {
            let _ = apk.content_digest();
            let _ = apk.align();
        }
    }

    #[test]
    fn mutated_apks_never_panic(
        signed in any::<bool>(),
        mutations in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..4), 1..6),
    ) {
        let base = sample();
        let mut z = if signed { sign_bytes(&base).0 } else { base };
        for (idx, byte, kind) in mutations {
            if z.is_empty() { break; }
            let i = idx.index(z.len());
            match kind {
                0 => z[i] = byte,
                1 => z[i] ^= 1 << (byte % 8),
                2 => z.truncate(i),
                _ => z.insert(i, byte),
            }
        }
        if let Ok(mut apk) = Apk::parse(&z) {
            apk.remove_signing_block();
            let _ = apk.content_digest();
            if apk.align().is_ok() {
                // Whatever parses must also sign, and the result must parse again.
                let out = soft_sign(&apk).unwrap();
                prop_assert!(Apk::parse(&out).unwrap().has_signing_block());
            }
        }
    }

    #[test]
    fn generated_archives_align_and_sign(z in arb_archive()) {
        let mut apk = Apk::parse(&z).unwrap();
        apk.align().unwrap();
        let digest = apk.content_digest().unwrap();
        let out = soft_sign(&apk).unwrap();
        for (name, off, method) in local_entries(&out) {
            if method == 0 {
                let a = if name.starts_with(b"lib/") && name.ends_with(b".so") { 16384 } else { 4 };
                prop_assert_eq!(off % a, 0);
            }
        }
        let mut again = Apk::parse(&out).unwrap();
        prop_assert!(again.remove_signing_block());
        prop_assert_eq!(again.content_digest().unwrap(), digest);
        prop_assert_eq!(again.len(), apk.len());
    }
}
