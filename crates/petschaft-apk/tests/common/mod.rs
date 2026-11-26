//! Test support: an independent minimal ZIP writer (deliberately not the crate's code),
//! a software P-256 signer and the `apksigner` runner.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::path::PathBuf;
use std::process::Command;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use petschaft_apk::{Apk, Certificate, SchemeVersion};

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub name: Vec<u8>,
    pub method: u16,
    pub data: Vec<u8>,
    pub crc: u32,
    pub uncompressed: u32,
    pub local_extra: Vec<u8>,
    /// Bit 3: zero CRC/sizes in the local header, data descriptor with signature.
    pub descriptor: bool,
}

pub fn stored(name: &str, data: &[u8]) -> ZipEntry {
    ZipEntry {
        name: name.as_bytes().to_vec(),
        method: 0,
        data: data.to_vec(),
        crc: crc32(data),
        uncompressed: data.len() as u32,
        local_extra: Vec::new(),
        descriptor: false,
    }
}

/// `b"petschaft deflate fixture\n" * 20`, raw deflate produced once with
/// `python3 -I -c 'import zlib; c=zlib.compressobj(9, zlib.DEFLATED, -15); …'`.
pub const DEFLATE_FIXTURE: [u8; 33] = [
    0x2b, 0x48, 0x2d, 0x29, 0x4e, 0xce, 0x48, 0x4c, 0x2b, 0x51, 0x48, 0x49, 0x4d, 0xcb, 0x49, 0x2c,
    0x49, 0x55, 0x48, 0xcb, 0xac, 0x28, 0x29, 0x2d, 0x4a, 0xe5, 0x2a, 0x18, 0x95, 0x19, 0x41, 0x32,
    0x00,
];

pub fn deflated(name: &str) -> ZipEntry {
    let plain = b"petschaft deflate fixture\n".repeat(20);
    assert_eq!(crc32(&plain), 0xdc85_f926);
    ZipEntry {
        name: name.as_bytes().to_vec(),
        method: 8,
        data: DEFLATE_FIXTURE.to_vec(),
        crc: crc32(&plain),
        uncompressed: plain.len() as u32,
        local_extra: Vec::new(),
        descriptor: false,
    }
}

pub fn write_zip(entries: &[ZipEntry], comment: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for e in entries {
        let offset = out.len() as u32;
        let flags: u16 = if e.descriptor { 8 } else { 0 };
        let (crc, cs, us) = if e.descriptor {
            (0, 0, 0)
        } else {
            (e.crc, e.data.len() as u32, e.uncompressed)
        };
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&e.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0x5c21u16.to_le_bytes()); // date 2026-01-01
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&cs.to_le_bytes());
        out.extend_from_slice(&us.to_le_bytes());
        out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(e.local_extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&e.name);
        out.extend_from_slice(&e.local_extra);
        out.extend_from_slice(&e.data);
        if e.descriptor {
            out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
            out.extend_from_slice(&e.crc.to_le_bytes());
            out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&e.uncompressed.to_le_bytes());
        }
        cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes()); // made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // needed
        cd.extend_from_slice(&flags.to_le_bytes());
        cd.extend_from_slice(&e.method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0x5c21u16.to_le_bytes());
        cd.extend_from_slice(&e.crc.to_le_bytes());
        cd.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&e.uncompressed.to_le_bytes());
        cd.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal
        cd.extend_from_slice(&0u32.to_le_bytes()); // external
        cd.extend_from_slice(&offset.to_le_bytes());
        cd.extend_from_slice(&e.name);
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    out
}

/// A small but realistic APK-shaped archive: stored + deflated entries, an odd-length
/// entry before a stored file so alignment matters.
pub fn sample_entries() -> Vec<ZipEntry> {
    vec![
        stored("AndroidManifest.xml", b"not a real binary manifest"),
        deflated("classes.dex"),
        stored("res/odd", b"123"),
        stored("resources.arsc", &[0x42; 100]),
    ]
}

pub fn key() -> SigningKey {
    SigningKey::from_slice(&[0x11; 32]).unwrap()
}

pub fn point(k: &SigningKey) -> [u8; 65] {
    k.verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

pub fn cert(k: &SigningKey) -> Certificate {
    let tbs = Certificate::build(&point(k), "petschaft test").unwrap();
    let sig: p256::ecdsa::Signature = k.sign_prehash(&tbs.digest()).unwrap();
    tbs.finish(&sig.to_der().to_bytes()).unwrap()
}

/// Parses, aligns and signs with the software key; returns the signed APK and the
/// schemes the callback was asked for.
pub fn sign_bytes(input: &[u8]) -> (Vec<u8>, Vec<SchemeVersion>) {
    let k = key();
    let c = cert(&k);
    let mut apk = Apk::parse(input).unwrap();
    apk.align().unwrap();
    let mut asked = Vec::new();
    let out = petschaft_apk::sign(&apk, &c, |digest, scheme| {
        asked.push(scheme);
        let sig: p256::ecdsa::Signature = k.sign_prehash(digest).unwrap();
        Ok(sig.to_der().to_bytes().to_vec())
    })
    .unwrap();
    (out, asked)
}

pub fn apksigner() -> PathBuf {
    match std::env::var_os("PETSCHAFT_APKSIGNER") {
        Some(p) => PathBuf::from(p),
        None => panic!(
            "PETSCHAFT_APKSIGNER is not set: point it at the apksigner binary \
             (e.g. PETSCHAFT_APKSIGNER=/nix/store/…-apksigner-35.0.6/bin/apksigner)"
        ),
    }
}

/// Runs `apksigner verify -v --print-certs --min-sdk-version N`; returns (success, output).
pub fn apksigner_verify(apk: &[u8], min_sdk: u32) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.apk");
    std::fs::write(&path, apk).unwrap();
    let out = Command::new(apksigner())
        .args(["verify", "-v", "--print-certs", "--min-sdk-version"])
        .arg(min_sdk.to_string())
        .arg(&path)
        .output()
        .expect("run apksigner");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Independent walk over the local headers: (name, data offset, method).
pub fn local_entries(apk: &[u8]) -> Vec<(Vec<u8>, usize, u16)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while apk[pos..pos + 4] == 0x0403_4b50u32.to_le_bytes() {
        let flags = u16::from_le_bytes([apk[pos + 6], apk[pos + 7]]);
        let method = u16::from_le_bytes([apk[pos + 8], apk[pos + 9]]);
        let mut csize = u32::from_le_bytes(apk[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let n = u16::from_le_bytes([apk[pos + 26], apk[pos + 27]]) as usize;
        let m = u16::from_le_bytes([apk[pos + 28], apk[pos + 29]]) as usize;
        let name = apk[pos + 30..pos + 30 + n].to_vec();
        let data = pos + 30 + n + m;
        let mut end = data;
        if flags & 8 != 0 {
            // Find the descriptor by signature (test data never contains it).
            let rel = apk[data..]
                .windows(4)
                .position(|w| w == 0x0807_4b50u32.to_le_bytes())
                .unwrap();
            csize = rel;
            end += 16;
        }
        end += csize;
        out.push((name, data, method));
        pos = end;
    }
    out
}
