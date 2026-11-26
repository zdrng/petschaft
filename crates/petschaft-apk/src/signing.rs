//! v2/v3 signed data, signer blocks and the APK Signing Block (`docs/apk.md` steps 4-6).
//!
//! All length prefixes inside the v2/v3 blocks are little-endian u32; the ID-value pairs
//! of the APK Signing Block use little-endian u64 lengths [v2 §APK Signing Block,
//! §APK Signature Scheme v2 Block]; v3 adds minSDK/maxSDK [v3 §Format].

use sha2::{Digest as _, Sha256};

use crate::cert::{self, Certificate};
use crate::zip::{self, Apk, EOCD_CD_OFFSET, Layout, SIGNING_BLOCK_MAGIC};
use crate::{Error, Result};

/// Signature algorithm 0x0201: ECDSA with SHA2-256 digest [v2 §Signature algorithm IDs].
const SIG_ECDSA_SHA256: u32 = 0x0201;
/// ID of the v2 block in the APK Signing Block [v2 §APK Signature Scheme v2 Block].
const V2_BLOCK_ID: u32 = 0x7109_871a;
/// ID of the v3 block [v3 §APK Signing Block].
const V3_BLOCK_ID: u32 = 0xf053_68c0;
/// v2 additional attribute: stripping protection, value = u32 scheme version of the
/// stronger scheme that is also present (3). Defined by apksigner
/// (`V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID`, value
/// `VERSION_APK_SIGNATURE_SCHEME_V3`) and enforced by Android ≥ 9 / apksigner verify:
/// a v2 verifier seeing it refuses an APK whose v3 block was stripped.
const STRIPPING_PROTECTION_ATTR_ID: u32 = 0xbeef_f00d;
const SCHEME_V3: u32 = 3;
/// The v3 signer's minSDK: Android 9 (API 28), the first platform that reads v3. Older
/// platforms (7.0-8.1, API 24-27) ignore the v3 block and use v2. apksigner writes the
/// same value.
pub const V3_MIN_SDK: u32 = 28;
/// The v3 signer's maxSDK: no upper bound (apksigner: `Integer.MAX_VALUE`).
pub const V3_MAX_SDK: u32 = 0x7fff_ffff;
/// Trailing u64 size field plus magic, counted in the block's size fields.
const SIZE_FIELD_AND_MAGIC: usize = 8 + 16;

/// Which signature the callback is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemeVersion {
    /// APK Signature Scheme v2 (read by Android 7.0-8.1).
    V2,
    /// APK Signature Scheme v3 (read by Android 9 and later).
    V3,
}

fn lp(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| Error::TooLarge)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn lp_vec(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len().saturating_add(4));
    lp(&mut out, data)?;
    Ok(out)
}

/// `length-prefixed sequence of length-prefixed digests` with one (0x0201, digest).
fn digests(content_digest: &[u8; 32]) -> Result<Vec<u8>> {
    let mut d = SIG_ECDSA_SHA256.to_le_bytes().to_vec();
    lp(&mut d, content_digest)?;
    lp_vec(&lp_vec(&d)?)
}

/// `length-prefixed sequence of X.509 certificates` with one certificate.
fn certificates(cert: &Certificate) -> Result<Vec<u8>> {
    lp_vec(&lp_vec(cert.der())?)
}

/// `length-prefixed sequence of length-prefixed additional attributes`.
fn attributes(attrs: &[(u32, &[u8])]) -> Result<Vec<u8>> {
    let mut seq = Vec::new();
    for (id, value) in attrs {
        let mut a = id.to_le_bytes().to_vec();
        a.extend_from_slice(value);
        lp(&mut seq, &a)?;
    }
    lp_vec(&seq)
}

/// v2 signed data [v2 §APK Signature Scheme v2 Block]: digests, certificates, attributes.
fn v2_signed_data(content_digest: &[u8; 32], cert: &Certificate, with_v3: bool) -> Result<Vec<u8>> {
    let mut sd = digests(content_digest)?;
    sd.extend_from_slice(&certificates(cert)?);
    let strip = SCHEME_V3.to_le_bytes();
    let attrs: &[(u32, &[u8])] = if with_v3 {
        &[(STRIPPING_PROTECTION_ATTR_ID, &strip)]
    } else {
        &[]
    };
    sd.extend_from_slice(&attributes(attrs)?);
    Ok(sd)
}

/// v3 signed data [v3 §Format]: digests, certificates, minSDK, maxSDK, attributes (none:
/// no proof-of-rotation).
fn v3_signed_data(content_digest: &[u8; 32], cert: &Certificate) -> Result<Vec<u8>> {
    let mut sd = digests(content_digest)?;
    sd.extend_from_slice(&certificates(cert)?);
    sd.extend_from_slice(&V3_MIN_SDK.to_le_bytes());
    sd.extend_from_slice(&V3_MAX_SDK.to_le_bytes());
    sd.extend_from_slice(&attributes(&[])?);
    Ok(sd)
}

/// `length-prefixed sequence of length-prefixed signatures` with one (0x0201, sig).
fn signatures(sig_der: &[u8]) -> Result<Vec<u8>> {
    let mut s = SIG_ECDSA_SHA256.to_le_bytes().to_vec();
    lp(&mut s, sig_der)?;
    lp_vec(&lp_vec(&s)?)
}

/// Scheme block value: `length-prefixed sequence of length-prefixed signer` with one
/// signer. v2 signer: signed data, signatures, public key; v3 signer: signed data,
/// minSDK, maxSDK (duplicates, "Must match signed data value"), signatures, public key.
fn scheme_block(
    scheme: SchemeVersion,
    signed_data: &[u8],
    sig_der: &[u8],
    spki: &[u8],
) -> Result<Vec<u8>> {
    let mut signer = lp_vec(signed_data)?;
    if scheme == SchemeVersion::V3 {
        signer.extend_from_slice(&V3_MIN_SDK.to_le_bytes());
        signer.extend_from_slice(&V3_MAX_SDK.to_le_bytes());
    }
    signer.extend_from_slice(&signatures(sig_der)?);
    lp(&mut signer, spki)?;
    lp_vec(&lp_vec(&signer)?)
}

/// APK Signing Block [v2 §APK Signing Block]: u64 size (excluding this field), ID-value
/// pairs (u64 length of id + value, u32 id, value), u64 size (same), magic.
fn signing_block(pairs: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for (id, value) in pairs {
        let len = value
            .len()
            .checked_add(4)
            .and_then(|l| u64::try_from(l).ok())
            .ok_or(Error::TooLarge)?;
        body.extend_from_slice(&len.to_le_bytes());
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(value);
    }
    let size = body
        .len()
        .checked_add(SIZE_FIELD_AND_MAGIC)
        .and_then(|l| u64::try_from(l).ok())
        .ok_or(Error::TooLarge)?;
    let mut block = Vec::with_capacity(body.len().saturating_add(32));
    block.extend_from_slice(&size.to_le_bytes());
    block.extend_from_slice(&body);
    block.extend_from_slice(&size.to_le_bytes());
    block.extend_from_slice(SIGNING_BLOCK_MAGIC);
    Ok(block)
}

/// Signs `apk` with APK Signature Scheme v2 and v3 (in this order), as apksigner does by
/// default for minSdkVersion 24-27; the v2 signature carries the stripping-protection
/// attribute for v3. Apps with minSdkVersion < 24 would need v1 (JAR) signatures, which
/// are not supported: such an APK would not install on Android < 7.0.
///
/// `sign_digest` receives SHA-256 of the scheme's signed data (the device signs exactly
/// this digest, ECDSA P-256) and returns a DER ECDSA signature. Every returned signature
/// is verified against `cert`'s public key before it is embedded; the assembled APK is
/// re-parsed and its content digest recomputed as a consistency check. The caller still
/// runs `apksigner verify` (`docs/apk.md` step 7).
///
/// The APK must not carry a signing block (see [`Apk::remove_signing_block`]) and must be
/// aligned (call [`Apk::align`]).
pub fn sign(
    apk: &Apk,
    cert: &Certificate,
    mut sign_digest: impl FnMut(&[u8; 32], SchemeVersion) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    // Android needs aligned stored entries (resources.arsc for targetSdk ≥ 30, 16 KiB
    // native libraries); refuse instead of producing an APK that installs nowhere.
    if apk.has_signing_block() {
        return Err(Error::SigningBlockPresent);
    }
    if !apk.is_aligned()? {
        return Err(Error::NotAligned);
    }
    let Layout {
        entries,
        cd,
        mut eocd,
    } = apk.layout()?;
    let content_digest = crate::digest::content_digest(&[&entries, &cd, &eocd])?;
    let spki = cert::subject_public_key_info(cert.public_key());
    let schemes = [
        (
            SchemeVersion::V2,
            v2_signed_data(&content_digest, cert, true)?,
        ),
        (SchemeVersion::V3, v3_signed_data(&content_digest, cert)?),
    ];

    let mut pairs = Vec::new();
    for (scheme, signed_data) in schemes {
        let digest: [u8; 32] = Sha256::digest(&signed_data).into();
        let sig = sign_digest(&digest, scheme)?;
        // Fail closed: never embed a signature that does not verify.
        cert::verify_digest(cert.public_key(), &digest, &sig)?;
        let id = match scheme {
            SchemeVersion::V2 => V2_BLOCK_ID,
            SchemeVersion::V3 => V3_BLOCK_ID,
        };
        pairs.push((id, scheme_block(scheme, &signed_data, &sig, &spki)?));
    }
    let block = signing_block(&pairs)?;

    let cd_off = entries
        .len()
        .checked_add(block.len())
        .ok_or(Error::TooLarge)?;
    zip::put_u32(
        &mut eocd,
        EOCD_CD_OFFSET,
        u32::try_from(cd_off).map_err(|_| Error::TooLarge)?,
    )?;
    let total = [entries.len(), block.len(), cd.len(), eocd.len()]
        .iter()
        .try_fold(0usize, |a, l| a.checked_add(*l))
        .ok_or(Error::TooLarge)?;
    if u32::try_from(total).is_err() {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&entries);
    drop(entries);
    out.extend_from_slice(&block);
    out.extend_from_slice(&cd);
    drop(cd);
    out.extend_from_slice(&eocd);

    // Self-check: the output parses strictly, carries exactly this block, and has the
    // content digest that was signed. The output is moved into the parser and back (no
    // further full copy).
    let mut reparsed =
        Apk::parse_owned(out).map_err(|_| Error::Internal("signed APK does not parse"))?;
    if !reparsed.remove_signing_block() || reparsed.content_digest()? != content_digest {
        return Err(Error::Internal("signed APK content digest mismatch"));
    }
    Ok(reparsed.into_bytes())
}
