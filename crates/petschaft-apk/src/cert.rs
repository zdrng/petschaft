//! Minimal self-signed X.509 v3 certificate for the APK signing key (RFC 5280).
//!
//! Android identifies an app's signer by the exact certificate bytes, so the encoding is
//! fully deterministic: the same public key and CN always give the same TBSCertificate.
//! ECDSA signatures are randomized (or RFC 6979), so the final certificate differs per
//! signing run; the config therefore stores it once (`pets apk init`).

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::{Digest as _, Sha256};

use crate::der::{self, Reader};
use crate::{Error, Result};

/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2), RFC 5758 §3.2: parameters MUST be absent.
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// `id-ecPublicKey` (1.2.840.10045.2.1), RFC 5480 §2.1.1.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `secp256r1` / `prime256v1` (1.2.840.10045.3.1.7), RFC 5480 §2.1.1.1 (namedCurve).
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `id-at-commonName` (2.5.4.3).
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// notBefore 2026-01-01T00:00:00Z as UTCTime (RFC 5280 §4.1.2.5: dates before 2050).
const NOT_BEFORE: &[u8] = b"260101000000Z";
/// notAfter 2126-01-01T00:00:00Z as GeneralizedTime (RFC 5280 §4.1.2.5: 2050 and later).
const NOT_AFTER: &[u8] = b"21260101000000Z";
/// Maximum CN length (RFC 5280 Appendix A, `ub-common-name` = 64).
const MAX_CN_LEN: usize = 64;

fn algorithm_identifier() -> Vec<u8> {
    der::constructed(der::SEQUENCE, &[&der::tlv(der::OID, OID_ECDSA_WITH_SHA256)])
}

/// `SubjectPublicKeyInfo` for an uncompressed P-256 point (RFC 5480 §2): this is also the
/// `public key` field of the v2/v3 signer [v2 §APK Signature Scheme v2 Block].
pub(crate) fn subject_public_key_info(point: &[u8; 65]) -> Vec<u8> {
    let alg = der::constructed(
        der::SEQUENCE,
        &[
            &der::tlv(der::OID, OID_EC_PUBLIC_KEY),
            &der::tlv(der::OID, OID_PRIME256V1),
        ],
    );
    // BIT STRING with 0 unused bits, then the SEC1 point (RFC 5480 §2.2).
    let bits = der::constructed(der::BIT_STRING, &[&[0], point]);
    der::constructed(der::SEQUENCE, &[&alg, &bits])
}

/// `Name ::= SEQUENCE OF SET OF AttributeTypeAndValue`, here exactly one CN, as UTF8String
/// (RFC 5280 §4.1.2.6: DirectoryString, UTF8String preferred).
fn name(cn: &str) -> Vec<u8> {
    let atv = der::constructed(
        der::SEQUENCE,
        &[
            &der::tlv(der::OID, OID_COMMON_NAME),
            &der::tlv(der::UTF8_STRING, cn.as_bytes()),
        ],
    );
    let rdn = der::tlv(der::SET, &atv);
    der::tlv(der::SEQUENCE, &rdn)
}

fn validate_cn(cn: &str) -> Result<()> {
    if cn.is_empty() {
        return Err(Error::InvalidSubject("empty"));
    }
    if cn.len() > MAX_CN_LEN {
        return Err(Error::InvalidSubject("longer than 64 characters"));
    }
    if !cn.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Error::InvalidSubject("not printable ASCII"));
    }
    Ok(())
}

fn verifying_key(point: &[u8; 65]) -> Result<VerifyingKey> {
    // Only the uncompressed form; `from_sec1_bytes` checks that the point is on the curve
    // and not the identity.
    if point.first() != Some(&0x04) {
        return Err(Error::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(point).map_err(|_| Error::InvalidPublicKey)
}

/// Verifies a DER ECDSA signature over a SHA-256 digest (strict DER, see `der`).
pub(crate) fn verify_digest(point: &[u8; 65], digest: &[u8; 32], sig_der: &[u8]) -> Result<()> {
    let vk = verifying_key(point)?;
    let sig = der::parse_ecdsa_signature(sig_der)?;
    vk.verify_prehash(digest, &sig)
        .map_err(|_| Error::SignatureMismatch)
}

/// An unsigned certificate (`TBSCertificate`). The device signs [`TbsCertificate::digest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbsCertificate {
    der: Vec<u8>,
    public_key: [u8; 65],
    subject_cn: String,
}

impl TbsCertificate {
    /// The DER encoding of the TBSCertificate.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// SHA-256 of the TBSCertificate DER: the digest the device signs (`ecdsa-with-SHA256`).
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.der).into()
    }

    /// Attaches the DER ECDSA signature over [`Self::digest`]. The signature is verified
    /// against the certificate's own public key first (fail closed).
    pub fn finish(self, signature_der: &[u8]) -> Result<Certificate> {
        verify_digest(&self.public_key, &self.digest(), signature_der)?;
        let bits = der::constructed(der::BIT_STRING, &[&[0], signature_der]);
        let der = der::constructed(der::SEQUENCE, &[&self.der, &algorithm_identifier(), &bits]);
        Ok(Certificate {
            der,
            public_key: self.public_key,
            subject_cn: self.subject_cn,
        })
    }
}

/// A self-signed certificate whose signature has been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
    public_key: [u8; 65],
    subject_cn: String,
}

impl Certificate {
    /// Builds the TBSCertificate (RFC 5280 §4.1) for an uncompressed SEC1 P-256 public key:
    ///
    /// - version v3 (§4.1.2.1), no extensions (minimal; Android does not need any),
    /// - serial = first 16 bytes of SHA-256(public key) as a positive minimal INTEGER
    ///   (§4.1.2.2: positive, at most 20 octets),
    /// - signature = issuer signature algorithm `ecdsa-with-SHA256` without parameters,
    /// - issuer = subject = `CN=<subject_cn>` (1-64 printable ASCII),
    /// - validity 2026-01-01T00:00:00Z to 2126-01-01T00:00:00Z.
    pub fn build(public_key: &[u8; 65], subject_cn: &str) -> Result<TbsCertificate> {
        verifying_key(public_key)?;
        validate_cn(subject_cn)?;
        let hash: [u8; 32] = Sha256::digest(public_key).into();
        let serial_bytes = hash.get(..16).ok_or(Error::Internal("hash length"))?;
        // A zero serial would need 128 zero bits of SHA-256; still refused, never encoded.
        let serial =
            der::positive_integer(serial_bytes).ok_or(Error::Internal("zero serial number"))?;
        let version = der::tlv(der::CONTEXT_0, &der::tlv(der::INTEGER, &[2]));
        let name = name(subject_cn);
        let validity = der::constructed(
            der::SEQUENCE,
            &[
                &der::tlv(der::UTC_TIME, NOT_BEFORE),
                &der::tlv(der::GENERALIZED_TIME, NOT_AFTER),
            ],
        );
        let der = der::constructed(
            der::SEQUENCE,
            &[
                &version,
                &serial,
                &algorithm_identifier(),
                &name,
                &validity,
                &name,
                &subject_public_key_info(public_key),
            ],
        );
        Ok(TbsCertificate {
            der,
            public_key: *public_key,
            subject_cn: subject_cn.to_owned(),
        })
    }

    /// Loads a stored certificate (e.g. from the config). Accepts exactly the bytes
    /// [`Certificate::build`] + [`TbsCertificate::finish`] would produce for
    /// `expected_public_key`, with a valid signature; anything else is rejected.
    pub fn from_der(der: &[u8], expected_public_key: &[u8; 65]) -> Result<Certificate> {
        let bad = Error::InvalidCertificate;
        let mut outer = Reader(der);
        let body = outer.expect(der::SEQUENCE).map_err(bad)?;
        outer.finish().map_err(bad)?;
        let mut parts = Reader(body);
        let tbs_raw = parts.expect_raw(der::SEQUENCE).map_err(bad)?;
        let _alg = parts.expect(der::SEQUENCE).map_err(bad)?;
        let bits = parts.expect(der::BIT_STRING).map_err(bad)?;
        parts.finish().map_err(bad)?;
        let cn = extract_cn(tbs_raw)?;
        let tbs = Certificate::build(expected_public_key, cn)?;
        if tbs.der != tbs_raw {
            return Err(bad(
                "not the certificate for this key (or not built by petschaft)",
            ));
        }
        let signature = match bits.split_first() {
            Some((0, sig)) => sig,
            _ => return Err(bad("signature BIT STRING")),
        };
        let cert = tbs.finish(signature)?;
        if cert.der != der {
            return Err(bad("non-canonical encoding"));
        }
        Ok(cert)
    }

    /// Loads a stored certificate whose public key is not known in advance (e.g. a
    /// config entry without `public_key`): takes the key from the certificate's own
    /// `SubjectPublicKeyInfo`, then applies exactly the checks of
    /// [`Certificate::from_der`] for that key (canonical petschaft encoding, valid
    /// self-signature). The caller must still compare [`Certificate::public_key`]
    /// with the key it trusts (pin, device key) before relying on it.
    pub fn parse(der: &[u8]) -> Result<Certificate> {
        let point = extract_public_key(der)?;
        Certificate::from_der(der, &point)
    }

    /// The DER encoding (what goes into the APK and the config).
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The uncompressed SEC1 public key.
    pub fn public_key(&self) -> &[u8; 65] {
        &self.public_key
    }

    /// The subject (and issuer) common name.
    pub fn subject_cn(&self) -> &str {
        &self.subject_cn
    }

    /// SHA-256 of the DER certificate: the "signing certificate digest" that
    /// `apksigner --print-certs` and app stores show.
    pub fn sha256_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.der).into()
    }
}

/// Walks Certificate → TBSCertificate → SubjectPublicKeyInfo and returns the 65-byte
/// SEC1 point. Structure only; [`Certificate::from_der`] rebuilds and compares the whole
/// certificate for that key.
fn extract_public_key(der: &[u8]) -> Result<[u8; 65]> {
    let bad = Error::InvalidCertificate;
    let mut cert = Reader(Reader(der).expect(der::SEQUENCE).map_err(bad)?);
    let mut tbs = Reader(cert.expect(der::SEQUENCE).map_err(bad)?);
    tbs.expect(der::CONTEXT_0).map_err(bad)?; // version
    tbs.expect(der::INTEGER).map_err(bad)?; // serial
    tbs.expect(der::SEQUENCE).map_err(bad)?; // signature algorithm
    tbs.expect(der::SEQUENCE).map_err(bad)?; // issuer
    tbs.expect(der::SEQUENCE).map_err(bad)?; // validity
    tbs.expect(der::SEQUENCE).map_err(bad)?; // subject
    let mut spki = Reader(tbs.expect(der::SEQUENCE).map_err(bad)?);
    spki.expect(der::SEQUENCE).map_err(bad)?; // algorithm
    let bits = spki.expect(der::BIT_STRING).map_err(bad)?;
    match bits.split_first() {
        Some((0, point)) => point
            .try_into()
            .map_err(|_| bad("public key is not a 65-byte SEC1 point")),
        _ => Err(bad("public key BIT STRING")),
    }
}

/// Walks TBSCertificate → issuer → RDN → AttributeTypeAndValue and returns the CN.
/// Structure only; the caller rebuilds and compares the whole TBSCertificate.
fn extract_cn(tbs_raw: &[u8]) -> Result<&str> {
    let bad = Error::InvalidCertificate;
    let mut tbs = Reader(Reader(tbs_raw).expect(der::SEQUENCE).map_err(bad)?);
    tbs.expect(der::CONTEXT_0).map_err(bad)?;
    tbs.expect(der::INTEGER).map_err(bad)?;
    tbs.expect(der::SEQUENCE).map_err(bad)?;
    let mut issuer = Reader(tbs.expect(der::SEQUENCE).map_err(bad)?);
    let mut rdn = Reader(issuer.expect(der::SET).map_err(bad)?);
    let mut atv = Reader(rdn.expect(der::SEQUENCE).map_err(bad)?);
    if atv.expect(der::OID).map_err(bad)? != OID_COMMON_NAME {
        return Err(bad("issuer is not a single CN"));
    }
    let cn = atv.expect(der::UTF8_STRING).map_err(bad)?;
    std::str::from_utf8(cn).map_err(|_| bad("CN is not UTF-8"))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use proptest::prelude::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn point(k: &SigningKey) -> [u8; 65] {
        k.verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn make(k: &SigningKey, cn: &str) -> Certificate {
        let tbs = Certificate::build(&point(k), cn).unwrap();
        let sig: p256::ecdsa::Signature = k.sign_prehash(&tbs.digest()).unwrap();
        tbs.finish(&sig.to_der().to_bytes()).unwrap()
    }

    #[test]
    fn cn_validation() {
        let p = point(&key(1));
        assert!(Certificate::build(&p, "").is_err());
        assert!(Certificate::build(&p, &"a".repeat(65)).is_err());
        assert!(Certificate::build(&p, &"a".repeat(64)).is_ok());
        assert!(Certificate::build(&p, "Ä").is_err());
        assert!(Certificate::build(&p, "a\nb").is_err());
        assert!(Certificate::build(&p, " ~Release Key (2026), Inc.").is_ok());
    }

    #[test]
    fn rejects_invalid_public_keys() {
        let mut p = point(&key(1));
        p[64] ^= 1; // off the curve
        assert!(matches!(
            Certificate::build(&p, "x"),
            Err(Error::InvalidPublicKey)
        ));
        let mut c = point(&key(1));
        c[0] = 0x02;
        assert!(matches!(
            Certificate::build(&c, "x"),
            Err(Error::InvalidPublicKey)
        ));
    }

    #[test]
    fn serial_and_layout() {
        let k = key(7);
        let p = point(&k);
        let tbs = Certificate::build(&p, "petschaft").unwrap();
        let hash = Sha256::digest(p);
        let expected = der::positive_integer(&hash[..16]).unwrap();
        // version [0] { INTEGER 2 } is 5 bytes after the outer header.
        let header = if tbs.der()[1] & 0x80 != 0 {
            2 + (tbs.der()[1] & 0x7f) as usize
        } else {
            2
        };
        let at = header + 5;
        assert_eq!(&tbs.der()[at..at + expected.len()], &expected[..]);
        // Deterministic.
        assert_eq!(tbs, Certificate::build(&p, "petschaft").unwrap());
    }

    #[test]
    fn finish_rejects_foreign_or_bad_signature() {
        let k = key(3);
        let tbs = Certificate::build(&point(&k), "x").unwrap();
        let other: p256::ecdsa::Signature = key(4).sign_prehash(&tbs.digest()).unwrap();
        assert!(matches!(
            tbs.clone().finish(&other.to_der().to_bytes()),
            Err(Error::SignatureMismatch)
        ));
        let wrong: p256::ecdsa::Signature = k.sign_prehash(&[0u8; 32]).unwrap();
        assert!(tbs.clone().finish(&wrong.to_der().to_bytes()).is_err());
        assert!(tbs.finish(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn from_der_roundtrip_and_rejections() {
        let k = key(5);
        let cert = make(&k, "Release");
        let p = point(&k);
        assert_eq!(Certificate::from_der(cert.der(), &p).unwrap(), cert);
        // Wrong key.
        assert!(Certificate::from_der(cert.der(), &point(&key(6))).is_err());
        // Any single-byte change is rejected.
        for i in 0..cert.der().len() {
            let mut d = cert.der().to_vec();
            d[i] ^= 0x01;
            assert!(Certificate::from_der(&d, &p).is_err(), "byte {i}");
        }
        // Trailing data.
        let mut d = cert.der().to_vec();
        d.push(0);
        assert!(Certificate::from_der(&d, &p).is_err());
        // `parse` takes the key from the certificate and checks the same way.
        assert_eq!(Certificate::parse(cert.der()).unwrap(), cert);
        assert!(Certificate::parse(&d).is_err());
        for i in 0..cert.der().len() {
            let mut d = cert.der().to_vec();
            d[i] ^= 0x01;
            assert!(Certificate::parse(&d).is_err(), "byte {i}");
        }
        assert_eq!(
            cert.sha256_fingerprint(),
            <[u8; 32]>::from(Sha256::digest(cert.der()))
        );
    }

    proptest! {
        #[test]
        fn from_der_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = Certificate::from_der(&bytes, &point(&key(5)));
            let _ = Certificate::parse(&bytes);
        }

        #[test]
        fn build_any_valid_cn(cn in "[ -~]{1,64}") {
            let k = key(9);
            let cert = make(&k, &cn);
            let parsed = Certificate::from_der(cert.der(), &point(&k)).unwrap();
            prop_assert_eq!(parsed.subject_cn(), cn.as_str());
        }
    }
}
