//! Minimal DER (X.690 §10) writer and reader, and strict ECDSA-Sig-Value handling.
//!
//! Only what the certificate and the signatures need: single-byte tags, definite lengths
//! in the shortest form, no recursion (callers walk nested structures explicitly).

use crate::{Error, Result};

pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OID: u8 = 0x06;
pub(crate) const UTF8_STRING: u8 = 0x0c;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
/// `[0] EXPLICIT` (context-specific, constructed).
pub(crate) const CONTEXT_0: u8 = 0xa0;

/// Encodes one TLV. X.690 §8.1.3: short form below 128, otherwise long form with the
/// minimal number of length octets (§10.1).
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = Vec::with_capacity(content.len().saturating_add(10));
    out.push(tag);
    if let Ok(short) = u8::try_from(len)
        && short < 0x80
    {
        out.push(short);
    } else {
        let be = len.to_be_bytes();
        let skip = be.iter().take_while(|b| **b == 0).count();
        let digits = be.get(skip..).unwrap_or_default();
        // At most size_of::<usize>() (≤ 16) octets, so the count fits in 7 bits.
        let count = u8::try_from(digits.len()).unwrap_or(0x7f) & 0x7f;
        out.push(0x80 | count);
        out.extend_from_slice(digits);
    }
    out.extend_from_slice(content);
    out
}

/// Concatenates TLVs into a constructed TLV.
pub(crate) fn constructed(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

/// DER INTEGER from big-endian unsigned magnitude bytes (X.690 §8.3: two's complement,
/// minimal; a leading 0x00 only before a byte with the high bit set). `None` for zero or
/// empty input: every integer encoded here (serial, r, s) must be positive.
pub(crate) fn positive_integer(magnitude: &[u8]) -> Option<Vec<u8>> {
    let skip = magnitude.iter().take_while(|b| **b == 0).count();
    let digits = magnitude.get(skip..)?;
    let first = *digits.first()?;
    let mut content = Vec::with_capacity(digits.len().saturating_add(1));
    if first & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(digits);
    Some(tlv(INTEGER, &content))
}

/// Strict reader over a DER byte string.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    /// Reads one TLV with tag `tag`; returns its content. Rejects indefinite lengths,
    /// non-minimal lengths and lengths beyond the input.
    pub(crate) fn expect(&mut self, tag: u8) -> Result<&'a [u8], &'static str> {
        let (t, content, _) = self.next_tlv()?;
        if t != tag {
            return Err("unexpected tag");
        }
        Ok(content)
    }

    /// Reads one TLV with tag `tag`; returns the complete encoding (tag, length, content).
    pub(crate) fn expect_raw(&mut self, tag: u8) -> Result<&'a [u8], &'static str> {
        let (t, _, whole) = self.next_tlv()?;
        if t != tag {
            return Err("unexpected tag");
        }
        Ok(whole)
    }

    fn next_tlv(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), &'static str> {
        let input = self.0;
        let (&tag, rest) = input.split_first().ok_or("truncated")?;
        if tag & 0x1f == 0x1f {
            return Err("multi-byte tag");
        }
        let (&first, rest) = rest.split_first().ok_or("truncated")?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            // 0x80 is the indefinite form (BER only); more than 4 octets is never needed here.
            if count == 0 || count > 4 {
                return Err("unsupported length form");
            }
            let digits = rest.get(..count).ok_or("truncated")?;
            let rest = rest.get(count..).ok_or("truncated")?;
            if digits.first() == Some(&0) {
                return Err("non-minimal length");
            }
            let mut len: usize = 0;
            for d in digits {
                len = len
                    .checked_mul(256)
                    .and_then(|l| l.checked_add(usize::from(*d)))
                    .ok_or("length overflow")?;
            }
            if len < 0x80 {
                return Err("non-minimal length");
            }
            (len, rest)
        };
        let content = rest.get(..len).ok_or("truncated")?;
        let after = rest.get(len..).ok_or("truncated")?;
        let header_len = input
            .len()
            .checked_sub(rest.len())
            .ok_or("internal length error")?;
        let whole_len = header_len.checked_add(len).ok_or("length overflow")?;
        let whole = input.get(..whole_len).ok_or("truncated")?;
        self.0 = after;
        Ok((tag, content, whole))
    }

    /// Fails unless all input was consumed.
    pub(crate) fn finish(&self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("trailing data")
        }
    }
}

/// Parses a strict DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
/// (RFC 3279 §2.2.3, as used by APK signature algorithm 0x0201 [v2 §Signature algorithm IDs])
/// into a P-256 signature. Rejects: BER length forms, trailing bytes, negative or
/// non-minimal integers, integers wider than 32 bytes, r or s equal to 0 or ≥ n.
/// High-S values are accepted (Android's verifier accepts them, and the device may emit them).
pub(crate) fn parse_ecdsa_signature(der: &[u8]) -> Result<p256::ecdsa::Signature> {
    let malformed = Error::MalformedSignature;
    let mut outer = Reader(der);
    let body = outer.expect(SEQUENCE).map_err(malformed)?;
    outer.finish().map_err(malformed)?;
    let mut inner = Reader(body);
    let r = scalar(inner.expect(INTEGER).map_err(malformed)?)?;
    let s = scalar(inner.expect(INTEGER).map_err(malformed)?)?;
    inner.finish().map_err(malformed)?;
    let mut rs = [0u8; 64];
    let (rd, sd) = rs.split_at_mut(32);
    rd.copy_from_slice(&r);
    sd.copy_from_slice(&s);
    // Range check r, s ∈ [1, n-1].
    p256::ecdsa::Signature::from_slice(&rs).map_err(|_| malformed("r or s out of range"))
}

/// Minimal positive DER INTEGER content → 32-byte big-endian.
fn scalar(content: &[u8]) -> Result<[u8; 32]> {
    let malformed = Error::MalformedSignature;
    let digits = match content {
        [] => return Err(malformed("empty integer")),
        [0, next, ..] if next & 0x80 != 0 => content.get(1..).unwrap_or_default(),
        [0, _, ..] => return Err(malformed("non-minimal integer")),
        [first, ..] if first & 0x80 != 0 => return Err(malformed("negative integer")),
        _ => content,
    };
    let pad = 32usize
        .checked_sub(digits.len())
        .ok_or(malformed("integer too large"))?;
    let mut out = [0u8; 32];
    out.get_mut(pad..)
        .ok_or(malformed("integer too large"))?
        .copy_from_slice(digits);
    Ok(out)
}

/// Encodes a P-256 ECDSA signature given as big-endian `r`, `s` (e.g. the 64 bytes a
/// Trezor returns after its leading byte) as DER `ECDSA-Sig-Value`. Errors for r or s
/// equal to zero; range against n is checked when the signature is verified.
pub fn ecdsa_der_from_scalars(r: &[u8; 32], s: &[u8; 32]) -> Result<Vec<u8>> {
    let r = positive_integer(r).ok_or(Error::MalformedSignature("r is zero"))?;
    let s = positive_integer(s).ok_or(Error::MalformedSignature("s is zero"))?;
    Ok(constructed(SEQUENCE, &[&r, &s]))
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
    use proptest::prelude::*;

    #[test]
    fn length_forms() {
        assert_eq!(tlv(0x04, &[]), vec![0x04, 0x00]);
        assert_eq!(tlv(0x04, &[0; 127])[..2], [0x04, 0x7f]);
        assert_eq!(tlv(0x04, &[0; 128])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[0; 256])[..4], [0x04, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn integers() {
        assert_eq!(positive_integer(&[0, 0, 1]).unwrap(), vec![2, 1, 1]);
        assert_eq!(positive_integer(&[0x80]).unwrap(), vec![2, 2, 0, 0x80]);
        assert_eq!(
            positive_integer(&[0, 0x7f, 0]).unwrap(),
            vec![2, 2, 0x7f, 0]
        );
        assert!(positive_integer(&[0, 0]).is_none());
        assert!(positive_integer(&[]).is_none());
    }

    fn sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut body = vec![2, r.len() as u8];
        body.extend_from_slice(r);
        body.extend_from_slice(&[2, s.len() as u8]);
        body.extend_from_slice(s);
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out
    }

    /// Hand-written edge cases in the spirit of Wycheproof `ecdsa_secp256r1_sha256_test`
    /// (DER encoding group); not the vendored vectors.
    #[test]
    fn strict_der_signature() {
        let one = [1u8];
        assert!(parse_ecdsa_signature(&sig(&one, &one)).is_ok());
        let high = [0x00, 0x80];
        assert!(parse_ecdsa_signature(&sig(&high, &one)).is_ok());
        // Zero, negative, non-minimal, too long.
        assert!(parse_ecdsa_signature(&sig(&[0], &one)).is_err());
        assert!(parse_ecdsa_signature(&sig(&[0x80], &one)).is_err());
        assert!(parse_ecdsa_signature(&sig(&[0, 1], &one)).is_err());
        assert!(parse_ecdsa_signature(&sig(&[0x01; 33], &one)).is_err());
        assert!(parse_ecdsa_signature(&sig(&[], &one)).is_err());
        // r = n (out of range).
        let n = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut n_int = vec![0];
        n_int.extend_from_slice(&n);
        assert!(parse_ecdsa_signature(&sig(&n_int, &one)).is_err());
        // Trailing data inside and outside, long-form length, indefinite length.
        let mut t = sig(&one, &one);
        t.push(0);
        assert!(parse_ecdsa_signature(&t).is_err());
        let ok = sig(&one, &one);
        let mut long = vec![0x30, 0x81, ok[1]];
        long.extend_from_slice(&ok[2..]);
        assert!(parse_ecdsa_signature(&long).is_err());
        let mut indef = vec![0x30, 0x80];
        indef.extend_from_slice(&ok[2..]);
        indef.extend_from_slice(&[0, 0]);
        assert!(parse_ecdsa_signature(&indef).is_err());
        let mut inner_trailing = vec![0x30, ok[1] + 2];
        inner_trailing.extend_from_slice(&ok[2..]);
        inner_trailing.extend_from_slice(&[5, 0]);
        assert!(parse_ecdsa_signature(&inner_trailing).is_err());
        // Wrong tags.
        let mut wrong = ok.clone();
        wrong[0] = 0x31;
        assert!(parse_ecdsa_signature(&wrong).is_err());
    }

    proptest! {
        #[test]
        fn signature_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..100)) {
            let _ = parse_ecdsa_signature(&bytes);
        }

        #[test]
        fn der_from_scalars_roundtrips(r in any::<[u8; 32]>(), s in any::<[u8; 32]>()) {
            prop_assume!(r != [0; 32] && s != [0; 32]);
            let der = ecdsa_der_from_scalars(&r, &s).unwrap();
            // Out-of-range values (≥ n) are rejected by the parser, everything else round-trips.
            if let Ok(parsed) = parse_ecdsa_signature(&der) {
                let bytes = parsed.to_bytes();
                prop_assert_eq!(&bytes[..32], &r[..]);
                prop_assert_eq!(&bytes[32..], &s[..]);
            }
        }

        #[test]
        fn reader_roundtrips_writer(content in proptest::collection::vec(any::<u8>(), 0..400)) {
            let enc = tlv(0x04, &content);
            let mut r = Reader(&enc);
            prop_assert_eq!(r.expect(0x04).unwrap(), &content[..]);
            prop_assert!(r.finish().is_ok());
        }
    }
}
