//! serde helpers for binary fields: standard base64 with canonical padding
//! (RFC 4648 §4). Error messages never echo the input.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serializer};

use crate::frame::MAX_FRAME_LEN;

/// No base64 string inside a valid frame can be longer than the frame itself.
const MAX_ENCODED_LEN: usize = MAX_FRAME_LEN;

pub(crate) fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() > MAX_ENCODED_LEN {
        return Err("base64 field too long");
    }
    STANDARD
        .decode(s.as_bytes())
        .map_err(|_| "invalid base64 (standard alphabet, canonical padding required)")
}

pub(crate) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&STANDARD.encode(bytes))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    decode(&s).map_err(D::Error::custom)
}

/// `Option<T>` that must be present on the wire (possibly `null`): using
/// `deserialize_with` disables serde's "missing Option field means None" rule.
pub(crate) fn required_option<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
