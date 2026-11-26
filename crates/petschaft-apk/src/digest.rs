//! v2/v3 content digest [v2 §Integrity-protected contents]: each section is split into
//! consecutive 1 MiB chunks (the last one may be shorter; chunks never span sections);
//! chunk digest = SHA-256(0xa5 || u32le chunk length || chunk); top-level digest =
//! SHA-256(0x5a || u32le number of chunks || chunk digests…). Algorithm 0x0201 uses SHA-256
//! [v2 §Signature algorithm IDs]. v3 uses the same digest [v3 §Format: "same as v2"].

use sha2::{Digest as _, Sha256};

use crate::{Error, Result};

/// 1 MiB = 2^20 bytes.
pub(crate) const CHUNK_SIZE: usize = 1 << 20;

/// Digest over the sections in order (ZIP entries, central directory, EOCD).
pub(crate) fn content_digest(sections: &[&[u8]]) -> Result<[u8; 32]> {
    let count = sections
        .iter()
        .try_fold(0usize, |acc, s| {
            acc.checked_add(s.len().div_ceil(CHUNK_SIZE))
        })
        .ok_or(Error::TooLarge)?;
    let count = u32::try_from(count).map_err(|_| Error::TooLarge)?;
    let mut top = Sha256::new();
    top.update([0x5a]);
    top.update(count.to_le_bytes());
    for section in sections {
        for chunk in section.chunks(CHUNK_SIZE) {
            let len = u32::try_from(chunk.len()).map_err(|_| Error::TooLarge)?;
            let mut h = Sha256::new();
            h.update([0xa5]);
            h.update(len.to_le_bytes());
            h.update(chunk);
            top.update(h.finalize());
        }
    }
    Ok(top.finalize().into())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// Independent re-implementation over the concatenation with explicit section bounds.
    fn reference(sections: &[&[u8]]) -> [u8; 32] {
        let mut digests = Vec::new();
        for s in sections {
            let mut off = 0;
            while off < s.len() {
                let end = (off + CHUNK_SIZE).min(s.len());
                let mut pre = vec![0xa5];
                pre.extend_from_slice(&((end - off) as u32).to_le_bytes());
                pre.extend_from_slice(&s[off..end]);
                digests.push(Sha256::digest(&pre));
                off = end;
            }
        }
        let mut top = vec![0x5a];
        top.extend_from_slice(&(digests.len() as u32).to_le_bytes());
        for d in &digests {
            top.extend_from_slice(d);
        }
        Sha256::digest(&top).into()
    }

    #[test]
    fn chunk_boundaries() {
        let big = vec![7u8; CHUNK_SIZE * 2 + 3];
        let exact = vec![1u8; CHUNK_SIZE];
        for secs in [
            vec![&big[..], &b"cd"[..], &b"eocd"[..]],
            vec![&exact[..], &[][..], &b"e"[..]],
            vec![&big[..CHUNK_SIZE - 1], &big[..CHUNK_SIZE + 1], &exact[..]],
        ] {
            assert_eq!(content_digest(&secs).unwrap(), reference(&secs));
        }
    }
}
