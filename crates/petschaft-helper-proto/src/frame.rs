//! Length-prefixed frames: 4-byte big-endian length `n` with `1 <= n <= 65536`, then `n`
//! payload bytes. This layer does not look at the payload; see [`crate::message`].

use std::io::{ErrorKind, Read, Write};

use crate::Error;

/// Maximum payload length of one frame (inclusive).
pub const MAX_FRAME_LEN: usize = 65536;

/// Check a frame length. Shared by reader and writer.
fn check_len(n: u64) -> Result<usize, Error> {
    match usize::try_from(n) {
        Ok(len) if (1..=MAX_FRAME_LEN).contains(&len) => Ok(len),
        _ => Err(Error::InvalidLength(n)),
    }
}

/// Read one frame.
///
/// Returns `Ok(None)` on a clean end of stream *before* the first byte of a frame, and
/// [`Error::Truncated`] if the stream ends anywhere inside a frame. The length is
/// validated before the payload buffer is allocated, so a hostile length costs nothing.
pub fn read_frame<R: Read + ?Sized>(r: &mut R) -> Result<Option<Vec<u8>>, Error> {
    let mut header = [0u8; 4];
    let mut filled = 0usize;
    while let Some(rest) = header.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        match r.read(rest) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(Error::Truncated),
            // `read` returns at most `rest.len()`, so this cannot exceed 4.
            Ok(k) => filled = filled.checked_add(k).ok_or(Error::Truncated)?,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    let len = check_len(u64::from(u32::from_be_bytes(header)))?;
    let mut payload = vec![0u8; len];
    match r.read_exact(&mut payload) {
        Ok(()) => Ok(Some(payload)),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err(Error::Truncated),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Write one frame and flush. Rejects payloads outside `1..=65536` bytes.
pub fn write_frame<W: Write + ?Sized>(w: &mut W, payload: &[u8]) -> Result<(), Error> {
    let len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    check_len(len)?;
    let header = u32::try_from(payload.len())
        .map_err(|_| Error::InvalidLength(len))?
        .to_be_bytes();
    // One buffer, one write: a frame is never interleaved with anything else.
    let mut buf = Vec::with_capacity(payload.len().saturating_add(4));
    buf.extend_from_slice(&header);
    buf.extend_from_slice(payload);
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    fn frame_bytes(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, payload).unwrap();
        out
    }

    /// A reader that panics if more than `limit` bytes are requested in one call:
    /// detects allocations sized by an unchecked length.
    struct NoBigReads<R> {
        inner: R,
        limit: usize,
    }
    impl<R: Read> Read for NoBigReads<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                buf.len() <= self.limit,
                "read buffer of {} bytes",
                buf.len()
            );
            self.inner.read(buf)
        }
    }

    /// Delivers one byte per call and an `Interrupted` error in between.
    struct Trickle<R> {
        inner: R,
        interrupt: bool,
    }
    impl<R: Read> Read for Trickle<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(std::io::Error::from(ErrorKind::Interrupted));
            }
            let n = buf.len().min(1);
            self.inner.read(&mut buf[..n])
        }
    }

    #[test]
    fn clean_eof_is_none() {
        assert!(
            read_frame(&mut Cursor::new(Vec::<u8>::new()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn truncated_header_and_payload() {
        for cut in 1..4 {
            let bytes = frame_bytes(b"{}");
            let err = read_frame(&mut Cursor::new(bytes[..cut].to_vec())).unwrap_err();
            assert!(matches!(err, Error::Truncated), "cut {cut}: {err}");
        }
        let bytes = frame_bytes(b"{\"a\":1}");
        let err = read_frame(&mut Cursor::new(bytes[..bytes.len() - 1].to_vec())).unwrap_err();
        assert!(matches!(err, Error::Truncated));
    }

    #[test]
    fn length_bounds() {
        let zero = [0u8, 0, 0, 0];
        assert!(matches!(
            read_frame(&mut Cursor::new(zero.to_vec())),
            Err(Error::InvalidLength(0))
        ));
        let max = vec![b' '; MAX_FRAME_LEN];
        assert_eq!(
            read_frame(&mut Cursor::new(frame_bytes(&max)))
                .unwrap()
                .unwrap(),
            max
        );
        let over = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
        assert!(matches!(
            read_frame(&mut Cursor::new(over.to_vec())),
            Err(Error::InvalidLength(65537))
        ));
        assert!(matches!(
            write_frame(&mut Vec::new(), &[]),
            Err(Error::InvalidLength(0))
        ));
        assert!(matches!(
            write_frame(&mut Vec::new(), &vec![0u8; MAX_FRAME_LEN + 1]),
            Err(Error::InvalidLength(65537))
        ));
    }

    #[test]
    fn interrupted_reads_are_retried() {
        let bytes = frame_bytes(b"{\"x\":true}");
        let mut r = Trickle {
            inner: Cursor::new(bytes),
            interrupt: false,
        };
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"{\"x\":true}");
        assert!(read_frame(&mut r).unwrap().is_none());
    }

    proptest! {
        #[test]
        fn roundtrip(payloads in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..2048), 0..8)) {
            let mut stream = Vec::new();
            for p in &payloads {
                write_frame(&mut stream, p).unwrap();
            }
            let mut cur = Cursor::new(stream);
            for p in &payloads {
                prop_assert_eq!(&read_frame(&mut cur).unwrap().unwrap(), p);
            }
            prop_assert!(read_frame(&mut cur).unwrap().is_none());
        }

        #[test]
        fn never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let mut cur = Cursor::new(bytes);
            // Read until error or EOF; must terminate without panicking.
            while let Ok(Some(_)) = read_frame(&mut cur) {}
        }

        #[test]
        fn oversize_rejected_without_allocating(
            len in (MAX_FRAME_LEN as u32 + 1)..=u32::MAX,
            tail in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut bytes = len.to_be_bytes().to_vec();
            bytes.extend(tail);
            // Header reads use a 4-byte buffer; a payload read would need `len` bytes.
            let mut r = NoBigReads { inner: Cursor::new(bytes), limit: 4 };
            let err = read_frame(&mut r).unwrap_err();
            prop_assert!(matches!(err, Error::InvalidLength(n) if n == u64::from(len)));
        }

        #[test]
        fn truncation_anywhere_is_detected(
            payload in prop::collection::vec(any::<u8>(), 1..256),
            cut_seed in any::<usize>(),
        ) {
            let bytes = frame_bytes(&payload);
            let cut = 1 + cut_seed % (bytes.len() - 1);
            let err = read_frame(&mut Cursor::new(bytes[..cut].to_vec())).unwrap_err();
            prop_assert!(matches!(err, Error::Truncated));
        }
    }
}
