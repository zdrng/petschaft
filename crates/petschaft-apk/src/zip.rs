//! Strict ZIP parsing, alignment and re-serialization (`docs/apk.md` steps 1-2).
//!
//! Accepted subset of PKZIP APPNOTE 6.3.x: one disk, no ZIP64, no encryption, methods 0
//! (stored) and 8 (deflate), data descriptors only with signature and values identical to
//! the central directory, local headers consistent with the central directory, unique
//! names, and local entries that tile `[0, start of central directory or signing block)`
//! without gaps or overlaps. Anything else is an error, never "best effort".

use std::collections::BTreeSet;
use std::ops::Range;

use crate::digest;
use crate::{Error, Result};

const LOCAL_SIG: u32 = 0x0403_4b50;
const CD_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const LOCAL_LEN: usize = 30;
const CD_LEN: usize = 46;
const EOCD_LEN: usize = 22;
const ZIP64_LOCATOR_LEN: usize = 20;
const DATA_DESCRIPTOR_LEN: usize = 16;
/// The EOCD record plus the longest possible comment (65 535) [APPNOTE §4.3.16].
const MAX_EOCD_SEARCH: usize = EOCD_LEN + 0xffff;
/// Offset of "offset of start of central directory" within the EOCD record.
pub(crate) const EOCD_CD_OFFSET: usize = 16;
/// Offset of "relative offset of local header" within a central directory record.
const CD_LOCAL_OFFSET: usize = 42;
/// Offset of "extra field length" within a local file header.
const LOCAL_EXTRA_LEN: usize = 28;
/// Flags: bit 0 encrypted, bit 6 strong encryption, bit 13 masked local headers.
const FLAG_ENCRYPTION: u16 = 0x0001 | 0x0040 | 0x2000;
/// Flags: bit 3, sizes and CRC in a data descriptor after the data.
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
/// ZIP64 extended information extra field [APPNOTE §4.5.3].
const EXTRA_ZIP64: u16 = 0x0001;
/// Android's alignment extra field (apksigner / zipalign `-p`): u16 alignment, zero padding.
const EXTRA_ALIGNMENT: u16 = 0xd935;
const EXTRA_ALIGNMENT_MIN_LEN: usize = 6;
/// "APK Sig Block 42" [v2 §APK Signing Block].
pub(crate) const SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
/// Smallest signing block: u64 size, (no pairs), u64 size, magic.
const SIGNING_BLOCK_MIN_LEN: usize = 8 + 8 + 16;
/// Default alignment of stored entries (zipalign; required e.g. for resources.arsc).
const ALIGN_DEFAULT: usize = 4;
/// Alignment of stored native libraries: 16 KiB pages (Android 15+ page-size support).
const ALIGN_NATIVE_LIB: usize = 16 * 1024;

fn malformed(what: &'static str) -> Error {
    Error::Malformed(what)
}

fn get(b: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start.checked_add(len).ok_or(malformed("offset overflow"))?;
    b.get(start..end).ok_or(malformed("truncated"))
}

fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    let s = get(b, off, 2)?;
    let a: [u8; 2] = s.try_into().map_err(|_| malformed("truncated"))?;
    Ok(u16::from_le_bytes(a))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    let s = get(b, off, 4)?;
    let a: [u8; 4] = s.try_into().map_err(|_| malformed("truncated"))?;
    Ok(u32::from_le_bytes(a))
}

fn u64_at(b: &[u8], off: usize) -> Result<u64> {
    let s = get(b, off, 8)?;
    let a: [u8; 8] = s.try_into().map_err(|_| malformed("truncated"))?;
    Ok(u64::from_le_bytes(a))
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(malformed("offset overflow"))
}

fn usize_of(v: u32) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::TooLarge)
}

pub(crate) fn put_u32(b: &mut [u8], off: usize, v: u32) -> Result<()> {
    let end = off.checked_add(4).ok_or(Error::Internal("offset"))?;
    b.get_mut(off..end)
        .ok_or(Error::Internal("offset"))?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Splits an extra field into `(header id, whole record)`; `None` if not well-formed
/// [APPNOTE §4.5.1: header id u16, data size u16, data].
fn extra_records(extra: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    let mut rest = extra;
    while !rest.is_empty() {
        let id = u16::from_le_bytes([*rest.first()?, *rest.get(1)?]);
        let len = usize::from(u16::from_le_bytes([*rest.get(2)?, *rest.get(3)?]));
        let total = len.checked_add(4)?;
        out.push((id, rest.get(..total)?));
        rest = rest.get(total..)?;
    }
    Some(out)
}

fn has_zip64_extra(extra: &[u8]) -> bool {
    extra_records(extra).is_some_and(|r| r.iter().any(|(id, _)| *id == EXTRA_ZIP64))
}

/// One ZIP entry; ranges point into [`Apk::src`].
#[derive(Clone, Debug)]
struct Entry {
    /// Local file header offset in the source.
    local: usize,
    /// File name (from the local header; identical to the central directory's).
    name: Range<usize>,
    /// Local extra field, possibly re-padded by [`Apk::align`].
    extra: Vec<u8>,
    /// Compressed data plus data descriptor, if any.
    data: Range<usize>,
    /// Complete central directory record.
    cd: Range<usize>,
    stored: bool,
}

/// A strictly parsed APK (ZIP archive), ready to be aligned, digested and signed.
#[derive(Clone, Debug)]
pub struct Apk {
    src: Vec<u8>,
    /// Entries in local-header order (= output order).
    entries: Vec<Entry>,
    /// Central directory order, as indices into `entries` (preserved on output).
    cd_order: Vec<usize>,
    /// EOCD record including its comment.
    eocd: Range<usize>,
    signing_block: bool,
}

/// The three digested sections of an unsigned layout [v2 §Integrity-protected contents];
/// the EOCD's central-directory offset is the offset of section 2 (where the signing
/// block will be inserted).
pub(crate) struct Layout {
    pub(crate) entries: Vec<u8>,
    pub(crate) cd: Vec<u8>,
    pub(crate) eocd: Vec<u8>,
}

impl Apk {
    /// Parses `bytes` strictly (`docs/apk.md` step 1). An existing APK Signing Block is
    /// recognised and recorded; it must be dropped with [`Apk::remove_signing_block`]
    /// before the APK can be digested or signed.
    pub fn parse(bytes: &[u8]) -> Result<Apk> {
        Apk::parse_owned(bytes.to_vec())
    }

    /// [`Apk::parse`] without copying: the parsed APK keeps `src` as its source.
    pub fn parse_owned(src: Vec<u8>) -> Result<Apk> {
        let bytes = src.as_slice();
        // Without ZIP64 every offset is a u32.
        if u32::try_from(bytes.len()).is_err() {
            return Err(Error::TooLarge);
        }
        let eocd_pos = find_eocd(bytes)?;
        if u16_at(bytes, add(eocd_pos, 4)?)? != 0 || u16_at(bytes, add(eocd_pos, 6)?)? != 0 {
            return Err(Error::Unsupported("multi-disk archive"));
        }
        let on_disk = u16_at(bytes, add(eocd_pos, 8)?)?;
        let total = u16_at(bytes, add(eocd_pos, 10)?)?;
        let cd_size = u32_at(bytes, add(eocd_pos, 12)?)?;
        let cd_off = u32_at(bytes, add(eocd_pos, EOCD_CD_OFFSET)?)?;
        // [APPNOTE §4.4.1.4]: 0xFFFF / 0xFFFFFFFF mean "see the ZIP64 record".
        if total == 0xffff || cd_size == 0xffff_ffff || cd_off == 0xffff_ffff {
            return Err(Error::Unsupported("ZIP64 archive"));
        }
        if let Some(loc) = eocd_pos.checked_sub(ZIP64_LOCATOR_LEN)
            && u32_at(bytes, loc)? == ZIP64_LOCATOR_SIG
        {
            return Err(Error::Unsupported("ZIP64 archive"));
        }
        if on_disk != total {
            return Err(Error::Unsupported("multi-disk archive"));
        }
        if total == 0 {
            return Err(malformed("archive has no entries"));
        }
        let cd_off = usize_of(cd_off)?;
        let cd_end = add(cd_off, usize_of(cd_size)?)?;
        // [v2 §APK Signing Block]: the signing block sits immediately before the central
        // directory, and the central directory immediately before the EOCD.
        if cd_end != eocd_pos {
            return Err(malformed("central directory does not end at the EOCD"));
        }
        let (entries_end, signing_block) = match find_signing_block(bytes, cd_off)? {
            Some(start) => (start, true),
            None => (cd_off, false),
        };

        let mut parsed: Vec<(usize, Entry)> = Vec::with_capacity(usize::from(total));
        let mut pos = cd_off;
        for cd_index in 0..usize::from(total) {
            let record = parse_cd_record(bytes, pos, cd_end)?;
            pos = record.range.end;
            parsed.push((cd_index, parse_local(bytes, &record, entries_end)?));
        }
        if pos != cd_end {
            return Err(malformed(
                "central directory size does not match its records",
            ));
        }

        let mut names = BTreeSet::new();
        for (_, e) in &parsed {
            let name = bytes.get(e.name.clone()).ok_or(malformed("truncated"))?;
            if !names.insert(name) {
                return Err(malformed("duplicate entry name"));
            }
        }

        // Local entries must tile [0, entries_end) exactly: no gaps (unsigned, unparsed
        // bytes), no overlaps (one byte range read as two entries), nothing left over.
        parsed.sort_by_key(|(_, e)| e.local);
        let mut expected = 0usize;
        for (_, e) in &parsed {
            if e.local != expected {
                return Err(malformed("local entries overlap or leave gaps"));
            }
            expected = e.data.end;
        }
        if expected != entries_end {
            return Err(malformed(
                "data between the last entry and the central directory",
            ));
        }

        let mut cd_order = vec![0usize; parsed.len()];
        for (local_index, (cd_index, _)) in parsed.iter().enumerate() {
            *cd_order
                .get_mut(*cd_index)
                .ok_or(Error::Internal("cd index"))? = local_index;
        }
        let eocd = eocd_pos..bytes.len();
        Ok(Apk {
            src,
            entries: parsed.into_iter().map(|(_, e)| e).collect(),
            cd_order,
            eocd,
            signing_block,
        })
    }

    /// The source bytes the APK was parsed from (unchanged by [`Apk::align`] and
    /// [`Apk::remove_signing_block`]).
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.src
    }

    /// Names of v1 (JAR) signature files from a previous signer: `META-INF/*.SF`,
    /// `*.RSA`, `*.DSA`, `*.EC` directly in `META-INF/` (ASCII case-insensitive, as
    /// Android's JAR verifier matches them). They would stay in the APK next to the new
    /// v2/v3 signatures, so the caller refuses such input.
    pub fn v1_signature_files(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|e| self.src.get(e.name.clone()))
            .filter(|name| is_v1_signature_file(name))
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect()
    }

    /// Whether the input carried an APK Signing Block that has not been removed.
    pub fn has_signing_block(&self) -> bool {
        self.signing_block
    }

    /// Drops an existing APK Signing Block (explicit opt-in to re-signing). Returns whether
    /// there was one.
    pub fn remove_signing_block(&mut self) -> bool {
        std::mem::replace(&mut self.signing_block, false)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always false: an archive without entries is rejected by [`Apk::parse`].
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Aligns the data of stored entries (`docs/apk.md` step 2): 16 KiB for `lib/**/*.so`,
    /// 4 bytes otherwise, by re-padding the local header's extra field (Android's 0xd935
    /// alignment field if the extra field is well-formed, zero bytes otherwise, as
    /// zipalign does). Entries that are already aligned are left untouched; deflated
    /// entries are never changed. Offsets are rebuilt on serialization.
    pub fn align(&mut self) -> Result<()> {
        let plan = plan_alignment(&self.src, &self.entries)?;
        for (e, extra) in self.entries.iter_mut().zip(plan) {
            if let Some(extra) = extra {
                e.extra = extra;
            }
        }
        Ok(())
    }

    /// Whether every stored entry is already aligned as [`Apk::align`] would align it.
    pub fn is_aligned(&self) -> Result<bool> {
        Ok(plan_alignment(&self.src, &self.entries)?
            .iter()
            .all(Option::is_none))
    }

    /// The v2/v3 content digest (algorithm 0x0201, chunked SHA-256) of the APK as it will
    /// be laid out (`docs/apk.md` step 3).
    pub fn content_digest(&self) -> Result<[u8; 32]> {
        let l = self.layout()?;
        digest::content_digest(&[&l.entries, &l.cd, &l.eocd])
    }

    /// Serializes entries, central directory and EOCD (central-directory offset = length of
    /// the entries section) with rebuilt offsets. Refuses while a signing block is present.
    pub(crate) fn layout(&self) -> Result<Layout> {
        if self.signing_block {
            return Err(Error::SigningBlockPresent);
        }
        let mut entries = Vec::with_capacity(self.src.len());
        let mut offsets = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            offsets.push(u32::try_from(entries.len()).map_err(|_| Error::TooLarge)?);
            let header = get(&self.src, e.local, LOCAL_EXTRA_LEN)?;
            entries.extend_from_slice(header);
            let extra_len = u16::try_from(e.extra.len()).map_err(|_| Error::TooLarge)?;
            entries.extend_from_slice(&extra_len.to_le_bytes());
            entries.extend_from_slice(self.src.get(e.name.clone()).ok_or(malformed("name"))?);
            entries.extend_from_slice(&e.extra);
            entries.extend_from_slice(self.src.get(e.data.clone()).ok_or(malformed("data"))?);
        }
        let mut cd = Vec::new();
        for &i in &self.cd_order {
            let e = self.entries.get(i).ok_or(Error::Internal("cd order"))?;
            let start = cd.len();
            cd.extend_from_slice(self.src.get(e.cd.clone()).ok_or(malformed("cd"))?);
            let off = *offsets.get(i).ok_or(Error::Internal("cd order"))?;
            put_u32(&mut cd, add(start, CD_LOCAL_OFFSET)?, off)?;
        }
        let mut eocd = self
            .src
            .get(self.eocd.clone())
            .ok_or(malformed("eocd"))?
            .to_vec();
        let cd_off = u32::try_from(entries.len()).map_err(|_| Error::TooLarge)?;
        put_u32(&mut eocd, EOCD_CD_OFFSET, cd_off)?;
        // The output (entries + signing block + CD + EOCD) must stay below 4 GiB as well;
        // checked again by the signer once the block size is known.
        Ok(Layout { entries, cd, eocd })
    }
}

/// `META-INF/<file>.{SF,RSA,DSA,EC}` (no subdirectory), ASCII case-insensitive.
fn is_v1_signature_file(name: &[u8]) -> bool {
    let upper = name.to_ascii_uppercase();
    let Some(file) = upper.strip_prefix(b"META-INF/") else {
        return false;
    };
    !file.contains(&b'/')
        && [&b".SF"[..], b".RSA", b".DSA", b".EC"]
            .iter()
            .any(|ext| file.ends_with(ext))
}

/// Locates the EOCD [APPNOTE §4.3.16]: searched backwards within the last 65 557 bytes;
/// a candidate counts only if its comment length reaches exactly the end of the input.
/// More than one consistent candidate (an EOCD hidden in the comment) is ambiguous and
/// rejected.
fn find_eocd(bytes: &[u8]) -> Result<usize> {
    let last = bytes.len().checked_sub(EOCD_LEN).ok_or(malformed(
        "too short for an end of central directory record",
    ))?;
    let first = bytes.len().saturating_sub(MAX_EOCD_SEARCH);
    let mut found = None;
    for pos in (first..=last).rev() {
        if u32_at(bytes, pos)? != EOCD_SIG {
            continue;
        }
        let comment = usize::from(u16_at(bytes, add(pos, 20)?)?);
        if add(add(pos, EOCD_LEN)?, comment)? == bytes.len() {
            if found.is_some() {
                return Err(malformed("ambiguous end of central directory record"));
            }
            found = Some(pos);
        }
    }
    found.ok_or(malformed("no end of central directory record"))
}

/// Detects an APK Signing Block ending at `cd_off` [v2 §APK Signing Block]: magic at the
/// end, both u64 size fields equal. Returns its start. A magic with inconsistent sizes is
/// an error, not "no block".
fn find_signing_block(bytes: &[u8], cd_off: usize) -> Result<Option<usize>> {
    let Some(magic_at) = cd_off.checked_sub(SIGNING_BLOCK_MAGIC.len()) else {
        return Ok(None);
    };
    if get(bytes, magic_at, SIGNING_BLOCK_MAGIC.len())? != SIGNING_BLOCK_MAGIC {
        return Ok(None);
    }
    let bad = malformed("inconsistent APK Signing Block");
    let footer_at = magic_at.checked_sub(8).ok_or(bad)?;
    let size = usize::try_from(u64_at(bytes, footer_at)?)
        .map_err(|_| malformed("inconsistent APK Signing Block"))?;
    // `size` counts everything after the first size field.
    let total = size
        .checked_add(8)
        .ok_or(malformed("inconsistent APK Signing Block"))?;
    if total < SIGNING_BLOCK_MIN_LEN {
        return Err(malformed("inconsistent APK Signing Block"));
    }
    let start = cd_off
        .checked_sub(total)
        .ok_or(malformed("inconsistent APK Signing Block"))?;
    if u64_at(bytes, start)? != u64::try_from(size).map_err(|_| Error::TooLarge)? {
        return Err(malformed("inconsistent APK Signing Block"));
    }
    Ok(Some(start))
}

/// The fields of a central directory record that the local header must agree with.
struct CdRecord<'a> {
    flags: u16,
    method: u16,
    crc: u32,
    csize: u32,
    usize_: u32,
    local: usize,
    name: &'a [u8],
    stored: bool,
    /// The complete record; its end is the start of the next one.
    range: Range<usize>,
}

/// Parses and checks the central directory file header at `pos` [APPNOTE §4.3.12].
fn parse_cd_record(bytes: &[u8], pos: usize, cd_end: usize) -> Result<CdRecord<'_>> {
    if add(pos, CD_LEN)? > cd_end {
        return Err(malformed(
            "central directory record exceeds the central directory",
        ));
    }
    if u32_at(bytes, pos)? != CD_SIG {
        return Err(malformed("bad central directory record signature"));
    }
    let flags = u16_at(bytes, add(pos, 8)?)?;
    let method = u16_at(bytes, add(pos, 10)?)?;
    let crc = u32_at(bytes, add(pos, 16)?)?;
    let csize = u32_at(bytes, add(pos, 20)?)?;
    let usize_ = u32_at(bytes, add(pos, 24)?)?;
    let name_len = usize::from(u16_at(bytes, add(pos, 28)?)?);
    let extra_len = usize::from(u16_at(bytes, add(pos, 30)?)?);
    let comment_len = usize::from(u16_at(bytes, add(pos, 32)?)?);
    let disk = u16_at(bytes, add(pos, 34)?)?;
    let local_u32 = u32_at(bytes, add(pos, CD_LOCAL_OFFSET)?)?;
    let name_at = add(pos, CD_LEN)?;
    let extra_at = add(name_at, name_len)?;
    let next = add(add(extra_at, extra_len)?, comment_len)?;
    if next > cd_end {
        return Err(malformed(
            "central directory record exceeds the central directory",
        ));
    }
    let cd_name = get(bytes, name_at, name_len)?;
    let cd_extra = get(bytes, extra_at, extra_len)?;

    if csize == 0xffff_ffff || usize_ == 0xffff_ffff || local_u32 == 0xffff_ffff || disk == 0xffff {
        return Err(Error::Unsupported("ZIP64 entry"));
    }
    if has_zip64_extra(cd_extra) {
        return Err(Error::Unsupported("ZIP64 entry"));
    }
    if disk != 0 {
        return Err(Error::Unsupported("multi-disk archive"));
    }
    if flags & FLAG_ENCRYPTION != 0 {
        return Err(Error::Unsupported("encrypted entry"));
    }
    let stored = match method {
        METHOD_STORED => true,
        METHOD_DEFLATE => false,
        _ => {
            return Err(Error::Unsupported(
                "compression method other than stored/deflate",
            ));
        }
    };
    if stored && csize != usize_ {
        return Err(malformed(
            "stored entry with different compressed and uncompressed size",
        ));
    }
    if name_len == 0 {
        return Err(malformed("empty entry name"));
    }
    Ok(CdRecord {
        flags,
        method,
        crc,
        csize,
        usize_,
        local: usize_of(local_u32)?,
        name: cd_name,
        stored,
        range: pos..next,
    })
}

/// Parses the local file header [APPNOTE §4.3.7] of `cd`, which must agree with the
/// central directory, and locates the entry's data (plus data descriptor) within
/// `[0, entries_end)`.
fn parse_local(bytes: &[u8], cd: &CdRecord<'_>, entries_end: usize) -> Result<Entry> {
    let CdRecord {
        flags,
        method,
        crc,
        csize,
        usize_,
        local,
        name: cd_name,
        stored,
        ..
    } = *cd;
    if add(local, LOCAL_LEN)? > entries_end {
        return Err(malformed("local header outside the entries section"));
    }
    if u32_at(bytes, local)? != LOCAL_SIG {
        return Err(malformed("bad local header signature"));
    }
    let l_flags = u16_at(bytes, add(local, 6)?)?;
    let l_method = u16_at(bytes, add(local, 8)?)?;
    let l_crc = u32_at(bytes, add(local, 14)?)?;
    let l_csize = u32_at(bytes, add(local, 18)?)?;
    let l_usize = u32_at(bytes, add(local, 22)?)?;
    let l_name_len = usize::from(u16_at(bytes, add(local, 26)?)?);
    let l_extra_len = usize::from(u16_at(bytes, add(local, LOCAL_EXTRA_LEN)?)?);
    if l_flags != flags || l_method != method {
        return Err(malformed(
            "local header disagrees with the central directory",
        ));
    }
    let l_name_at = add(local, LOCAL_LEN)?;
    let l_extra_at = add(l_name_at, l_name_len)?;
    let data_start = add(l_extra_at, l_extra_len)?;
    if data_start > entries_end {
        return Err(malformed("local header outside the entries section"));
    }
    if get(bytes, l_name_at, l_name_len)? != cd_name {
        return Err(malformed(
            "local file name differs from the central directory",
        ));
    }
    let l_extra = get(bytes, l_extra_at, l_extra_len)?;
    if has_zip64_extra(l_extra) {
        return Err(Error::Unsupported("ZIP64 entry"));
    }
    let descriptor = flags & FLAG_DATA_DESCRIPTOR != 0;
    // With a data descriptor the local fields may be zero [APPNOTE §4.4.4]; any other
    // value must still be the real one.
    let consistent = |local_value: u32, cd_value: u32| {
        local_value == cd_value || (descriptor && local_value == 0)
    };
    if !consistent(l_crc, crc) || !consistent(l_csize, csize) || !consistent(l_usize, usize_) {
        return Err(malformed(
            "local header disagrees with the central directory",
        ));
    }
    let mut data_end = add(data_start, usize_of(csize)?)?;
    if descriptor {
        // Only the unambiguous form: signature, CRC, 32-bit sizes, equal to the CD.
        let d = data_end;
        if u32_at(bytes, d)? != DATA_DESCRIPTOR_SIG
            || u32_at(bytes, add(d, 4)?)? != crc
            || u32_at(bytes, add(d, 8)?)? != csize
            || u32_at(bytes, add(d, 12)?)? != usize_
        {
            return Err(malformed("data descriptor missing or inconsistent"));
        }
        data_end = add(d, DATA_DESCRIPTOR_LEN)?;
    }
    if data_end > entries_end {
        return Err(malformed("entry data outside the entries section"));
    }
    Ok(Entry {
        local,
        name: l_name_at..l_extra_at,
        extra: l_extra.to_vec(),
        data: data_start..data_end,
        cd: cd.range.clone(),
        stored,
    })
}

/// Stored `lib/**/*.so` → 16 KiB, other stored entries → 4 bytes.
fn alignment_for(name: &[u8]) -> usize {
    if name.starts_with(b"lib/") && name.ends_with(b".so") {
        ALIGN_NATIVE_LIB
    } else {
        ALIGN_DEFAULT
    }
}

/// Lays the entries out in order and returns, per entry, the new local extra field if
/// its data would be misaligned (`None`: keep as is). Entries are re-padded in order, so
/// each position already accounts for the padding added before it.
fn plan_alignment(src: &[u8], entries: &[Entry]) -> Result<Vec<Option<Vec<u8>>>> {
    let mut plan = Vec::with_capacity(entries.len());
    let mut pos = 0usize;
    for e in entries {
        let name = src.get(e.name.clone()).ok_or(Error::Internal("name"))?;
        let without_extra = add(add(pos, LOCAL_LEN)?, name.len())?;
        let alignment = alignment_for(name);
        let new_extra = if e.stored && !add(without_extra, e.extra.len())?.is_multiple_of(alignment)
        {
            Some(aligned_extra(&e.extra, without_extra, alignment)?)
        } else {
            None
        };
        let extra_len = new_extra.as_ref().map_or(e.extra.len(), Vec::len);
        pos = add(add(without_extra, extra_len)?, e.data.len())?;
        plan.push(new_extra);
    }
    if u32::try_from(pos).is_err() {
        return Err(Error::TooLarge);
    }
    Ok(plan)
}

/// New local extra field so that data starting at `without_extra + extra.len()` is a
/// multiple of `alignment`.
fn aligned_extra(extra: &[u8], without_extra: usize, alignment: usize) -> Result<Vec<u8>> {
    let records = extra_records(extra);
    let mut out: Vec<u8> = match &records {
        // Drop previous alignment fields, keep everything else byte for byte.
        Some(r) => r
            .iter()
            .filter(|(id, _)| *id != EXTRA_ALIGNMENT)
            .flat_map(|(_, raw)| raw.iter().copied())
            .collect(),
        None => extra.to_vec(),
    };
    let rem = add(without_extra, out.len())?
        .checked_rem(alignment)
        .ok_or(Error::Internal("alignment"))?;
    let mut pad = if rem == 0 {
        0
    } else {
        alignment
            .checked_sub(rem)
            .ok_or(Error::Internal("alignment"))?
    };
    if pad > 0 {
        if records.is_some() {
            while pad < EXTRA_ALIGNMENT_MIN_LEN {
                pad = add(pad, alignment)?;
            }
            let data_len = u16::try_from(pad.checked_sub(4).ok_or(Error::Internal("pad"))?)
                .map_err(|_| Error::TooLarge)?;
            let align_u16 = u16::try_from(alignment).map_err(|_| Error::Internal("alignment"))?;
            out.extend_from_slice(&EXTRA_ALIGNMENT.to_le_bytes());
            out.extend_from_slice(&data_len.to_le_bytes());
            out.extend_from_slice(&align_u16.to_le_bytes());
            let zeros = pad
                .checked_sub(EXTRA_ALIGNMENT_MIN_LEN)
                .ok_or(Error::Internal("pad"))?;
            out.resize(add(out.len(), zeros)?, 0);
        } else {
            out.resize(add(out.len(), pad)?, 0);
        }
    }
    if out.len() > usize::from(u16::MAX) {
        return Err(Error::Unsupported(
            "local extra field too long after alignment",
        ));
    }
    // Zero padding can turn a malformed extra field into a well-formed one (`[0x01]` →
    // `01 00 00 00`, a ZIP64 record) that the parser would then reject.
    if has_zip64_extra(&out) {
        return Err(Error::Unsupported(
            "local extra field that cannot be aligned",
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn aligned_extra_structured_and_raw() {
        for base in 0..40usize {
            for alignment in [4usize, 16384] {
                let e = aligned_extra(&[], base, alignment).unwrap();
                assert_eq!((base + e.len()) % alignment, 0);
                assert!(e.is_empty() || e.len() >= 6);
                assert!(extra_records(&e).is_some());
                // Malformed input (3 zero bytes, old zipalign) gets raw zero padding.
                let e = aligned_extra(&[0, 0, 0], base, alignment).unwrap();
                assert_eq!((base + e.len()) % alignment, 0);
                assert_eq!(&e[..3], &[0, 0, 0]);
            }
        }
        // Zero padding must not create a ZIP64 extra record.
        assert!(matches!(
            aligned_extra(&[1], 45 - 1, 4),
            Err(Error::Unsupported(_))
        ));
        // Existing alignment fields are replaced, other fields kept.
        let mut extra = vec![0x55, 0x54, 1, 0, 9];
        extra.extend_from_slice(&[0x35, 0xd9, 3, 0, 4, 0, 0]);
        let e = aligned_extra(&extra, 1, 4).unwrap();
        assert_eq!(&e[..5], &[0x55, 0x54, 1, 0, 9]);
        assert_eq!((1 + e.len()) % 4, 0);
        assert_eq!(extra_records(&e).unwrap().len(), 2);
    }
}
