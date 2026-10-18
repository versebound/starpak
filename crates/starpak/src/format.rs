//! On-disk ZIP / p4k record layouts.
//!
//! A p4k is a ZIP64 archive written by CIG's own packer. It follows the
//! PKWARE layout closely enough that the standard records apply, with these
//! deviations (all handled here):
//!
//! * The extra-field length of the ZIP64 block (tag `0x0001`) and of the
//!   CIG blocks (`0x5000`, `0x5002`, `0x5003`, `0x0666`) *includes* the
//!   four-byte tag header, whereas PKWARE sizes exclude it.
//! * Tag `0x5002` carries a `u16` "encrypted" flag; `0x5000` (128 bytes)
//!   and `0x5003` (32 bytes) are opaque.
//! * Local file headers of encrypted entries use the signature `PK\x03\x14`
//!   instead of `PK\x03\x04`; their extra field is padding (tag `0x0666`)
//!   that aligns the payload to 4096 bytes.
//! * Compression method `100` is zstd; the CRC field holds CRC32C
//!   (Castagnoli) of the uncompressed data rather than CRC32.
//! * The archive ends with a 16-byte `CIG` comment and zero padding to a
//!   4096-byte boundary after the EOCD record.

#![allow(missing_docs)]

use crate::error::{Error, Result};
use crate::util::Le;

pub const LOCAL_SIG: u32 = 0x0403_4b50;
pub const LOCAL_SIG_ENCRYPTED: u32 = 0x1403_4b50;
pub const CD_SIG: u32 = 0x0201_4b50;
pub const EOCD_SIG: u32 = 0x0605_4b50;
pub const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
pub const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;

pub const EOCD_LEN: usize = 22;
pub const ZIP64_LOCATOR_LEN: usize = 20;
pub const ZIP64_EOCD_LEN: usize = 56;
pub const CD_HEADER_LEN: usize = 46;
pub const LOCAL_HEADER_LEN: usize = 30;

pub const EXTRA_ZIP64: u16 = 0x0001;
pub const EXTRA_CIG_0: u16 = 0x5000;
pub const EXTRA_CIG_ENCRYPTED: u16 = 0x5002;
pub const EXTRA_CIG_3: u16 = 0x5003;
pub const EXTRA_CIG_PADDING: u16 = 0x0666;

pub const METHOD_STORE: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;
pub const METHOD_ZSTD: u16 = 100;

/// End-of-central-directory record (classic, 22 bytes + comment).
#[derive(Debug, Clone)]
pub struct Eocd {
    pub disk: u16,
    pub cd_disk: u16,
    pub entries_on_disk: u16,
    pub total_entries: u16,
    pub cd_size: u32,
    pub cd_offset: u32,
    pub comment: Vec<u8>,
}

impl Eocd {
    pub fn parse(buf: &[u8]) -> Option<Eocd> {
        let mut r = Le::new(buf);
        if r.u32()? != EOCD_SIG {
            return None;
        }
        let disk = r.u16()?;
        let cd_disk = r.u16()?;
        let entries_on_disk = r.u16()?;
        let total_entries = r.u16()?;
        let cd_size = r.u32()?;
        let cd_offset = r.u32()?;
        let comment_len = r.u16()? as usize;
        let comment = r.bytes(comment_len).unwrap_or(&[]).to_vec();
        Some(Eocd {
            disk,
            cd_disk,
            entries_on_disk,
            total_entries,
            cd_size,
            cd_offset,
            comment,
        })
    }

    /// True when any field carries a ZIP64 sentinel.
    pub fn needs_zip64(&self) -> bool {
        self.disk == 0xFFFF
            || self.cd_disk == 0xFFFF
            || self.entries_on_disk == 0xFFFF
            || self.total_entries == 0xFFFF
            || self.cd_size == 0xFFFF_FFFF
            || self.cd_offset == 0xFFFF_FFFF
    }
}

/// ZIP64 end-of-central-directory locator (20 bytes).
#[derive(Debug, Clone, Copy)]
pub struct Zip64Locator {
    pub eocd64_disk: u32,
    pub eocd64_offset: u64,
    pub total_disks: u32,
}

impl Zip64Locator {
    pub fn parse(buf: &[u8]) -> Option<Zip64Locator> {
        let mut r = Le::new(buf);
        if r.u32()? != ZIP64_LOCATOR_SIG {
            return None;
        }
        Some(Zip64Locator {
            eocd64_disk: r.u32()?,
            eocd64_offset: r.u64()?,
            total_disks: r.u32()?,
        })
    }
}

/// ZIP64 end-of-central-directory record (first 56 bytes).
#[derive(Debug, Clone, Copy)]
pub struct Zip64Eocd {
    pub record_size: u64,
    pub version_made_by: u16,
    pub version_needed: u16,
    pub disk: u32,
    pub cd_disk: u32,
    pub entries_on_disk: u64,
    pub total_entries: u64,
    pub cd_size: u64,
    pub cd_offset: u64,
}

impl Zip64Eocd {
    pub fn parse(buf: &[u8]) -> Option<Zip64Eocd> {
        let mut r = Le::new(buf);
        if r.u32()? != ZIP64_EOCD_SIG {
            return None;
        }
        Some(Zip64Eocd {
            record_size: r.u64()?,
            version_made_by: r.u16()?,
            version_needed: r.u16()?,
            disk: r.u32()?,
            cd_disk: r.u32()?,
            entries_on_disk: r.u64()?,
            total_entries: r.u64()?,
            cd_size: r.u64()?,
            cd_offset: r.u64()?,
        })
    }
}

/// Fixed part of a central-directory file header.
#[derive(Debug, Clone, Copy)]
pub struct CdHeader {
    pub version_made_by: u16,
    pub version_needed: u16,
    pub flags: u16,
    pub method: u16,
    pub dos_time: u32,
    pub crc: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub name_len: u16,
    pub extra_len: u16,
    pub comment_len: u16,
    pub disk_start: u16,
    pub internal_attrs: u16,
    pub external_attrs: u32,
    pub local_header_offset: u32,
}

impl CdHeader {
    /// Parses the 46-byte fixed header; `None` on short input or bad magic.
    #[inline]
    pub fn parse(buf: &[u8]) -> Option<CdHeader> {
        if buf.len() < CD_HEADER_LEN {
            return None;
        }
        let mut r = Le::new(buf);
        if r.u32()? != CD_SIG {
            return None;
        }
        Some(CdHeader {
            version_made_by: r.u16()?,
            version_needed: r.u16()?,
            flags: r.u16()?,
            method: r.u16()?,
            dos_time: r.u32()?,
            crc: r.u32()?,
            compressed_size: r.u32()?,
            uncompressed_size: r.u32()?,
            name_len: r.u16()?,
            extra_len: r.u16()?,
            comment_len: r.u16()?,
            disk_start: r.u16()?,
            internal_attrs: r.u16()?,
            external_attrs: r.u32()?,
            local_header_offset: r.u32()?,
        })
    }

    /// Total length of this entry including name, extra field and comment.
    #[inline]
    pub fn total_len(&self) -> usize {
        CD_HEADER_LEN + self.name_len as usize + self.extra_len as usize + self.comment_len as usize
    }
}

/// Values resolved from a central-directory entry's extra field.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExtraInfo {
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_header_offset: u64,
    pub disk_start: u32,
    pub encrypted: bool,
}

/// Walks a central-directory extra field, resolving ZIP64 values and the
/// CIG encryption flag. Tolerates both PKWARE-style sizes (payload only)
/// and CIG-style sizes (payload plus tag header).
pub fn parse_cd_extra(header: &CdHeader, extra: &[u8]) -> ExtraInfo {
    let mut info = ExtraInfo {
        compressed_size: header.compressed_size as u64,
        uncompressed_size: header.uncompressed_size as u64,
        local_header_offset: header.local_header_offset as u64,
        disk_start: header.disk_start as u32,
        encrypted: false,
    };
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let tag = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let size = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        let body_start = pos + 4;
        match tag {
            EXTRA_ZIP64 => {
                let mut r = Le::at(extra, body_start);
                if header.uncompressed_size == u32::MAX {
                    if let Some(v) = r.u64() {
                        info.uncompressed_size = v;
                    }
                }
                if header.compressed_size == u32::MAX {
                    if let Some(v) = r.u64() {
                        info.compressed_size = v;
                    }
                }
                if header.local_header_offset == u32::MAX {
                    if let Some(v) = r.u64() {
                        info.local_header_offset = v;
                    }
                }
                if header.disk_start == u16::MAX {
                    if let Some(v) = r.u32() {
                        info.disk_start = v;
                    }
                }
                let consumed = r.pos - body_start;
                // CIG declares `consumed + 4`; PKWARE declares `consumed`.
                // Prefer the position where a known tag follows.
                let cig_next = body_start + consumed;
                let std_next = body_start + size;
                pos = if size != consumed && is_known_tag_at(extra, cig_next) {
                    cig_next
                } else {
                    std_next
                };
            }
            EXTRA_CIG_ENCRYPTED => {
                if body_start + 2 <= extra.len() {
                    info.encrypted =
                        u16::from_le_bytes([extra[body_start], extra[body_start + 1]]) != 0;
                }
                pos = body_start + cig_body_len(size);
            }
            EXTRA_CIG_0 | EXTRA_CIG_3 | EXTRA_CIG_PADDING => {
                pos = body_start + cig_body_len(size);
            }
            _ => {
                pos = body_start + size;
            }
        }
        if pos <= body_start - 4 {
            break; // no progress; malformed
        }
    }
    info
}

#[inline]
fn cig_body_len(size: usize) -> usize {
    // CIG sizes include the 4-byte header; a size below 4 is malformed and
    // treated as an empty body so the walk still advances.
    size.saturating_sub(4)
}

#[inline]
fn is_known_tag_at(extra: &[u8], pos: usize) -> bool {
    if pos + 2 > extra.len() {
        return pos == extra.len();
    }
    matches!(
        u16::from_le_bytes([extra[pos], extra[pos + 1]]),
        EXTRA_CIG_0 | EXTRA_CIG_ENCRYPTED | EXTRA_CIG_3 | EXTRA_CIG_PADDING | EXTRA_ZIP64
    )
}

/// Fixed part of a local file header.
#[derive(Debug, Clone, Copy)]
pub struct LocalHeader {
    pub signature: u32,
    pub version_needed: u16,
    pub flags: u16,
    pub method: u16,
    pub dos_time: u32,
    pub crc: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub name_len: u16,
    pub extra_len: u16,
}

impl LocalHeader {
    pub fn parse(buf: &[u8], offset: u64) -> Result<LocalHeader> {
        let mut r = Le::new(buf);
        let short = || {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short local file header",
            ))
        };
        let signature = r.u32().ok_or_else(short)?;
        if signature != LOCAL_SIG && signature != LOCAL_SIG_ENCRYPTED {
            return Err(Error::BadSignature {
                what: "local file header",
                offset,
                expected: LOCAL_SIG,
                found: signature,
            });
        }
        Ok(LocalHeader {
            signature,
            version_needed: r.u16().ok_or_else(short)?,
            flags: r.u16().ok_or_else(short)?,
            method: r.u16().ok_or_else(short)?,
            dos_time: r.u32().ok_or_else(short)?,
            crc: r.u32().ok_or_else(short)?,
            compressed_size: r.u32().ok_or_else(short)?,
            uncompressed_size: r.u32().ok_or_else(short)?,
            name_len: r.u16().ok_or_else(short)?,
            extra_len: r.u16().ok_or_else(short)?,
        })
    }

    /// Offset of the payload relative to the header start.
    #[inline]
    pub fn data_start(&self) -> u64 {
        LOCAL_HEADER_LEN as u64 + self.name_len as u64 + self.extra_len as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(comp: u32, uncomp: u32, off: u32, disk: u16) -> CdHeader {
        CdHeader {
            version_made_by: 46,
            version_needed: 45,
            flags: 0,
            method: 100,
            dos_time: 0,
            crc: 0,
            compressed_size: comp,
            uncompressed_size: uncomp,
            name_len: 0,
            extra_len: 0,
            comment_len: 0,
            disk_start: disk,
            internal_attrs: 0,
            external_attrs: 0,
            local_header_offset: off,
        }
    }

    #[test]
    fn cig_style_extra() {
        // ZIP64 block declares 32 bytes but carries 28 (CIG quirk), then
        // 0x5000 (132 incl. header), 0x5002 (6 incl. header), 0x5003 (36).
        let mut e = Vec::new();
        e.extend_from_slice(&0x0001u16.to_le_bytes());
        e.extend_from_slice(&32u16.to_le_bytes());
        e.extend_from_slice(&10u64.to_le_bytes());
        e.extend_from_slice(&20u64.to_le_bytes());
        e.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&0x5000u16.to_le_bytes());
        e.extend_from_slice(&132u16.to_le_bytes());
        e.extend_from_slice(&[0u8; 128]);
        e.extend_from_slice(&0x5002u16.to_le_bytes());
        e.extend_from_slice(&6u16.to_le_bytes());
        e.extend_from_slice(&1u16.to_le_bytes());
        e.extend_from_slice(&0x5003u16.to_le_bytes());
        e.extend_from_slice(&36u16.to_le_bytes());
        e.extend_from_slice(&[0u8; 32]);
        assert_eq!(e.len(), 206);
        let info = parse_cd_extra(&header(u32::MAX, u32::MAX, u32::MAX, u16::MAX), &e);
        assert_eq!(info.uncompressed_size, 10);
        assert_eq!(info.compressed_size, 20);
        assert_eq!(info.local_header_offset, 0x1_0000_0000);
        assert_eq!(info.disk_start, 0);
        assert!(info.encrypted);
    }

    #[test]
    fn pkware_style_extra() {
        let mut e = Vec::new();
        e.extend_from_slice(&0x0001u16.to_le_bytes());
        e.extend_from_slice(&16u16.to_le_bytes());
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&9u64.to_le_bytes());
        // unknown tag with 3-byte body
        e.extend_from_slice(&0x7075u16.to_le_bytes());
        e.extend_from_slice(&3u16.to_le_bytes());
        e.extend_from_slice(&[1, 2, 3]);
        let info = parse_cd_extra(&header(u32::MAX, u32::MAX, 5, 0), &e);
        assert_eq!(info.uncompressed_size, 7);
        assert_eq!(info.compressed_size, 9);
        assert_eq!(info.local_header_offset, 5);
        assert!(!info.encrypted);
    }

    #[test]
    fn malformed_extra_terminates() {
        let e = [0x02u8, 0x50, 0x00, 0x00, 0xff];
        let info = parse_cd_extra(&header(1, 1, 1, 0), &e);
        assert!(!info.encrypted);
        let e = [0x01u8, 0x00, 0xff, 0xff, 1, 2];
        let _ = parse_cd_extra(&header(u32::MAX, 1, 1, 0), &e);
    }

    #[test]
    fn eocd_parse_and_sentinels() {
        let mut b = Vec::new();
        b.extend_from_slice(&EOCD_SIG.to_le_bytes());
        b.extend_from_slice(&[0xff; 4]);
        b.extend_from_slice(&3u16.to_le_bytes());
        b.extend_from_slice(&3u16.to_le_bytes());
        b.extend_from_slice(&100u32.to_le_bytes());
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(b"hi");
        let e = Eocd::parse(&b).unwrap();
        assert!(e.needs_zip64());
        assert_eq!(e.comment, b"hi");
        assert!(Eocd::parse(&b[1..]).is_none());
    }

    #[test]
    fn local_header_signatures() {
        let mut b = vec![0u8; 30];
        b[..4].copy_from_slice(&LOCAL_SIG_ENCRYPTED.to_le_bytes());
        b[26..28].copy_from_slice(&5u16.to_le_bytes());
        b[28..30].copy_from_slice(&7u16.to_le_bytes());
        let h = LocalHeader::parse(&b, 0).unwrap();
        assert_eq!(h.data_start(), 42);
        b[..4].copy_from_slice(&CD_SIG.to_le_bytes());
        assert!(matches!(
            LocalHeader::parse(&b, 9),
            Err(Error::BadSignature { offset: 9, .. })
        ));
        b[..4].copy_from_slice(&LOCAL_SIG.to_le_bytes());
        assert!(matches!(LocalHeader::parse(&b[..10], 0), Err(Error::Io(_))));
    }
}
