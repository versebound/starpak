//! Entry metadata types.

use std::fmt;

use crate::format::{METHOD_DEFLATE, METHOD_STORE, METHOD_ZSTD};

/// Index of an entry inside an [`Archive`](crate::Archive).
///
/// Ids are dense (`0..archive.len()`) and stable for the lifetime of the
/// archive, which makes them the natural handle to pass across an FFI
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct EntryId(pub u32);

impl EntryId {
    /// Numeric index.
    #[inline]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for EntryId {
    fn from(v: u32) -> Self {
        EntryId(v)
    }
}

impl From<usize> for EntryId {
    fn from(v: usize) -> Self {
        EntryId(v as u32)
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Compression method of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Stored verbatim (method 0).
    Store,
    /// Raw deflate (method 8).
    Deflate,
    /// zstd frame (CIG method 100).
    Zstd,
    /// Any other method; the raw value is kept.
    Other(u16),
}

impl Method {
    /// Maps a raw ZIP method value.
    pub fn from_raw(raw: u16) -> Method {
        match raw {
            METHOD_STORE => Method::Store,
            METHOD_DEFLATE => Method::Deflate,
            METHOD_ZSTD => Method::Zstd,
            other => Method::Other(other),
        }
    }

    /// Raw ZIP method value.
    pub fn raw(self) -> u16 {
        match self {
            Method::Store => METHOD_STORE,
            Method::Deflate => METHOD_DEFLATE,
            Method::Zstd => METHOD_ZSTD,
            Method::Other(v) => v,
        }
    }

    /// True when the library can decode this method.
    pub fn is_supported(self) -> bool {
        !matches!(self, Method::Other(_))
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::Store => f.write_str("store"),
            Method::Deflate => f.write_str("deflate"),
            Method::Zstd => f.write_str("zstd"),
            Method::Other(v) => write!(f, "method{v}"),
        }
    }
}

/// MS-DOS date/time as stored in ZIP headers (two-second resolution, local time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DosDateTime {
    /// Full year (1980..=2107).
    pub year: u16,
    /// Month 1..=12 (0 when unset).
    pub month: u8,
    /// Day of month 1..=31 (0 when unset).
    pub day: u8,
    /// Hour 0..=23.
    pub hour: u8,
    /// Minute 0..=59.
    pub minute: u8,
    /// Second 0..=58 (even values only).
    pub second: u8,
}

impl DosDateTime {
    /// Decodes the packed 32-bit `(date << 16) | time` value.
    pub fn from_raw(raw: u32) -> DosDateTime {
        DosDateTime {
            year: 1980 + (raw >> 25) as u16,
            month: ((raw >> 21) & 0x0F) as u8,
            day: ((raw >> 16) & 0x1F) as u8,
            hour: ((raw >> 11) & 0x1F) as u8,
            minute: ((raw >> 5) & 0x3F) as u8,
            second: ((raw & 0x1F) * 2) as u8,
        }
    }

    /// Packs back into the raw 32-bit form.
    pub fn to_raw(self) -> u32 {
        ((self.year.saturating_sub(1980) as u32) << 25)
            | ((self.month as u32) << 21)
            | ((self.day as u32) << 16)
            | ((self.hour as u32) << 11)
            | ((self.minute as u32) << 5)
            | (self.second as u32 / 2)
    }
}

impl fmt::Display for DosDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Fully decoded metadata of one entry (owned; no borrow of the archive).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// Dense index of the entry.
    pub id: EntryId,
    /// Name exactly as stored (p4k uses `\` separators).
    pub name: Box<str>,
    /// Compression method.
    pub method: Method,
    /// True when the payload is AES-128-CBC encrypted.
    pub encrypted: bool,
    /// CRC32C (Castagnoli) of the uncompressed data.
    pub crc32c: u32,
    /// Size of the stored payload (for encrypted entries, padded to 16).
    pub compressed_size: u64,
    /// Size of the decoded data.
    pub uncompressed_size: u64,
    /// Absolute offset of the local file header.
    pub local_header_offset: u64,
    /// Packed DOS modification time.
    pub dos_time: u32,
    /// General purpose bit flags.
    pub flags: u16,
    /// "Version made by" field.
    pub version_made_by: u16,
    /// "Version needed to extract" field.
    pub version_needed: u16,
    /// External file attributes.
    pub external_attrs: u32,
    /// Index of the disk the entry starts on (always 0 for p4k).
    pub disk_start: u32,
}

impl Entry {
    /// Entry name with `/` separators.
    pub fn path(&self) -> String {
        self.name.replace('\\', "/")
    }

    /// Decoded modification time.
    pub fn modified(&self) -> DosDateTime {
        DosDateTime::from_raw(self.dos_time)
    }

    /// Last path component.
    pub fn file_name(&self) -> &str {
        self.name.rsplit(['\\', '/']).next().unwrap_or(&self.name)
    }

    /// Extension (lower-cased) without the dot, if any.
    pub fn extension(&self) -> Option<String> {
        let f = self.file_name();
        f.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
    }

    /// True when the entry names a directory (trailing separator).
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('\\') || self.name.ends_with('/')
    }
}

/// Borrowed view of an entry produced while iterating; cheap to copy.
#[derive(Debug, Clone, Copy)]
pub struct EntryRef<'a> {
    pub(crate) archive: &'a crate::Archive,
    pub(crate) id: EntryId,
    pub(crate) name: &'a str,
}

impl<'a> EntryRef<'a> {
    /// Dense index.
    #[inline]
    pub fn id(&self) -> EntryId {
        self.id
    }

    /// Name as stored (no allocation).
    #[inline]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Fully decoded, owned metadata.
    pub fn entry(&self) -> Entry {
        self.archive
            .entry(self.id)
            .expect("entry id produced by the archive is valid")
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_time_roundtrip() {
        let t = DosDateTime {
            year: 2026,
            month: 10,
            day: 4,
            hour: 2,
            minute: 48,
            second: 30,
        };
        assert_eq!(DosDateTime::from_raw(t.to_raw()), t);
        assert_eq!(t.to_string(), "2026-10-04 02:48:30");
        assert_eq!(
            DosDateTime::from_raw(0),
            DosDateTime {
                year: 1980,
                month: 0,
                day: 0,
                hour: 0,
                minute: 0,
                second: 0
            }
        );
    }

    #[test]
    fn method_mapping() {
        assert_eq!(Method::from_raw(0), Method::Store);
        assert_eq!(Method::from_raw(8), Method::Deflate);
        assert_eq!(Method::from_raw(100), Method::Zstd);
        assert_eq!(Method::from_raw(12), Method::Other(12));
        assert_eq!(Method::Other(12).raw(), 12);
        assert!(!Method::Other(12).is_supported());
        assert_eq!(Method::Zstd.to_string(), "zstd");
        assert_eq!(Method::Other(3).to_string(), "method3");
    }
}
