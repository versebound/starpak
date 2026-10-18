//! Error type shared by every part of the crate.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every failure the library can report.
///
/// The enum is `#[non_exhaustive]` so new variants can be added without a
/// breaking change; match with a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure (open, pread, mmap).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The file is too small or has no end-of-central-directory record.
    /// Either it is not a ZIP/p4k at all, or it was truncated.
    #[error(
        "no end-of-central-directory record found: not a p4k/zip archive or the file is truncated"
    )]
    NoEndOfCentralDirectory,

    /// The file starts like a ZIP but the trailing records are missing: it
    /// was cut short (e.g. an interrupted download or copy).
    #[error("archive is truncated: local file headers present but no end-of-central-directory record (file size {file_size})")]
    Truncated {
        /// Size of the file that was inspected.
        file_size: u64,
    },

    /// A ZIP64 record references a position outside the file.
    #[error("central directory out of bounds: offset {offset} + size {size} exceeds file size {file_size}")]
    CentralDirectoryOutOfBounds {
        /// Central directory start offset.
        offset: u64,
        /// Central directory size in bytes.
        size: u64,
        /// Size of the file.
        file_size: u64,
    },

    /// A structural problem while walking the central directory.
    #[error("corrupt central directory at entry #{index} (offset {offset}): {reason}")]
    CorruptCentralDirectory {
        /// Index of the entry being decoded.
        index: u64,
        /// Byte offset of the entry header relative to the central directory start.
        offset: u64,
        /// Human readable reason.
        reason: &'static str,
    },

    /// A record signature did not match the expected magic.
    #[error(
        "bad {what} signature at offset {offset}: expected 0x{expected:08x}, found 0x{found:08x}"
    )]
    BadSignature {
        /// Which record carried the bad signature.
        what: &'static str,
        /// Absolute file offset.
        offset: u64,
        /// Expected signature value.
        expected: u32,
        /// Signature actually found.
        found: u32,
    },

    /// An entry index or path does not exist.
    #[error("entry not found: {0}")]
    NotFound(String),

    /// The entry uses a compression method the library does not implement.
    #[error("unsupported compression method {method} for entry {name}")]
    UnsupportedMethod {
        /// Raw compression method value from the central directory.
        method: u16,
        /// Entry name.
        name: String,
    },

    /// An encrypted entry has a payload that is not a multiple of the AES block size.
    #[error("encrypted entry {name} has a compressed size ({size}) that is not a multiple of 16")]
    BadEncryptedSize {
        /// Entry name.
        name: String,
        /// Compressed size.
        size: u64,
    },

    /// Decompression failed (corrupt or misdescribed payload).
    #[error("decompression failed for entry {name}: {reason}")]
    Decompress {
        /// Entry name.
        name: String,
        /// Reason reported by the codec.
        reason: String,
    },

    /// The payload decoded to a different length than the central directory claims.
    #[error("entry {name} decoded to {actual} bytes, expected {expected}")]
    SizeMismatch {
        /// Entry name.
        name: String,
        /// Expected size.
        expected: u64,
        /// Actual size.
        actual: u64,
    },

    /// The CRC32C of the decoded data does not match the central directory.
    #[error("CRC mismatch for entry {name}: expected 0x{expected:08x}, computed 0x{actual:08x}")]
    CrcMismatch {
        /// Entry name.
        name: String,
        /// CRC recorded in the central directory.
        expected: u32,
        /// CRC computed from the decoded bytes.
        actual: u32,
    },

    /// An entry's data range extends past the end of the file.
    #[error("entry {name} data range {offset}+{len} lies outside the file (size {file_size})")]
    DataOutOfBounds {
        /// Entry name.
        name: String,
        /// Absolute data offset.
        offset: u64,
        /// Data length.
        len: u64,
        /// File size.
        file_size: u64,
    },

    /// An entry name is not valid UTF-8.
    #[error("entry #{index} has a name that is not valid UTF-8")]
    InvalidEntryName {
        /// Index of the entry.
        index: u64,
    },

    /// A glob pattern could not be compiled.
    #[error("invalid glob pattern: {0}")]
    Glob(#[from] globset::Error),

    /// Binary CryXML decoding failed.
    #[error("CryXmlB: {0}")]
    CryXml(String),

    /// The bytes are neither binary CryXML nor text XML.
    #[error("data is neither CryXmlB nor text XML")]
    NotXml,

    /// DataForge (.dcb) decoding failed.
    #[error("DataForge: {0}")]
    DataForge(String),
}

impl Error {
    pub(crate) fn corrupt_cd(index: u64, offset: u64, reason: &'static str) -> Self {
        Error::CorruptCentralDirectory {
            index,
            offset,
            reason,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn cryxml(msg: impl fmt::Display) -> Self {
        Error::CryXml(msg.to_string())
    }

    #[allow(dead_code)]
    pub(crate) fn dataforge(msg: impl fmt::Display) -> Self {
        Error::DataForge(msg.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(io) => io,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
        }
    }
}
