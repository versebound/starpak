//! Reading entry payloads: bulk into memory and as a streaming [`Read`].

use std::cell::RefCell;
use std::io::{self, BufReader, Read};
use std::sync::Arc;

use crate::archive::{Archive, Inner};
use crate::crypto::{self, CbcReader, BLOCK};
use crate::entry::{Entry, EntryId, Method};
use crate::error::{Error, Result};
use crate::util::{read_at, read_exact_at};

/// Chunk size used by the streaming readers.
const STREAM_CHUNK: usize = 256 << 10;

thread_local! {
    static ZSTD: RefCell<Option<zstd::bulk::Decompressor<'static>>> = const { RefCell::new(None) };
}

fn with_zstd<T>(
    f: impl FnOnce(&mut zstd::bulk::Decompressor<'static>) -> io::Result<T>,
) -> io::Result<T> {
    ZSTD.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let mut d = zstd::bulk::Decompressor::new()?;
            d.window_log_max(31)?;
            *slot = Some(d);
        }
        f(slot.as_mut().expect("initialised above"))
    })
}

/// Positional reader over a byte range of the archive file.
struct RangeReader {
    inner: Arc<Inner>,
    pos: u64,
    end: u64,
}

impl Read for RangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.end - self.pos;
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(left) as usize;
        let n = read_at(&self.inner.file, &mut buf[..want], self.pos)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "archive file ended inside an entry payload",
            ));
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// Streaming reader over one entry's decoded bytes.
///
/// Implements [`Read`]; the CRC32C of everything read so far is tracked and
/// checked once the final byte is delivered (unless disabled with
/// [`EntryReader::verify`]). The reader owns a reference to the archive and
/// has no lifetime parameter.
pub struct EntryReader {
    inner: Box<dyn Read + Send>,
    total: u64,
    remaining: u64,
    crc: u32,
    expected: u32,
    verify: bool,
    checked: bool,
    name: Box<str>,
}

impl EntryReader {
    /// Enables or disables the CRC check performed on the final read.
    pub fn verify(mut self, on: bool) -> Self {
        self.verify = on;
        self
    }

    /// Bytes not yet delivered.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Name of the entry being read.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// CRC32C of the bytes delivered so far.
    pub fn crc32c(&self) -> u32 {
        self.crc
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.checked {
            return Ok(());
        }
        self.checked = true;
        if self.verify && self.crc != self.expected {
            return Err(Error::CrcMismatch {
                name: self.name.to_string(),
                expected: self.expected,
                actual: self.crc,
            }
            .into());
        }
        Ok(())
    }
}

impl Read for EntryReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            self.finish()?;
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.remaining) as usize;
        if want == 0 {
            return Ok(0);
        }
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(Error::SizeMismatch {
                name: self.name.to_string(),
                expected: self.total,
                actual: self.total - self.remaining,
            }
            .into());
        }
        self.crc = crc32c::crc32c_append(self.crc, &buf[..n]);
        self.remaining -= n as u64;
        if self.remaining == 0 {
            self.finish()?;
        }
        Ok(n)
    }
}

impl Archive {
    fn resolve(&self, id: EntryId) -> Result<Entry> {
        self.stat(id)
    }

    /// Reads the whole entry into a new buffer, verifying its CRC32C.
    pub fn read(&self, id: EntryId) -> Result<Vec<u8>> {
        let e = self.resolve(id)?;
        let mut out = Vec::new();
        self.read_entry_into(&e, &mut out, true)?;
        Ok(out)
    }

    /// Like [`Archive::read`] but skips the CRC check.
    pub fn read_unverified(&self, id: EntryId) -> Result<Vec<u8>> {
        let e = self.resolve(id)?;
        let mut out = Vec::new();
        self.read_entry_into(&e, &mut out, false)?;
        Ok(out)
    }

    /// Appends the decoded entry to `out` (reusing its allocation).
    pub fn read_into(&self, id: EntryId, out: &mut Vec<u8>) -> Result<()> {
        let e = self.resolve(id)?;
        self.read_entry_into(&e, out, true)
    }

    /// Reads an entry by path (see [`Archive::find`] for matching rules).
    pub fn read_path(&self, path: &str) -> Result<Vec<u8>> {
        let e = self.entry_by_path(path)?;
        let mut out = Vec::new();
        self.read_entry_into(&e, &mut out, true)?;
        Ok(out)
    }

    /// Reads an entry whose metadata is already at hand.
    pub fn read_entry(&self, e: &Entry) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_entry_into(e, &mut out, true)?;
        Ok(out)
    }

    /// Core bulk path: one positional read of the payload, in-place
    /// decryption, single-shot decompression into `out`'s spare capacity.
    pub fn read_entry_into(&self, e: &Entry, out: &mut Vec<u8>, verify: bool) -> Result<()> {
        check_supported(e)?;
        let (_, data_off) = self.local_header(e)?;
        let comp = usize::try_from(e.compressed_size).map_err(|_| too_big(e))?;
        let uncomp = usize::try_from(e.uncompressed_size).map_err(|_| too_big(e))?;
        let start = out.len();

        match (e.method, e.encrypted) {
            (Method::Store, false) => {
                if comp < uncomp {
                    return Err(Error::SizeMismatch {
                        name: e.name.to_string(),
                        expected: e.uncompressed_size,
                        actual: e.compressed_size,
                    });
                }
                out.resize(start + uncomp, 0);
                read_exact_at(&self.inner.file, &mut out[start..], data_off)?;
            }
            (Method::Store, true) => {
                out.resize(start + comp, 0);
                read_exact_at(&self.inner.file, &mut out[start..], data_off)?;
                crypto::decrypt_in_place(&self.inner.key, &mut out[start..]);
                if comp < uncomp {
                    return Err(Error::SizeMismatch {
                        name: e.name.to_string(),
                        expected: e.uncompressed_size,
                        actual: e.compressed_size,
                    });
                }
                out.truncate(start + uncomp);
            }
            (method, encrypted) => {
                let mut raw = vec![0u8; comp];
                read_exact_at(&self.inner.file, &mut raw, data_off)?;
                if encrypted {
                    crypto::decrypt_in_place(&self.inner.key, &mut raw);
                }
                match method {
                    Method::Zstd => {
                        // Encrypted payloads carry zero padding after the
                        // frame, so measure the frame instead of trusting the
                        // stored size (cheap: only block headers are read).
                        let n = zstd::zstd_safe::find_frame_compressed_size(&raw)
                            .map_err(|c| decompress_err(e, zstd::zstd_safe::get_error_name(c)))?;
                        let src = &raw[..n.min(raw.len())];
                        // Decode into a pre-sized slice: zstd's `Vec` sink
                        // would overwrite `out` from its start.
                        out.resize(start + uncomp, 0);
                        let n = with_zstd(|d| d.decompress_to_buffer(src, &mut out[start..]))
                            .map_err(|err| decompress_err(e, err))?;
                        if n != uncomp {
                            out.truncate(start);
                            return Err(Error::SizeMismatch {
                                name: e.name.to_string(),
                                expected: e.uncompressed_size,
                                actual: n as u64,
                            });
                        }
                    }
                    Method::Deflate => {
                        out.reserve(uncomp);
                        let d = flate2::read::DeflateDecoder::new(&raw[..]);
                        let n = d
                            .take(uncomp as u64 + 1)
                            .read_to_end(out)
                            .map_err(|err| decompress_err(e, err))?;
                        if n != uncomp {
                            out.truncate(start);
                            return Err(Error::SizeMismatch {
                                name: e.name.to_string(),
                                expected: e.uncompressed_size,
                                actual: n as u64,
                            });
                        }
                    }
                    Method::Store | Method::Other(_) => unreachable!("handled above"),
                }
            }
        }

        if verify {
            let actual = crc32c::crc32c(&out[start..]);
            if actual != e.crc32c {
                out.truncate(start);
                return Err(Error::CrcMismatch {
                    name: e.name.to_string(),
                    expected: e.crc32c,
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Opens a streaming reader over the decoded bytes of entry `id`.
    pub fn open_entry(&self, id: EntryId) -> Result<EntryReader> {
        let e = self.resolve(id)?;
        self.open_entry_stream(&e)
    }

    /// Opens a streaming reader for an entry whose metadata is at hand.
    pub fn open_entry_stream(&self, e: &Entry) -> Result<EntryReader> {
        check_supported(e)?;
        let (_, data_off) = self.local_header(e)?;
        let raw = RangeReader {
            inner: Arc::clone(&self.inner),
            pos: data_off,
            end: data_off + e.compressed_size,
        };
        let source: Box<dyn Read + Send> = if e.encrypted {
            Box::new(CbcReader::new(raw, &self.inner.key, STREAM_CHUNK))
        } else {
            Box::new(raw)
        };
        let decoded: Box<dyn Read + Send> = match e.method {
            Method::Store => source,
            Method::Deflate => Box::new(flate2::read::DeflateDecoder::new(
                BufReader::with_capacity(STREAM_CHUNK, source),
            )),
            Method::Zstd => {
                let mut d = zstd::stream::read::Decoder::with_buffer(BufReader::with_capacity(
                    STREAM_CHUNK,
                    source,
                ))
                .map_err(|err| decompress_err(e, err))?;
                d.window_log_max(31).map_err(|err| decompress_err(e, err))?;
                Box::new(d.single_frame())
            }
            Method::Other(_) => unreachable!("rejected by check_supported"),
        };
        Ok(EntryReader {
            inner: decoded,
            total: e.uncompressed_size,
            remaining: e.uncompressed_size,
            crc: 0,
            expected: e.crc32c,
            verify: true,
            checked: false,
            name: e.name.clone(),
        })
    }

    /// Streams the entry through the decoder and checks its CRC32C without
    /// keeping the data in memory.
    pub fn verify(&self, id: EntryId) -> Result<()> {
        let mut r = self.open_entry(id)?;
        let mut sink = vec![0u8; STREAM_CHUNK];
        loop {
            let n = r.read(&mut sink).map_err(unwrap_io)?;
            if n == 0 {
                return Ok(());
            }
        }
    }

    /// Reads the stored payload exactly as it sits in the file (compressed
    /// and/or encrypted).
    pub fn read_raw(&self, id: EntryId) -> Result<Vec<u8>> {
        let e = self.resolve(id)?;
        let (_, data_off) = self.local_header(&e)?;
        let comp = usize::try_from(e.compressed_size).map_err(|_| too_big(&e))?;
        let mut raw = vec![0u8; comp];
        read_exact_at(&self.inner.file, &mut raw, data_off)?;
        Ok(raw)
    }
}

fn check_supported(e: &Entry) -> Result<()> {
    if !e.method.is_supported() {
        return Err(Error::UnsupportedMethod {
            method: e.method.raw(),
            name: e.name.to_string(),
        });
    }
    if e.encrypted && e.compressed_size % BLOCK as u64 != 0 {
        return Err(Error::BadEncryptedSize {
            name: e.name.to_string(),
            size: e.compressed_size,
        });
    }
    Ok(())
}

fn too_big(e: &Entry) -> Error {
    Error::Decompress {
        name: e.name.to_string(),
        reason: "entry does not fit in memory on this platform".into(),
    }
}

fn decompress_err(e: &Entry, reason: impl std::fmt::Display) -> Error {
    Error::Decompress {
        name: e.name.to_string(),
        reason: reason.to_string(),
    }
}

/// Converts an `io::Error` produced by [`EntryReader`] back into the
/// library error it wraps, when it does.
pub(crate) fn unwrap_io(err: io::Error) -> Error {
    if err.get_ref().is_some_and(|inner| inner.is::<Error>()) {
        match err.into_inner().and_then(|b| b.downcast::<Error>().ok()) {
            Some(e) => *e,
            None => Error::Io(io::Error::other("unknown error")),
        }
    } else {
        Error::Io(err)
    }
}
