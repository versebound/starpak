//! The [`Archive`] handle: opening a p4k and indexing its central directory.

use std::fs::File;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use crate::entry::{Entry, EntryId, EntryRef, Method};
use crate::error::{Error, Result};
use crate::format::{
    self, CdHeader, Eocd, LocalHeader, Zip64Eocd, Zip64Locator, CD_HEADER_LEN, EOCD_LEN,
    LOCAL_HEADER_LEN, ZIP64_EOCD_LEN, ZIP64_LOCATOR_LEN,
};
use crate::tree::DirTree;
use crate::util::{self, hash_path, path_eq, path_starts_with, read_exact_at, Le};

/// Options for [`Archive::open_with`].
#[derive(Debug, Clone)]
pub struct OpenOptions {
    /// AES-128 key for encrypted entries. Defaults to the Star Citizen key.
    pub key: [u8; 16],
    /// Memory-map the central directory instead of reading it into a `Vec`.
    /// Mapping is lazy and shares the page cache; disable it for archives on
    /// filesystems that do not support `mmap`.
    pub mmap: bool,
    /// Largest tail window (bytes) scanned for the end-of-central-directory
    /// record. ZIP allows a 64 KiB comment; p4k adds a little zero padding.
    pub max_tail_scan: u64,
}

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions {
            key: crate::crypto::P4K_KEY,
            mmap: true,
            max_tail_scan: 64 << 20,
        }
    }
}

/// Summary of the archive container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveInfo {
    /// Number of entries.
    pub entries: u64,
    /// Size of the archive file.
    pub file_size: u64,
    /// Absolute offset of the central directory.
    pub cd_offset: u64,
    /// Size of the central directory.
    pub cd_size: u64,
    /// Absolute offset of the end-of-central-directory record.
    pub eocd_offset: u64,
    /// True when ZIP64 records were used.
    pub zip64: bool,
    /// Archive comment (p4k stores a 16-byte `CIG` block).
    pub comment: Vec<u8>,
    /// True when the central directory is memory-mapped.
    pub mmapped: bool,
}

enum CdBuf {
    Mmap(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl Deref for CdBuf {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            CdBuf::Mmap(m) => m,
            CdBuf::Owned(v) => v,
        }
    }
}

/// Open-addressing hash set from normalised name to entry index.
struct NameIndex {
    mask: usize,
    slots: Box<[u32]>,
}

const EMPTY: u32 = u32::MAX;

impl NameIndex {
    fn build(inner: &Inner) -> NameIndex {
        let n = inner.index.len();
        let cap = (n * 2).next_power_of_two().max(16);
        let mask = cap - 1;
        let mut slots = vec![EMPTY; cap].into_boxed_slice();
        for id in 0..n {
            let name = inner.name_bytes(id);
            let mut i = hash_path(name) as usize & mask;
            while slots[i] != EMPTY {
                i = (i + 1) & mask;
            }
            slots[i] = id as u32;
        }
        NameIndex { mask, slots }
    }

    fn lookup(&self, inner: &Inner, query: &[u8]) -> Option<EntryId> {
        let mut i = hash_path(query) as usize & self.mask;
        loop {
            let slot = self.slots[i];
            if slot == EMPTY {
                return None;
            }
            if path_eq(inner.name_bytes(slot as usize), query) {
                return Some(EntryId(slot));
            }
            i = (i + 1) & self.mask;
        }
    }
}

pub(crate) struct Inner {
    path: Option<PathBuf>,
    pub(crate) file: File,
    pub(crate) file_len: u64,
    cd: CdBuf,
    cd_offset: u64,
    eocd_offset: u64,
    zip64: bool,
    comment: Vec<u8>,
    /// Offset of every central-directory entry header within `cd`.
    index: Vec<u64>,
    pub(crate) key: [u8; 16],
    names: OnceLock<NameIndex>,
    tree: OnceLock<DirTree>,
}

impl Inner {
    #[inline]
    fn header_at(&self, pos: u64) -> CdHeader {
        CdHeader::parse(&self.cd[pos as usize..]).expect("central directory validated at open")
    }

    #[inline]
    pub(crate) fn name_bytes(&self, id: usize) -> &[u8] {
        let pos = self.index[id] as usize;
        let name_len = u16::from_le_bytes([self.cd[pos + 28], self.cd[pos + 29]]) as usize;
        &self.cd[pos + CD_HEADER_LEN..pos + CD_HEADER_LEN + name_len]
    }

    #[inline]
    pub(crate) fn name_str(&self, id: usize) -> &str {
        // Validated as UTF-8 while walking the central directory.
        std::str::from_utf8(self.name_bytes(id)).unwrap_or("")
    }

    fn entry(&self, id: EntryId) -> Option<Entry> {
        let pos = *self.index.get(id.index())?;
        let h = self.header_at(pos);
        let start = pos as usize + CD_HEADER_LEN;
        let name = &self.cd[start..start + h.name_len as usize];
        let extra = &self.cd
            [start + h.name_len as usize..start + h.name_len as usize + h.extra_len as usize];
        let x = format::parse_cd_extra(&h, extra);
        Some(Entry {
            id,
            name: std::str::from_utf8(name).unwrap_or("").into(),
            method: Method::from_raw(h.method),
            encrypted: x.encrypted,
            crc32c: h.crc,
            compressed_size: x.compressed_size,
            uncompressed_size: x.uncompressed_size,
            local_header_offset: x.local_header_offset,
            dos_time: h.dos_time,
            flags: h.flags,
            version_made_by: h.version_made_by,
            version_needed: h.version_needed,
            external_attrs: h.external_attrs,
            disk_start: x.disk_start,
        })
    }
}

/// A read-only, thread-safe handle to a `Data.p4k` archive.
///
/// Opening reads only the trailing records and the central directory, which
/// is memory-mapped and indexed with eight bytes per entry; names and
/// metadata are decoded on demand straight from that buffer. The handle is a
/// cheap `Arc` clone and every read uses positional I/O, so one archive can
/// be shared across threads and read from concurrently without locking.
#[derive(Clone)]
pub struct Archive {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("path", &self.inner.path)
            .field("entries", &self.inner.index.len())
            .field("cd_offset", &self.inner.cd_offset)
            .field("cd_size", &self.inner.cd.len())
            .finish()
    }
}

impl Archive {
    /// Opens a p4k with default options.
    pub fn open(path: impl AsRef<Path>) -> Result<Archive> {
        Self::open_with(path, OpenOptions::default())
    }

    /// Opens a p4k with explicit options.
    pub fn open_with(path: impl AsRef<Path>, opts: OpenOptions) -> Result<Archive> {
        let path = path.as_ref();
        let file = File::open(path)?;
        Self::from_file_inner(file, Some(path.to_path_buf()), opts)
    }

    /// Builds an archive from an already opened file handle.
    pub fn from_file(file: File, opts: OpenOptions) -> Result<Archive> {
        Self::from_file_inner(file, None, opts)
    }

    fn from_file_inner(file: File, path: Option<PathBuf>, opts: OpenOptions) -> Result<Archive> {
        let file_len = file.metadata()?.len();
        let (eocd_offset, eocd) = find_eocd(&file, file_len, opts.max_tail_scan)?;

        let (cd_offset, cd_size, total_entries, zip64) = if eocd.needs_zip64() {
            let loc = read_zip64_locator(&file, eocd_offset)?;
            if loc.eocd64_offset + ZIP64_EOCD_LEN as u64 > eocd_offset {
                return Err(Error::CentralDirectoryOutOfBounds {
                    offset: loc.eocd64_offset,
                    size: ZIP64_EOCD_LEN as u64,
                    file_size: file_len,
                });
            }
            let z = read_zip64_eocd(&file, loc.eocd64_offset)?;
            (z.cd_offset, z.cd_size, z.total_entries, true)
        } else {
            (
                eocd.cd_offset as u64,
                eocd.cd_size as u64,
                eocd.total_entries as u64,
                false,
            )
        };

        let cd_end = cd_offset
            .checked_add(cd_size)
            .filter(|&end| end <= eocd_offset)
            .ok_or(Error::CentralDirectoryOutOfBounds {
                offset: cd_offset,
                size: cd_size,
                file_size: file_len,
            })?;
        debug_assert!(cd_end <= file_len);
        if cd_size > usize::MAX as u64 {
            return Err(Error::CentralDirectoryOutOfBounds {
                offset: cd_offset,
                size: cd_size,
                file_size: file_len,
            });
        }

        let cd = load_cd(&file, cd_offset, cd_size as usize, opts.mmap)?;
        let index = walk_cd(&cd, total_entries)?;

        Ok(Archive {
            inner: Arc::new(Inner {
                path,
                file,
                file_len,
                cd,
                cd_offset,
                eocd_offset,
                zip64,
                comment: eocd.comment,
                index,
                key: opts.key,
                names: OnceLock::new(),
                tree: OnceLock::new(),
            }),
        })
    }

    /// Path the archive was opened from, if known.
    pub fn path(&self) -> Option<&Path> {
        self.inner.path.as_deref()
    }

    /// Number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.index.len()
    }

    /// True when the archive has no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.index.is_empty()
    }

    /// Container-level information.
    pub fn info(&self) -> ArchiveInfo {
        let i = &self.inner;
        ArchiveInfo {
            entries: i.index.len() as u64,
            file_size: i.file_len,
            cd_offset: i.cd_offset,
            cd_size: i.cd.len() as u64,
            eocd_offset: i.eocd_offset,
            zip64: i.zip64,
            comment: i.comment.clone(),
            mmapped: matches!(i.cd, CdBuf::Mmap(_)),
        }
    }

    /// Decoded metadata of entry `id`, or `None` when out of range.
    pub fn entry(&self, id: EntryId) -> Option<Entry> {
        self.inner.entry(id)
    }

    /// Metadata of entry `id`, as an error when out of range.
    pub fn stat(&self, id: EntryId) -> Result<Entry> {
        self.entry(id)
            .ok_or_else(|| Error::NotFound(id.to_string()))
    }

    /// Name of entry `id` as stored, without allocating.
    pub fn name(&self, id: EntryId) -> Option<&str> {
        if id.index() < self.len() {
            Some(self.inner.name_str(id.index()))
        } else {
            None
        }
    }

    /// Looks up an entry by path. Case-insensitive; `/` and `\` are
    /// interchangeable; leading separators and `./` are ignored.
    pub fn find(&self, path: &str) -> Option<EntryId> {
        let q = util::trim_lookup_path(path);
        let names = self
            .inner
            .names
            .get_or_init(|| NameIndex::build(&self.inner));
        names.lookup(&self.inner, q.as_bytes())
    }

    /// Looks up an entry by path and decodes its metadata.
    pub fn entry_by_path(&self, path: &str) -> Result<Entry> {
        let id = self
            .find(path)
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        self.stat(id)
    }

    /// True when the name index has already been built.
    pub fn has_name_index(&self) -> bool {
        self.inner.names.get().is_some()
    }

    /// Iterates over every entry in central-directory order.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            archive: self,
            next: 0,
            end: self.len() as u32,
        }
    }

    /// Entries whose normalised path starts with `prefix` (case-insensitive,
    /// separator-agnostic). A trailing separator in `prefix` restricts the
    /// match to that directory.
    pub fn with_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = EntryRef<'a>> + 'a {
        let p = util::trim_lookup_path(prefix).as_bytes();
        self.iter()
            .filter(move |e| path_starts_with(e.name.as_bytes(), p))
    }

    /// Entries matching a glob. Matching is case-insensitive and treats `\`
    /// and `/` alike; `*` also crosses directory separators (so
    /// `Data/*.xml` finds every XML under `Data`).
    pub fn glob(&self, pattern: &str) -> Result<GlobIter<'_>> {
        let matcher = compile_glob(pattern)?;
        Ok(GlobIter {
            iter: self.iter(),
            matcher,
            buf: Vec::with_capacity(256),
        })
    }

    /// Lazily built directory tree over all entries.
    pub fn tree(&self) -> &DirTree {
        self.inner.tree.get_or_init(|| DirTree::build(self))
    }

    /// Parses the local file header of entry `e` and returns it together
    /// with the absolute offset of the payload.
    pub fn local_header(&self, e: &Entry) -> Result<(LocalHeader, u64)> {
        let mut buf = [0u8; LOCAL_HEADER_LEN];
        if e.local_header_offset + LOCAL_HEADER_LEN as u64 > self.inner.file_len {
            return Err(Error::DataOutOfBounds {
                name: e.name.to_string(),
                offset: e.local_header_offset,
                len: LOCAL_HEADER_LEN as u64,
                file_size: self.inner.file_len,
            });
        }
        read_exact_at(&self.inner.file, &mut buf, e.local_header_offset)?;
        let h = LocalHeader::parse(&buf, e.local_header_offset)?;
        let data = e.local_header_offset + h.data_start();
        if data + e.compressed_size > self.inner.file_len {
            return Err(Error::DataOutOfBounds {
                name: e.name.to_string(),
                offset: data,
                len: e.compressed_size,
                file_size: self.inner.file_len,
            });
        }
        Ok((h, data))
    }

    /// Absolute offset of the stored payload of `e`.
    pub fn data_offset(&self, e: &Entry) -> Result<u64> {
        self.local_header(e).map(|(_, off)| off)
    }

    /// Decryption key in use.
    pub fn key(&self) -> &[u8; 16] {
        &self.inner.key
    }
}

/// Compiles a glob for entry-name matching (see [`Archive::glob`]).
pub(crate) fn compile_glob(pattern: &str) -> Result<globset::GlobMatcher> {
    let norm = util::trim_lookup_path(pattern).replace('\\', "/");
    Ok(globset::GlobBuilder::new(&norm)
        .case_insensitive(true)
        .literal_separator(false)
        .backslash_escape(false)
        .build()?
        .compile_matcher())
}

/// Iterator over all entries.
pub struct Iter<'a> {
    archive: &'a Archive,
    next: u32,
    end: u32,
}

impl<'a> Iterator for Iter<'a> {
    type Item = EntryRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<EntryRef<'a>> {
        if self.next >= self.end {
            return None;
        }
        let id = self.next;
        self.next += 1;
        Some(EntryRef {
            archive: self.archive,
            id: EntryId(id),
            name: self.archive.inner.name_str(id as usize),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = (self.end - self.next) as usize;
        (n, Some(n))
    }
}

impl ExactSizeIterator for Iter<'_> {}

/// Iterator produced by [`Archive::glob`].
pub struct GlobIter<'a> {
    iter: Iter<'a>,
    matcher: globset::GlobMatcher,
    buf: Vec<u8>,
}

impl<'a> Iterator for GlobIter<'a> {
    type Item = EntryRef<'a>;

    fn next(&mut self) -> Option<EntryRef<'a>> {
        for e in &mut self.iter {
            util::normalize_into(e.name.as_bytes(), &mut self.buf);
            // Normalisation only rewrites ASCII bytes, so UTF-8 validity holds.
            let s = std::str::from_utf8(&self.buf).unwrap_or("");
            if self.matcher.is_match(Path::new(s)) {
                return Some(e);
            }
        }
        None
    }
}

fn find_eocd(file: &File, file_len: u64, max_scan: u64) -> Result<(u64, Eocd)> {
    if file_len < EOCD_LEN as u64 {
        return Err(Error::NoEndOfCentralDirectory);
    }
    let mut window: u64 = (64 << 10) + EOCD_LEN as u64;
    let mut buf = Vec::new();
    loop {
        let n = window.min(file_len);
        buf.resize(n as usize, 0);
        read_exact_at(file, &mut buf, file_len - n)?;
        // Scan backwards for a plausible record.
        let mut pos = buf.len() - EOCD_LEN;
        loop {
            if buf[pos] == b'P' && buf[pos + 1] == b'K' && buf[pos + 2] == 5 && buf[pos + 3] == 6 {
                if let Some(e) = Eocd::parse(&buf[pos..]) {
                    let declared = pos + EOCD_LEN + e.comment.len();
                    let abs = file_len - n + pos as u64;
                    if declared <= buf.len() && eocd_is_plausible(file, abs, &e)? {
                        return Ok((abs, e));
                    }
                }
            }
            if pos == 0 {
                break;
            }
            pos -= 1;
        }
        if n == file_len || window >= max_scan {
            break;
        }
        window = (window * 16).min(max_scan.max(window + 1));
    }
    // Distinguish "not a zip" from "a zip that lost its tail".
    let mut head = [0u8; 4];
    if file_len >= 4 {
        read_exact_at(file, &mut head, 0)?;
        let sig = u32::from_le_bytes(head);
        if sig == format::LOCAL_SIG || sig == format::LOCAL_SIG_ENCRYPTED {
            return Err(Error::Truncated {
                file_size: file_len,
            });
        }
    }
    Err(Error::NoEndOfCentralDirectory)
}

/// Rejects end-of-central-directory records that belong to a ZIP stored
/// *inside* the archive (p4k keeps `.socpak`/`.pak` entries uncompressed, so
/// their trailers can sit inside the tail window of a truncated file): the
/// referenced central directory or ZIP64 records must really be there.
fn eocd_is_plausible(file: &File, eocd_offset: u64, e: &Eocd) -> Result<bool> {
    let mut sig = [0u8; 4];
    if e.needs_zip64() {
        if eocd_offset < ZIP64_LOCATOR_LEN as u64 {
            return Ok(false);
        }
        read_exact_at(file, &mut sig, eocd_offset - ZIP64_LOCATOR_LEN as u64)?;
        if u32::from_le_bytes(sig) != format::ZIP64_LOCATOR_SIG {
            return Ok(false);
        }
        let mut loc = [0u8; ZIP64_LOCATOR_LEN];
        read_exact_at(file, &mut loc, eocd_offset - ZIP64_LOCATOR_LEN as u64)?;
        let loc = match Zip64Locator::parse(&loc) {
            Some(l) => l,
            None => return Ok(false),
        };
        if loc.eocd64_offset + ZIP64_EOCD_LEN as u64 > eocd_offset {
            return Ok(false);
        }
        read_exact_at(file, &mut sig, loc.eocd64_offset)?;
        return Ok(u32::from_le_bytes(sig) == format::ZIP64_EOCD_SIG);
    }
    let end = match (e.cd_offset as u64).checked_add(e.cd_size as u64) {
        Some(v) => v,
        None => return Ok(false),
    };
    if end > eocd_offset {
        return Ok(false);
    }
    if e.total_entries == 0 && e.cd_size == 0 {
        return Ok(true);
    }
    read_exact_at(file, &mut sig, e.cd_offset as u64)?;
    Ok(u32::from_le_bytes(sig) == format::CD_SIG)
}

fn read_zip64_locator(file: &File, eocd_offset: u64) -> Result<Zip64Locator> {
    if eocd_offset < ZIP64_LOCATOR_LEN as u64 {
        return Err(Error::BadSignature {
            what: "zip64 locator",
            offset: 0,
            expected: format::ZIP64_LOCATOR_SIG,
            found: 0,
        });
    }
    let off = eocd_offset - ZIP64_LOCATOR_LEN as u64;
    let mut buf = [0u8; ZIP64_LOCATOR_LEN];
    read_exact_at(file, &mut buf, off)?;
    Zip64Locator::parse(&buf).ok_or_else(|| Error::BadSignature {
        what: "zip64 locator",
        offset: off,
        expected: format::ZIP64_LOCATOR_SIG,
        found: Le::new(&buf).u32().unwrap_or(0),
    })
}

fn read_zip64_eocd(file: &File, off: u64) -> Result<Zip64Eocd> {
    let mut buf = [0u8; ZIP64_EOCD_LEN];
    read_exact_at(file, &mut buf, off)?;
    Zip64Eocd::parse(&buf).ok_or_else(|| Error::BadSignature {
        what: "zip64 end of central directory",
        offset: off,
        expected: format::ZIP64_EOCD_SIG,
        found: Le::new(&buf).u32().unwrap_or(0),
    })
}

fn load_cd(file: &File, offset: u64, size: usize, use_mmap: bool) -> Result<CdBuf> {
    if use_mmap && size > 0 {
        // SAFETY: the mapping is read-only and the archive is treated as
        // immutable for the lifetime of the handle; a concurrent writer
        // could only corrupt the bytes we read, which the parser tolerates
        // by validating every access against the buffer length.
        let map = unsafe {
            memmap2::MmapOptions::new()
                .offset(offset)
                .len(size)
                .map(file)
        };
        if let Ok(m) = map {
            let _ = m.advise(memmap2::Advice::WillNeed);
            return Ok(CdBuf::Mmap(m));
        }
    }
    let mut v = vec![0u8; size];
    read_exact_at(file, &mut v, offset)?;
    Ok(CdBuf::Owned(v))
}

fn walk_cd(cd: &[u8], total_entries: u64) -> Result<Vec<u64>> {
    let max_possible = (cd.len() / CD_HEADER_LEN) as u64;
    let mut index: Vec<u64> = Vec::with_capacity(total_entries.min(max_possible) as usize);
    let mut pos = 0usize;
    for i in 0..total_entries {
        if pos + CD_HEADER_LEN > cd.len() {
            return Err(Error::corrupt_cd(
                i,
                pos as u64,
                "central directory ends before the declared entry count",
            ));
        }
        let sig = u32::from_le_bytes([cd[pos], cd[pos + 1], cd[pos + 2], cd[pos + 3]]);
        if sig != format::CD_SIG {
            return Err(Error::corrupt_cd(
                i,
                pos as u64,
                "bad central directory header signature",
            ));
        }
        let name_len = u16::from_le_bytes([cd[pos + 28], cd[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([cd[pos + 30], cd[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([cd[pos + 32], cd[pos + 33]]) as usize;
        let total = CD_HEADER_LEN + name_len + extra_len + comment_len;
        if pos + total > cd.len() {
            return Err(Error::corrupt_cd(
                i,
                pos as u64,
                "entry extends past the end of the central directory",
            ));
        }
        if std::str::from_utf8(&cd[pos + CD_HEADER_LEN..pos + CD_HEADER_LEN + name_len]).is_err() {
            return Err(Error::InvalidEntryName { index: i });
        }
        index.push(pos as u64);
        pos += total;
    }
    Ok(index)
}
