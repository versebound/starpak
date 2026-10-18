# starpak technical specification

This is the authoritative technical reference for the `starpak` library and command-line tool: the design, the three binary formats it reads (`Data.p4k`, CryXmlB, DataForge `Game2.dcb`), the CLI contract, the test strategy and the known gaps. The [README](README.md) is the user-facing overview (usage examples, API tour, benchmarks) and is not repeated here.

Every offset, constant and rule below comes from the code in `crates/starpak/src` and `crates/starpak-cli/src`, or was checked against the real archive (`Data.p4k` of the 2026-10 LIVE build: 160,498,634,752 bytes, 1,366,371 entries, `Game2.dcb` dated 2026-09-15) with the release binary and a read-only byte walk of its central directory and local headers. Facts that are inferred rather than verified, or simply unknown, are marked as such. All multi-byte integers in every format are little-endian.

## 1. Scope and design

### 1.1 Goals

- Read-only. The library never writes to an archive and has no extraction logic of its own; the CLI's `extract` is a thin loop over `read_entry_into`.
- Bare-minimum I/O at open. Opening reads only the trailing records (EOCD, ZIP64 locator, ZIP64 EOCD) and maps the central directory; nothing else is touched until an entry is read. The real archive opens in tens of milliseconds and allocates eight bytes per entry (see [README](README.md) for measurements).
- Positional reads, `Send + Sync`. Every file access is `pread`-style (`read_at`/`read_exact_at`), so a single `Archive` handle (an `Arc` inside, `Clone`) serves any number of threads without locks.
- Lazy indexes. The name index, the directory tree and every DataForge index are built on first use behind `OnceLock` and never on open.
- FFI-ready shape. Entries, structs, records and directories are addressed by dense integer ids; reads fill caller-owned buffers; every failure is a `starpak::Error` variant with a stable message. The planned C ABI is described in `docs/ffi-plan.md` (not started).

### 1.2 Crate and module map

| Path | Owns |
|---|---|
| `crates/starpak/src/lib.rs` | Public re-exports (`Archive`, `ArchiveInfo`, `OpenOptions`, `Entry`, `EntryId`, `EntryRef`, `Method`, `DosDateTime`, `EntryReader`, `DirTree`, `DirId`, `Error`, `Result`, `VERSION`), `#![forbid(unsafe_op_in_unsafe_fn)]`, `#![warn(missing_docs)]`. |
| `format.rs` | On-disk ZIP/p4k record parsers (`Eocd`, `Zip64Locator`, `Zip64Eocd`, `CdHeader`, `LocalHeader`), the extra-field walker `parse_cd_extra` → `ExtraInfo`, and the signature/tag/method constants. Pure functions over byte slices. |
| `archive.rs` | `Archive`/`Inner`: trailer discovery (`find_eocd`, `eocd_is_plausible`), ZIP64 resolution, central-directory loading (`load_cd`, mmap or `Vec`), the per-entry offset index (`walk_cd`), name decoding, the lazy `NameIndex` (open-addressing hash set), `find`/`entry_by_path`/`iter`/`with_prefix`/`glob`/`tree`, `local_header`/`data_offset`, `info`. |
| `entry.rs` | `EntryId` (dense `u32`), `Method`, `DosDateTime`, owned `Entry` metadata, borrowed `EntryRef`. |
| `reader.rs` | Payload decoding: bulk path `read_entry_into` (one `pread`, in-place AES, single-shot zstd/deflate, CRC32C), streaming `EntryReader` (`Read` + CRC on the last byte) over `RangeReader` → optional `CbcReader` → optional decoder, `verify`, `read_raw`, the thread-local zstd decompressor, `unwrap_io`. |
| `crypto.rs` | `P4K_KEY`, AES-128-CBC zero-IV `decrypt_in_place`, streaming `CbcReader`. |
| `tree.rs` | `DirTree`/`DirId`: hierarchical view over the flat entry list, case-insensitive lookup. |
| `util.rs` | `Le` bounds-checked little-endian cursor, `read_at`/`read_exact_at` (unix `FileExt::read_at`, windows `seek_read`), path normalisation (`norm_byte`, SWAR `norm_word`, `hash_path`, `path_eq`, `path_starts_with`, `trim_lookup_path`, `normalize_into`). |
| `cryxml.rs` | CryXmlB parser (`CryXml`, `NodeRef`), text-XML detection, XML serialisation and escaping, `Archive::read_xml`/`read_xml_entry`/`read_cryxml`. |
| `dataforge/mod.rs` | `DataForge` loader and validator, definition tables (`StructDef`, `PropDef`, `EnumDef`), `Record`, `Guid`, `DataType`, `Conversion`, `Pointer`, `Reference`, lazy indexes, instance addressing. |
| `dataforge/value.rs` | `Instance`, `Field`, `Value`, `ArrayRef`: lazy decoding of instance bytes and typed arrays. |
| `dataforge/export.rs` | unp4k-style XML and JSON export, `ExportOptions`, `element_name`, `json_string`. |
| `error.rs` | The `Error` enum (`thiserror`, `#[non_exhaustive]`) and `From<Error> for io::Error`. |
| `crates/starpak-cli/src/main.rs` | `clap` definitions, `info`/`ls`/`stat`/`cat`/`extract`/`xml`/`tree`/`verify`, exit-code policy. |
| `crates/starpak-cli/src/dcb.rs` | `starpak dcb` subcommands. |
| `crates/starpak-cli/src/bench.rs` | `starpak bench`. |
| `crates/starpak-cli/src/util.rs` | `human` byte formatting, `/proc/self/status` RSS reader (Linux only), xorshift64* `Rng`. |

Dependencies of the library: `memmap2`, `zstd`, `flate2` (zlib-rs backend), `aes` + `cbc`, `crc32c`, `globset`, `thiserror`. The CLI adds `clap` (derive + env) and `globset`. Rust 1.85+, edition 2021.

### 1.3 Data flow

**Open** (`Archive::open` → `from_file_inner`):

1. `File::open`, `metadata().len()` → `file_len`.
2. `find_eocd`: read a tail window of 64 KiB + 22 bytes (or the whole file if smaller), scan backwards for `PK\x05\x06`, parse the candidate, require that its declared comment fits inside the window and that `eocd_is_plausible` holds (section 2.2). If nothing is found the window grows by 16× (capped at `OpenOptions::max_tail_scan`, default 64 MiB) until the whole file or the cap has been scanned. Failure is `Truncated` when the first four bytes of the file are a local-header signature, `NoEndOfCentralDirectory` otherwise.
3. If any EOCD field holds a ZIP64 sentinel (`0xFFFF`/`0xFFFFFFFF`), read the 20-byte locator immediately before the EOCD and the 56-byte ZIP64 EOCD record at the locator's offset (which must end at or before the EOCD); take `cd_offset`, `cd_size`, `total_entries` from it. Otherwise take them from the EOCD.
4. Require `cd_offset + cd_size <= eocd_offset` (no overflow) and `cd_size <= usize::MAX`.
5. `load_cd`: `mmap` the range `[cd_offset, cd_offset + cd_size)` read-only with `MADV_WILLNEED` (when `OpenOptions::mmap`, the default, and `cd_size > 0`); on mmap failure or when disabled, `pread` it into a `Vec`.
6. `walk_cd`: for `i in 0..total_entries` check that 46 bytes remain, that the signature is `PK\x01\x02`, that `46 + name_len + extra_len + comment_len` fits, and that the name is valid UTF-8; push the entry's offset within the CD. Bytes after the last declared entry are ignored.
7. Build `Inner` (file, mapped CD, offsets, key, empty `OnceLock`s for the name index and tree).

**Lookup** (`Archive::find`): strip leading `/`, `\`, `./`, `.\` repeatedly (`trim_lookup_path`); build the `NameIndex` on first call (capacity `max(16, next_power_of_two(2n))` slots of `u32`, linear probing, keyed by `hash_path` of the normalised name); probe until an empty slot, comparing candidates with `path_eq`. `entry_by_path` adds metadata decoding (`stat`). Metadata decoding (`Inner::entry`) re-parses the 46-byte header and walks the extra field each time; nothing is cached per entry.

**Read** (`Archive::read` and friends → `read_entry_into`): `stat(id)` → `check_supported` (method known, encrypted size multiple of 16) → `local_header` (one 30-byte `pread` at `local_header_offset`, signature check, `data_offset = local_header_offset + 30 + name_len + extra_len`, bounds check against `file_len`) → one `pread` of `compressed_size` bytes → in-place AES-128-CBC if encrypted → decode by method into the caller's `Vec` (appended after its current length) → CRC32C check unless disabled. The streaming path (`open_entry`) wires `RangeReader` (positional reads over `[data_offset, data_offset + compressed_size)`) → `CbcReader` (if encrypted, 256 KiB chunks) → `BufReader` (256 KiB) → `DeflateDecoder` or zstd `Decoder::single_frame` (window log max 31) → `EntryReader`, which caps output at `uncompressed_size` and checks the CRC when the last byte is delivered.

### 1.4 Memory model

| Item | Where | Size |
|---|---|---|
| Central directory | file-backed `mmap` (default) or heap `Vec` | `cd_size` bytes (464,191,950 for the real archive; page cache, not anonymous memory, when mapped) |
| Entry offset index (`Inner::index`) | heap | 8 bytes per entry (`Vec<u64>` of offsets into the CD) |
| Name index (`NameIndex`, lazy) | heap | 4 bytes × `next_power_of_two(2 × entries)` slots, minimum 16 (16 MiB for 1,366,371 entries) |
| Directory tree (`DirTree`, lazy) | heap | per directory: a `Node` (`Box<str>` name, `u32` parent, `Vec<DirId>`, `Vec<EntryId>`) plus a `HashMap<(u32, u64), u32>` slot; per file: 4 bytes |
| `Entry` (owned metadata) | caller | ~72 bytes plus the heap `Box<str>` name; `EntryRef` borrows the name from the CD and is `Copy` |
| Bulk read | caller's `Vec` | `uncompressed_size` appended; non-store/encrypted paths also allocate a transient `compressed_size` buffer |
| Streaming read | heap | 256 KiB `CbcReader` buffer (encrypted) + 256 KiB `BufReader` + decoder state; `Archive::verify` adds a 256 KiB sink |
| zstd bulk decompressor | thread-local | one `zstd::bulk::Decompressor` per thread, reused |
| `DataForge` | heap | the whole `.dcb` as one `Box<[u8]>` plus definition vectors: 16 B per struct, 8 B per property, 8 B per enum, 36 B per record, 8 B per flattened property, 28 B per struct for ranges/offsets/counts (≈5 MiB for the real file) |
| DataForge indexes (lazy) | heap | `HashMap<Guid, u32>`, `HashMap<Box<str>, FileRecords { main: u32, all: Vec<u32> }>`, `HashMap<Box<str>, u32>` |
| `Instance`/`Value`/`ArrayRef` | borrowed | `Copy` views into the `DataForge` buffer; strings are `&str` into the string tables |

### 1.5 Concurrency guarantees

- `Archive` is `Clone + Send + Sync`; clones share one `Arc<Inner>`. All reads are positional, so no shared cursor exists and no mutex is taken anywhere in the library.
- Lazy structures (`NameIndex`, `DirTree`, DataForge `by_guid`/`by_file`/`struct_by_name`) use `OnceLock`: concurrent first callers may race to build, exactly one result is kept.
- `EntryReader` owns an `Arc<Inner>` and is `Send` (not `Sync`); it has no lifetime parameter.
- `DataForge` is `Send + Sync`; its navigation types borrow it immutably.
- The mmap is read-only; the archive is assumed immutable while open. A concurrent writer could only corrupt bytes, which every parser tolerates by bounds-checking against the buffer length (the only `unsafe` block in the crate is the `mmap` call in `load_cd`).

### 1.6 Error model

`starpak::Error` is `#[non_exhaustive]`; match with a wildcard arm. `From<Error> for io::Error` wraps non-I/O variants as `ErrorKind::InvalidData` so `EntryReader` can surface them through `Read`; `reader::unwrap_io` reverses that.

| Variant | Fields | Raised when |
|---|---|---|
| `Io` | `io::Error` | `File::open`/`metadata` failure, any positional read failure, a local header shorter than 30 bytes (`UnexpectedEof`, "short local file header"), a streaming source ending inside the payload (`UnexpectedEof`), a streaming encrypted payload not a block multiple (`InvalidData`). |
| `NoEndOfCentralDirectory` | – | File shorter than 22 bytes, or no plausible EOCD found in the scanned tail and the file does not start with a local-header signature (garbage, text, empty). |
| `Truncated` | `file_size` | No plausible EOCD found but the file starts with `PK\x03\x04` or `PK\x03\x14`: a zip that lost its tail (including a cut inside the central directory, or a tail that only contains a nested zip's trailer). |
| `CentralDirectoryOutOfBounds` | `offset, size, file_size` | ZIP64 EOCD record would extend past the EOCD; `cd_offset + cd_size` overflows or exceeds the EOCD offset; `cd_size > usize::MAX`. |
| `CorruptCentralDirectory` | `index, offset, reason` | While walking the CD: it ends before the declared entry count; a header signature is not `PK\x01\x02`; an entry extends past the CD end. `offset` is relative to the CD start. |
| `BadSignature` | `what, offset, expected, found` | Missing/bad ZIP64 locator (`what = "zip64 locator"`; offset 0 and found 0 when the EOCD sits in the first 20 bytes), bad ZIP64 EOCD signature, local file header whose signature is neither `0x04034b50` nor `0x14034b50`. |
| `NotFound` | `String` | `stat`/`read`/`open_entry` with an id ≥ `len()` (message is `#id`), `entry_by_path`/`read_path`/`read_xml` miss (message is the query). |
| `UnsupportedMethod` | `method, name` | Reading an entry whose method is not 0, 8 or 100. Checked before any I/O. |
| `BadEncryptedSize` | `name, size` | Reading an encrypted entry whose `compressed_size % 16 != 0`. Checked before any I/O. |
| `Decompress` | `name, reason` | zstd frame probe (`find_frame_compressed_size`) or decode failure, deflate decode failure, streaming decoder construction failure, or a size that does not fit `usize` (`"entry does not fit in memory on this platform"`). Wrong key on a zstd entry surfaces here. |
| `SizeMismatch` | `name, expected, actual` | Store: `compressed_size < uncompressed_size`; zstd/deflate: decoded length ≠ `uncompressed_size` (deflate reads at most `uncompressed_size + 1` bytes to detect overrun); streaming: the source ends before `uncompressed_size` bytes were produced (`actual` = bytes delivered so far). |
| `CrcMismatch` | `name, expected, actual` | CRC32C of the decoded bytes differs from the CD value (bulk: after decode, the output is truncated back to its previous length; streaming: on the read that delivers the last byte, or the first read after). Wrong key on a stored encrypted entry surfaces here. |
| `DataOutOfBounds` | `name, offset, len, file_size` | `local_header_offset + 30 > file_len`, or `data_offset + compressed_size > file_len`. |
| `InvalidEntryName` | `index` | A CD name is not valid UTF-8 (at open). |
| `Glob` | `globset::Error` | Pattern failed to compile (`Archive::glob`, `DataForge::records_matching`). |
| `CryXml` | `String` | Any CryXmlB structural failure (section 3.3). |
| `NotXml` | – | `cryxml::to_xml` on bytes that are neither CryXmlB nor text XML. |
| `DataForge` | `String` | `.dcb` parse/validation failure (section 4.10), instance or array index out of range, `Instance::get` on a missing property, negative array header, nested array in export, unparsable GUID text. |

## 2. p4k container format

`Data.p4k` is a ZIP64 archive written by CIG's packer. Standard PKWARE records are used with the deviations listed in this section; `starpak` also opens plain PKWARE ZIP64 and classic ZIP files (both exercised by the fixture generators).

### 2.1 Observed layout of the real archive

| Region | Offset | Size |
|---|---|---|
| Local headers + payloads | 0 | 160,034,438,916 |
| Central directory (1,366,371 records) | 160,034,438,916 | 464,191,950 |
| ZIP64 end of central directory record | 160,498,630,866 | 56 |
| ZIP64 locator | 160,498,630,922 | 20 |
| End of central directory record | 160,498,630,942 | 22 |
| Comment | 160,498,630,964 | 16 |
| Zero padding | 160,498,630,980 | 3,772 |
| End of file | 160,498,634,752 | (multiple of 4,096) |

The regions are contiguous: the CD ends exactly where the ZIP64 EOCD begins, and the file is padded with zeros to the next 4,096-byte boundary after the comment.

### 2.2 Trailer records and discovery

End of central directory record (`EOCD_SIG = 0x06054b50`, `EOCD_LEN = 22`):

| Offset | Type | Field | Real archive |
|---|---|---|---|
| 0 | u32 | signature `PK\x05\x06` | |
| 4 | u16 | number of this disk | 0xFFFF |
| 6 | u16 | disk with the CD | 0xFFFF |
| 8 | u16 | entries on this disk | 0xFFFF |
| 10 | u16 | total entries | 0xFFFF |
| 12 | u32 | CD size | 0xFFFFFFFF |
| 16 | u32 | CD offset | 0xFFFFFFFF |
| 20 | u16 | comment length | 16 |
| 22 | bytes | comment | `43 49 47 00 01 00 00 10 E6 89 00 00 00 00 00 00` (`CIG\0`, then `01 00 00 10`, then `E6 89` and six zero bytes; meaning unknown beyond the `CIG` marker) |

ZIP64 end of central directory locator (`ZIP64_LOCATOR_SIG = 0x07064b50`, 20 bytes), always immediately before the EOCD:

| Offset | Type | Field | Real archive |
|---|---|---|---|
| 0 | u32 | signature `PK\x06\x07` | |
| 4 | u32 | disk holding the ZIP64 EOCD | 0 |
| 8 | u64 | offset of the ZIP64 EOCD | 160,498,630,866 |
| 16 | u32 | total disks | 1 |

ZIP64 end of central directory record (`ZIP64_EOCD_SIG = 0x06064b50`; the first 56 bytes are parsed, `ZIP64_EOCD_LEN = 56`):

| Offset | Type | Field | Real archive |
|---|---|---|---|
| 0 | u32 | signature `PK\x06\x06` | |
| 4 | u64 | size of the remainder of this record | 44 (so no extensible data) |
| 12 | u16 | version made by | 46 |
| 14 | u16 | version needed | 45 |
| 16 | u32 | this disk | 0 |
| 20 | u32 | disk with the CD | 0 |
| 24 | u64 | entries on this disk | 1,366,371 |
| 32 | u64 | total entries | 1,366,371 |
| 40 | u64 | CD size | 464,191,950 |
| 48 | u64 | CD offset | 160,034,438,916 |

Discovery algorithm (`find_eocd` + `eocd_is_plausible`): candidates are every `PK\x05\x06` found scanning backwards through the tail window whose declared comment ends inside the window. A candidate is accepted only if its referenced structures exist:

- ZIP64 candidate (any sentinel field): there must be a `PK\x06\x07` signature exactly 20 bytes before it, the locator must parse, the ZIP64 EOCD offset + 56 must not exceed the candidate's offset, and a `PK\x06\x06` signature must sit at that offset.
- Classic candidate: `cd_offset + cd_size` must not overflow or exceed the candidate's offset, and a `PK\x01\x02` signature must sit at `cd_offset` (an archive declaring zero entries and a zero-size CD is accepted without that read).

This matters because `.socpak`/`.pak` entries (nested ZIPs) are stored uncompressed; a copy of the archive truncated right after such an entry ends with that inner archive's own EOCD, which would otherwise be mistaken for the outer one. The inner EOCD fails the plausibility check (its CD offset is relative to the inner file, so the signature is not found there), the scan continues, and the open ends in `Error::Truncated`. The fixture test `nested_zip_trailer_is_not_mistaken_for_ours` reproduces this.

### 2.3 Central directory record

`CdHeader` (`CD_SIG = 0x02014b50`, `CD_HEADER_LEN = 46`), followed by name, extra field and comment:

| Offset | Type | Field | Real archive (all 1,366,371 entries) |
|---|---|---|---|
| 0 | u32 | signature `PK\x01\x02` | |
| 4 | u16 | version made by | 46 |
| 6 | u16 | version needed | 45 |
| 8 | u16 | general purpose flags | 0 |
| 10 | u16 | compression method | 100 or 0 |
| 12 | u32 | DOS date/time (`date << 16 \| time`) | 2009-01-22 … 2026-09-15 |
| 16 | u32 | CRC32C of the uncompressed data | |
| 20 | u32 | compressed size | 0xFFFFFFFF (sentinel) |
| 24 | u32 | uncompressed size | 0xFFFFFFFF (sentinel) |
| 28 | u16 | name length | 1 … 180 |
| 30 | u16 | extra field length | 206 |
| 32 | u16 | comment length | 0 |
| 34 | u16 | disk number start | 0xFFFF (sentinel) |
| 36 | u16 | internal attributes | 0 |
| 38 | u32 | external attributes | 0 |
| 42 | u32 | local header offset | 0xFFFFFFFF (sentinel) |
| 46 | bytes | name (`\` separators) | |
| 46 + name | bytes | extra field | |
| … | bytes | comment | absent |

Every entry in the real archive carries all four ZIP64 sentinels, so the 64-bit values always come from the extra field.

`DosDateTime::from_raw`: year = 1980 + bits 25..31, month = bits 21..24, day = bits 16..20, hour = bits 11..15, minute = bits 5..10, second = 2 × bits 0..4. Times are local, two-second resolution.

### 2.4 Extra fields

The CIG extra field is always 206 bytes with the same four blocks in the same order:

| Offset in extra | Tag | Declared size | Body | Content |
|---|---|---|---|---|
| 0 | `0x0001` (ZIP64) | 32 | 28 | u64 uncompressed size, u64 compressed size, u64 local header offset, u32 disk start |
| 32 | `0x5000` | 132 | 128 | Opaque. Differs for every entry (2,000 distinct values in the first 2,000 entries) and looks high-entropy; it is not any common hash of the payload (SHA-256/384/512, SHA-3, BLAKE2, MD5, SHA-1 were tried). Possibly a signature; unknown. |
| 164 | `0x5002` | 6 | 2 | u16: 1 = encrypted, 0 = plain. Only these two values occur. |
| 170 | `0x5003` | 36 | 32 | SHA-256 of the stored payload (the bytes between the local header and the next entry: compressed and, when applicable, encrypted). Verified against the real archive for stored, zstd and encrypted-zstd entries; `starpak` does not check it. |

The quirk: CIG's declared sizes include the 4-byte tag header (32 = 4 + 28, 132 = 4 + 128, 6 = 4 + 2, 36 = 4 + 32), whereas PKWARE sizes count only the body. `parse_cd_extra` handles both:

- `0x0001`: values are consumed in the order uncompressed size, compressed size, local header offset, disk start, each only if the corresponding 32/16-bit header field holds its sentinel (`u32::MAX`/`u16::MAX`). Let `consumed` be the bytes actually read. The walk continues at `body_start + consumed` if `size != consumed` and a known tag (`0x0001`, `0x5000`, `0x5002`, `0x5003`, `0x0666`) starts there (or that position is exactly the end of the extra field); otherwise at `body_start + size` (PKWARE semantics).
- `0x5000`, `0x5002`, `0x5003`, `0x0666`: body length is `size - 4` (saturating; a size below 4 is treated as an empty body). `0x5002` sets `encrypted` when its first two body bytes are non-zero.
- Any other tag: PKWARE semantics (`body_start + size`).
- A step that fails to advance ends the walk; a truncated block is skipped silently.

Consequence to be aware of: the CIG interpretation of the ZIP64 block relies on the header sentinels being present. If a CIG-style record carried real 32-bit sizes (none does), `consumed` would be 0 and the walk would land four bytes into the `0x5000` body.

### 2.5 Local file header, alignment and the data offset

`LocalHeader` (`LOCAL_HEADER_LEN = 30`):

| Offset | Type | Field |
|---|---|---|
| 0 | u32 | signature: `LOCAL_SIG = 0x04034b50` (`PK\x03\x04`) or `LOCAL_SIG_ENCRYPTED = 0x14034b50` (`PK\x03\x14`) |
| 4 | u16 | version needed (45 everywhere) |
| 6 | u16 | flags (0 everywhere) |
| 8 | u16 | method |
| 10 | u32 | DOS date/time |
| 14 | u32 | CRC32C |
| 18 | u32 | compressed size (0xFFFFFFFF) |
| 22 | u32 | uncompressed size (0xFFFFFFFF) |
| 26 | u16 | name length |
| 28 | u16 | extra field length |

The payload starts at `local_header_offset + 30 + name_len + extra_len` (`LocalHeader::data_start`). `starpak` reads these 30 bytes exactly once per entry read (`Archive::local_header`), uses only the signature and the two lengths, and never parses the local extra field. The local header offset itself comes from the central directory.

Observed in the real archive (every entry's local header was read): the local extra field is a ZIP64 block (`0x0001`, declared 32, 28-byte body carrying uncompressed size, compressed size, local header offset, disk) followed by a padding block `0x0666` whose declared size includes its header, sized so that `30 + name_len + extra_len == 4096` for every entry. Local header offsets are multiples of 4,096, so every payload starts at `local_header_offset + 4096`, on a 4 KiB boundary. The padding bytes are zero.

The signature byte: the constant is named `LOCAL_SIG_ENCRYPTED` and the doc comments say encrypted entries use `PK\x03\x14`, but the real archive does not bear this out. Of the 4,262 encrypted entries 3,212 have `PK\x03\x04` and 1,050 have `PK\x03\x14`; of the 1,362,109 plain entries 33,686 have `PK\x03\x14`. What the `0x14` signature does coincide with is a relocated entry: 34,735 of the 34,736 entries carrying it are exactly the entries whose local ZIP64 block records a local-header offset smaller than the one in the central directory (no `0x04` entry has that), as if the packer rewrote the signature when it moved the entry to a higher offset. `starpak` accepts both signatures for every entry and takes the encryption flag only from `0x5002`, so this has no functional effect; treat the constant's name as historical.

Local-vs-central disagreement observed: 146,606 entries have a different DOS time in the local header than in the CD (older in the local header for 120,357, newer for 26,249); 34,735 have a different (always smaller) local-header offset inside the local ZIP64 block. Method, CRC, name and sizes always agree. The CD is authoritative; `starpak` never reads sizes or times from local headers.

### 2.6 Compression methods

| Raw | `Method` | Decoder | Notes |
|---|---|---|---|
| 0 | `Store` | none | Bulk path reads straight into the output `Vec`. Requires `compressed_size >= uncompressed_size` (encrypted stored entries are padded, so equality is not required); output is truncated to `uncompressed_size`. |
| 8 | `Deflate` | `flate2` raw deflate (zlib-rs) | Supported and fixture-tested; the real archive contains no deflate entries. |
| 100 | `Zstd` | `zstd` | One frame per entry. Bulk: `find_frame_compressed_size` delimits the frame (so trailing zero padding of encrypted entries is ignored), then `Decompressor::decompress_to_buffer` into a pre-sized slice; the decoder is thread-local with `window_log_max(31)`. Streaming: `Decoder::single_frame()` with the same window limit. |
| other | `Other(u16)` | – | `Error::UnsupportedMethod` on read; metadata is still readable. |

Zero-length entries (62 in the real archive, all stored) decode to empty buffers with CRC 0.

### 2.7 Encryption

Encrypted entries (`0x5002 == 1`) are AES-128-CBC with an all-zero IV, no padding scheme, key `crypto::P4K_KEY = 5E 7A 20 02 30 2E EB 1A 3B B6 17 C3 0F DE 1E 47` (`OpenOptions::key` can override it). The stored payload is the ciphertext of the compressed (or stored) bytes zero-filled to the next 16-byte boundary; `compressed_size` counts the padding and must be a multiple of 16 (`Error::BadEncryptedSize` otherwise, checked before any I/O; the streaming `CbcReader` additionally rejects a partial final block with `InvalidData`). Decryption is in place over the whole payload (`decrypt_in_place`) or in 256 KiB block-aligned chunks (`CbcReader`). What delimits the real data afterwards is the zstd frame (bulk: frame size probe; streaming: `single_frame`) or `uncompressed_size` (store). All 4,262 encrypted entries in the real archive are zstd; the fixtures also cover encrypted store. A wrong key produces `Decompress` (zstd) or `CrcMismatch` (store), never a panic.

### 2.8 CRC32C

The CRC field in both headers is CRC32C (Castagnoli polynomial), computed over the uncompressed data; it is not the ZIP CRC-32. `starpak` uses the `crc32c` crate (SSE4.2/ARMv8 accelerated) and verifies on every bulk read unless `read_unverified`/`read_entry_into(.., false)` is used, and on every streaming read unless `EntryReader::verify(false)`. `Archive::verify(id)` streams an entry through a 256 KiB sink purely to check it. `EntryReader::crc32c()` exposes the running value.

### 2.9 Names, case folding and path normalisation

- Stored names use `\` as separator (every entry in the real archive; none contain `/`, none end in a separator, none contain non-ASCII bytes, longest is 180 bytes). Names must be valid UTF-8 (`InvalidEntryName` otherwise). `Entry::path()` returns the name with `/`; `Entry::name` is verbatim.
- Normalised form (used by hashing, equality, prefix tests and glob matching): `\` → `/`, ASCII `A`–`Z` → `a`–`z`, every other byte unchanged. Implemented bytewise (`norm_byte`) and eight bytes at a time (`norm_word`, SWAR) with a test asserting both agree. Non-ASCII bytes are compared verbatim, so `Ünïcode` ≠ `ünïcode`.
- Lookup queries (`find`, `entry_by_path`, `read_path`, `with_prefix`, `DirTree::find`, `glob` patterns) are first stripped of any number of leading `/`, `\`, `./`, `.\`.
- `with_prefix(p)` matches when the normalised name starts with the normalised prefix bytewise, so `Data/Loc` also matches `Data/Locker/...`; end the prefix with a separator to restrict to a directory.
- Globs (`Archive::glob`, `DataForge::records_matching`): the pattern is trimmed as above and `\` is replaced by `/`; `globset::GlobBuilder` with `case_insensitive(true)`, `literal_separator(false)` (so `*` and `?` match across `/`; `Data/*.xml` matches every `.xml` below `Data` at any depth) and `backslash_escape(false)`; the matcher is applied to the normalised name. Every glob iteration is a linear scan over all entries (no index).
- `DirTree` (built on first `tree()` call): components split on either separator with empty components dropped; the file part is the text after the last separator (an empty file part, i.e. a name ending in a separator, creates the directory only). Directory names keep the case of their first occurrence; lookups go through a `(parent, hash_path(component))` map with a linear scan fallback on hash collision. Sub-directories and files are sorted ASCII-case-insensitively. The real archive yields 21,369 directories including the root; 1,365,062 entries live below `Data\` (21,303 directories), 1,306 below `Engine\` and 3 below `mods\`.

### 2.10 Observed statistics (2026-10 LIVE `Data.p4k`)

| Statistic | Value |
|---|---|
| Entries | 1,366,371 (ZIP64 EOCD and CD walk agree) |
| Version made by / needed | 46 / 45 for every entry (central and local) |
| General purpose flags | 0 for every entry |
| Method 100 (zstd) | 1,237,756 |
| Method 0 (store) | 128,615 |
| Method 8 (deflate) | 0 |
| Encrypted (`0x5002 = 1`) | 4,262, all zstd, all with `compressed_size % 16 == 0` |
| Extra field | 206 bytes, same four tags in the same order, for every entry |
| Comments, internal/external attributes | all zero |
| ZIP64 sentinels | all four set in every CD record |
| Local header length (30 + name + extra) | 4,096 for every entry; payloads 4,096-aligned |
| Zero-length entries | 62, all stored |
| Nested archives | 9,630 `.socpak` + 5 `.pak`, all stored, none encrypted |
| Name separator | `\` only; no directory entries; ASCII only; no two names equal after normalisation |
| DOS time range | 2009-01-22 … 2026-09-15 |
| Central directory | 464,191,950 bytes (339.7 bytes per entry on average) |
| `**/*.xml` | 13,252 entries |

## 3. CryXmlB format

CryEngine binary XML. Detection: the first eight bytes equal `cryxml::MAGIC = "CryXmlB\0"` (`is_cryxmlb`).

### 3.1 Header (44 bytes)

| Offset | Type | Field |
|---|---|---|
| 0 | 8 bytes | magic `CryXmlB\0` |
| 8 | u32 | total size (ignored by the parser; equals the entry size in the real files) |
| 12 | u32 | node table offset (absolute, from the start of the buffer) |
| 16 | u32 | node count |
| 20 | u32 | attribute table offset |
| 24 | u32 | attribute count |
| 28 | u32 | child table offset |
| 32 | u32 | child count |
| 36 | u32 | string table offset |
| 40 | u32 | string table size in bytes |

Tables may appear in any order and with gaps (the fixture encoder exercises strings-first and padded layouts). In the real files the node table follows the header directly at offset 44; `Data/Scripts/Network/wrld.xml`, for example, has 7,441 nodes, 6 attributes and 7,440 child indices, with the attribute table after the child table and the strings last.

### 3.2 Tables

Node (28 bytes, `NODE_LEN`):

| Offset | Type | Field |
|---|---|---|
| 0 | u32 | tag: string offset of the element name |
| 4 | u32 | content: string offset of the text content (empty string when none) |
| 8 | u16 | attribute count |
| 10 | u16 | child count |
| 12 | i32 | parent node index, `-1` for the root |
| 16 | i32 | first attribute index |
| 20 | i32 | first child index into the child table |
| 24 | i32 | reserved (ignored) |

Attribute (8 bytes, `ATTR_LEN`): u32 key string offset, u32 value string offset. Child table: u32 node index per slot; a node's children are the slots `first_child .. first_child + child_count`. String table: NUL-terminated byte strings addressed by offset from the table start; a string that is not valid UTF-8, or an offset at or beyond the table, reads as `""`.

### 3.3 Validation rules (`CryXml::parse`)

All failures are `Error::CryXml(message)`; every prefix of a valid document and 5,000 random byte mutations are tested to fail or parse without panicking.

1. Magic present; buffer at least 44 bytes.
2. `node_count > 0`; `node_count` and `attribute_count` at most `u32::MAX / 2` (rejects absurd allocations before any table is read).
3. Each table (`count × width`, widths 28/8/4/1) must lie within the buffer, with overflow-checked arithmetic.
4. Per node: `tag` and `content` offsets `< max(string_table_size, 1)`; `first_attr >= 0` and `first_attr + attr_count <= attribute_count`; `first_child >= 0` and `first_child + child_count <= child_count_total`; `parent < node_count` (negative values are allowed on any node).
5. Node 0 must have `parent == -1`.
6. Every child-table index `< node_count`; every attribute key/value offset `< string_table_size`.
7. The child lists must form a tree rooted at node 0: a depth-first walk from node 0 fails on any node reached twice (true cycles and shared subtrees alike). Nodes unreachable from the root are permitted and simply never serialised; `parent` fields are not cross-checked against the child lists.

The decoded `CryXml` owns copies of the node, child and attribute tables and the string bytes; `NodeRef` is a `Copy` cursor (`tag`, `text`, `attributes`, `attr`, `children`, `child`, `parent`, `index`). Attribute lookup is case-sensitive.

### 3.4 Text XML passthrough

`cryxml::to_xml(data)` (and `Archive::read_xml`): if the magic matches, decode and serialise; otherwise, if `looks_like_text_xml` holds (an optional UTF-8 BOM `EF BB BF`, then any ASCII whitespace, then `<`), return the bytes unchanged via `String::from_utf8_lossy` (the BOM is kept); otherwise `Error::NotXml`. Some `.xml` entries in the real archive are plain text.

### 3.5 Serialisation

`to_xml_string`/`write_xml` emit `<?xml version="1.0" encoding="utf-8"?>` + newline, then the tree from node 0 with two-space indentation per depth:

- `<tag k="v" ...>`; attributes in table order.
- A node with no children and empty text closes as ` />`.
- Text content is written immediately after the opening tag; if the node also has children, a newline follows the text, each child is written on its own lines, and the closing tag is indented at the node's depth.
- Escaping (`escape_into`): `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;` everywhere; in attribute values additionally `"` → `&quot;`, newline → `&#10;`, tab → `&#9;`, carriage return → `&#13;`. The apostrophe is never escaped.

## 4. DataForge format (`Game2.dcb`)

A column store: a header of element counts, definition tables (structs, properties, enums), data mappings (instances per struct), the record table, typed value arrays, two string tables and the instance data. The default archive path is `dataforge::DEFAULT_PATH = "Data/Game2.dcb"` (zstd, 331,932,921 bytes decoded in the 2026-09-15 build).

### 4.1 Versions

| Version | Record size | String tables | Status |
|---|---|---|---|
| 5 | 32 | one (`text1` holds names and values) | accepted; fixture-tested only |
| 6 | 32 | two (`text1` values, `text2` names) | accepted; fixture-tested only |
| 7 | – | – | rejected (`unsupported DataForge version 7`); never seen |
| 8 | 36 (adds a tag) | two | current real file |
| < 5, > 8 | – | – | rejected |

Loading only varies by version in two places: the record length (36 when `version >= 8`, else 32) and the name table (`text2` when `version >= 6`, else `text1`).

### 4.2 Header (120 bytes = 30 × u32)

| Offset | Field | Real file |
|---|---|---|
| 0 | magic (read, not checked) | 0 |
| 4 | version | 8 |
| 8, 12 | two unknown u32 (skipped) | 0, 0 |
| 16 | struct count | 6,694 |
| 20 | property count | 23,789 |
| 24 | enum count | 774 |
| 28 | data mapping count | 6,694 |
| 32 | record count | 117,022 |
| 36 | bool value count | 45,996 |
| 40 | i8 | 10 |
| 44 | i16 | 10 |
| 48 | i32 | 774 |
| 52 | i64 | 10,667 |
| 56 | u8 | 10 |
| 60 | u16 | 10 |
| 64 | u32 | 36 |
| 68 | u64 | 10 |
| 72 | f32 | 76,807 |
| 76 | f64 | 10 |
| 80 | GUID | 159 |
| 84 | string | 100,731 |
| 88 | locale | 6,837 |
| 92 | enum value | 144,578 |
| 96 | strong pointer | 1,817,970 |
| 100 | weak pointer | 184,395 |
| 104 | reference | 748,905 |
| 108 | enum option | 6,357 |
| 112 | `text1` (value string table) length | 17,183,397 |
| 116 | `text2` (name string table) length | 7,195,714 |

Note that the header lists the bool count before the integer counts, whereas the bool table is stored ninth (section 4.3). The tables whose count is exactly 10 (i8, i16, u8, u16, u64, f64) contain repeated constant values and look like placeholders.

### 4.3 File layout

Everything after the header is packed back to back in this order, with no alignment:

| # | Table | Element size | Real offset |
|---|---|---|---|
| 1 | struct definitions | 16 | 120 |
| 2 | property definitions | 12 | 107,224 |
| 3 | enum definitions | 8 | 392,692 |
| 4 | data mappings | 8 | 398,884 |
| 5 | records | 32 (v5/6) or 36 (v8) | 452,436 |
| 6 | i8 values | 1 | 4,665,228 |
| 7 | i16 | 2 | 4,665,238 |
| 8 | i32 | 4 | 4,665,258 |
| 9 | i64 | 8 | 4,668,354 |
| 10 | u8 | 1 | 4,753,690 |
| 11 | u16 | 2 | 4,753,700 |
| 12 | u32 | 4 | 4,753,720 |
| 13 | u64 | 8 | 4,753,864 |
| 14 | bool | 1 | 4,753,944 |
| 15 | f32 | 4 | 4,799,940 |
| 16 | f64 | 8 | 5,107,168 |
| 17 | GUID | 16 | 5,107,248 |
| 18 | string (u32 `text1` offsets) | 4 | 5,109,792 |
| 19 | locale (u32 `text1` offsets) | 4 | 5,512,716 |
| 20 | enum values (u32 `text1` offsets) | 4 | 5,540,064 |
| 21 | strong pointers | 8 | 6,118,376 |
| 22 | weak pointers | 8 | 20,662,136 |
| 23 | references | 20 | 22,137,296 |
| 24 | enum options (u32 `text2` offsets) | 4 | 37,115,396 |
| 25 | `text1` | bytes | 37,140,824 |
| 26 | `text2` (absent in v5) | bytes | 54,324,221 |
| 27 | instance data, to end of file | per mapping | 61,519,935 (270,412,986 bytes) |

### 4.4 Definition tables

Struct definition (16 bytes): u32 name offset (`text2`), i32 parent struct index (`-1` = none), u16 property count, u16 first property index, u32 instance size in bytes.

Property definition (12 bytes): u32 name offset (`text2`), u16 struct index (target struct for class/pointer/reference properties, enum index for enum properties, unused otherwise), u16 data type, u16 conversion, u16 unknown/padding (not read; always 0 in the real file).

Enum definition (8 bytes): u32 name offset (`text2`), u16 option count, u16 first option index into the enum option table. Each option is a u32 offset into `text2`.

Data mapping (8 bytes): u32 instance count, i32 struct index. Instance blocks are laid out contiguously in mapping order; the real file has exactly one mapping per struct, in ascending struct order, 2,663 of them with a zero count.

Record (36 bytes in v8; the tag field is absent in v5/v6, giving 32):

| Offset | Type | Field |
|---|---|---|
| 0 | u32 | record name (`text2`), e.g. `EntityClassDefinition.AEGS_Avenger_Titan` |
| 4 | u32 | source file name (`text1`), e.g. `libs/foundry/records/entities/spaceships/aegs_avenger_titan.xml` |
| 8 | u32 | tag (`text2`); `0xFFFFFFFF` = none (v8 only; synthesised as none for v5/v6) |
| 12 | i32 | struct index of the root instance |
| 16 | 16 bytes | GUID |
| 32 | u16 | instance index within the struct's instance block |
| 34 | u16 | struct size (read and discarded; equals the struct's declared size in every real record) |

### 4.5 Type codes and conversions

| Raw | `DataType` | Export name | Inline / table element size |
|---|---|---|---|
| 0x01 | `Bool` | `Bool` | 1 |
| 0x02 | `I8` | `Int8` | 1 |
| 0x03 | `I16` | `Int16` | 2 |
| 0x04 | `I32` | `Int32` | 4 |
| 0x05 | `I64` | `Int64` | 8 |
| 0x06 | `U8` | `UInt8` | 1 |
| 0x07 | `U16` | `UInt16` | 2 |
| 0x08 | `U32` | `UInt32` | 4 |
| 0x09 | `U64` | `UInt64` | 8 |
| 0x0A | `String` | `String` | 4 (u32 `text1` offset) |
| 0x0B | `F32` | `Single` | 4 |
| 0x0C | `F64` | `Double` | 8 |
| 0x0D | `Locale` | `LocID` | 4 (u32 `text1` offset) |
| 0x0E | `Guid` | `Guid` | 16 |
| 0x0F | `Enum` | `Enum` | 4 (u32 `text1` offset of the option text) |
| 0x10 | `Class` | `Class` | inline: the target struct's size; never stored in a value table |
| 0x110 | `StrongPointer` | `StrongPointer` | 8 |
| 0x210 | `WeakPointer` | `WeakPointer` | 8 |
| 0x310 | `Reference` | `Reference` | 20 |

Any other code fails the load (`unknown data type`). All nineteen codes occur in the real file.

| Raw | `Conversion` | Meaning |
|---|---|---|
| 0 | `Attribute` | value stored inline in the instance |
| 1 | `ComplexArray` | array header; elements in the pointer/reference tables |
| 2 | `SimpleArray` | array header; elements in a scalar table |
| 3 | `ClassArray` | array header; elements are consecutive instances of the target struct |

Any other value fails the load. The parser treats all three array kinds identically (an 8-byte header) and dispatches on the data type when reading elements.

### 4.6 Instance layout

The flattened property list of a struct is the parent chain root-first, each struct contributing its own properties in declaration order. Offsets are assigned sequentially: an array property occupies 8 bytes (i32 count, i32 first index), a `Class` attribute occupies the target struct's inline size (computed recursively with memoisation and a depth guard of 64; a struct embedding itself therefore computes to a size that cannot match its declaration and is rejected), every other attribute its element size. Instances are `size` bytes, unaligned, laid out back to back per struct.

Array elements: for scalar types the index addresses the typed table of that type; for `StrongPointer`/`WeakPointer`/`Reference` the respective pointer tables; for `Class` the index is an instance index into the target struct's block, with `count` consecutive instances. A negative count or first index is reported as an error on decode. Arrays of arrays cannot be expressed (an array element is never an array header; the exporter guards the case anyway).

Scalars are read as plain little-endian values; `Bool` is any non-zero byte; strings resolve through `text1` (an offset at or beyond the table, or non-UTF-8 bytes, reads as `""`).

### 4.7 Pointers and references

| Kind | Bytes | Null encoding | Resolution |
|---|---|---|---|
| `StrongPointer` | i32 struct index, i32 instance index | either value negative (real file: `-1, -1`) | `DataForge::deref`/`instance(StructId, index)`: `struct_offsets[struct] + index × size`; error when the struct has no mapping or `index >= count`. Owning: exporters inline the target. |
| `WeakPointer` | same | same | same resolution; non-owning: exporters print a label instead of recursing (except inside arrays, see 4.13). |
| `Reference` | i32 instance index, 16-byte GUID | GUID all zero | `DataForge::record_by_guid(guid)`. The i32 is kept as `Reference::instance_index` and otherwise unused; its meaning is unknown (18,002 of 748,905 table entries hold `-1`, 17,912 hold a nil GUID, and the two sets do not coincide). Exporters print the GUID only. |

Pointer targets are not validated at load; a dangling pointer yields `Error::DataForge` when dereferenced. Strong pointers may point at a subtype of the property's declared struct; `PropDef::target_struct` gives the declared one and `Instance::struct_def` the actual one.

### 4.8 String tables

`text1` holds values: file names, `String`/`Locale`/`Enum` values. `text2` holds names: struct, property, enum and record names, tags and enum options. Both are sequences of NUL-terminated UTF-8 strings addressed by byte offset (the real tables are valid UTF-8 and NUL-terminated throughout). In version 5 there is a single table and every name offset is read from `text1`.

### 4.9 GUID text form

`Guid` wraps the 16 stored bytes. `Display`/`FromStr` use the order the game and community tools (unforge/unp4k) use: the first eight bytes are read as a little-endian u64 `a`, the last eight as a little-endian u64 `c`, and the text is `{a >> 32:08x}-{(a >> 16) & 0xffff:04x}-{a & 0xffff:04x}-{c >> 48:04x}-{c & 0xffffffffffff:012x}`. In byte positions that is `[7 6 5 4]-[3 2]-[1 0]-[15 14]-[13 12 11 10 9 8]`, which is not RFC 4122 order for the last two groups. Example from the tests: bytes `78 56 34 12 AB CD EF 01 23 45 67 89 9A BC DE F0` print as `01efcdab-1234-5678-f0de-bc9a89674523`. The real Avenger Titan record prints as `0079c5d5-1678-4f8c-85ba-18ca8f642af6`. Parsing accepts exactly 32 hex digits with optional hyphens (total length ≤ 36).

### 4.10 Validation at load (`DataForge::parse`)

Every failure is `Error::DataForge(message)`; all prefixes (step 7) and 3,000 random mutations of the fixture file are tested to fail or load without panicking, and loaded mutants are fully exported without panicking.

1. Buffer ≥ 120 bytes; version ∈ {5, 6, 8}.
2. Every table (counts × widths, then `text1`, `text2`) must fit, with overflow-checked arithmetic.
3. Property data type and conversion codes must be known.
4. Enum option ranges must lie inside the enum option table.
5. Struct parent indices in range; inheritance chains must terminate (cycle check bounded by the struct count); property ranges inside the property table.
6. Enum properties must name a valid enum; class/pointer/reference properties a valid struct.
7. Each struct's declared size must equal the size computed from its flattened property layout.
8. Data mapping struct indices in range; the sum of `count × size` over the mappings, laid out from the end of `text2`, must end exactly at the end of the file (so trailing bytes are an error).
9. Record struct indices in range and instance indices below the struct's mapped count.

### 4.11 Lazy decoding and indexes

`parse` retains the whole file in one buffer, materialises only the definition tables and the record table, and precomputes per struct the flattened property list with offsets and the instance block offset/count. Nothing else is decoded until asked: `Record::instance()` is a slice, `Field::value()` decodes one property, `ArrayRef::get(i)` one element.

Indexes, each built on first use:

- `by_guid`: `Guid → record index`, first record wins on duplicates (none in the real file). Used by `record_by_guid`.
- `by_file`: normalised file name (`trim_lookup_path`, `\` → `/`, ASCII lower-case) → `{ main, all }`. `all` lists every record stored under that file in table order; `main` is the record whose name (either the full name or the part after its last `.`) equals the file stem (the part of the last path component before the last `.`) case-insensitively, else the first record. Used by `record_by_path`, `records_in_file`, `file_count`, `Record::is_main`. The real file has 62,062 distinct file names (all under `libs/`) for 117,022 records; e.g. `tagdatabase.tagdatabase.xml` holds hundreds of `Tag` records and one main record of another type.
- `struct_by_name`: exact struct name → index, first wins. Used by `find_struct`, `records_of_type` (filters all records by `struct_is_a`, which walks the parent chain), and the CLI.
- `records_matching(glob)`: linear filter of the normalised file names through a glob compiled with the same rules as archive globs.

### 4.12 Observed statistics (`Game2.dcb`, 2026-09-15, version 8)

6,694 structs (3,386 with a parent, 832 of size 0, largest 3,205 bytes); 23,789 properties (21,537 attributes, 2,037 complex arrays, 7 simple arrays, 208 class arrays); 774 enums with 6,357 options; 6,694 data mappings, largest 162,021 instances, 13 structs with more than 65,535 instances; 117,022 records, no duplicate GUIDs, highest record instance index 29,230, every record tagged (25 distinct tags: `Unknown` 85,638, `SystemsDesign` 22,407, `Character` 4,416, `Ship` 2,462, `TechDesign` 494, `UI` 446, `MissionDesign` 428, and 18 rarer ones); 1,817,970 strong pointers (33,285 null), 184,395 weak pointers (8,910 null, highest instance index 157,097), 748,905 references (17,912 nil). Full decode of every record reaches about 12.8 M instances and 64 M values (see the README benchmarks).

### 4.13 XML export (`Record::to_xml`, `dataforge::to_xml`)

Shape (follows unforge/unp4k conventions; no XML declaration, two-space indentation, `\n` line ends):

- Root element: the record name passed through `element_name` (every character outside `[A-Za-z0-9.]` becomes `_`), e.g. `<EntityClassDefinition.AEGS_Avenger_Titan …>`.
- Attributes of an element, in this order: every scalar field in layout order (`Value::to_text`: booleans as `1`/`0`, integers and floats via Rust `Display` of the native type, strings/locale/enum texts verbatim, GUIDs in the text form above, references as their GUID or the nil GUID `00000000-0000-0000-0000-000000000000` when null), then the extra attributes: on the root `__type` (struct name), `__ref` (record GUID), `__path` (file name); on inline classes and class-array elements `__type`; on resolved pointer targets `__type` = the declared struct and, when the actual struct differs, `__polymorphicType` = the actual struct name (`__type` alone when they match).
- Child elements, in layout order, for every non-scalar field:
  - `Class`: `<fieldName …attrs __type="Struct">…</fieldName>`.
  - `StrongPointer(Some)`: `<fieldName>` wrapping `<StructName …>` (the element is the `element_name` of the target's actual struct); a null pointer writes nothing.
  - `WeakPointer(Some)`: `<fieldName value="StructName[XXXX]" />` where `XXXX` is the instance index formatted `{:04X}` after truncation to `u16`; null writes nothing.
  - `Array`: `<fieldName />` when empty, else `<fieldName>` containing one element per item: class items as `<StructName …__type>`; strong and weak pointer items alike are resolved and inlined (`__type`/`__polymorphicType` relative to the array's element struct), null items skipped; references as `<Reference value="guid" />`; scalars as `<TypeName value="…" />` using the export names of 4.5 (`<Int32 value="5" />`, `<Single value="1.5" />`, `<Bool value="1" />`, `<String value="…" />`, `<LocID …>`, `<Enum …>`, `<Guid …>`).
- An element with no written children self-closes (` />`).
- Attribute values use the CryXmlB attribute escaping (section 3.5). Property names are written as-is and are assumed XML-safe.

Depth and cycles: a walk context keeps a stack of `(struct, instance)` pairs starting with the root. `enter(pointer)` refuses (returns `None`, so the field is silently omitted) when the stack already holds `max_depth` entries or already contains the target, then pushes it; `leave` pops after the subtree. With `ExportOptions::max_depth` = 100 (default) pointers nest up to 99 levels; `max_depth` 0 or 1 follows no pointer at all. Class values and arrays do not count towards depth. Dangling pointers are errors.

### 4.14 JSON export (`Record::to_json`, `dataforge::to_json`)

An object per instance. Root keys in order: `__name`, `__type`, `__ref`, `__path`, `__tag` (only when the record has a tag), then the fields in layout order. Nested objects (inline classes, resolved strong pointers, class-array elements) start with `__type` (and `__polymorphicType` after it for pointer targets of a subtype). Values: booleans native, integers native (u64 unquoted), `F32` widened to `f64` before formatting (so `0.1f32` prints as `0.10000000149011612`; non-finite floats become `null`), strings/locale/enum/GUID/reference as JSON strings (references as their GUID), null pointers and nil references as `null`, weak pointers as `{"__weak": "StructName", "__instance": n}` with the full index, arrays as JSON arrays (pointer elements resolved like strong pointers). A pointer refused by the depth/cycle rule becomes `null`. String escaping covers `"`, `\`, `\n`, `\r`, `\t` and `\u00XX` for other control characters. `pretty` (default on) uses two-space indentation, `": "` separators and a trailing newline; off produces a single line.

### 4.15 Relation to unforge/unp4k output

The XML shape (scalars as attributes, `__type`/`__ref`/`__path`, `__polymorphicType`, type-named array elements, `Struct[XXXX]` weak-pointer labels, inlined pointers inside arrays) is modelled on unforge so dumps can be diffed, and the GUID text order matches unforge's reader. No test compares `starpak` output byte-for-byte against unforge, so attribute order, whitespace and corner cases (for example `__type` on every inline class, the nil-GUID text for null references, or the `u16` truncation of weak-pointer indices above 65,535, which the real file does reach) have not been confirmed identical. The JSON shape is `starpak`'s own.

## 5. CLI contract

Binary `starpak` (`crates/starpak-cli`). Global options, valid on every subcommand: `-p, --p4k <PATH>` (falls back to the environment variable `STARPAK_P4K`; required by every command except `dcb … --dcb <FILE>`), `--no-mmap` (read the central directory into heap memory instead of mapping it), `-h`, `-V`. An entry argument is either a path (case-insensitive, either separator, leading `/`/`./` ignored) or `#<index>`.

Exit codes: 0 on success; 1 on any runtime error (the message is printed as `error: …` on stderr); 2 on a usage error (clap); a broken stdout pipe (`head`-style early close) is treated as success. Data goes to stdout; progress and summaries of multi-entry commands go to stderr where noted.

| Command | Arguments and options | Output |
|---|---|---|
| `info` | – | `key: value` lines: `entries`, `file size` (bytes and human), `cd offset`, `cd size`, `eocd offset`, `zip64`, `cd mmapped`, `comment` (Rust debug-quoted). |
| `ls [GLOB] [--prefix P] [-l] [-c]` | glob and/or prefix filter | One name per line. `-l`: `{id:>7} {method:>7} {E or -} {compressed:>12} {uncompressed:>12} {crc32c:08x} {YYYY-MM-DD HH:MM:SS} {name}` followed by `N entries, X uncompressed`. `-c`: only the count. With both filters the prefix drives iteration and the glob is matched against the name with `\` replaced by `/` (that glob is not stripped of leading separators). |
| `stat ENTRY` | – | `name`, `id`, `method (raw)`, `encrypted`, `compressed`, `uncompressed`, `crc32c`, `modified`, `local header`, `data offset` (or `unavailable (reason)`), `local sig` with name/extra lengths, `flags`, `version`. |
| `cat ENTRY [--raw] [--no-verify] [--stream]` | `--raw`: stored bytes as on disk; `--stream`: streaming reader; `--no-verify`: skip CRC | Bytes to stdout. |
| `extract GLOB DIR [-j N] [--xml]` | `-j` defaults to the CPU count; `--xml` converts entries that start with the CryXmlB magic | Files under `DIR` at the entry's path (`..` and empty components removed). Per-entry errors and a final `extracted N entries, X in T (R/s), F failed` on stderr; exit 1 if any failed or nothing matched. |
| `xml ENTRY` | – | CryXmlB decoded to text, text XML passed through. |
| `tree [DIR] [-d DEPTH] [-f]` | depth default 1 | Indented `name/` lines (root line is the full path), files as `name (size)` with `-f`, then `N directories, M files below "path" (tree built in T)`. |
| `verify [GLOB] [-j N]` | default everything | Decodes and CRC-checks; `FAIL …` per failure on stderr; `verified N entries (X) in T (R/s), F failed` on stdout; exit 1 if any failed. |
| `bench [--sample N] [--max-size B] [-j N] [--seed S] [--glob G] [--lookups N] [--no-read]` | defaults 4000, 64 MiB, CPU count, 42, none, 200000 | Timing lines for open, listing, metadata decode, glob, name index, lookups, tree, then first-pass/warm single-thread bulk reads, streaming reads and parallel reads over a seeded random sample (entries ≤ `--max-size`, supported method, not a directory). RSS figures are read from `/proc/self/status` (zero elsewhere). |
| `dcb [--dcb FILE] [--entry PATH] <sub>` | `--entry` defaults to `Data/Game2.dcb`; `--dcb` reads a file instead of the archive | see below |
| `dcb info` | – | `version`, `size`, `structs`, `properties`, `enums`, `records`, `files`, `instance data`, `string tables` (values + names), `pointers` (strong, weak, references), `loaded in`. |
| `dcb records [--type T] [--path GLOB] [--tag TAG] [--main] [--limit N] [-l]` | `--type` includes subtypes (unknown type is an error); `--tag` case-insensitive | `{guid} {name}` per line, or with `-l` `{guid} {type:<32} {tag:<14} {name} {file}`; `N records` on stderr. |
| `dcb get KEY [--json] [--xml] [--fields]` | `KEY` is tried as a GUID, then as a file path (`record_by_path`), then as a record name (case-insensitive linear search) | XML (default; `--xml` is accepted and has no effect), JSON, or with `--fields` a header line `name (type) guid file` followed by `  {field:<40} {type:<28} {value}` for the root instance's own fields (arrays shown as `Type[len]`, pointers unresolved). |
| `dcb types [--search S] [-p, --props]` | substring filter, case-insensitive | `{name:<48} parent={parent:<32} size={n:<6} instances={n}` per struct, with `-p` each property as `    +{offset:<5} {name:<36} {type}`; `N types` on stderr. The short flag `-p` collides with the global `-p/--p4k`; see section 7. |
| `dcb enums [--search S]` | – | `Name: option, option, …` per enum. |
| `dcb bench [--export]` | – | Read/parse timings and RSS, index build times, a full decode of every record (instances, values, rate) and optionally a full XML export with byte totals. |

## 6. Testing

### 6.1 Hermetic suite (`cargo test`, no environment needed)

Fixture generators live in `crates/starpak/tests/common/mod.rs`:

- `P4kBuilder` writes a complete archive image in three flavours. `Flavor::Cig` reproduces the real layout: ZIP64 records, header-inclusive extra sizes (ZIP64 block declared 32 with a 28-byte body, `0x5000`/132, `0x5002`/6, `0x5003`/36), `PK\x03\x14` on encrypted entries, local extra padded with `0x0666` to 4,096-byte aligned payloads, the 16-byte `CIG` comment and 3,772 zero bytes of tail padding. `Flavor::Pkware64` is a conventional ZIP64 (PKWARE sizes, no CIG tags), `Flavor::Classic` a 32-bit ZIP. Per file (`FileSpec`): method (store/deflate/zstd/unknown), encryption, CRC override, local signature override, local-offset override, unpadded encryption, trailing junk counted in the compressed size. Per archive: key, comment, tail padding, alignment, leading junk. Payloads are CRC32C'd, compressed with `flate2`/`zstd`, then AES-encrypted with the same primitives the library uses.
- `encode_cryxml` turns an `Elem` tree into CryXmlB with optional strings-first table order and inter-table gaps.
- `DcbBuilder` writes `.dcb` images for versions 5, 6 and 8 from struct/enum/instance/record declarations (`DcbProp`, `V` values for every type including inline classes, strong/weak/null pointers, references, scalar/pointer/class arrays), computing struct sizes, flattened layouts, typed tables, both string tables (one for v5), record tags (v8) and optionally reversed mapping order.
- `Rng` is a xorshift64* generator for deterministic data.

Test files and coverage:

- Unit tests inside the crate (22): extra-field parsing in CIG and PKWARE style and malformed termination, EOCD sentinels, local signatures, DOS time round trip, method mapping, AES bulk/stream round trips and partial-block rejection, SWAR normalisation versus scalar, hash/equality invariance, lookup trimming, `Le` bounds, CryXmlB detection/garbage headers/escaping, GUID formatting and parsing, type codes, file-name normalisation, JSON escaping, element names.
- `tests/archive.rs` (21): round trips in all three flavours (with and without mmap, from a `File` handle), lookup rules, entry helpers, glob/prefix/tree navigation, bad CRC (bulk, streaming, `verify`), truncation before the EOCD and inside the CD, garbage and text inputs, missing file, EOCD pointing at junk, corrupt CD signature, missing ZIP64 EOCD signature, nested-zip trailer rejection, unsupported method, bad encrypted size, corrupt payloads (zstd, deflate, trailing junk), wrong key, out-of-bounds data and bad local signature, invalid UTF-8 names, empty archive, long comment with padding, 16-thread concurrent reads, streaming edge cases, glob matching against normalised names.
- `tests/cryxml.rs` (9): exact text output, navigation, single node and empty strings, every prefix truncation, 5,000 random mutations, structural errors (child index, cycle, root parent, attribute offsets), text passthrough, decoding through an archive, a large document.
- `tests/dataforge.rs` (10): every value kind in v8, v6 with reversed mappings, v5 single string table; exact XML and JSON output; pointer cycles and depth limits; malformed inputs (all prefixes, trailing bytes, version 7, size mismatch, unknown type/conversion, bad parent, inheritance cycle, 3,000 mutations); GUID helpers; loading from an archive; multi-threaded sharing.
- One doctest (the crate-level example, `no_run`).

### 6.2 Real-file suite (`crates/starpak/tests/real.rs`)

Every test returns early unless `STARPAK_TEST_P4K=/path/to/Data.p4k` is set; `STARPAK_TEST_P4K_TRUNCATED=/path/to/damaged-copy` enables one more test that expects `Error::Truncated`. Coverage: open and count (ZIP64, `CIG` comment, lazy index, `\` names), `global.ini` bulk and streaming equality, a sample across every method/encryption combination with CRC verification, streaming-vs-bulk on known and encrypted entries, CryXmlB decoding of hundreds of `.xml` entries, 16-thread concurrent reads, tree and case-insensitive lookups, DataForge load (`Send + Sync`), a full decode of every record, and spot checks of the Avenger Titan entity (path/GUID lookups, components, XML/JSON markers), crafting records, the tag database and enums.

Run with `STARPAK_TEST_P4K=… cargo test --release --test real` (the full decode is slow in debug builds). On the 2026-10 archive the eleven tests pass in about 2.5 s.

## 7. Known gaps and open questions

- Extra field `0x5000` (128 bytes per entry) is unexplained; `0x5003` matches SHA-256 of the stored payload but is not verified by the library; only bit 0 of `0x5002` has a known meaning; the 16-byte EOCD comment beyond `CIG\0` is unexplained; the stale local headers (differing DOS time, differing offset inside the local ZIP64 block) and the `PK\x03\x14` signature that accompanies them are not understood. `LOCAL_SIG_ENCRYPTED` and the related doc comments and fixture behaviour (which puts `0x14` on encrypted entries) describe a correlation the real archive does not have.
- Deflate (method 8) is implemented and fixture-tested but the real archive has no deflate entries, so it is untested on real data.
- DataForge version 7 is rejected without evidence either way; versions 5 and 6 are known only through fixtures. The two header words at offsets 8 and 12, the property padding word, the record's struct-size word and the reference's i32 are unexplained.
- Case folding is ASCII-only; a name differing only in non-ASCII case would not be found by a differently-cased query (no such names exist in the real archive).
- Nested archives (`.socpak`, `.pak`) are not opened transparently; read the entry and open the bytes as a separate file (`Archive::from_file` on a temp file, as the fixture test does). Memory-backed archives are not supported.
- The CLI defines `-p` twice under `dcb types` (`--p4k` and `--props`); the release binary resolves it to `--props`, a debug build panics in clap's assertions. `dcb get --xml` is a no-op flag. The combined `ls GLOB --prefix P` path and `dcb records --path` compile the glob without the library's leading-separator trimming.
- Weak-pointer labels in XML truncate the instance index to `u16`; the real file has instance indices up to 157,097 for weak-pointer targets, so such labels are ambiguous.
- `ExportOptions::max_depth` counts the root, so values 0 and 1 behave identically (no pointer is followed).
- A few `u64` additions on hostile offsets (`local_header_offset + 30`, `data_offset + compressed_size`, ZIP64 EOCD offset + 56) are unchecked; in release builds they wrap and are then caught by the bounds checks or by the read failing, in debug builds they would panic on a crafted file.
- No byte-for-byte parity tests against unforge/unp4k exist; the CLI has no automated tests; the benchmark's "name index" memory delta also includes the 200,000 query strings the benchmark allocates beforehand.
- `starpak-ffi` (C ABI, `cbindgen` header, stable error codes) is designed in `docs/ffi-plan.md` but not started.
