# starpak

Fast, allocation-light Rust library for reading Star Citizen's `Data.p4k` archive without extracting it, plus decoders for CryEngine binary XML (`CryXmlB`) and the DataForge database (`Game2.dcb`). Ships with a `starpak` command-line tool for listing, extracting, decoding and benchmarking.

The archive is ~160 GB with 1.37 million entries. Opening it reads only the trailing records and memory-maps the central directory; the index costs eight bytes per entry and names/metadata are decoded straight from the mapped bytes on demand. All reads use positional I/O, so one `Archive` handle can be shared across threads and read from concurrently with no locking.

The byte-level format descriptions, design notes, CLI contract, test strategy and known gaps are in [SPEC.md](SPEC.md); this README is the overview.

## Workspace

| Crate | Purpose |
|---|---|
| `crates/starpak` | The library: `Archive`, `cryxml`, `dataforge`. Minimal dependencies: `zstd`, `flate2` (zlib-rs backend), `aes` + `cbc`, `memmap2`, `crc32c`, `globset`, `thiserror`. |
| `crates/starpak-cli` | The `starpak` binary (`clap`). |
| `docs/ffi-plan.md` | Design note for the future `starpak-ffi` C ABI crate. |

Stable Rust (1.85+); `cargo clippy --all-targets -- -D warnings` and `cargo fmt` are clean.

## Library

```rust
use starpak::{Archive, EntryId};
use starpak::dataforge::DataForge;

let p4k = Archive::open("Data.p4k")?;
println!("{} entries", p4k.len());

// Lookup is case-insensitive and accepts either separator.
let ini = p4k.read_path("Data/Localization/english/global.ini")?;

// Metadata without reading the payload.
let e = p4k.entry_by_path("Data/Scripts/Network/wrld.xml")?;
println!("{} {} -> {} bytes, encrypted={} crc32c={:08x}", e.method, e.compressed_size, e.uncompressed_size, e.encrypted, e.crc32c);

// Binary or text XML in one call.
let xml = p4k.read_xml("Data/Scripts/Network/wrld.xml")?;

// Streaming read (implements std::io::Read, verifies the CRC at the end).
let mut r = p4k.open_entry(e.id)?;
std::io::copy(&mut r, &mut std::io::sink())?;

// Globs, prefixes and a directory tree; iteration never allocates per entry.
for entry in p4k.glob("Data/Libs/Foundry/Records/entities/spaceships/*.xml")? {
    println!("{}", entry.name());
}
let tree = p4k.tree();
let dir = tree.find("Data/Localization").unwrap();
println!("{} files, {} subdirectories", tree.files(dir).len(), tree.dirs(dir).len());

// Concurrency: Archive is Clone + Send + Sync (an Arc inside).
std::thread::scope(|s| {
    for id in 0..8u32 {
        let p4k = &p4k;
        s.spawn(move || p4k.read(EntryId(id)));
    }
});

// DataForge straight from the archive.
let df = DataForge::from_archive(&p4k)?;
let ship = df.record_by_path("libs/foundry/records/entities/spaceships/aegs_avenger_titan.xml").unwrap();
let inst = ship.instance()?;
for f in inst.fields() {
    println!("{} = {:?}", f.name(), f.value()?);
}
println!("{}", ship.to_xml()?);
# Ok::<(), starpak::Error>(())
```

Key types: `Archive` (open, `len`, `entry`, `find`, `entry_by_path`, `iter`, `with_prefix`, `glob`, `tree`, `read`, `read_into`, `read_unverified`, `read_path`, `read_entry`, `open_entry`, `verify`, `read_raw`, `local_header`, `info`), `Entry` (owned metadata), `EntryRef` (borrowed view with a `&str` name), `EntryId` (dense `u32` handle), `EntryReader` (`Read` + CRC check), `DirTree`/`DirId`, `cryxml::CryXml`/`NodeRef`/`to_xml`, `dataforge::DataForge`/`Record`/`Instance`/`Field`/`Value`/`ArrayRef`/`StructDef`/`PropDef`/`EnumDef`/`Guid`. Errors are the `starpak::Error` enum (`thiserror`), with distinct variants for truncated archives, corrupt central directories, CRC mismatches, unsupported methods, bad encrypted sizes, out-of-bounds data, CryXmlB and DataForge decoding failures.

## Command line

```
starpak --p4k Data.p4k info                           # container facts (or set STARPAK_P4K)
starpak ls 'Data/Scripts/**/*.xml' -l                 # glob listing; -l adds method/size/crc/time; -c counts
starpak ls --prefix Data/Localization/
starpak stat Data/Game2.dcb                           # metadata + local header / data offset (also accepts #index)
starpak cat Data/Localization/english/global.ini      # decoded bytes to stdout (--stream, --raw, --no-verify)
starpak xml Data/Scripts/Network/wrld.xml             # CryXmlB -> text (text XML passes through)
starpak extract 'Data/Libs/Foundry/Records/**' out/ --xml -j 16
starpak tree Data -d 2 -f
starpak verify 'Data/Sounds/**' -j 32                 # decode + CRC-check without writing
starpak bench -j 32 --sample 4000
starpak dcb info                                      # DataForge, read from the archive (or --dcb file.dcb)
starpak dcb records --type EntityClassDefinition --path 'libs/foundry/records/entities/spaceships/*' -l
starpak dcb get libs/foundry/records/entities/spaceships/aegs_avenger_titan.xml          # unp4k-style XML
starpak dcb get 0079c5d5-1678-4f8c-85ba-18ca8f642af6 --json
starpak dcb get EntityClassDefinition.AEGS_Avenger_Titan --fields                        # own fields, no pointer chasing
starpak dcb types --search Vehicle -p
starpak dcb enums --search Weapon
starpak dcb bench --export
```

Exit code 0 on success, 1 on any error; `head`-style early pipe closure is not an error.

## Format notes

### p4k container

`Data.p4k` is a ZIP64 archive produced by CIG's own packer. It follows PKWARE's layout closely enough that the standard records apply (local headers, central directory, ZIP64 EOCD record + locator, EOCD), with these deviations, all handled by `starpak`:

- Extra-field sizes written by CIG include the four-byte tag header. This affects the ZIP64 block (declared 32, carrying 28 bytes) as well as the CIG blocks `0x5000` (128 bytes, opaque), `0x5002` (`u16`: 1 = encrypted), `0x5003` (32 bytes, opaque) and `0x0666` (padding). PKWARE-style archives are accepted too; the parser picks the interpretation under which the next tag is recognisable.
- Compression method `100` is zstd (one frame per entry). Encrypted entries use AES-128-CBC with a zero IV, no padding scheme, and the well-known key `5E7A2002302EEB1A3BB617C30FDE1E47`; the stored size is already a multiple of 16 and the zstd frame carries its own content size, so the trailing zero bytes are ignored. Stored (method 0) entries also occur, encrypted or not. Deflate (method 8) is supported although the current archive does not use it.
- Local file headers of encrypted entries carry the signature `PK\x03\x14` instead of `PK\x03\x04`. The local extra field pads every payload to a 4096-byte boundary, so the payload offset is only known after reading the 30-byte local header; `starpak` reads it exactly once per entry read.
- The CRC field is CRC32C (Castagnoli) of the uncompressed data, not CRC-32; this is why older tools report mismatches. `starpak` verifies it (hardware-accelerated) on every read unless asked not to.
- The archive ends with a 16-byte `CIG` comment and zero padding up to a 4096-byte boundary. Nested ZIPs (`.socpak`, `.pak`) are stored uncompressed, so a truncated copy can end in a foreign end-of-central-directory record; the trailer scan validates that a candidate's central directory (or ZIP64 locator) really exists before trusting it and otherwise reports `Error::Truncated`.
- All 1,366,371 entries in the 2026-10 archive use version 46/45, flags 0, 206-byte central extra fields and `\` separators; 4,262 entries are encrypted.

### CryXmlB

Binary CryEngine XML: an 8-byte magic, a 36-byte header with the offsets and counts of the node, attribute, child-index and string tables, then the tables. Nodes are 28 bytes (tag and content string offsets, attribute/child counts, parent, first attribute, first child, reserved). `starpak` validates every index and offset, rejects cycles, decodes to an arena tree (`CryXml`, `NodeRef`) and serialises to indented XML. Text XML entries (some `.xml` files are plain text) pass through unchanged.

### DataForge (`Game2.dcb`)

A column store: a 120-byte header with element counts; struct, property and enum definition tables; data mappings (instances per struct); the record table; typed value arrays (bool, ints, floats, GUIDs, string ids, locale ids, enum ids, strong/weak pointers, references, enum options); two string tables (values, names); then the instance data laid out per struct. Property values are inline (scalars, inline classes, 8-byte pointers, 20-byte references) or array headers (`count`, `first index`) into the typed arrays. Version 8 (current archive) grew records from 32 to 36 bytes with a category tag; versions 5 and 6 are also read. `starpak` validates all definition tables (including that every struct's declared size equals its property layout), keeps the whole file in one buffer, and decodes instances lazily. The XML export follows the `unforge`/`unp4k` shape (scalars as attributes, `__type`/`__ref`/`__path`, `__polymorphicType` for subtype pointers, `<Int32 value="…"/>` array elements, `Struct[XXXX]` weak pointers) so dumps diff against community tools; JSON uses `__name`/`__type`/`__ref`/`__path`/`__tag` keys and native values.

## Benchmarks

Measured with `starpak bench -j 32 --sample 4000` and `starpak dcb bench --export` on the 2026-10-04 `Data.p4k` (160,498,634,752 bytes, 1,366,371 entries, 443 MiB central directory) stored on a SATA SSD (btrfs on dm-crypt), 46-core machine, release build. "First pass" reads are whatever the page cache holds; "warm" reads repeat the same sample.

| Measurement | Result |
|---|---|
| Open (trailer + mmap + index walk of 1.37M entries) | 56 ms |
| Anonymous memory after open | +10.4 MiB (the 443 MiB central directory is a file-backed mapping) |
| List all 1,366,371 names | 40 ms (30 ns/entry, no allocation) |
| Decode all metadata (sizes, offsets, flags) | 107 ms (79 ns/entry) |
| Glob `**/*.xml` over all entries | 326 ms (13,252 matches) |
| Name index (built lazily on first lookup) | 188 ms, +40 MiB |
| Path lookup after that | 0.5 µs |
| Directory tree (21,369 directories) | 1.1 s, built on first use |
| Random reads, 1 thread, bulk + CRC32C, first pass | 1,539 entries/s, 129 MiB/s in, 234 MiB/s out |
| Random reads, 1 thread, bulk + CRC32C, warm | 7,080 entries/s, 592 MiB/s in, 1.0 GiB/s out |
| Random reads, 1 thread, streaming + CRC32C, warm | 1.1 GiB/s out |
| Random reads, 32 threads, bulk + CRC32C, warm | 88,600 entries/s, 7.2 GiB/s in, 13.1 GiB/s out |
| DataForge: read `Game2.dcb` (317 MiB, zstd) from the archive | 53 ms |
| DataForge: parse (definitions + 117,022 records) | 4.9 ms, memory = file size + ~5 MiB |
| DataForge: GUID index / file index (lazy) | 5 ms / 62 ms |
| DataForge: decode every record (12.8M instances, 64M values) | 1.24 s (52 M values/s) |
| DataForge: export every record to XML (2.9 GiB of text) | 14.8 s (201 MiB/s) |

The sample for the read phases is 4,000 random entries up to 64 MiB each (335 MiB stored, 607 MiB decoded); the mix is dominated by zstd textures and models like the archive itself.

## Tests

`cargo test` runs hermetic tests only: synthetic p4k images are generated in-test in three flavours (CIG layout with its extra-field quirks, encryption and 4096-byte alignment; PKWARE ZIP64; classic ZIP) covering store/deflate/zstd, encrypted zstd and store, ZIP64, bad CRCs, truncation at every layer, garbage input, nested-zip trailers, unsupported methods, bad encrypted sizes, damaged payloads, wrong keys, out-of-bounds offsets, invalid names, empty archives, long comments and padding, streaming edge cases and 16-thread concurrent reads. CryXmlB tests encode crafted documents and check exact text output, navigation, every truncation, 5,000 random mutations and structural corruption. DataForge tests build synthetic `.dcb` images (versions 5, 6 and 8) with every value kind, inheritance, inline classes, pointers, references and arrays, and check typed navigation, exact XML/JSON output, cycle handling, malformed input and multi-threaded use.

Setting `STARPAK_TEST_P4K=/path/to/Data.p4k` (and optionally `STARPAK_TEST_P4K_TRUNCATED` for a damaged copy) enables the real-file suite: open and count, `global.ini`, a sample across every method/encryption combination with CRC verification, streaming-vs-bulk equality, CryXmlB decoding of hundreds of entries, 16-thread concurrent reads, tree and lookups, DataForge load, a full decode of every record and spot checks of a ship entity and crafting records.

## FFI roadmap

A `starpak-ffi` crate (cdylib + `cbindgen`) is planned; see `docs/ffi-plan.md`. The library is shaped for it already: `Archive` and `DataForge` are opaque, thread-safe handles; entries, structs and records are addressed by dense integer ids; reads fill caller-visible buffers; and every failure is an enum variant that maps to a stable error code plus a message.

## License

MIT.
