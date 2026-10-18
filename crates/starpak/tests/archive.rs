//! Hermetic archive tests over synthetic p4k fixtures.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::{temp_archive, FileSpec, Flavor, P4kBuilder, Rng, DEFLATE, STORE, ZSTD};
use starpak::{Archive, DirId, EntryId, Error, Method, OpenOptions};

fn sample_files() -> Vec<FileSpec> {
    let mut rng = Rng::new(1);
    vec![
        FileSpec::new("Data\\empty.bin", Vec::new(), STORE),
        FileSpec::new("Data\\one.bin", vec![0x42], STORE),
        FileSpec::new("Data\\Scripts\\fifteen.txt", rng.text(15), ZSTD),
        FileSpec::new("Data\\Scripts\\sixteen.txt", rng.text(16), ZSTD).encrypted(),
        FileSpec::new("Data\\Scripts\\seventeen.txt", rng.text(17), ZSTD).encrypted(),
        FileSpec::new("Data\\Textures\\random.dds", rng.bytes(100_003), STORE),
        FileSpec::new("Data\\Textures\\random_enc.dds", rng.bytes(70_001), STORE).encrypted(),
        FileSpec::new("Data\\Libs\\text.xml", rng.text(300_000), DEFLATE),
        FileSpec::new("Data\\Libs\\zeros.bin", vec![0u8; 1 << 20], ZSTD),
        FileSpec::new("Data\\Libs\\big_enc.bin", rng.text(777_777), ZSTD).encrypted(),
        FileSpec::new("Data\\Libs\\Ünïcode name.txt", rng.text(50), ZSTD),
    ]
}

fn build(flavor: Flavor, files: Vec<FileSpec>) -> Vec<u8> {
    let mut b = P4kBuilder::new(flavor);
    for f in files {
        if flavor != Flavor::Cig {
            let mut f = f;
            f.encrypted = false;
            b = b.file(f);
        } else {
            b = b.file(f);
        }
    }
    b.build()
}

fn open_bytes(bytes: &[u8]) -> (Archive, tempfile::NamedTempFile) {
    let tmp = temp_archive(bytes);
    let a = Archive::open(tmp.path()).unwrap();
    (a, tmp)
}

fn check_roundtrip(a: &Archive, files: &[FileSpec]) {
    assert_eq!(a.len(), files.len());
    for (i, f) in files.iter().enumerate() {
        let name = std::str::from_utf8(&f.name).unwrap();
        let id = a.find(name).unwrap_or_else(|| panic!("find {name}"));
        assert_eq!(id, EntryId(i as u32));
        let e = a.entry(id).unwrap();
        assert_eq!(&*e.name, name);
        assert_eq!(e.method, Method::from_raw(f.method));
        assert_eq!(e.encrypted, f.encrypted, "{name}");
        assert_eq!(e.uncompressed_size, f.data.len() as u64);
        assert_eq!(e.crc32c, crc32c::crc32c(&f.data));
        assert_eq!(e.dos_time, f.dos_time);
        if f.encrypted {
            assert_eq!(e.compressed_size % 16, 0);
        }
        if f.method == STORE && !f.encrypted {
            assert_eq!(e.compressed_size, e.uncompressed_size);
        }

        // bulk
        let data = a.read(id).unwrap();
        assert_eq!(data, f.data, "bulk {name}");
        // append semantics
        let mut buf = b"prefix".to_vec();
        a.read_into(id, &mut buf).unwrap();
        assert_eq!(&buf[..6], b"prefix");
        assert_eq!(&buf[6..], &f.data[..]);
        // unverified + by path + by entry
        assert_eq!(a.read_unverified(id).unwrap(), f.data);
        assert_eq!(a.read_path(name).unwrap(), f.data);
        assert_eq!(a.read_entry(&e).unwrap(), f.data);
        // streaming, small chunks
        let mut r = a.open_entry(id).unwrap();
        assert_eq!(r.remaining(), f.data.len() as u64);
        assert_eq!(r.name(), name);
        let mut out = Vec::new();
        let mut chunk = [0u8; 1000];
        loop {
            let n = r.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(out, f.data, "stream {name}");
        assert_eq!(r.crc32c(), e.crc32c);
        assert_eq!(r.remaining(), 0);
        // verify without buffering
        a.verify(id).unwrap();
        // raw payload
        let raw = a.read_raw(id).unwrap();
        assert_eq!(raw.len() as u64, e.compressed_size);
        // local header
        let (lh, off) = a.local_header(&e).unwrap();
        assert_eq!(lh.method, f.method);
        assert_eq!(off, e.local_header_offset + lh.data_start());
        assert_eq!(a.data_offset(&e).unwrap(), off);
    }
}

#[test]
fn cig_flavor_roundtrip() {
    let files = sample_files();
    let (a, _t) = open_bytes(&build(Flavor::Cig, files.clone()));
    let info = a.info();
    assert!(info.zip64);
    assert!(info.mmapped);
    assert_eq!(info.entries, files.len() as u64);
    assert!(info.comment.starts_with(b"CIG\0"));
    assert_eq!(a.path().unwrap(), _t.path());
    check_roundtrip(&a, &files);
}

#[test]
fn cig_flavor_without_mmap() {
    let files = sample_files();
    let tmp = temp_archive(&build(Flavor::Cig, files.clone()));
    let a = Archive::open_with(
        tmp.path(),
        OpenOptions {
            mmap: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!a.info().mmapped);
    check_roundtrip(&a, &files);
}

#[test]
fn pkware_zip64_roundtrip() {
    let files: Vec<FileSpec> = sample_files()
        .into_iter()
        .map(|mut f| {
            f.encrypted = false;
            f
        })
        .collect();
    let (a, _t) = open_bytes(&build(Flavor::Pkware64, files.clone()));
    assert!(a.info().zip64);
    check_roundtrip(&a, &files);
}

#[test]
fn classic_zip_roundtrip() {
    let files: Vec<FileSpec> = sample_files()
        .into_iter()
        .map(|mut f| {
            f.encrypted = false;
            f
        })
        .collect();
    let (a, _t) = open_bytes(&build(Flavor::Classic, files.clone()));
    assert!(!a.info().zip64);
    assert!(a.info().comment.is_empty());
    check_roundtrip(&a, &files);
}

#[test]
fn from_file_handle() {
    let bytes = build(Flavor::Cig, sample_files());
    let tmp = temp_archive(&bytes);
    let a = Archive::from_file(
        std::fs::File::open(tmp.path()).unwrap(),
        OpenOptions::default(),
    )
    .unwrap();
    assert!(a.path().is_none());
    assert_eq!(a.len(), sample_files().len());
    assert!(format!("{a:?}").contains("entries"));
}

#[test]
fn lookup_rules() {
    let (a, _t) = open_bytes(&build(Flavor::Cig, sample_files()));
    let id = a.find("Data\\Scripts\\fifteen.txt").unwrap();
    for q in [
        "data/scripts/FIFTEEN.TXT",
        "/Data/Scripts/fifteen.txt",
        "\\data\\scripts\\fifteen.txt",
        "./Data/Scripts/fifteen.txt",
        "DATA\\SCRIPTS\\fifteen.txt",
    ] {
        assert_eq!(a.find(q), Some(id), "{q}");
    }
    assert!(a.find("Data/Scripts/fifteen").is_none());
    assert!(a.find("Data/Scripts/fifteen.txt2").is_none());
    assert!(a.find("").is_none());
    assert!(a.has_name_index());
    // Only ASCII is case-folded; non-ASCII bytes must match exactly.
    assert_eq!(a.find("data/libs/Ünïcode NAME.txt"), Some(EntryId(10)));
    assert_eq!(a.find("data/libs/ünïcode name.txt"), None);
    assert!(matches!(a.entry_by_path("nope"), Err(Error::NotFound(_))));
    assert!(matches!(a.read_path("nope"), Err(Error::NotFound(_))));
    assert!(matches!(a.stat(EntryId(999)), Err(Error::NotFound(_))));
    assert!(a.entry(EntryId(999)).is_none());
    assert!(a.name(EntryId(999)).is_none());
    assert_eq!(a.name(EntryId(0)), Some("Data\\empty.bin"));
    assert!(matches!(a.read(EntryId(999)), Err(Error::NotFound(_))));
    assert!(matches!(
        a.open_entry(EntryId(999)),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn entry_helpers() {
    let (a, _t) = open_bytes(&build(Flavor::Cig, sample_files()));
    let e = a.entry_by_path("Data/Libs/text.xml").unwrap();
    assert_eq!(e.path(), "Data/Libs/text.xml");
    assert_eq!(e.file_name(), "text.xml");
    assert_eq!(e.extension().as_deref(), Some("xml"));
    assert!(!e.is_dir());
    assert_eq!(e.modified().to_string(), "2025-02-02 03:18:24");
    let e = a.entry_by_path("Data/empty.bin").unwrap();
    assert_eq!(e.extension().as_deref(), Some("bin"));
    let r = a.iter().next().unwrap();
    assert_eq!(r.id(), EntryId(0));
    assert_eq!(r.entry().id, EntryId(0));
    assert_eq!(r.read().unwrap(), Vec::<u8>::new());
    assert_eq!(a.iter().len(), a.len());
    assert_eq!(a.iter().count(), a.len());
}

#[test]
fn glob_prefix_and_tree() {
    let b = P4kBuilder::new(Flavor::Cig)
        .add("Data\\A\\x.xml", "x", ZSTD)
        .add("Data\\A\\B\\y.XML", "y", ZSTD)
        .add("Data\\AB\\q.xml", "q", ZSTD)
        .add("Data\\C\\z.txt", "z", STORE)
        .add("other\\w.xml", "w", STORE)
        .add("Data\\A\\B\\", "", STORE)
        .add("rootfile.txt", "r", STORE);
    let (a, _t) = open_bytes(&b.build());

    let names = |it: Box<dyn Iterator<Item = starpak::EntryRef<'_>> + '_>| -> Vec<String> {
        it.map(|e| e.name().to_string()).collect()
    };
    assert_eq!(names(Box::new(a.glob("*.xml").unwrap())).len(), 4);
    assert_eq!(names(Box::new(a.glob("**/*.xml").unwrap())).len(), 4);
    assert_eq!(names(Box::new(a.glob("data/a/*.xml").unwrap())).len(), 2);
    assert_eq!(names(Box::new(a.glob("DATA\\A\\*.xml").unwrap())).len(), 2);
    assert_eq!(
        names(Box::new(a.glob("data/a/b/y.xml").unwrap())),
        vec!["Data\\A\\B\\y.XML"]
    );
    assert_eq!(names(Box::new(a.glob("*.{xml,txt}").unwrap())).len(), 6);
    assert_eq!(names(Box::new(a.glob("nothing/*").unwrap())).len(), 0);
    assert!(matches!(a.glob("[unclosed"), Err(Error::Glob(_))));

    assert_eq!(names(Box::new(a.with_prefix("DATA/A/"))).len(), 3);
    assert_eq!(names(Box::new(a.with_prefix("Data/A"))).len(), 4); // also Data\AB
    assert_eq!(names(Box::new(a.with_prefix("/other"))).len(), 1);
    assert_eq!(names(Box::new(a.with_prefix(""))).len(), 7);

    let t = a.tree();
    assert_eq!(t.dirs(DirId::ROOT).len(), 2);
    assert_eq!(t.name(t.dirs(DirId::ROOT)[0]), "Data");
    assert_eq!(t.name(t.dirs(DirId::ROOT)[1]), "other");
    assert_eq!(t.files(DirId::ROOT).len(), 1);
    assert_eq!(t.name(DirId::ROOT), "");
    assert_eq!(t.path(DirId::ROOT), "");
    assert!(t.parent(DirId::ROOT).is_none());
    let data = t.find("data").unwrap();
    assert_eq!(t.path(data), "Data");
    let names_of = |d: DirId| -> Vec<&str> { t.dirs(d).iter().map(|x| t.name(*x)).collect() };
    assert_eq!(names_of(data), vec!["A", "AB", "C"]);
    let b = t.find("DATA\\a/b").unwrap();
    assert_eq!(t.path(b), "Data/A/B");
    assert_eq!(t.parent(b), t.find("Data/A"));
    assert_eq!(t.files(b).len(), 1);
    assert_eq!(a.name(t.files(b)[0]), Some("Data\\A\\B\\y.XML"));
    assert_eq!(t.file_count(data), 4);
    assert_eq!(t.file_count(DirId::ROOT), 6);
    assert_eq!(t.walk(DirId::ROOT).len(), t.dir_count());
    assert_eq!(t.dir_count(), 7);
    assert!(t.find("data/zzz").is_none());
    assert_eq!(t.find("/"), Some(DirId::ROOT));
    assert!(a.entry_by_path("Data/A/B/").unwrap().is_dir());
}

#[test]
fn bad_crc_is_reported() {
    let b = P4kBuilder::new(Flavor::Cig)
        .file(FileSpec::new("a.bin", vec![1, 2, 3, 4, 5], ZSTD).bad_crc())
        .file(
            FileSpec::new("b.bin", vec![9; 40], STORE)
                .bad_crc()
                .encrypted(),
        )
        .file(FileSpec::new("c.bin", vec![7; 40], DEFLATE).bad_crc());
    let (a, _t) = open_bytes(&b.build());
    for id in 0..3u32 {
        let id = EntryId(id);
        match a.read(id) {
            Err(Error::CrcMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(expected, 0xDEAD_BEEF);
                assert_ne!(actual, expected);
            }
            other => panic!("expected CRC error, got {other:?}"),
        }
        assert!(a.read_unverified(id).is_ok());
        assert!(matches!(a.verify(id), Err(Error::CrcMismatch { .. })));
        let mut r = a.open_entry(id).unwrap();
        let mut v = Vec::new();
        let err = r.read_to_end(&mut v).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("CRC mismatch"), "{err}");
        let mut r = a.open_entry(id).unwrap().verify(false);
        let mut v = Vec::new();
        r.read_to_end(&mut v).unwrap();
        assert!(!v.is_empty());
    }
    let mut buf = vec![0xAA; 3];
    assert!(a.read_into(EntryId(0), &mut buf).is_err());
    assert_eq!(buf.len(), 3, "failed read must not leave partial data");
}

#[test]
fn truncated_and_garbage_inputs() {
    let full = build(Flavor::Cig, sample_files());

    // Cut before the EOCD: a zip that lost its tail.
    let cut = &full[..full.len() - 5000];
    let tmp = temp_archive(cut);
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::Truncated { .. })
    ));

    // Cut inside the central directory.
    let info = open_bytes(&full).0.info();
    let cut = &full[..(info.cd_offset + info.cd_size / 2) as usize];
    let tmp = temp_archive(cut);
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::Truncated { .. })
    ));

    // Garbage of various sizes.
    let mut rng = Rng::new(9);
    for n in [0usize, 1, 21, 22, 100, 70_000] {
        let tmp = temp_archive(&rng.bytes(n));
        assert!(
            matches!(
                Archive::open(tmp.path()),
                Err(Error::NoEndOfCentralDirectory)
            ),
            "size {n}"
        );
    }
    // Text file.
    let tmp = temp_archive(b"hello world, definitely not a zip file\n");
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::NoEndOfCentralDirectory)
    ));
    // Missing file.
    assert!(matches!(
        Archive::open("/nonexistent/Data.p4k"),
        Err(Error::Io(_))
    ));

    // EOCD whose central directory offset points at junk is rejected.
    let classic = build(Flavor::Classic, vec![FileSpec::new("a", vec![1], STORE)]);
    let mut broken = classic.clone();
    let eocd = broken.len() - 22;
    broken[eocd + 16..eocd + 20].copy_from_slice(&5u32.to_le_bytes());
    let tmp = temp_archive(&broken);
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::Truncated { .. } | Error::NoEndOfCentralDirectory)
    ));

    // Corrupt a central directory signature.
    let mut broken = full.clone();
    let cd = info.cd_offset as usize;
    broken[cd + 46 + 20] ^= 0xFF; // second entry's signature region
    let second = cd + 46 + sample_files()[0].name.len() + 206;
    broken[second] = 0;
    let tmp = temp_archive(&broken);
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::CorruptCentralDirectory { index: 1, .. })
    ));

    // ZIP64 EOCD record missing its signature.
    let mut broken = full.clone();
    let z64 = info.eocd_offset as usize - 20;
    let z64_off = u64::from_le_bytes(broken[z64 + 8..z64 + 16].try_into().unwrap()) as usize;
    broken[z64_off] = 0;
    let tmp = temp_archive(&broken);
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::Truncated { .. } | Error::BadSignature { .. })
    ));
}

#[test]
fn nested_zip_trailer_is_not_mistaken_for_ours() {
    // An inner classic zip stored verbatim as the last entry.
    let inner = build(
        Flavor::Classic,
        vec![
            FileSpec::new("inner/a.txt", b"aaaa".to_vec(), DEFLATE),
            FileSpec::new("inner/b.txt", b"bbbb".to_vec(), STORE),
        ],
    );
    let outer = P4kBuilder::new(Flavor::Cig)
        .add("Data\\first.txt", "first", ZSTD)
        .add("Data\\nested.socpak", inner.clone(), STORE)
        .build();
    let (a, _t) = open_bytes(&outer);
    assert_eq!(a.len(), 2);
    let got = a.read_path("data/nested.socpak").unwrap();
    assert_eq!(got, inner);
    // ...and the inner archive can itself be opened from a file.
    let tmp = temp_archive(&got);
    let ia = Archive::open(tmp.path()).unwrap();
    assert_eq!(ia.read_path("inner/a.txt").unwrap(), b"aaaa");

    // Truncate the outer archive right after the nested entry: the inner
    // trailer sits in the tail window but must be rejected.
    let e = a.entry_by_path("Data/nested.socpak").unwrap();
    let end = a.data_offset(&e).unwrap() + e.compressed_size;
    let tmp = temp_archive(&outer[..end as usize]);
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn unsupported_method_and_bad_encrypted_size() {
    let b = P4kBuilder::new(Flavor::Cig)
        .file(FileSpec::new("bz.bin", vec![1; 100], 12))
        .file({
            let mut f = FileSpec::new("short.bin", vec![2; 100], ZSTD).encrypted();
            f.no_pad = true;
            f
        })
        .file({
            let mut f = FileSpec::new("junk.bin", vec![3; 100], ZSTD);
            f.trailing_junk = 7;
            f
        });
    let (a, _t) = open_bytes(&b.build());
    let e = a.entry(EntryId(0)).unwrap();
    assert_eq!(e.method, Method::Other(12));
    assert!(matches!(
        a.read(EntryId(0)),
        Err(Error::UnsupportedMethod { method: 12, .. })
    ));
    assert!(matches!(
        a.open_entry(EntryId(0)),
        Err(Error::UnsupportedMethod { .. })
    ));
    let e = a.entry(EntryId(1)).unwrap();
    assert!(e.encrypted);
    assert_ne!(e.compressed_size % 16, 0);
    assert!(matches!(
        a.read(EntryId(1)),
        Err(Error::BadEncryptedSize { .. })
    ));
    assert!(matches!(
        a.open_entry(EntryId(1)),
        Err(Error::BadEncryptedSize { .. })
    ));
    // Trailing bytes after a zstd frame are tolerated by both paths.
    assert_eq!(a.read(EntryId(2)).unwrap(), vec![3; 100]);
    let mut v = Vec::new();
    a.open_entry(EntryId(2))
        .unwrap()
        .read_to_end(&mut v)
        .unwrap();
    assert_eq!(v, vec![3; 100]);
}

#[test]
fn corrupt_payloads_are_errors_not_panics() {
    let files = vec![
        FileSpec::new("z.bin", Rng::new(3).text(50_000), ZSTD),
        FileSpec::new("d.bin", Rng::new(4).text(50_000), DEFLATE),
        FileSpec::new("e.bin", Rng::new(5).text(50_000), ZSTD).encrypted(),
        FileSpec::new("s.bin", Rng::new(6).text(5_000), STORE),
    ];
    let bytes = build(Flavor::Cig, files);
    let (a, _t) = open_bytes(&bytes);
    let mut damaged = bytes.clone();
    for id in 0..4u32 {
        let e = a.entry(EntryId(id)).unwrap();
        let off = a.data_offset(&e).unwrap() as usize;
        for i in (off + 2..off + e.compressed_size as usize).step_by(97) {
            damaged[i] ^= 0x5A;
        }
    }
    let (d, _t2) = open_bytes(&damaged);
    for id in 0..4u32 {
        let r = d.read(EntryId(id));
        assert!(
            matches!(
                r,
                Err(Error::Decompress { .. }
                    | Error::CrcMismatch { .. }
                    | Error::SizeMismatch { .. })
            ),
            "{id}: {r:?}"
        );
        let mut v = Vec::new();
        assert!(d
            .open_entry(EntryId(id))
            .unwrap()
            .read_to_end(&mut v)
            .is_err());
    }
}

#[test]
fn wrong_key_fails_cleanly() {
    let bytes = build(Flavor::Cig, sample_files());
    let tmp = temp_archive(&bytes);
    let a = Archive::open_with(
        tmp.path(),
        OpenOptions {
            key: [7u8; 16],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(a.key(), &[7u8; 16]);
    let id = a.find("Data/Scripts/sixteen.txt").unwrap();
    assert!(a.read(id).is_err());
    let id = a.find("Data/Textures/random_enc.dds").unwrap();
    assert!(matches!(a.read(id), Err(Error::CrcMismatch { .. })));
    let id = a.find("Data/Textures/random.dds").unwrap();
    assert!(a.read(id).is_ok(), "plain entries ignore the key");
}

#[test]
fn data_out_of_bounds_and_bad_local_header() {
    let mut f = FileSpec::new("far.bin", vec![1; 10], STORE);
    f.local_offset_override = Some(1 << 40);
    let mut g = FileSpec::new("badsig.bin", vec![2; 10], STORE);
    g.local_sig = Some(0x0201_4b50);
    let b = P4kBuilder::new(Flavor::Cig).file(f).file(g);
    let (a, _t) = open_bytes(&b.build());
    assert!(matches!(
        a.read(EntryId(0)),
        Err(Error::DataOutOfBounds { .. })
    ));
    assert!(matches!(
        a.open_entry(EntryId(0)),
        Err(Error::DataOutOfBounds { .. })
    ));
    assert!(matches!(
        a.read(EntryId(1)),
        Err(Error::BadSignature {
            what: "local file header",
            ..
        })
    ));
}

#[test]
fn invalid_utf8_name_is_rejected() {
    let mut f = FileSpec::new("x", vec![1], STORE);
    f.name = vec![b'a', 0xFF, 0xFE, b'b'];
    let b = P4kBuilder::new(Flavor::Cig).file(f);
    let tmp = temp_archive(&b.build());
    assert!(matches!(
        Archive::open(tmp.path()),
        Err(Error::InvalidEntryName { index: 0 })
    ));
}

#[test]
fn empty_archive() {
    for flavor in [Flavor::Cig, Flavor::Pkware64, Flavor::Classic] {
        let (a, _t) = open_bytes(&P4kBuilder::new(flavor).build());
        assert_eq!(a.len(), 0);
        assert!(a.is_empty());
        assert!(a.iter().next().is_none());
        assert!(a.find("x").is_none());
        assert_eq!(a.glob("*").unwrap().count(), 0);
        assert_eq!(a.tree().dir_count(), 1);
    }
}

#[test]
fn eocd_with_long_comment_and_padding() {
    let mut b = P4kBuilder::new(Flavor::Pkware64).add("a.txt", "hello", ZSTD);
    b.comment = vec![b'c'; 65_000];
    b.tail_padding = 100_000;
    let (a, _t) = open_bytes(&b.build());
    assert_eq!(a.info().comment.len(), 65_000);
    assert_eq!(a.read_path("a.txt").unwrap(), b"hello");

    // Leading junk before the first local header (self-extracting style).
    let mut b = P4kBuilder::new(Flavor::Classic).add("a.txt", "hello", DEFLATE);
    b.leading_junk = vec![0x90; 12_345];
    let (a, _t) = open_bytes(&b.build());
    assert_eq!(a.read_path("a.txt").unwrap(), b"hello");
}

#[test]
fn concurrent_reads_from_many_threads() {
    let files = sample_files();
    let bytes = build(Flavor::Cig, files.clone());
    let tmp = temp_archive(&bytes);
    let a = Arc::new(Archive::open(tmp.path()).unwrap());
    let expected: Arc<Vec<Vec<u8>>> = Arc::new(files.iter().map(|f| f.data.clone()).collect());
    let mut handles = Vec::new();
    for t in 0..16u32 {
        let a = Arc::clone(&a);
        let expected = Arc::clone(&expected);
        handles.push(std::thread::spawn(move || {
            let mut buf = Vec::new();
            for round in 0..20u32 {
                let id = EntryId((t + round) % a.len() as u32);
                buf.clear();
                a.read_into(id, &mut buf).unwrap();
                assert_eq!(buf, expected[id.index()]);
                let mut r = a.open_entry(id).unwrap();
                let mut v = Vec::new();
                r.read_to_end(&mut v).unwrap();
                assert_eq!(v, expected[id.index()]);
                assert!(a.find("Data/Libs/text.xml").is_some());
                let _ = a.tree();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // The handle itself is Clone + Send + Sync.
    fn assert_send_sync<T: Send + Sync + Clone>(_: &T) {}
    assert_send_sync(&*a);
    let b = (*a).clone();
    assert_eq!(b.len(), a.len());
}

#[test]
fn stream_reader_edge_cases() {
    let (a, _t) = open_bytes(&build(Flavor::Cig, sample_files()));
    // Zero-length reads return 0 without touching state.
    let id = a.find("Data/Libs/big_enc.bin").unwrap();
    let mut r = a.open_entry(id).unwrap();
    assert_eq!(r.read(&mut []).unwrap(), 0);
    // Empty entry: first read returns 0 and verifies.
    let id = a.find("Data/empty.bin").unwrap();
    let mut r = a.open_entry(id).unwrap();
    assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 0);
    assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 0);
    // io::Error from the reader converts back to the library error.
    let err: starpak::Error = std::io::Error::other(Error::NotXml).into();
    assert!(matches!(err, Error::Io(_)));
    let io: std::io::Error = Error::NotXml.into();
    assert_eq!(io.kind(), std::io::ErrorKind::InvalidData);
    let io: std::io::Error = Error::Io(std::io::Error::other("x")).into();
    assert_eq!(io.kind(), std::io::ErrorKind::Other);
}

#[test]
fn glob_matches_against_normalised_names() {
    let b = P4kBuilder::new(Flavor::Cig)
        .add("Data/forward.xml", "f", STORE)
        .add("Data\\Back.XML", "b", STORE);
    let (a, _t) = open_bytes(&b.build());
    assert_eq!(a.glob("data/*.xml").unwrap().count(), 2);
    assert_eq!(a.find("data\\forward.xml"), Some(EntryId(0)));
    assert_eq!(a.find("data/back.xml"), Some(EntryId(1)));
    assert_eq!(a.entry(EntryId(0)).unwrap().path(), "Data/forward.xml");
    assert_eq!(a.entry(EntryId(1)).unwrap().path(), "Data/Back.XML");
}
