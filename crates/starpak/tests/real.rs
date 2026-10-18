//! Tests against a real `Data.p4k`, enabled with `STARPAK_TEST_P4K=<path>`.
//! `STARPAK_TEST_P4K_TRUNCATED=<path>` optionally points at a damaged copy.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use starpak::{Archive, EntryId, Error, Method};

fn archive() -> Option<Archive> {
    let path = std::env::var_os("STARPAK_TEST_P4K")?;
    Some(Archive::open(path).expect("open real archive"))
}

macro_rules! real {
    ($a:ident) => {
        let Some($a) = archive() else {
            eprintln!("STARPAK_TEST_P4K not set; skipping");
            return;
        };
    };
}

#[test]
fn opens_and_counts() {
    real!(a);
    let info = a.info();
    assert!(info.zip64);
    assert!(info.entries > 100_000, "{}", info.entries);
    assert_eq!(a.len() as u64, info.entries);
    assert!(info.comment.starts_with(b"CIG"));
    assert!(info.cd_offset + info.cd_size <= info.eocd_offset);
    assert!(!a.has_name_index(), "index must be lazy");
    assert!(a
        .iter()
        .all(|e| !e.name().is_empty() && e.name().contains('\\')));
}

#[test]
fn global_ini() {
    real!(a);
    let e = a
        .entry_by_path("Data/Localization/english/global.ini")
        .unwrap();
    assert!(e.uncompressed_size > 1_000_000);
    let data = a.read_entry(&e).unwrap();
    assert_eq!(data.len() as u64, e.uncompressed_size);
    let text = String::from_utf8_lossy(&data);
    assert!(text.contains("="));
    assert!(text.lines().count() > 10_000);
    // Streaming path yields identical bytes.
    let mut v = Vec::new();
    a.open_entry(e.id).unwrap().read_to_end(&mut v).unwrap();
    assert_eq!(v, data);
}

#[test]
fn sample_across_methods_verifies() {
    real!(a);
    let mut per_kind: HashMap<(Method, bool), Vec<EntryId>> = HashMap::new();
    let mut i = 0usize;
    for e in a.iter() {
        i += 1;
        if i % 97 != 0 {
            continue;
        }
        let d = e.entry();
        if d.uncompressed_size > 32 << 20 {
            continue;
        }
        let v = per_kind.entry((d.method, d.encrypted)).or_default();
        if v.len() < 25 {
            v.push(d.id);
        }
        if per_kind.len() >= 4 && per_kind.values().all(|v| v.len() >= 25) {
            break;
        }
    }
    // Encrypted entries are rare; make sure we have some.
    per_kind.entry((Method::Zstd, true)).or_insert_with(|| {
        a.iter()
            .filter(|e| e.entry().encrypted)
            .take(10)
            .map(|e| e.id())
            .collect()
    });
    assert!(per_kind.contains_key(&(Method::Zstd, false)));
    assert!(per_kind.contains_key(&(Method::Store, false)));
    let mut total = 0usize;
    for ((m, enc), ids) in &per_kind {
        for id in ids {
            let d = a.stat(*id).unwrap();
            assert_eq!(d.method, *m);
            assert_eq!(d.encrypted, *enc);
            let data = a
                .read(*id)
                .unwrap_or_else(|e| panic!("{m}/{enc} {}: {e}", d.name));
            assert_eq!(data.len() as u64, d.uncompressed_size);
            assert_eq!(crc32c::crc32c(&data), d.crc32c);
            total += 1;
        }
    }
    assert!(total >= 40, "{total}");
}

#[test]
fn stream_matches_bulk() {
    real!(a);
    let picks = [
        "Data/Scripts/Network/wrld.xml",
        "Data/Localization/english/global.ini",
    ];
    let mut n = 0;
    for p in picks {
        if let Some(id) = a.find(p) {
            let bulk = a.read(id).unwrap();
            let mut s = Vec::new();
            a.open_entry(id).unwrap().read_to_end(&mut s).unwrap();
            assert_eq!(bulk, s, "{p}");
            a.verify(id).unwrap();
            n += 1;
        }
    }
    // Plus a few encrypted ones found by scanning.
    for e in a.iter().filter(|e| e.entry().encrypted).take(5) {
        let bulk = e.read().unwrap();
        let mut s = Vec::new();
        a.open_entry(e.id()).unwrap().read_to_end(&mut s).unwrap();
        assert_eq!(bulk, s, "{}", e.name());
        n += 1;
    }
    assert!(n >= 5);
}

#[test]
fn cryxml_entries_decode() {
    real!(a);
    let mut binary = 0;
    let mut text = 0;
    for e in a.glob("Data/**/*.xml").unwrap().take(400) {
        let d = e.entry();
        if d.uncompressed_size > 8 << 20 {
            continue;
        }
        let data = e.read().unwrap();
        if starpak::cryxml::is_cryxmlb(&data) {
            let doc = starpak::cryxml::CryXml::parse(&data)
                .unwrap_or_else(|err| panic!("{}: {err}", e.name()));
            assert!(!doc.root().tag().is_empty());
            let xml = doc.to_xml_string();
            assert!(xml.starts_with("<?xml"));
            binary += 1;
        } else {
            match starpak::cryxml::to_xml(&data) {
                Ok(_) => text += 1,
                Err(Error::NotXml) => {}
                Err(err) => panic!("{}: {err}", e.name()),
            }
        }
        if binary >= 50 && text >= 5 {
            break;
        }
    }
    assert!(binary >= 20, "binary={binary} text={text}");
    // One-call convenience.
    let xml = a.read_xml("Data/Scripts/Network/wrld.xml");
    if let Ok(xml) = xml {
        assert!(xml.starts_with("<?xml"));
    }
}

#[test]
fn concurrent_reads() {
    real!(a);
    let a = Arc::new(a);
    let ids: Vec<EntryId> = {
        let mut v = Vec::new();
        let mut i = 0usize;
        for e in a.iter() {
            i += 1;
            if i % 1013 == 0 {
                let d = e.entry();
                if d.uncompressed_size <= 16 << 20 {
                    v.push(d.id);
                }
            }
            if v.len() >= 400 {
                break;
            }
        }
        v
    };
    let ids = Arc::new(ids);
    let threads = 16;
    let mut handles = Vec::new();
    for t in 0..threads {
        let a = Arc::clone(&a);
        let ids = Arc::clone(&ids);
        handles.push(std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut n = 0;
            for (i, id) in ids.iter().enumerate() {
                if i % threads != t {
                    continue;
                }
                buf.clear();
                a.read_into(*id, &mut buf).unwrap();
                n += 1;
            }
            n
        }));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, ids.len());
}

#[test]
fn tree_and_lookup() {
    real!(a);
    let t = a.tree();
    let data = t.find("Data").expect("Data directory");
    assert!(t.dirs(data).len() > 10);
    assert!(t.file_count(data) > 100_000);
    let loc = t
        .find("data/localization/english")
        .expect("localization dir");
    let names: Vec<&str> = t.files(loc).iter().filter_map(|id| a.name(*id)).collect();
    assert!(names.iter().any(|n| n.ends_with("global.ini")), "{names:?}");
    // Random lookups hit.
    let mut i = 0;
    for e in a.iter().step_by(50_000) {
        assert_eq!(a.find(&e.name().to_ascii_uppercase()), Some(e.id()));
        i += 1;
    }
    assert!(i > 5);
}

#[test]
fn truncated_copy_reports_truncation() {
    let Some(path) = std::env::var_os("STARPAK_TEST_P4K_TRUNCATED") else {
        eprintln!("STARPAK_TEST_P4K_TRUNCATED not set; skipping");
        return;
    };
    match Archive::open(path) {
        Err(Error::Truncated { file_size }) => assert!(file_size > 0),
        other => panic!("expected Truncated, got {:?}", other.map(|a| a.len())),
    }
}
