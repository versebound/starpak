//! CryXmlB round trips with crafted binaries.

mod common;

use common::{encode_cryxml, temp_archive, CryXmlLayout, Elem, Flavor, P4kBuilder, Rng, ZSTD};
use starpak::cryxml::{self, CryXml};
use starpak::{Archive, Error};

fn sample_tree() -> Elem {
    Elem::new("Vehicle")
        .attr("name", "AEGS_Avenger")
        .attr("size", "2")
        .child(
            Elem::new("Parts")
                .child(
                    Elem::new("Part")
                        .attr("name", "hull")
                        .attr("mass", "1200.5"),
                )
                .child(
                    Elem::new("Part")
                        .attr("name", "wing \"left\" <A&B>")
                        .child(Elem::new("Note").text("text & <markup> \"quoted\""))
                        .child(Elem::new("Empty")),
                ),
        )
        .child(Elem::new("Mixed").text("leading").child(Elem::new("Inner")))
}

const EXPECTED: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Vehicle name="AEGS_Avenger" size="2">
  <Parts>
    <Part name="hull" mass="1200.5" />
    <Part name="wing &quot;left&quot; &lt;A&amp;B&gt;">
      <Note>text &amp; &lt;markup&gt; "quoted"</Note>
      <Empty />
    </Part>
  </Parts>
  <Mixed>leading
    <Inner />
  </Mixed>
</Vehicle>
"#;

#[test]
fn roundtrip_to_text() {
    for layout in [
        CryXmlLayout::default(),
        CryXmlLayout {
            strings_first: true,
            gaps: false,
        },
        CryXmlLayout {
            strings_first: false,
            gaps: true,
        },
        CryXmlLayout {
            strings_first: true,
            gaps: true,
        },
    ] {
        let bin = encode_cryxml(&sample_tree(), layout);
        assert!(cryxml::is_cryxmlb(&bin));
        let doc = CryXml::parse(&bin).unwrap();
        assert_eq!(doc.to_xml_string(), EXPECTED);
        assert_eq!(cryxml::to_xml(&bin).unwrap(), EXPECTED);
        let mut w = Vec::new();
        doc.write_xml(&mut w).unwrap();
        assert_eq!(String::from_utf8(w).unwrap(), EXPECTED);
    }
}

#[test]
fn navigation() {
    let bin = encode_cryxml(&sample_tree(), CryXmlLayout::default());
    let doc = CryXml::parse(&bin).unwrap();
    assert_eq!(doc.node_count(), 8);
    assert_eq!(doc.attribute_count(), 5);
    let root = doc.root();
    assert_eq!(root.tag(), "Vehicle");
    assert_eq!(root.attr("name"), Some("AEGS_Avenger"));
    assert_eq!(root.attr("size"), Some("2"));
    assert_eq!(root.attr("missing"), None);
    assert_eq!(root.attribute_count(), 2);
    assert_eq!(root.child_count(), 2);
    assert!(root.parent().is_none());
    assert_eq!(root.text(), "");
    assert_eq!(root.index(), 0);
    let parts = root.child("Parts").unwrap();
    assert_eq!(parts.parent().unwrap().tag(), "Vehicle");
    let names: Vec<&str> = parts.children().map(|c| c.attr("name").unwrap()).collect();
    assert_eq!(names, vec!["hull", "wing \"left\" <A&B>"]);
    let note = parts.children().nth(1).unwrap().child("Note").unwrap();
    assert_eq!(note.text(), "text & <markup> \"quoted\"");
    assert_eq!(root.child("Mixed").unwrap().text(), "leading");
    assert!(root.child("Nope").is_none());
    assert!(doc.node(99).is_none());
    assert_eq!(doc.node(0).unwrap().tag(), "Vehicle");
    let dbg = format!("{:?}", root);
    assert!(dbg.contains("Vehicle"));
    let attrs: Vec<(&str, &str)> = root.attributes().collect();
    assert_eq!(attrs[0], ("name", "AEGS_Avenger"));
}

#[test]
fn single_node_and_empty_strings() {
    let bin = encode_cryxml(&Elem::new("Root"), CryXmlLayout::default());
    let doc = CryXml::parse(&bin).unwrap();
    assert_eq!(
        doc.to_xml_string(),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Root />\n"
    );
    let bin = encode_cryxml(
        &Elem::new("R").attr("", "").text(""),
        CryXmlLayout::default(),
    );
    let doc = CryXml::parse(&bin).unwrap();
    assert_eq!(doc.root().attr(""), Some(""));
}

#[test]
fn truncations_never_panic() {
    let bin = encode_cryxml(&sample_tree(), CryXmlLayout::default());
    for n in 0..bin.len() {
        let r = CryXml::parse(&bin[..n]);
        assert!(r.is_err(), "prefix of {n} bytes parsed");
        assert!(matches!(r, Err(Error::CryXml(_))));
    }
    assert!(CryXml::parse(&bin).is_ok());
}

#[test]
fn mutations_never_panic() {
    let bin = encode_cryxml(&sample_tree(), CryXmlLayout::default());
    let mut rng = Rng::new(77);
    let mut ok = 0;
    for _ in 0..5000 {
        let mut m = bin.clone();
        let flips = 1 + rng.below(4);
        for _ in 0..flips {
            let i = rng.below(m.len());
            m[i] = rng.next_u64() as u8;
        }
        if let Ok(doc) = CryXml::parse(&m) {
            ok += 1;
            let _ = doc.to_xml_string();
            for i in 0..doc.node_count() {
                let n = doc.node(i).unwrap();
                let _ = n.attributes().count();
                let _ = n.children().count();
                let _ = n.parent();
            }
        }
    }
    assert!(
        ok > 0,
        "some mutations should still parse (e.g. string bytes)"
    );
}

#[test]
fn structural_errors() {
    let bin = encode_cryxml(&sample_tree(), CryXmlLayout::default());
    let child_off = u32::from_le_bytes(bin[28..32].try_into().unwrap()) as usize;
    let child_count = u32::from_le_bytes(bin[32..36].try_into().unwrap()) as usize;
    assert!(child_count >= 2);

    // Cycle: make a child point back at the root.
    let mut cyc = bin.clone();
    cyc[child_off..child_off + 4].copy_from_slice(&0u32.to_le_bytes());
    let e = CryXml::parse(&cyc).unwrap_err().to_string();
    assert!(e.contains("twice"), "{e}");

    // Child index out of range.
    let mut oor = bin.clone();
    oor[child_off..child_off + 4].copy_from_slice(&999u32.to_le_bytes());
    let e = CryXml::parse(&oor).unwrap_err().to_string();
    assert!(e.contains("out of range"), "{e}");

    // Root with a parent.
    let node_off = u32::from_le_bytes(bin[12..16].try_into().unwrap()) as usize;
    let mut rp = bin.clone();
    rp[node_off + 12..node_off + 16].copy_from_slice(&1i32.to_le_bytes());
    let e = CryXml::parse(&rp).unwrap_err().to_string();
    assert!(e.contains("root"), "{e}");

    // Attribute range past the table.
    let mut ar = bin.clone();
    ar[node_off + 8..node_off + 10].copy_from_slice(&500u16.to_le_bytes());
    assert!(CryXml::parse(&ar).is_err());

    // String offset past the string table.
    let mut so = bin.clone();
    so[node_off..node_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CryXml::parse(&so).is_err());

    // Not CryXml at all.
    assert!(matches!(CryXml::parse(b"<xml/>"), Err(Error::CryXml(_))));
    assert!(matches!(cryxml::to_xml(&[0u8; 100]), Err(Error::NotXml)));
}

#[test]
fn text_xml_passthrough() {
    let text = "\u{FEFF}<?xml version=\"1.0\"?>\n<a b=\"1\"/>";
    assert_eq!(cryxml::to_xml(text.as_bytes()).unwrap(), text);
    assert_eq!(cryxml::to_xml(b"  \n<a/>").unwrap(), "  \n<a/>");
    let invalid = b"<a>\xFF</a>";
    assert_eq!(cryxml::to_xml(invalid).unwrap(), "<a>\u{FFFD}</a>");
}

#[test]
fn through_the_archive() {
    let bin = encode_cryxml(&sample_tree(), CryXmlLayout::default());
    let b = P4kBuilder::new(Flavor::Cig)
        .add("Data\\Libs\\vehicle.xml", bin.clone(), ZSTD)
        .add("Data\\Libs\\plain.xml", "<plain attr=\"1\" />", ZSTD)
        .add("Data\\Libs\\notxml.bin", vec![0u8; 32], ZSTD);
    let tmp = temp_archive(&b.build());
    let a = Archive::open(tmp.path()).unwrap();
    assert_eq!(a.read_xml("data/libs/VEHICLE.xml").unwrap(), EXPECTED);
    assert_eq!(
        a.read_xml("Data/Libs/plain.xml").unwrap(),
        "<plain attr=\"1\" />"
    );
    assert!(matches!(
        a.read_xml("Data/Libs/notxml.bin"),
        Err(Error::NotXml)
    ));
    assert!(matches!(
        a.read_xml("Data/Libs/missing.xml"),
        Err(Error::NotFound(_))
    ));
    let id = a.find("Data/Libs/vehicle.xml").unwrap();
    let doc = a.read_cryxml(id).unwrap();
    assert_eq!(doc.root().tag(), "Vehicle");
    let id = a.find("Data/Libs/plain.xml").unwrap();
    assert!(matches!(a.read_cryxml(id), Err(Error::CryXml(_))));
    let e = a.entry_by_path("Data/Libs/vehicle.xml").unwrap();
    assert_eq!(a.read_xml_entry(&e).unwrap(), EXPECTED);
}

#[test]
fn large_document() {
    let mut root = Elem::new("Root");
    for i in 0..5000 {
        let mut item = Elem::new("Item").attr("id", &i.to_string()).attr("v", "x");
        if i % 10 == 0 {
            item = item.child(Elem::new("Sub").text(&format!("t{i}")));
        }
        root = root.child(item);
    }
    let bin = encode_cryxml(&root, CryXmlLayout::default());
    let doc = CryXml::parse(&bin).unwrap();
    assert_eq!(doc.root().child_count(), 5000);
    assert_eq!(doc.node_count(), 5501);
    let text = doc.to_xml_string();
    assert!(text.contains("<Sub>t4990</Sub>"));
    assert_eq!(text.matches("<Item ").count(), 5000);
}
