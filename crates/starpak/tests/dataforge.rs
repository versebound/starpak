//! Hermetic DataForge tests over synthetic `.dcb` images.

mod common;

use common::{dt, guid, temp_archive, DcbBuilder, DcbProp, Flavor, P4kBuilder, Rng, V, ZSTD};
use starpak::dataforge::{DataForge, DataType, ExportOptions, Guid, RecordId, StructId, Value};
use starpak::{Archive, Error};

/// Builds a database exercising every value kind.
///
/// Structs: `Base { id: I32 }`, `Vec3 { x, y, z: F32 }`, `Child : Base { name }`,
/// `Grand : Child { flag }`, `Item { ... }`, `Everything : Base { every type }`.
fn everything(version: u32, reverse: bool) -> (DcbBuilder, [u8; 16]) {
    let mut b = DcbBuilder::new(version);
    b.reverse_mappings = reverse;
    let color = b.enum_def("EColor", &["Red", "Green", "Blue"]);
    let base = b.struct_def("Base", None, vec![DcbProp::attr("id", dt::I32)]);
    let vec3 = b.struct_def(
        "Vec3",
        None,
        vec![
            DcbProp::attr("x", dt::F32),
            DcbProp::attr("y", dt::F32),
            DcbProp::attr("z", dt::F32),
        ],
    );
    let child = b.struct_def("Child", Some(base), vec![DcbProp::attr("name", dt::STRING)]);
    let grand = b.struct_def("Grand", Some(child), vec![DcbProp::attr("flag", dt::BOOL)]);
    let item = b.struct_def(
        "Item",
        None,
        vec![
            DcbProp::attr("label", dt::STRING),
            DcbProp::attr_of("pos", dt::CLASS, vec3),
        ],
    );
    let every = b.struct_def(
        "Everything",
        Some(base),
        vec![
            DcbProp::attr("b", dt::BOOL),
            DcbProp::attr("i8", dt::I8),
            DcbProp::attr("i16", dt::I16),
            DcbProp::attr("i64", dt::I64),
            DcbProp::attr("u8", dt::U8),
            DcbProp::attr("u16", dt::U16),
            DcbProp::attr("u32", dt::U32),
            DcbProp::attr("u64", dt::U64),
            DcbProp::attr("f32", dt::F32),
            DcbProp::attr("f64", dt::F64),
            DcbProp::attr("s", dt::STRING),
            DcbProp::attr("loc", dt::LOCALE),
            DcbProp::attr("g", dt::GUID),
            DcbProp::attr_of("color", dt::ENUM, color),
            DcbProp::attr_of("pos", dt::CLASS, vec3),
            DcbProp::attr_of("strong", dt::STRONG, child),
            DcbProp::attr_of("strong_null", dt::STRONG, child),
            DcbProp::attr_of("weak", dt::WEAK, item),
            DcbProp::attr_of("weak_null", dt::WEAK, item),
            DcbProp::attr_of("reference", dt::REFERENCE, base),
            DcbProp::attr_of("reference_null", dt::REFERENCE, base),
            DcbProp::array("bools", dt::BOOL),
            DcbProp::array("i8s", dt::I8),
            DcbProp::array("i16s", dt::I16),
            DcbProp::array("i32s", dt::I32),
            DcbProp::array("i64s", dt::I64),
            DcbProp::array("u8s", dt::U8),
            DcbProp::array("u16s", dt::U16),
            DcbProp::array("u32s", dt::U32),
            DcbProp::array("u64s", dt::U64),
            DcbProp::array("f32s", dt::F32),
            DcbProp::array("f64s", dt::F64),
            DcbProp::array("strs", dt::STRING),
            DcbProp::array("locs", dt::LOCALE),
            DcbProp::array("guids", dt::GUID),
            DcbProp::array_of("colors", dt::ENUM, color),
            DcbProp::array_of("items", dt::CLASS, item),
            DcbProp::array_of("strongs", dt::STRONG, child),
            DcbProp::array_of("weaks", dt::WEAK, item),
            DcbProp::array_of("refs", dt::REFERENCE, base),
            DcbProp::array("empty", dt::I32),
        ],
    );

    // Instances.
    let v3 = |x: f32, y: f32, z: f32| V::Class(vec![V::F32(x), V::F32(y), V::F32(z)]);
    let child0 = b.instance(child, vec![V::I32(10), V::Str("child zero".into())]);
    let grand0 = b.instance(
        grand,
        vec![V::I32(11), V::Str("grand".into()), V::Bool(true)],
    );
    let item0 = b.instance(item, vec![V::Str("first".into()), v3(1.0, 2.0, 3.0)]);
    let item1 = b.instance(
        item,
        vec![V::Str("second & <escaped>".into()), v3(0.5, -1.0, 1e10)],
    );
    let _item2 = b.instance(item, vec![V::Str("third".into()), v3(0.0, 0.0, 0.0)]);
    let other_guid = guid(2);
    let every0 = b.instance(
        every,
        vec![
            V::I32(-7),
            V::Bool(true),
            V::I8(-8),
            V::I16(-16),
            V::I64(-64),
            V::U8(8),
            V::U16(16),
            V::U32(32),
            V::U64(u64::MAX),
            V::F32(1.5),
            V::F64(2.25),
            V::Str("hello \"quoted\"".into()),
            V::Loc("@ui_hello".into()),
            V::Guid(guid(9)),
            V::Enum("Green".into()),
            v3(4.0, 5.0, 6.0),
            V::Strong(Some((grand, grand0))),
            V::Strong(None),
            V::Weak(Some((item, item1))),
            V::Weak(None),
            V::Ref(Some((other_guid, 0))),
            V::Ref(None),
            V::Array(vec![V::Bool(true), V::Bool(false)]),
            V::Array(vec![V::I8(-1), V::I8(2)]),
            V::Array(vec![V::I16(-300)]),
            V::Array(vec![V::I32(1), V::I32(2), V::I32(3)]),
            V::Array(vec![V::I64(i64::MIN)]),
            V::Array(vec![V::U8(255)]),
            V::Array(vec![V::U16(65535)]),
            V::Array(vec![V::U32(7)]),
            V::Array(vec![V::U64(9)]),
            V::Array(vec![V::F32(0.25), V::F32(-0.5)]),
            V::Array(vec![V::F64(1e100)]),
            V::Array(vec![V::Str("a".into()), V::Str("b".into())]),
            V::Array(vec![V::Loc("@l".into())]),
            V::Array(vec![V::Guid(guid(1)), V::Guid(guid(2))]),
            V::Array(vec![V::Enum("Blue".into()), V::Enum("Red".into())]),
            V::ClassArray(item0, 2),
            V::Array(vec![
                V::Strong(Some((child, child0))),
                V::Strong(None),
                V::Strong(Some((grand, grand0))),
            ]),
            V::Array(vec![V::Weak(Some((item, item0))), V::Weak(None)]),
            V::Array(vec![V::Ref(Some((other_guid, 0))), V::Ref(None)]),
            V::Array(vec![]),
        ],
    );
    let main_guid = guid(1);
    b.record_tagged(
        "Everything.Main",
        "libs/foundry/records/test/main.xml",
        "Test",
        every,
        every0,
        main_guid,
    );
    b.record(
        "Child.Other",
        "libs/foundry/records/test/other.xml",
        child,
        child0,
        other_guid,
    );
    // Two records in one file: the main one is named after the file stem.
    b.record(
        "Item.Sub",
        "libs/foundry/records/test/shared.xml",
        item,
        item1,
        guid(3),
    );
    b.record(
        "Item.Shared",
        "libs/foundry/records/test/shared.xml",
        item,
        item0,
        guid(4),
    );
    b.record(
        "Grand.G",
        "libs/foundry/records/test/grand.xml",
        grand,
        grand0,
        guid(5),
    );
    (b, main_guid)
}

fn check_everything(df: &DataForge, main_guid: [u8; 16]) {
    assert_eq!(df.record_count(), 5);
    assert_eq!(df.struct_count(), 6);
    assert_eq!(df.enum_count(), 1);
    assert_eq!(df.file_count(), 4);

    let r = df.record_by_guid(Guid(main_guid)).expect("main record");
    assert_eq!(r.name(), "Everything.Main");
    assert_eq!(r.type_name(), "Everything");
    assert_eq!(r.file_name(), "libs/foundry/records/test/main.xml");
    assert_eq!(r.guid(), Guid(main_guid));
    assert!(r.is_main());
    if df.version() >= 8 {
        assert_eq!(r.tag(), "Test");
    } else {
        assert_eq!(r.tag(), "");
    }
    assert_eq!(
        df.record_by_path("LIBS\\foundry/records/test/MAIN.xml")
            .unwrap()
            .id(),
        r.id()
    );
    assert_eq!(df.record(r.id()).unwrap().guid(), r.guid());
    assert!(df.record(RecordId(99)).is_none());

    let inst = r.instance().unwrap();
    assert_eq!(inst.type_name(), "Everything");
    assert_eq!(inst.field_count(), 42);
    assert_eq!(
        inst.fields().next().unwrap().name(),
        "id",
        "inherited field first"
    );
    let g = |n: &str| inst.get(n).unwrap();
    assert_eq!(g("id").as_i64(), Some(-7));
    assert_eq!(g("b").as_bool(), Some(true));
    assert!(matches!(g("i8"), Value::I8(-8)));
    assert!(matches!(g("i16"), Value::I16(-16)));
    assert!(matches!(g("i64"), Value::I64(-64)));
    assert!(matches!(g("u8"), Value::U8(8)));
    assert!(matches!(g("u16"), Value::U16(16)));
    assert!(matches!(g("u32"), Value::U32(32)));
    assert!(matches!(g("u64"), Value::U64(u64::MAX)));
    assert_eq!(g("u64").as_i64(), None);
    assert_eq!(g("f32").as_f64(), Some(1.5));
    assert_eq!(g("f64").as_f64(), Some(2.25));
    assert_eq!(g("s").as_str(), Some("hello \"quoted\""));
    assert_eq!(g("loc").as_str(), Some("@ui_hello"));
    assert!(matches!(g("loc"), Value::Locale(_)));
    assert_eq!(g("g").as_guid(), Some(Guid(guid(9))));
    assert_eq!(g("color").as_str(), Some("Green"));
    assert!(matches!(g("color"), Value::Enum(_)));
    let pos = g("pos").as_class().unwrap();
    assert_eq!(pos.type_name(), "Vec3");
    assert_eq!(
        pos.get("y").as_ref().ok().and_then(Value::as_f64),
        Some(5.0)
    );
    assert!(pos.get("nope").is_err());
    assert!(inst.field("nope").is_none());

    // Pointers and references.
    let strong = match g("strong") {
        Value::StrongPointer(Some(p)) => p,
        other => panic!("{other:?}"),
    };
    let target = df.deref(Some(strong)).unwrap().unwrap();
    assert_eq!(target.type_name(), "Grand");
    assert_eq!(target.get("name").unwrap().as_str(), Some("grand"));
    assert_eq!(target.get("flag").unwrap().as_bool(), Some(true));
    assert_eq!(target.get("id").unwrap().as_i64(), Some(11));
    assert!(matches!(g("strong_null"), Value::StrongPointer(None)));
    assert!(df.deref(None).unwrap().is_none());
    let weak = match g("weak") {
        Value::WeakPointer(Some(p)) => p,
        other => panic!("{other:?}"),
    };
    let w = df
        .instance(StructId(weak.struct_index), weak.instance_index)
        .unwrap();
    assert_eq!(w.get("label").unwrap().as_str(), Some("second & <escaped>"));
    assert!(matches!(g("weak_null"), Value::WeakPointer(None)));
    let reference = match g("reference") {
        Value::Reference(Some(r)) => r,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        df.record_by_guid(reference.guid).unwrap().name(),
        "Child.Other"
    );
    assert_eq!(g("reference").as_guid(), Some(reference.guid));
    assert!(matches!(g("reference_null"), Value::Reference(None)));

    // Arrays.
    let arr = |n: &str| g(n).as_array().unwrap();
    assert_eq!(
        arr("bools")
            .iter()
            .map(|v| v.unwrap().as_bool().unwrap())
            .collect::<Vec<_>>(),
        vec![true, false]
    );
    assert_eq!(
        arr("i8s")
            .iter()
            .map(|v| v.unwrap().as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![-1, 2]
    );
    assert_eq!(arr("i16s").get(0).unwrap().as_i64(), Some(-300));
    assert_eq!(arr("i32s").len(), 3);
    assert_eq!(arr("i64s").get(0).unwrap().as_i64(), Some(i64::MIN));
    assert_eq!(arr("u8s").get(0).unwrap().as_i64(), Some(255));
    assert_eq!(arr("u16s").get(0).unwrap().as_i64(), Some(65535));
    assert_eq!(arr("u32s").get(0).unwrap().as_i64(), Some(7));
    assert_eq!(arr("u64s").get(0).unwrap().as_i64(), Some(9));
    assert_eq!(arr("f32s").get(1).unwrap().as_f64(), Some(-0.5));
    assert_eq!(arr("f64s").get(0).unwrap().as_f64(), Some(1e100));
    assert_eq!(arr("strs").get(1).unwrap().as_str(), Some("b"));
    assert_eq!(arr("locs").get(0).unwrap().as_str(), Some("@l"));
    assert_eq!(arr("guids").get(1).unwrap().as_guid(), Some(Guid(guid(2))));
    assert_eq!(arr("colors").get(0).unwrap().as_str(), Some("Blue"));
    assert_eq!(arr("colors").data_type(), DataType::Enum);
    let items = arr("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items.element_struct().unwrap().name(), "Item");
    assert_eq!(
        items
            .get(0)
            .unwrap()
            .as_class()
            .unwrap()
            .get("label")
            .unwrap()
            .as_str(),
        Some("first")
    );
    assert_eq!(
        items
            .get(1)
            .unwrap()
            .as_class()
            .unwrap()
            .get("pos")
            .unwrap()
            .as_class()
            .unwrap()
            .get("z")
            .unwrap()
            .as_f64(),
        Some(1e10)
    );
    assert!(items.get(2).is_err());
    let strongs = arr("strongs");
    assert_eq!(strongs.len(), 3);
    assert!(matches!(
        strongs.get(1).unwrap(),
        Value::StrongPointer(None)
    ));
    let weaks = arr("weaks");
    assert!(matches!(weaks.get(0).unwrap(), Value::WeakPointer(Some(_))));
    let refs = arr("refs");
    assert!(matches!(refs.get(1).unwrap(), Value::Reference(None)));
    assert!(arr("empty").is_empty());
    assert_eq!(arr("i32s").first_index(), 0);
    assert_eq!(
        arr("empty").first_index(),
        3,
        "empty arrays still carry the table position"
    );

    // Definitions.
    let every = df.find_struct("Everything").unwrap();
    assert_eq!(every.parent().unwrap().name(), "Base");
    assert!(every.is_a(df.find_struct("Base").unwrap().id()));
    assert!(!every.is_a(df.find_struct("Item").unwrap().id()));
    assert_eq!(every.instance_count(), 1);
    assert_eq!(every.size(), inst.bytes().len() as u32);
    let props: Vec<String> = every.properties().map(|p| p.type_name()).collect();
    assert_eq!(props[0], "Int32");
    assert!(props.contains(&"Vec3".to_string()));
    assert!(props.contains(&"EColor".to_string()));
    assert!(props.contains(&"Item[]".to_string()));
    assert!(props.contains(&"Child[]".to_string()));
    let id_prop = every.properties().next().unwrap();
    assert_eq!(id_prop.offset(), 0);
    assert_eq!(id_prop.data_type(), DataType::I32);
    assert!(!id_prop.is_array());
    assert!(id_prop.target_struct().is_none());
    let color_prop = every.properties().find(|p| p.name() == "color").unwrap();
    assert_eq!(color_prop.target_enum().unwrap().name(), "EColor");
    assert_eq!(
        df.enum_def(0).unwrap().values().collect::<Vec<_>>(),
        vec!["Red", "Green", "Blue"]
    );
    assert_eq!(df.enum_def(0).unwrap().len(), 3);
    assert!(df.enum_def(1).is_none());
    assert!(df.find_struct("Nope").is_none());
    assert!(df.struct_def(StructId(99)).is_none());
    assert_eq!(df.structs().count(), 6);

    // Records by type, file and glob.
    assert_eq!(
        df.records_of_type("Base").count(),
        3,
        "Everything, Child and Grand records inherit Base"
    );
    assert_eq!(df.records_of_type("Item").count(), 2);
    assert_eq!(df.records_of_type("Nope").count(), 0);
    assert_eq!(
        df.records_matching("libs/foundry/records/test/*")
            .unwrap()
            .count(),
        5
    );
    assert_eq!(df.records_matching("**/shared.xml").unwrap().count(), 2);
    assert!(df.records_matching("[bad").is_err());
    let shared = df.records_in_file("libs/foundry/records/test/shared.xml");
    assert_eq!(shared.len(), 2);
    let main = df
        .record_by_path("libs/foundry/records/test/shared.xml")
        .unwrap();
    assert_eq!(main.name(), "Item.Shared", "named after the file stem");
    assert!(main.is_main());
    assert!(!df.record_by_guid(Guid(guid(3))).unwrap().is_main());
    assert!(df.record_by_path("libs/nope.xml").is_none());
    assert!(df.records_in_file("libs/nope.xml").is_empty());
    assert!(df.instance(StructId(0), 99).is_err());
    assert!(df.instance(StructId(99), 0).is_err());
    assert!(
        df.instance(StructId(1), 0).is_err(),
        "Vec3 has no standalone instances"
    );

    // Debug output does not panic.
    let _ = format!(
        "{df:?} {r:?} {inst:?} {every:?} {:?} {:?}",
        df.enum_def(0).unwrap(),
        inst.fields().next().unwrap()
    );
}

#[test]
fn every_value_kind_v8() {
    let (b, g) = everything(8, false);
    let df = DataForge::parse(b.build()).unwrap();
    assert_eq!(df.version(), 8);
    check_everything(&df, g);
}

#[test]
fn every_value_kind_v6_reversed_mappings() {
    let (b, g) = everything(6, true);
    let bytes = b.build();
    let df = DataForge::from_slice(&bytes).unwrap();
    assert_eq!(df.version(), 6);
    check_everything(&df, g);
    let info = df.info();
    assert_eq!(info.records, 5);
    assert!(info.name_table_bytes > 0);
}

#[test]
fn every_value_kind_v5_single_string_table() {
    let (b, g) = everything(5, false);
    let df = DataForge::parse(b.build()).unwrap();
    assert_eq!(df.version(), 5);
    assert_eq!(df.info().name_table_bytes, 0);
    check_everything(&df, g);
}

#[test]
fn xml_export_shape() {
    let (b, g) = everything(8, false);
    let df = DataForge::parse(b.build()).unwrap();
    let r = df.record_by_guid(Guid(g)).unwrap();
    let xml = r.to_xml().unwrap();
    let expected = r#"<Everything.Main id="-7" b="1" i8="-8" i16="-16" i64="-64" u8="8" u16="16" u32="32" u64="18446744073709551615" f32="1.5" f64="2.25" s="hello &quot;quoted&quot;" loc="@ui_hello" g="G9" color="Green" reference="G2" reference_null="00000000-0000-0000-0000-000000000000" __type="Everything" __ref="G1" __path="libs/foundry/records/test/main.xml">
  <pos x="4" y="5" z="6" __type="Vec3" />
  <strong>
    <Grand id="11" name="grand" flag="1" __type="Child" __polymorphicType="Grand" />
  </strong>
  <weak value="Item[0001]" />
  <bools>
    <Bool value="1" />
    <Bool value="0" />
  </bools>
  <i8s>
    <Int8 value="-1" />
    <Int8 value="2" />
  </i8s>
  <i16s>
    <Int16 value="-300" />
  </i16s>
  <i32s>
    <Int32 value="1" />
    <Int32 value="2" />
    <Int32 value="3" />
  </i32s>
  <i64s>
    <Int64 value="-9223372036854775808" />
  </i64s>
  <u8s>
    <UInt8 value="255" />
  </u8s>
  <u16s>
    <UInt16 value="65535" />
  </u16s>
  <u32s>
    <UInt32 value="7" />
  </u32s>
  <u64s>
    <UInt64 value="9" />
  </u64s>
  <f32s>
    <Single value="0.25" />
    <Single value="-0.5" />
  </f32s>
  <f64s>
    <Double value="D100" />
  </f64s>
  <strs>
    <String value="a" />
    <String value="b" />
  </strs>
  <locs>
    <LocID value="@l" />
  </locs>
  <guids>
    <Guid value="G1" />
    <Guid value="G2" />
  </guids>
  <colors>
    <Enum value="Blue" />
    <Enum value="Red" />
  </colors>
  <items>
    <Item label="first" __type="Item">
      <pos x="1" y="2" z="3" __type="Vec3" />
    </Item>
    <Item label="second &amp; &lt;escaped&gt;" __type="Item">
      <pos x="0.5" y="-1" z="10000000000" __type="Vec3" />
    </Item>
  </items>
  <strongs>
    <Child id="10" name="child zero" __type="Child" />
    <Grand id="11" name="grand" flag="1" __type="Child" __polymorphicType="Grand" />
  </strongs>
  <weaks>
    <Item label="first" __type="Item">
      <pos x="1" y="2" z="3" __type="Vec3" />
    </Item>
  </weaks>
  <refs>
    <Reference value="G2" />
    <Reference value="00000000-0000-0000-0000-000000000000" />
  </refs>
  <empty />
</Everything.Main>
"#
        .replace("G1", &Guid(guid(1)).to_string())
        .replace("G2", &Guid(guid(2)).to_string())
        .replace("G9", &Guid(guid(9)).to_string())
        .replace("D100", &1e100f64.to_string());
    assert_eq!(xml, expected);

    // A record with no children is self-closing; odd names are sanitised.
    let other = df.record_by_guid(Guid(guid(2))).unwrap();
    assert_eq!(
        other.to_xml().unwrap(),
        format!(
            "<Child.Other id=\"10\" name=\"child zero\" __type=\"Child\" __ref=\"{}\" __path=\"libs/foundry/records/test/other.xml\" />\n",
            Guid(guid(2))
        )
    );
    assert_eq!(
        starpak::dataforge::to_xml(&other, &ExportOptions::default()).unwrap(),
        other.to_xml().unwrap()
    );
}

#[test]
fn json_export_shape() {
    let (b, g) = everything(8, false);
    let df = DataForge::parse(b.build()).unwrap();
    let r = df.record_by_guid(Guid(g)).unwrap();
    let json = r.to_json().unwrap();
    let head = format!(
        "{{\n  \"__name\": \"Everything.Main\",\n  \"__type\": \"Everything\",\n  \"__ref\": \"{}\",\n  \"__path\": \"libs/foundry/records/test/main.xml\",\n  \"__tag\": \"Test\",\n  \"id\": -7,\n  \"b\": true,\n  \"i8\": -8,",
        Guid(guid(1))
    );
    assert!(json.starts_with(&head), "{json}");
    assert!(json.contains("\"u64\": 18446744073709551615,"));
    assert!(json.contains("\"s\": \"hello \\\"quoted\\\"\","));
    assert!(json.contains("\"pos\": {\n    \"__type\": \"Vec3\",\n    \"x\": 4,"));
    assert!(json.contains("\"strong\": {\n    \"__type\": \"Child\",\n    \"__polymorphicType\": \"Grand\",\n    \"id\": 11,"));
    assert!(json.contains("\"strong_null\": null,"));
    assert!(json.contains("\"weak\": {\"__weak\":\"Item\",\"__instance\":1},"));
    assert!(json.contains("\"weak_null\": null,"));
    assert!(json.contains(&format!("\"reference\": \"{}\",", Guid(guid(2)))));
    assert!(json.contains("\"reference_null\": null,"));
    assert!(json.contains("\"bools\": [\n    true,\n    false\n  ],"));
    assert!(json.contains("\"empty\": []\n}"));
    assert!(json.contains("\"items\": [\n    {\n      \"__type\": \"Item\","));
    assert!(json.ends_with("}\n"));

    let compact = starpak::dataforge::to_json(
        &r,
        &ExportOptions {
            pretty: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(compact.starts_with("{\"__name\":\"Everything.Main\",\"__type\":"));
    assert!(!compact.contains('\n'));
}

#[test]
fn pointer_cycles_terminate() {
    let mut b = DcbBuilder::new(8);
    let node = b.struct_def("Node", None, vec![]);
    b.structs[node].props = vec![
        DcbProp::attr("n", dt::I32),
        DcbProp::attr_of("next", dt::STRONG, node),
        DcbProp::array_of("more", dt::STRONG, node),
    ];
    let n0 = b.instance(
        node,
        vec![
            V::I32(0),
            V::Strong(Some((node, 1))),
            V::Array(vec![V::Strong(Some((node, 0)))]),
        ],
    );
    let _n1 = b.instance(
        node,
        vec![V::I32(1), V::Strong(Some((node, 0))), V::Array(vec![])],
    );
    b.record("Node.Root", "libs/cycle.xml", node, n0, guid(1));
    let df = DataForge::parse(b.build()).unwrap();
    let r = df.record_by_guid(Guid(guid(1))).unwrap();
    let xml = r.to_xml().unwrap();
    assert_eq!(xml.matches("<Node ").count(), 1, "{xml}");
    assert!(
        xml.contains(
            "<next>\n    <Node n=\"1\" __type=\"Node\">\n      <more />\n    </Node>\n  </next>"
        ),
        "{xml}"
    );
    let json = r.to_json().unwrap();
    assert!(
        json.contains("\"next\": {\n    \"__type\": \"Node\",\n    \"n\": 1,\n    \"next\": null,"),
        "{json}"
    );
    // A tight depth limit cuts the walk early.
    let shallow = starpak::dataforge::to_xml(
        &r,
        &ExportOptions {
            max_depth: 0,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!shallow.contains("<next>"), "{shallow}");
}

#[test]
fn malformed_inputs_are_errors() {
    let (b, _) = everything(8, false);
    let good = b.build();
    assert!(DataForge::parse(good.clone()).is_ok());

    // Every truncation fails cleanly.
    for n in (0..good.len()).step_by(7).chain([good.len() - 1]) {
        let r = DataForge::from_slice(&good[..n]);
        assert!(matches!(r, Err(Error::DataForge(_))), "prefix {n} parsed");
    }
    // Trailing garbage breaks the instance-data accounting.
    let mut extra = good.clone();
    extra.extend_from_slice(&[0u8; 3]);
    assert!(DataForge::parse(extra).is_err());

    // Unsupported version.
    let mut v = good.clone();
    v[4..8].copy_from_slice(&7u32.to_le_bytes());
    let e = DataForge::parse(v).unwrap_err().to_string();
    assert!(e.contains("version 7"), "{e}");

    // Struct size that disagrees with the property layout.
    let mut s = good.clone();
    s[120 + 12..120 + 16].copy_from_slice(&999u32.to_le_bytes());
    let e = DataForge::parse(s).unwrap_err().to_string();
    assert!(e.contains("declared size"), "{e}");

    // Unknown property type / conversion.
    let props_off = 120 + 16 * 6;
    let mut p = good.clone();
    p[props_off + 6..props_off + 8].copy_from_slice(&0x77u16.to_le_bytes());
    assert!(DataForge::parse(p)
        .unwrap_err()
        .to_string()
        .contains("unknown data type"));
    let mut p = good.clone();
    p[props_off + 8..props_off + 10].copy_from_slice(&9u16.to_le_bytes());
    assert!(DataForge::parse(p)
        .unwrap_err()
        .to_string()
        .contains("unknown conversion"));

    // Parent index out of range / inheritance cycle.
    let mut s = good.clone();
    s[120 + 4..120 + 8].copy_from_slice(&77i32.to_le_bytes());
    assert!(DataForge::parse(s)
        .unwrap_err()
        .to_string()
        .contains("parent index"));
    let mut s = good.clone();
    s[120 + 4..120 + 8].copy_from_slice(&0i32.to_le_bytes());
    assert!(DataForge::parse(s)
        .unwrap_err()
        .to_string()
        .contains("cycle"));

    // Random mutations never panic.
    let mut rng = Rng::new(5);
    let mut parsed = 0;
    for _ in 0..3000 {
        let mut m = good.clone();
        for _ in 0..1 + rng.below(3) {
            let i = rng.below(m.len());
            m[i] = rng.next_u64() as u8;
        }
        if let Ok(df) = DataForge::parse(m) {
            parsed += 1;
            for r in df.records() {
                let _ = r.to_xml();
                let _ = r.to_json();
                let _ = r.is_main();
            }
            let _ = df.records_of_type("Everything").count();
        }
    }
    assert!(parsed > 0);
}

#[test]
fn guid_helpers() {
    let g: Guid = "01efcdab-1234-5678-f0de-bc9a89674523".parse().unwrap();
    assert_eq!(g.to_string(), "01efcdab-1234-5678-f0de-bc9a89674523");
    assert_eq!(g.as_bytes()[0], 0x78);
    assert_eq!(Guid::default(), Guid::NIL);
}

#[test]
fn through_the_archive() {
    let (b, g) = everything(8, false);
    let dcb = b.build();
    let p4k = P4kBuilder::new(Flavor::Cig)
        .add("Data\\Game2.dcb", dcb.clone(), ZSTD)
        .add("Data\\Other.dcb", dcb, ZSTD)
        .build();
    let tmp = temp_archive(&p4k);
    let a = Archive::open(tmp.path()).unwrap();
    let df = DataForge::from_archive(&a).unwrap();
    check_everything(&df, g);
    let df2 = DataForge::from_archive_path(&a, "data/other.dcb").unwrap();
    assert_eq!(df2.record_count(), 5);
    assert!(matches!(
        DataForge::from_archive_path(&a, "data/missing.dcb"),
        Err(Error::NotFound(_))
    ));
    let tmpf = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmpf.path(), a.read_path("Data/Game2.dcb").unwrap()).unwrap();
    assert_eq!(DataForge::open(tmpf.path()).unwrap().record_count(), 5);
    assert!(DataForge::open("/nonexistent.dcb").is_err());
}

#[test]
fn shared_across_threads() {
    let (b, g) = everything(8, false);
    let df = std::sync::Arc::new(DataForge::parse(b.build()).unwrap());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let df = std::sync::Arc::clone(&df);
            std::thread::spawn(move || {
                for _ in 0..20 {
                    check_everything(&df, g);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
