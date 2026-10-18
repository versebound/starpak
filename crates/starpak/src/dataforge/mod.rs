//! DataForge (`Game2.dcb`) reader.
//!
//! The DataCore binary is a column store: a header with element counts,
//! definition tables (structs, properties, enums), data mappings (how many
//! instances of each struct exist), the record table, typed value arrays,
//! two string tables and finally the instance data. Instances of a struct
//! are laid out back to back; a property is either inline (scalar, nested
//! class, pointer, reference) or an array header (`count`, `first index`)
//! into the typed value arrays. Everything is little-endian.
//!
//! Supported versions: 5, 6 (32-byte records) and 8 (36-byte records with a
//! tag). Loading parses the definition tables and the record table; record
//! instances are decoded lazily from the retained buffer.

mod export;
mod value;

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;

use crate::archive::Archive;
use crate::error::{Error, Result};
use crate::util::Le;

pub use export::{to_json, to_xml, ExportOptions};
pub use value::{ArrayRef, Field, Instance, Value};

/// Default location of the database inside the archive.
pub const DEFAULT_PATH: &str = "Data/Game2.dcb";

const HEADER_LEN: usize = 120;
const STRUCT_LEN: usize = 16;
const PROP_LEN: usize = 12;
const ENUM_LEN: usize = 8;
const MAPPING_LEN: usize = 8;
const RECORD_LEN_V5: usize = 32;
const RECORD_LEN_V8: usize = 36;

/// 128-bit record identifier.
///
/// Formatted the way the game and community tools print it: the first eight
/// bytes as a little-endian `u64` (`8-4-4`), the last eight as another
/// (`4-12`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The all-zero GUID used for null references.
    pub const NIL: Guid = Guid([0; 16]);

    /// True for the all-zero GUID.
    pub fn is_nil(&self) -> bool {
        self.0 == [0; 16]
    }

    /// Raw bytes as stored in the file.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    fn from_slice(b: &[u8]) -> Guid {
        let mut g = [0u8; 16];
        g.copy_from_slice(&b[..16]);
        Guid(g)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = u64::from_le_bytes(self.0[..8].try_into().expect("8 bytes"));
        let c = u64::from_le_bytes(self.0[8..].try_into().expect("8 bytes"));
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            a >> 32,
            (a >> 16) & 0xFFFF,
            a & 0xFFFF,
            c >> 48,
            c & 0xFFFF_FFFF_FFFF
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

impl FromStr for Guid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Guid> {
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 || s.len() > 36 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::dataforge(format!("invalid GUID {s:?}")));
        }
        let a = u64::from_str_radix(&hex[..16], 16).map_err(Error::dataforge)?;
        let c = u64::from_str_radix(&hex[16..], 16).map_err(Error::dataforge)?;
        let mut g = [0u8; 16];
        g[..8].copy_from_slice(&a.to_le_bytes());
        g[8..].copy_from_slice(&c.to_le_bytes());
        Ok(Guid(g))
    }
}

/// Property value kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataType {
    /// Boolean.
    Bool,
    /// Signed 8-bit integer.
    I8,
    /// Signed 16-bit integer.
    I16,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// String from the value table.
    String,
    /// 32-bit float.
    F32,
    /// 64-bit float.
    F64,
    /// Localisation key.
    Locale,
    /// 128-bit GUID.
    Guid,
    /// Enum option name.
    Enum,
    /// Nested struct stored inline.
    Class,
    /// Owning pointer to an instance.
    StrongPointer,
    /// Non-owning pointer to an instance.
    WeakPointer,
    /// Reference to a record by GUID.
    Reference,
}

impl DataType {
    /// Maps the raw type code.
    pub fn from_raw(raw: u16) -> Option<DataType> {
        Some(match raw {
            0x01 => DataType::Bool,
            0x02 => DataType::I8,
            0x03 => DataType::I16,
            0x04 => DataType::I32,
            0x05 => DataType::I64,
            0x06 => DataType::U8,
            0x07 => DataType::U16,
            0x08 => DataType::U32,
            0x09 => DataType::U64,
            0x0A => DataType::String,
            0x0B => DataType::F32,
            0x0C => DataType::F64,
            0x0D => DataType::Locale,
            0x0E => DataType::Guid,
            0x0F => DataType::Enum,
            0x10 => DataType::Class,
            0x110 => DataType::StrongPointer,
            0x210 => DataType::WeakPointer,
            0x310 => DataType::Reference,
            _ => return None,
        })
    }

    /// Raw type code.
    pub fn raw(self) -> u16 {
        match self {
            DataType::Bool => 0x01,
            DataType::I8 => 0x02,
            DataType::I16 => 0x03,
            DataType::I32 => 0x04,
            DataType::I64 => 0x05,
            DataType::U8 => 0x06,
            DataType::U16 => 0x07,
            DataType::U32 => 0x08,
            DataType::U64 => 0x09,
            DataType::String => 0x0A,
            DataType::F32 => 0x0B,
            DataType::F64 => 0x0C,
            DataType::Locale => 0x0D,
            DataType::Guid => 0x0E,
            DataType::Enum => 0x0F,
            DataType::Class => 0x10,
            DataType::StrongPointer => 0x110,
            DataType::WeakPointer => 0x210,
            DataType::Reference => 0x310,
        }
    }

    /// Name used by community exporters for array elements.
    pub fn name(self) -> &'static str {
        match self {
            DataType::Bool => "Bool",
            DataType::I8 => "Int8",
            DataType::I16 => "Int16",
            DataType::I32 => "Int32",
            DataType::I64 => "Int64",
            DataType::U8 => "UInt8",
            DataType::U16 => "UInt16",
            DataType::U32 => "UInt32",
            DataType::U64 => "UInt64",
            DataType::String => "String",
            DataType::F32 => "Single",
            DataType::F64 => "Double",
            DataType::Locale => "LocID",
            DataType::Guid => "Guid",
            DataType::Enum => "Enum",
            DataType::Class => "Class",
            DataType::StrongPointer => "StrongPointer",
            DataType::WeakPointer => "WeakPointer",
            DataType::Reference => "Reference",
        }
    }

    /// Size of one element in the typed value arrays (and inline, except
    /// for `Class`, whose inline size is the struct size).
    pub fn element_size(self) -> usize {
        match self {
            DataType::Bool | DataType::I8 | DataType::U8 => 1,
            DataType::I16 | DataType::U16 => 2,
            DataType::I32
            | DataType::U32
            | DataType::F32
            | DataType::String
            | DataType::Locale
            | DataType::Enum => 4,
            DataType::I64 | DataType::U64 | DataType::F64 => 8,
            DataType::Guid => 16,
            DataType::StrongPointer | DataType::WeakPointer => 8,
            DataType::Reference => 20,
            DataType::Class => 0,
        }
    }

    /// True for pointer/reference/class kinds that lead to other instances.
    pub fn is_complex(self) -> bool {
        matches!(
            self,
            DataType::Class | DataType::StrongPointer | DataType::WeakPointer | DataType::Reference
        )
    }
}

/// How a property is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Conversion {
    /// Inline value.
    Attribute,
    /// Array of complex values (pointers/references).
    ComplexArray,
    /// Array of scalars.
    SimpleArray,
    /// Array of nested class instances.
    ClassArray,
}

impl Conversion {
    fn from_raw(raw: u16) -> Option<Conversion> {
        Some(match raw {
            0 => Conversion::Attribute,
            1 => Conversion::ComplexArray,
            2 => Conversion::SimpleArray,
            3 => Conversion::ClassArray,
            _ => return None,
        })
    }

    /// True for every array flavour.
    pub fn is_array(self) -> bool {
        !matches!(self, Conversion::Attribute)
    }
}

/// Pointer to an instance of a struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pointer {
    /// Struct index of the target.
    pub struct_index: u32,
    /// Instance index within that struct's instance array.
    pub instance_index: u32,
}

/// Reference to a record by GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reference {
    /// Target record.
    pub guid: Guid,
    /// Instance index stored alongside (informational).
    pub instance_index: i32,
}

#[derive(Clone, Copy)]
pub(crate) struct StructDefRaw {
    name: u32,
    pub(crate) parent: i32,
    pub(crate) attr_count: u16,
    pub(crate) first_attr: u16,
    pub(crate) size: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct PropDefRaw {
    name: u32,
    pub(crate) struct_index: u16,
    pub(crate) data_type: DataType,
    pub(crate) conversion: Conversion,
}

#[derive(Clone, Copy)]
pub(crate) struct EnumDefRaw {
    name: u32,
    count: u16,
    first: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct RecordRaw {
    name: u32,
    file: u32,
    tag: u32,
    struct_index: u32,
    guid: Guid,
    instance_index: u16,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Table {
    pub(crate) offset: usize,
    pub(crate) count: usize,
}

#[derive(Default)]
pub(crate) struct Tables {
    i8: Table,
    pub(crate) i16: Table,
    pub(crate) i32: Table,
    pub(crate) i64: Table,
    pub(crate) u8: Table,
    pub(crate) u16: Table,
    pub(crate) u32: Table,
    pub(crate) u64: Table,
    pub(crate) bool: Table,
    pub(crate) f32: Table,
    pub(crate) f64: Table,
    pub(crate) guid: Table,
    pub(crate) string: Table,
    pub(crate) locale: Table,
    pub(crate) enum_: Table,
    pub(crate) strong: Table,
    pub(crate) weak: Table,
    pub(crate) reference: Table,
    pub(crate) enum_option: Table,
}

/// Index of a record in the record table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct RecordId(pub u32);

/// Index of a struct definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct StructId(pub u32);

/// A loaded DataForge database. `Send + Sync`; share it behind an `Arc`.
pub struct DataForge {
    data: Box<[u8]>,
    version: u32,
    structs: Vec<StructDefRaw>,
    props: Vec<PropDefRaw>,
    enums: Vec<EnumDefRaw>,
    records: Vec<RecordRaw>,
    tables: Tables,
    text1: (usize, usize),
    text2: (usize, usize),
    /// Absolute offset of each struct's instance block; `None` when the
    /// struct has no data mapping.
    struct_offsets: Vec<Option<usize>>,
    struct_counts: Vec<u32>,
    /// Flattened property list (parent properties first) for every struct,
    /// as `(property index, byte offset within the instance)`.
    flat_props: Vec<(u32, u32)>,
    flat_ranges: Vec<(u32, u32)>,
    by_guid: OnceLock<HashMap<Guid, u32>>,
    by_file: OnceLock<HashMap<Box<str>, FileRecords>>,
    struct_by_name: OnceLock<HashMap<Box<str>, u32>>,
}

struct FileRecords {
    main: u32,
    all: Vec<u32>,
}

impl fmt::Debug for DataForge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataForge")
            .field("version", &self.version)
            .field("structs", &self.structs.len())
            .field("properties", &self.props.len())
            .field("enums", &self.enums.len())
            .field("records", &self.records.len())
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// Container-level statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataForgeInfo {
    /// File format version.
    pub version: u32,
    /// Total size in bytes.
    pub size: usize,
    /// Struct definitions.
    pub structs: usize,
    /// Property definitions.
    pub properties: usize,
    /// Enum definitions.
    pub enums: usize,
    /// Records.
    pub records: usize,
    /// Bytes of instance data.
    pub instance_bytes: usize,
    /// Size of the value string table.
    pub string_table_bytes: usize,
    /// Size of the name string table.
    pub name_table_bytes: usize,
    /// Entries in the strong pointer table.
    pub strong_pointers: usize,
    /// Entries in the weak pointer table.
    pub weak_pointers: usize,
    /// Entries in the reference table.
    pub references: usize,
}

impl DataForge {
    /// Parses a `.dcb` held in memory, taking ownership of the buffer.
    pub fn parse(data: Vec<u8>) -> Result<DataForge> {
        Self::parse_boxed(data.into_boxed_slice())
    }

    /// Parses a `.dcb` from a slice (the bytes are copied).
    pub fn from_slice(data: &[u8]) -> Result<DataForge> {
        Self::parse_boxed(data.into())
    }

    /// Loads a `.dcb` file from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<DataForge> {
        Self::parse(std::fs::read(path)?)
    }

    /// Reads `Data/Game2.dcb` out of an archive.
    pub fn from_archive(archive: &Archive) -> Result<DataForge> {
        Self::from_archive_path(archive, DEFAULT_PATH)
    }

    /// Reads a database entry out of an archive.
    pub fn from_archive_path(archive: &Archive, path: &str) -> Result<DataForge> {
        Self::parse(archive.read_path(path)?)
    }

    fn parse_boxed(data: Box<[u8]>) -> Result<DataForge> {
        let bad = |msg: String| Error::DataForge(msg);
        if data.len() < HEADER_LEN {
            return Err(bad("file shorter than the header".into()));
        }
        let mut r = Le::new(&data);
        let _magic = r.u32().unwrap_or(0);
        let version = r.u32().unwrap_or(0);
        r.skip(8);
        if !matches!(version, 5 | 6 | 8) {
            return Err(bad(format!("unsupported DataForge version {version}")));
        }
        let mut counts = [0usize; 24];
        for c in counts.iter_mut() {
            *c = r.u32().unwrap_or(0) as usize;
        }
        let text1_len = r.u32().unwrap_or(0) as usize;
        let text2_len = r.u32().unwrap_or(0) as usize;
        let [n_structs, n_props, n_enums, n_mappings, n_records, n_bool, n_i8, n_i16, n_i32, n_i64, n_u8, n_u16, n_u32, n_u64, n_f32, n_f64, n_guid, n_string, n_locale, n_enum, n_strong, n_weak, n_ref, n_enum_opt] =
            counts;

        let mut pos = HEADER_LEN;
        let mut take = |count: usize, width: usize, what: &str| -> Result<usize> {
            let len = count
                .checked_mul(width)
                .ok_or_else(|| bad(format!("{what} table size overflows")))?;
            let start = pos;
            pos = start
                .checked_add(len)
                .filter(|&e| e <= data.len())
                .ok_or_else(|| bad(format!("{what} table extends past end of file")))?;
            Ok(start)
        };
        let structs_off = take(n_structs, STRUCT_LEN, "struct")?;
        let props_off = take(n_props, PROP_LEN, "property")?;
        let enums_off = take(n_enums, ENUM_LEN, "enum")?;
        let mappings_off = take(n_mappings, MAPPING_LEN, "data mapping")?;
        let record_len = if version >= 8 {
            RECORD_LEN_V8
        } else {
            RECORD_LEN_V5
        };
        let records_off = take(n_records, record_len, "record")?;
        let mut tables = Tables::default();
        let mut tbl = |count: usize, width: usize, what: &str| -> Result<Table> {
            Ok(Table {
                offset: take(count, width, what)?,
                count,
            })
        };
        tables.i8 = tbl(n_i8, 1, "int8")?;
        tables.i16 = tbl(n_i16, 2, "int16")?;
        tables.i32 = tbl(n_i32, 4, "int32")?;
        tables.i64 = tbl(n_i64, 8, "int64")?;
        tables.u8 = tbl(n_u8, 1, "uint8")?;
        tables.u16 = tbl(n_u16, 2, "uint16")?;
        tables.u32 = tbl(n_u32, 4, "uint32")?;
        tables.u64 = tbl(n_u64, 8, "uint64")?;
        tables.bool = tbl(n_bool, 1, "bool")?;
        tables.f32 = tbl(n_f32, 4, "single")?;
        tables.f64 = tbl(n_f64, 8, "double")?;
        tables.guid = tbl(n_guid, 16, "guid")?;
        tables.string = tbl(n_string, 4, "string")?;
        tables.locale = tbl(n_locale, 4, "locale")?;
        tables.enum_ = tbl(n_enum, 4, "enum value")?;
        tables.strong = tbl(n_strong, 8, "strong pointer")?;
        tables.weak = tbl(n_weak, 8, "weak pointer")?;
        tables.reference = tbl(n_ref, 20, "reference")?;
        tables.enum_option = tbl(n_enum_opt, 4, "enum option")?;
        let text1_off = take(text1_len, 1, "string")?;
        let text2_off = take(text2_len, 1, "name")?;
        let data_off = take(0, 1, "instance")?;
        // Versions before 6 keep every string in the first table.
        let text2 = if version >= 6 {
            (text2_off, text2_len)
        } else {
            (text1_off, text1_len)
        };
        let text1 = (text1_off, text1_len);

        // --- definition tables ---
        let mut structs = Vec::with_capacity(n_structs);
        for i in 0..n_structs {
            let mut c = Le::at(&data, structs_off + i * STRUCT_LEN);
            structs.push(StructDefRaw {
                name: c.u32().unwrap_or(0),
                parent: c.i32().unwrap_or(-1),
                attr_count: c.u16().unwrap_or(0),
                first_attr: c.u16().unwrap_or(0),
                size: c.u32().unwrap_or(0),
            });
        }
        let mut props = Vec::with_capacity(n_props);
        for i in 0..n_props {
            let mut c = Le::at(&data, props_off + i * PROP_LEN);
            let name = c.u32().unwrap_or(0);
            let struct_index = c.u16().unwrap_or(0);
            let dt = c.u16().unwrap_or(0);
            let cv = c.u16().unwrap_or(0);
            let data_type = DataType::from_raw(dt)
                .ok_or_else(|| bad(format!("property {i}: unknown data type 0x{dt:x}")))?;
            let conversion = Conversion::from_raw(cv)
                .ok_or_else(|| bad(format!("property {i}: unknown conversion type {cv}")))?;
            props.push(PropDefRaw {
                name,
                struct_index,
                data_type,
                conversion,
            });
        }
        let mut enums = Vec::with_capacity(n_enums);
        for i in 0..n_enums {
            let mut c = Le::at(&data, enums_off + i * ENUM_LEN);
            let e = EnumDefRaw {
                name: c.u32().unwrap_or(0),
                count: c.u16().unwrap_or(0),
                first: c.u16().unwrap_or(0),
            };
            if e.first as usize + e.count as usize > n_enum_opt {
                return Err(bad(format!("enum {i}: options out of range")));
            }
            enums.push(e);
        }

        // --- validate definitions ---
        for (i, s) in structs.iter().enumerate() {
            if s.parent >= 0 && s.parent as usize >= n_structs {
                return Err(bad(format!("struct {i}: parent index out of range")));
            }
            if s.first_attr as usize + s.attr_count as usize > n_props {
                return Err(bad(format!("struct {i}: property range out of bounds")));
            }
            // Parent chains must terminate.
            let mut hops = 0;
            let mut cur = s.parent;
            while cur >= 0 {
                hops += 1;
                if hops > n_structs {
                    return Err(bad(format!("struct {i}: inheritance cycle")));
                }
                cur = structs[cur as usize].parent;
            }
        }
        for (i, p) in props.iter().enumerate() {
            let si = p.struct_index as usize;
            match p.data_type {
                DataType::Enum if si >= n_enums => {
                    return Err(bad(format!("property {i}: enum index out of range")));
                }
                DataType::Class
                | DataType::StrongPointer
                | DataType::WeakPointer
                | DataType::Reference
                    if si >= n_structs =>
                {
                    return Err(bad(format!("property {i}: struct index out of range")));
                }
                _ => {}
            }
        }

        // --- flattened property layout per struct ---
        let mut flat_props = Vec::new();
        let mut flat_ranges = Vec::with_capacity(n_structs);
        let mut inline_sizes = vec![0u32; n_structs];
        for si in 0..n_structs {
            let start = flat_props.len();
            let mut chain = Vec::new();
            let mut cur = Some(si);
            while let Some(s) = cur {
                chain.push(s);
                let p = structs[s].parent;
                cur = (p >= 0).then_some(p as usize);
            }
            for &s in chain.iter().rev() {
                let d = structs[s];
                for pi in d.first_attr as u32..d.first_attr as u32 + d.attr_count as u32 {
                    flat_props.push((pi, 0));
                }
            }
            flat_ranges.push((start as u32, (flat_props.len() - start) as u32));
        }
        // Inline sizes need nested class sizes, so resolve them on demand.
        // A struct embedding itself never reaches its declared size (the
        // depth guard yields 0 for the cycle), which the check below rejects.
        fn inline_size(
            si: usize,
            props: &[PropDefRaw],
            flat_props: &[(u32, u32)],
            flat_ranges: &[(u32, u32)],
            memo: &mut [u32],
            depth: usize,
        ) -> u32 {
            if memo[si] != 0 || depth > 64 {
                return memo[si];
            }
            let (start, len) = flat_ranges[si];
            let mut total = 0u32;
            for &(pi, _) in &flat_props[start as usize..(start + len) as usize] {
                let p = props[pi as usize];
                total += if p.conversion.is_array() {
                    8
                } else if p.data_type == DataType::Class {
                    inline_size(
                        p.struct_index as usize,
                        props,
                        flat_props,
                        flat_ranges,
                        memo,
                        depth + 1,
                    )
                } else {
                    p.data_type.element_size() as u32
                };
            }
            memo[si] = total;
            total
        }
        for si in 0..n_structs {
            inline_size(si, &props, &flat_props, &flat_ranges, &mut inline_sizes, 0);
            if inline_sizes[si] != structs[si].size {
                return Err(bad(format!(
                    "struct {si}: declared size {} does not match property layout {}",
                    structs[si].size, inline_sizes[si]
                )));
            }
        }
        for &(start, len) in &flat_ranges {
            let mut off = 0u32;
            for slot in &mut flat_props[start as usize..(start + len) as usize] {
                slot.1 = off;
                let p = props[slot.0 as usize];
                off += if p.conversion.is_array() {
                    8
                } else if p.data_type == DataType::Class {
                    inline_sizes[p.struct_index as usize]
                } else {
                    p.data_type.element_size() as u32
                };
            }
        }

        // --- data mappings -> instance offsets ---
        let mut struct_offsets = vec![None; n_structs];
        let mut struct_counts = vec![0u32; n_structs];
        let mut running = data_off;
        for i in 0..n_mappings {
            let mut c = Le::at(&data, mappings_off + i * MAPPING_LEN);
            let count = c.u32().unwrap_or(0);
            let si = c.i32().unwrap_or(-1);
            if si < 0 || si as usize >= n_structs {
                return Err(bad(format!("data mapping {i}: struct index out of range")));
            }
            let si = si as usize;
            struct_offsets[si] = Some(running);
            struct_counts[si] = count;
            running = running
                .checked_add(count as usize * structs[si].size as usize)
                .filter(|&e| e <= data.len())
                .ok_or_else(|| {
                    bad(format!(
                        "data mapping {i}: instances extend past end of file"
                    ))
                })?;
        }
        if running != data.len() {
            return Err(bad(format!(
                "instance data is {} bytes but mappings describe {}",
                data.len() - data_off,
                running - data_off
            )));
        }

        // --- records ---
        let mut records = Vec::with_capacity(n_records);
        for i in 0..n_records {
            let mut c = Le::at(&data, records_off + i * record_len);
            let name = c.u32().unwrap_or(0);
            let file = c.u32().unwrap_or(0);
            let tag = if version >= 8 {
                c.u32().unwrap_or(u32::MAX)
            } else {
                u32::MAX
            };
            let struct_index = c.i32().unwrap_or(-1);
            let guid = Guid::from_slice(c.bytes(16).unwrap_or(&[0; 16]));
            let instance_index = c.u16().unwrap_or(0);
            let _struct_size = c.u16();
            if struct_index < 0 || struct_index as usize >= n_structs {
                return Err(bad(format!("record {i}: struct index out of range")));
            }
            if instance_index as u32 >= struct_counts[struct_index as usize] {
                return Err(bad(format!("record {i}: instance index out of range")));
            }
            records.push(RecordRaw {
                name,
                file,
                tag,
                struct_index: struct_index as u32,
                guid,
                instance_index,
            });
        }

        Ok(DataForge {
            data,
            version,
            structs,
            props,
            enums,
            records,
            tables,
            text1,
            text2,
            struct_offsets,
            struct_counts,
            flat_props,
            flat_ranges,
            by_guid: OnceLock::new(),
            by_file: OnceLock::new(),
            struct_by_name: OnceLock::new(),
        })
    }

    /// File format version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Container statistics.
    pub fn info(&self) -> DataForgeInfo {
        DataForgeInfo {
            version: self.version,
            size: self.data.len(),
            structs: self.structs.len(),
            properties: self.props.len(),
            enums: self.enums.len(),
            records: self.records.len(),
            instance_bytes: self.data.len()
                - (self.text2.0 + self.text2.1).max(self.text1.0 + self.text1.1),
            string_table_bytes: self.text1.1,
            name_table_bytes: if self.version >= 6 { self.text2.1 } else { 0 },
            strong_pointers: self.tables.strong.count,
            weak_pointers: self.tables.weak.count,
            references: self.tables.reference.count,
        }
    }

    // ----- strings -----

    fn string_at(&self, table: (usize, usize), off: u32) -> &str {
        let off = off as usize;
        if off >= table.1 {
            return "";
        }
        let bytes = &self.data[table.0 + off..table.0 + table.1];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).unwrap_or("")
    }

    /// String from the value table (file names, string/locale/enum values).
    pub(crate) fn text(&self, off: u32) -> &str {
        self.string_at(self.text1, off)
    }

    /// String from the name table (struct/property/enum/record names).
    pub(crate) fn name(&self, off: u32) -> &str {
        self.string_at(self.text2, off)
    }

    // ----- structs / enums -----

    /// Number of struct definitions.
    pub fn struct_count(&self) -> usize {
        self.structs.len()
    }

    /// Struct definition by index.
    pub fn struct_def(&self, id: StructId) -> Option<StructDef<'_>> {
        ((id.0 as usize) < self.structs.len()).then_some(StructDef {
            df: self,
            index: id.0,
        })
    }

    /// All struct definitions.
    pub fn structs(&self) -> impl Iterator<Item = StructDef<'_>> + '_ {
        (0..self.structs.len() as u32).map(move |index| StructDef { df: self, index })
    }

    /// Finds a struct by exact name.
    pub fn find_struct(&self, name: &str) -> Option<StructDef<'_>> {
        let map = self.struct_by_name.get_or_init(|| {
            let mut m = HashMap::with_capacity(self.structs.len());
            for (i, s) in self.structs.iter().enumerate() {
                m.entry(self.name(s.name).into()).or_insert(i as u32);
            }
            m
        });
        map.get(name).map(|&index| StructDef { df: self, index })
    }

    /// Number of enum definitions.
    pub fn enum_count(&self) -> usize {
        self.enums.len()
    }

    /// Enum definition by index.
    pub fn enum_def(&self, index: usize) -> Option<EnumDef<'_>> {
        (index < self.enums.len()).then_some(EnumDef {
            df: self,
            index: index as u32,
        })
    }

    /// All enum definitions.
    pub fn enums(&self) -> impl Iterator<Item = EnumDef<'_>> + '_ {
        (0..self.enums.len() as u32).map(move |index| EnumDef { df: self, index })
    }

    // ----- records -----

    /// Number of records.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Record by table index.
    pub fn record(&self, id: RecordId) -> Option<Record<'_>> {
        ((id.0 as usize) < self.records.len()).then_some(Record {
            df: self,
            index: id.0,
        })
    }

    /// All records in table order.
    pub fn records(&self) -> impl Iterator<Item = Record<'_>> + '_ {
        (0..self.records.len() as u32).map(move |index| Record { df: self, index })
    }

    fn guid_map(&self) -> &HashMap<Guid, u32> {
        self.by_guid.get_or_init(|| {
            let mut m = HashMap::with_capacity(self.records.len());
            for (i, r) in self.records.iter().enumerate() {
                m.entry(r.guid).or_insert(i as u32);
            }
            m
        })
    }

    /// Record by GUID.
    pub fn record_by_guid(&self, guid: Guid) -> Option<Record<'_>> {
        self.guid_map()
            .get(&guid)
            .map(|&index| Record { df: self, index })
    }

    fn file_map(&self) -> &HashMap<Box<str>, FileRecords> {
        self.by_file.get_or_init(|| {
            let mut m: HashMap<Box<str>, FileRecords> = HashMap::new();
            for (i, r) in self.records.iter().enumerate() {
                let key = normalize_file(self.text(r.file));
                m.entry(key.into_boxed_str())
                    .or_insert_with(|| FileRecords {
                        main: i as u32,
                        all: Vec::new(),
                    })
                    .all
                    .push(i as u32);
            }
            // The main record of a file is the one named after the file
            // stem; failing that, the first record stored under that file.
            for (file, fr) in m.iter_mut() {
                if fr.all.len() < 2 {
                    continue;
                }
                let stem = file
                    .rsplit('/')
                    .next()
                    .unwrap_or(file)
                    .rsplit_once('.')
                    .map(|(s, _)| s)
                    .unwrap_or(file);
                let hit = fr.all.iter().copied().find(|&i| {
                    let n = self.name(self.records[i as usize].name);
                    let short = n.rsplit_once('.').map(|(_, s)| s).unwrap_or(n);
                    short.eq_ignore_ascii_case(stem) || n.eq_ignore_ascii_case(stem)
                });
                if let Some(i) = hit {
                    fr.main = i;
                }
            }
            m
        })
    }

    /// Main record stored under a file name (case-insensitive, `/` or `\`).
    pub fn record_by_path(&self, path: &str) -> Option<Record<'_>> {
        self.file_map()
            .get(normalize_file(path).as_str())
            .map(|fr| Record {
                df: self,
                index: fr.main,
            })
    }

    /// Every record stored under a file name, in table order.
    pub fn records_in_file(&self, path: &str) -> Vec<Record<'_>> {
        self.file_map()
            .get(normalize_file(path).as_str())
            .map(|fr| {
                fr.all
                    .iter()
                    .map(|&index| Record { df: self, index })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of distinct file names in the record table.
    pub fn file_count(&self) -> usize {
        self.file_map().len()
    }

    /// Records whose struct is `name` or inherits from it.
    pub fn records_of_type<'a>(&'a self, name: &str) -> impl Iterator<Item = Record<'a>> + 'a {
        let target = self.find_struct(name).map(|s| s.index);
        self.records()
            .filter(move |r| target.is_some_and(|t| self.struct_is_a(r.raw().struct_index, t)))
    }

    /// Records whose file name matches a glob (case-insensitive).
    pub fn records_matching<'a>(
        &'a self,
        glob: &str,
    ) -> Result<impl Iterator<Item = Record<'a>> + 'a> {
        let m = crate::archive::compile_glob(glob)?;
        Ok(self.records().filter(move |r| {
            let p = normalize_file(r.file_name());
            m.is_match(Path::new(&p))
        }))
    }

    /// True when struct `child` equals `ancestor` or inherits from it.
    pub(crate) fn struct_is_a(&self, child: u32, ancestor: u32) -> bool {
        let mut cur = child as i32;
        let mut hops = 0;
        while cur >= 0 {
            if cur as u32 == ancestor {
                return true;
            }
            cur = self.structs[cur as usize].parent;
            hops += 1;
            if hops > self.structs.len() {
                break;
            }
        }
        false
    }

    // ----- instances -----

    /// Instance `instance_index` of struct `struct_id`.
    pub fn instance(&self, struct_id: StructId, instance_index: u32) -> Result<Instance<'_>> {
        let si = struct_id.0 as usize;
        let def = self
            .structs
            .get(si)
            .ok_or_else(|| Error::dataforge(format!("struct index {si} out of range")))?;
        let base = self
            .struct_offsets
            .get(si)
            .copied()
            .flatten()
            .filter(|_| instance_index < self.struct_counts[si])
            .ok_or_else(|| {
                Error::dataforge(format!(
                    "instance {instance_index} of struct {} ({si}) does not exist",
                    self.name(def.name)
                ))
            })?;
        let start = base + instance_index as usize * def.size as usize;
        Ok(Instance {
            df: self,
            struct_index: struct_id.0,
            data: &self.data[start..start + def.size as usize],
        })
    }

    /// Resolves a pointer to its instance (`None` for null pointers).
    pub fn deref(&self, ptr: Option<Pointer>) -> Result<Option<Instance<'_>>> {
        match ptr {
            None => Ok(None),
            Some(p) => self
                .instance(StructId(p.struct_index), p.instance_index)
                .map(Some),
        }
    }

    pub(crate) fn raw_struct(&self, si: u32) -> &StructDefRaw {
        &self.structs[si as usize]
    }

    pub(crate) fn raw_prop(&self, pi: u32) -> &PropDefRaw {
        &self.props[pi as usize]
    }

    pub(crate) fn flat(&self, si: u32) -> &[(u32, u32)] {
        let (start, len) = self.flat_ranges[si as usize];
        &self.flat_props[start as usize..(start + len) as usize]
    }

    pub(crate) fn table_slice(&self, t: Table, index: usize, width: usize) -> Result<&[u8]> {
        if index >= t.count {
            return Err(Error::dataforge(format!(
                "value index {index} out of range (table holds {})",
                t.count
            )));
        }
        let start = t.offset + index * width;
        Ok(&self.data[start..start + width])
    }

    pub(crate) fn tables(&self) -> &Tables {
        &self.tables
    }

    pub(crate) fn enum_option(&self, index: usize) -> Result<&str> {
        let b = self.table_slice(self.tables.enum_option, index, 4)?;
        Ok(self.name(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }
}

/// Lower-cases a file path and normalises separators for lookups.
fn normalize_file(path: &str) -> String {
    let p = crate::util::trim_lookup_path(path);
    p.chars()
        .map(|c| {
            if c == '\\' {
                '/'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// A struct (type) definition.
#[derive(Clone, Copy)]
pub struct StructDef<'a> {
    df: &'a DataForge,
    index: u32,
}

impl<'a> StructDef<'a> {
    /// Index of this struct.
    pub fn id(&self) -> StructId {
        StructId(self.index)
    }

    /// Type name.
    pub fn name(&self) -> &'a str {
        self.df.name(self.df.structs[self.index as usize].name)
    }

    /// Parent type, if any.
    pub fn parent(&self) -> Option<StructDef<'a>> {
        let p = self.df.structs[self.index as usize].parent;
        (p >= 0).then_some(StructDef {
            df: self.df,
            index: p as u32,
        })
    }

    /// Size of one instance in bytes.
    pub fn size(&self) -> u32 {
        self.df.structs[self.index as usize].size
    }

    /// Number of stored instances.
    pub fn instance_count(&self) -> u32 {
        self.df.struct_counts[self.index as usize]
    }

    /// All properties including inherited ones (parents first).
    pub fn properties(&self) -> impl Iterator<Item = PropDef<'a>> + 'a {
        let df = self.df;
        df.flat(self.index).iter().map(move |&(pi, off)| PropDef {
            df,
            index: pi,
            offset: off,
        })
    }

    /// Number of properties including inherited ones.
    pub fn property_count(&self) -> usize {
        self.df.flat(self.index).len()
    }

    /// True when this struct is `other` or inherits from it.
    pub fn is_a(&self, other: StructId) -> bool {
        self.df.struct_is_a(self.index, other.0)
    }

    /// Instance by index.
    pub fn instance(&self, index: u32) -> Result<Instance<'a>> {
        self.df.instance(StructId(self.index), index)
    }
}

impl fmt::Debug for StructDef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructDef")
            .field("name", &self.name())
            .field("parent", &self.parent().map(|p| p.name()))
            .field("size", &self.size())
            .field("properties", &self.property_count())
            .finish()
    }
}

/// A property definition.
#[derive(Clone, Copy)]
pub struct PropDef<'a> {
    df: &'a DataForge,
    pub(crate) index: u32,
    offset: u32,
}

impl<'a> PropDef<'a> {
    /// Property name.
    pub fn name(&self) -> &'a str {
        self.df.name(self.df.props[self.index as usize].name)
    }

    /// Value kind.
    pub fn data_type(&self) -> DataType {
        self.df.props[self.index as usize].data_type
    }

    /// Storage flavour.
    pub fn conversion(&self) -> Conversion {
        self.df.props[self.index as usize].conversion
    }

    /// True for array properties.
    pub fn is_array(&self) -> bool {
        self.conversion().is_array()
    }

    /// Byte offset within an instance of the owning struct.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Struct named by class/pointer/reference properties.
    pub fn target_struct(&self) -> Option<StructDef<'a>> {
        let p = self.df.props[self.index as usize];
        p.data_type.is_complex().then_some(StructDef {
            df: self.df,
            index: p.struct_index as u32,
        })
    }

    /// Enum named by enum properties.
    pub fn target_enum(&self) -> Option<EnumDef<'a>> {
        let p = self.df.props[self.index as usize];
        (p.data_type == DataType::Enum).then_some(EnumDef {
            df: self.df,
            index: p.struct_index as u32,
        })
    }

    /// Human-readable type, e.g. `Int32`, `Vec3`, `SItemPort[]`.
    pub fn type_name(&self) -> String {
        let base = match self.target_struct() {
            Some(s) => s.name().to_string(),
            None => match self.target_enum() {
                Some(e) => e.name().to_string(),
                None => self.data_type().name().to_string(),
            },
        };
        if self.is_array() {
            format!("{base}[]")
        } else {
            base
        }
    }
}

impl fmt::Debug for PropDef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name(), self.type_name())
    }
}

/// An enum definition.
#[derive(Clone, Copy)]
pub struct EnumDef<'a> {
    df: &'a DataForge,
    index: u32,
}

impl<'a> EnumDef<'a> {
    /// Enum name.
    pub fn name(&self) -> &'a str {
        self.df.name(self.df.enums[self.index as usize].name)
    }

    /// Enum options in declaration order.
    pub fn values(&self) -> impl Iterator<Item = &'a str> + 'a {
        let e = self.df.enums[self.index as usize];
        let df = self.df;
        (e.first as usize..e.first as usize + e.count as usize)
            .map(move |i| df.enum_option(i).unwrap_or(""))
    }

    /// Number of options.
    pub fn len(&self) -> usize {
        self.df.enums[self.index as usize].count as usize
    }

    /// True when the enum has no options.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for EnumDef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnumDef")
            .field("name", &self.name())
            .field("values", &self.values().collect::<Vec<_>>())
            .finish()
    }
}

/// A record: a named, GUID-identified root instance.
#[derive(Clone, Copy)]
pub struct Record<'a> {
    df: &'a DataForge,
    index: u32,
}

impl<'a> Record<'a> {
    fn raw(&self) -> &'a RecordRaw {
        &self.df.records[self.index as usize]
    }

    /// Table index.
    pub fn id(&self) -> RecordId {
        RecordId(self.index)
    }

    /// Record name (`Type.Name`).
    pub fn name(&self) -> &'a str {
        self.df.name(self.raw().name)
    }

    /// Source file name (`libs/foundry/records/...`).
    pub fn file_name(&self) -> &'a str {
        self.df.text(self.raw().file)
    }

    /// Category tag (version 8+), empty otherwise.
    pub fn tag(&self) -> &'a str {
        let t = self.raw().tag;
        if t == u32::MAX {
            ""
        } else {
            self.df.name(t)
        }
    }

    /// Record GUID.
    pub fn guid(&self) -> Guid {
        self.raw().guid
    }

    /// Struct of the root instance.
    pub fn struct_def(&self) -> StructDef<'a> {
        StructDef {
            df: self.df,
            index: self.raw().struct_index,
        }
    }

    /// Name of the root struct.
    pub fn type_name(&self) -> &'a str {
        self.struct_def().name()
    }

    /// Instance index of the root instance.
    pub fn instance_index(&self) -> u32 {
        self.raw().instance_index as u32
    }

    /// Root instance.
    pub fn instance(&self) -> Result<Instance<'a>> {
        self.df.instance(
            StructId(self.raw().struct_index),
            self.raw().instance_index as u32,
        )
    }

    /// True when this is the main record of its file.
    pub fn is_main(&self) -> bool {
        self.df
            .file_map()
            .get(normalize_file(self.file_name()).as_str())
            .is_some_and(|fr| fr.main == self.index)
    }

    /// Database this record belongs to.
    pub fn database(&self) -> &'a DataForge {
        self.df
    }

    /// Exports the record as unp4k-style XML.
    pub fn to_xml(&self) -> Result<String> {
        export::to_xml(self, &ExportOptions::default())
    }

    /// Exports the record as JSON.
    pub fn to_json(&self) -> Result<String> {
        export::to_json(self, &ExportOptions::default())
    }
}

impl fmt::Debug for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("name", &self.name())
            .field("guid", &self.guid())
            .field("file", &self.file_name())
            .field("type", &self.type_name())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_format_and_parse() {
        let g = Guid([
            0x78, 0x56, 0x34, 0x12, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC,
            0xDE, 0xF0,
        ]);
        let s = g.to_string();
        assert_eq!(s, "01efcdab-1234-5678-f0de-bc9a89674523");
        assert_eq!(s.parse::<Guid>().unwrap(), g);
        assert!(Guid::NIL.is_nil());
        assert_eq!(
            Guid::NIL.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
        assert!("nope".parse::<Guid>().is_err());
        assert!("01efcdab-1234-5678-f0de-bc9a8967452"
            .parse::<Guid>()
            .is_err());
        assert!("zzefcdab-1234-5678-f0de-bc9a89674523"
            .parse::<Guid>()
            .is_err());
        assert_eq!(format!("{g:?}"), format!("Guid({s})"));
    }

    #[test]
    fn data_type_codes() {
        for raw in [
            1u16, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x110, 0x210, 0x310,
        ] {
            let dt = DataType::from_raw(raw).unwrap();
            assert_eq!(dt.raw(), raw);
            assert!(!dt.name().is_empty());
        }
        assert!(DataType::from_raw(0x11).is_none());
        assert!(Conversion::from_raw(4).is_none());
        assert!(Conversion::from_raw(1).unwrap().is_array());
    }

    #[test]
    fn normalize_file_paths() {
        assert_eq!(normalize_file("Libs\\Foundry\\A.xml"), "libs/foundry/a.xml");
        assert_eq!(normalize_file("/libs/x"), "libs/x");
    }
}
