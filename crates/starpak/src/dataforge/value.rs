//! Lazy, typed access to record instances.

use std::fmt;

use super::{DataForge, DataType, Guid, Pointer, PropDef, Reference, StructDef, StructId};
use crate::error::{Error, Result};
use crate::util::Le;

/// One instance of a struct: a borrowed byte slice plus its layout.
#[derive(Clone, Copy)]
pub struct Instance<'a> {
    pub(crate) df: &'a DataForge,
    pub(crate) struct_index: u32,
    pub(crate) data: &'a [u8],
}

impl<'a> Instance<'a> {
    /// Struct of this instance.
    pub fn struct_def(&self) -> StructDef<'a> {
        self.df
            .struct_def(StructId(self.struct_index))
            .expect("instance struct index validated at load")
    }

    /// Struct id.
    pub fn struct_id(&self) -> StructId {
        StructId(self.struct_index)
    }

    /// Struct name.
    pub fn type_name(&self) -> &'a str {
        self.struct_def().name()
    }

    /// Raw instance bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Database this instance belongs to.
    pub fn database(&self) -> &'a DataForge {
        self.df
    }

    /// Fields in layout order (inherited properties first).
    pub fn fields(&self) -> impl Iterator<Item = Field<'a>> + 'a {
        let inst = *self;
        inst.struct_def()
            .properties()
            .map(move |prop| Field { inst, prop })
    }

    /// Number of fields.
    pub fn field_count(&self) -> usize {
        self.struct_def().property_count()
    }

    /// Field by name (exact match).
    pub fn field(&self, name: &str) -> Option<Field<'a>> {
        self.fields().find(|f| f.name() == name)
    }

    /// Decoded value of the field `name`.
    pub fn get(&self, name: &str) -> Result<Value<'a>> {
        self.field(name)
            .ok_or_else(|| {
                Error::dataforge(format!(
                    "struct {} has no property {name:?}",
                    self.type_name()
                ))
            })?
            .value()
    }

    fn decode(&self, prop: &PropDef<'a>) -> Result<Value<'a>> {
        let off = prop.offset() as usize;
        let raw = self.df.raw_prop(prop.index);
        let dt = raw.data_type;
        let mut c = Le::at(self.data, off);
        let short = || Error::dataforge("instance data shorter than its layout");
        if raw.conversion.is_array() {
            let count = c.i32().ok_or_else(short)?;
            let first = c.i32().ok_or_else(short)?;
            if count < 0 || first < 0 {
                return Err(Error::dataforge(format!(
                    "array {} has a negative range ({first}, {count})",
                    prop.name()
                )));
            }
            return Ok(Value::Array(ArrayRef {
                df: self.df,
                data_type: dt,
                struct_index: raw.struct_index,
                first: first as u32,
                count: count as u32,
            }));
        }
        Ok(match dt {
            DataType::Bool => Value::Bool(c.u8().ok_or_else(short)? != 0),
            DataType::I8 => Value::I8(c.u8().ok_or_else(short)? as i8),
            DataType::I16 => Value::I16(c.u16().ok_or_else(short)? as i16),
            DataType::I32 => Value::I32(c.i32().ok_or_else(short)?),
            DataType::I64 => Value::I64(c.u64().ok_or_else(short)? as i64),
            DataType::U8 => Value::U8(c.u8().ok_or_else(short)?),
            DataType::U16 => Value::U16(c.u16().ok_or_else(short)?),
            DataType::U32 => Value::U32(c.u32().ok_or_else(short)?),
            DataType::U64 => Value::U64(c.u64().ok_or_else(short)?),
            DataType::F32 => Value::F32(f32::from_bits(c.u32().ok_or_else(short)?)),
            DataType::F64 => Value::F64(f64::from_bits(c.u64().ok_or_else(short)?)),
            DataType::String => Value::String(self.df.text(c.u32().ok_or_else(short)?)),
            DataType::Locale => Value::Locale(self.df.text(c.u32().ok_or_else(short)?)),
            DataType::Enum => Value::Enum(self.df.text(c.u32().ok_or_else(short)?)),
            DataType::Guid => Value::Guid(Guid::from_slice(c.bytes(16).ok_or_else(short)?)),
            DataType::Class => {
                let size = self.df.raw_struct(raw.struct_index as u32).size as usize;
                let data = self.data.get(off..off + size).ok_or_else(short)?;
                Value::Class(Instance {
                    df: self.df,
                    struct_index: raw.struct_index as u32,
                    data,
                })
            }
            DataType::StrongPointer => {
                Value::StrongPointer(read_pointer(&mut c).ok_or_else(short)?)
            }
            DataType::WeakPointer => Value::WeakPointer(read_pointer(&mut c).ok_or_else(short)?),
            DataType::Reference => Value::Reference(read_reference(&mut c).ok_or_else(short)?),
        })
    }
}

impl fmt::Debug for Instance<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instance")
            .field("type", &self.type_name())
            .field("fields", &self.field_count())
            .finish()
    }
}

fn read_pointer(c: &mut Le<'_>) -> Option<Option<Pointer>> {
    let s = c.i32()?;
    let i = c.i32()?;
    Some(if s < 0 || i < 0 {
        None
    } else {
        Some(Pointer {
            struct_index: s as u32,
            instance_index: i as u32,
        })
    })
}

fn read_reference(c: &mut Le<'_>) -> Option<Option<Reference>> {
    let i = c.i32()?;
    let guid = Guid::from_slice(c.bytes(16)?);
    Some(if guid.is_nil() {
        None
    } else {
        Some(Reference {
            guid,
            instance_index: i,
        })
    })
}

/// A property of an instance.
#[derive(Clone, Copy)]
pub struct Field<'a> {
    inst: Instance<'a>,
    prop: PropDef<'a>,
}

impl<'a> Field<'a> {
    /// Property name.
    pub fn name(&self) -> &'a str {
        self.prop.name()
    }

    /// Property definition.
    pub fn prop(&self) -> PropDef<'a> {
        self.prop
    }

    /// Decoded value.
    pub fn value(&self) -> Result<Value<'a>> {
        self.inst.decode(&self.prop)
    }
}

impl fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {:?}", self.name(), self.value())
    }
}

/// A decoded property value.
#[derive(Clone, Copy)]
pub enum Value<'a> {
    /// Boolean.
    Bool(bool),
    /// Signed 8-bit integer.
    I8(i8),
    /// Signed 16-bit integer.
    I16(i16),
    /// Signed 32-bit integer.
    I32(i32),
    /// Signed 64-bit integer.
    I64(i64),
    /// Unsigned 8-bit integer.
    U8(u8),
    /// Unsigned 16-bit integer.
    U16(u16),
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// 32-bit float.
    F32(f32),
    /// 64-bit float.
    F64(f64),
    /// Plain string.
    String(&'a str),
    /// Localisation key (`@ui_...`).
    Locale(&'a str),
    /// Enum option name.
    Enum(&'a str),
    /// 128-bit GUID.
    Guid(Guid),
    /// Nested struct stored inline.
    Class(Instance<'a>),
    /// Owned instance elsewhere in the instance data; `None` when null.
    StrongPointer(Option<Pointer>),
    /// Non-owning pointer; `None` when null.
    WeakPointer(Option<Pointer>),
    /// Cross-record reference by GUID; `None` when null.
    Reference(Option<Reference>),
    /// Array property.
    Array(ArrayRef<'a>),
}

impl<'a> Value<'a> {
    /// Kind of this value.
    pub fn data_type(&self) -> DataType {
        match self {
            Value::Bool(_) => DataType::Bool,
            Value::I8(_) => DataType::I8,
            Value::I16(_) => DataType::I16,
            Value::I32(_) => DataType::I32,
            Value::I64(_) => DataType::I64,
            Value::U8(_) => DataType::U8,
            Value::U16(_) => DataType::U16,
            Value::U32(_) => DataType::U32,
            Value::U64(_) => DataType::U64,
            Value::F32(_) => DataType::F32,
            Value::F64(_) => DataType::F64,
            Value::String(_) => DataType::String,
            Value::Locale(_) => DataType::Locale,
            Value::Enum(_) => DataType::Enum,
            Value::Guid(_) => DataType::Guid,
            Value::Class(_) => DataType::Class,
            Value::StrongPointer(_) => DataType::StrongPointer,
            Value::WeakPointer(_) => DataType::WeakPointer,
            Value::Reference(_) => DataType::Reference,
            Value::Array(a) => a.data_type,
        }
    }

    /// True for scalar values (everything but class, pointers, arrays).
    pub fn is_scalar(&self) -> bool {
        !matches!(
            self,
            Value::Class(_)
                | Value::StrongPointer(_)
                | Value::WeakPointer(_)
                | Value::Reference(_)
                | Value::Array(_)
        )
    }

    /// String content of string-like values.
    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            Value::String(s) | Value::Locale(s) | Value::Enum(s) => Some(s),
            _ => None,
        }
    }

    /// Numeric content widened to `f64`.
    pub fn as_f64(&self) -> Option<f64> {
        Some(match *self {
            Value::I8(v) => v as f64,
            Value::I16(v) => v as f64,
            Value::I32(v) => v as f64,
            Value::I64(v) => v as f64,
            Value::U8(v) => v as f64,
            Value::U16(v) => v as f64,
            Value::U32(v) => v as f64,
            Value::U64(v) => v as f64,
            Value::F32(v) => v as f64,
            Value::F64(v) => v,
            _ => return None,
        })
    }

    /// Integer content widened to `i64` (unsigned 64-bit values that do not fit yield `None`).
    pub fn as_i64(&self) -> Option<i64> {
        Some(match *self {
            Value::I8(v) => v as i64,
            Value::I16(v) => v as i64,
            Value::I32(v) => v as i64,
            Value::I64(v) => v,
            Value::U8(v) => v as i64,
            Value::U16(v) => v as i64,
            Value::U32(v) => v as i64,
            Value::U64(v) => i64::try_from(v).ok()?,
            _ => return None,
        })
    }

    /// Boolean content.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Nested class instance.
    pub fn as_class(&self) -> Option<Instance<'a>> {
        match self {
            Value::Class(i) => Some(*i),
            _ => None,
        }
    }

    /// Array content.
    pub fn as_array(&self) -> Option<ArrayRef<'a>> {
        match self {
            Value::Array(a) => Some(*a),
            _ => None,
        }
    }

    /// GUID content (plain GUIDs and references).
    pub fn as_guid(&self) -> Option<Guid> {
        match self {
            Value::Guid(g) => Some(*g),
            Value::Reference(Some(r)) => Some(r.guid),
            _ => None,
        }
    }

    /// Scalar formatted the way the exporters print it (booleans as `1`/`0`).
    pub fn to_text(&self) -> Option<String> {
        Some(match *self {
            Value::Bool(b) => (b as u8).to_string(),
            Value::I8(v) => v.to_string(),
            Value::I16(v) => v.to_string(),
            Value::I32(v) => v.to_string(),
            Value::I64(v) => v.to_string(),
            Value::U8(v) => v.to_string(),
            Value::U16(v) => v.to_string(),
            Value::U32(v) => v.to_string(),
            Value::U64(v) => v.to_string(),
            Value::F32(v) => v.to_string(),
            Value::F64(v) => v.to_string(),
            Value::String(s) | Value::Locale(s) | Value::Enum(s) => s.to_string(),
            Value::Guid(g) => g.to_string(),
            Value::Reference(Some(r)) => r.guid.to_string(),
            Value::Reference(None) => Guid::NIL.to_string(),
            _ => return None,
        })
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Class(i) => write!(f, "Class({})", i.type_name()),
            Value::StrongPointer(p) => write!(f, "StrongPointer({p:?})"),
            Value::WeakPointer(p) => write!(f, "WeakPointer({p:?})"),
            Value::Reference(r) => write!(f, "Reference({r:?})"),
            Value::Array(a) => write!(f, "Array({}; {})", a.data_type.name(), a.count),
            other => match other.to_text() {
                Some(t) => write!(f, "{}({t})", other.data_type().name()),
                None => f.write_str("?"),
            },
        }
    }
}

/// A view of an array property's elements.
#[derive(Clone, Copy)]
pub struct ArrayRef<'a> {
    df: &'a DataForge,
    data_type: DataType,
    struct_index: u16,
    first: u32,
    count: u32,
}

impl<'a> ArrayRef<'a> {
    /// Number of elements.
    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// True when the array has no elements.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Element kind.
    pub fn data_type(&self) -> DataType {
        self.data_type
    }

    /// Struct named by the property (element type for class arrays, base
    /// type for pointer arrays).
    pub fn element_struct(&self) -> Option<StructDef<'a>> {
        self.data_type
            .is_complex()
            .then(|| self.df.struct_def(StructId(self.struct_index as u32)))
            .flatten()
    }

    /// Index into the typed value table of the first element.
    pub fn first_index(&self) -> u32 {
        self.first
    }

    /// Element `i`.
    pub fn get(&self, i: usize) -> Result<Value<'a>> {
        if i >= self.count as usize {
            return Err(Error::dataforge(format!(
                "array index {i} out of range (len {})",
                self.count
            )));
        }
        let idx = self.first as usize + i;
        let df = self.df;
        let t = df.tables();
        let dt = self.data_type;
        Ok(match dt {
            DataType::Bool => Value::Bool(df.table_slice(t.bool, idx, 1)?[0] != 0),
            DataType::I8 => Value::I8(df.table_slice(t.i8, idx, 1)?[0] as i8),
            DataType::U8 => Value::U8(df.table_slice(t.u8, idx, 1)?[0]),
            DataType::I16 => Value::I16(le16(df.table_slice(t.i16, idx, 2)?) as i16),
            DataType::U16 => Value::U16(le16(df.table_slice(t.u16, idx, 2)?)),
            DataType::I32 => Value::I32(le32(df.table_slice(t.i32, idx, 4)?) as i32),
            DataType::U32 => Value::U32(le32(df.table_slice(t.u32, idx, 4)?)),
            DataType::I64 => Value::I64(le64(df.table_slice(t.i64, idx, 8)?) as i64),
            DataType::U64 => Value::U64(le64(df.table_slice(t.u64, idx, 8)?)),
            DataType::F32 => Value::F32(f32::from_bits(le32(df.table_slice(t.f32, idx, 4)?))),
            DataType::F64 => Value::F64(f64::from_bits(le64(df.table_slice(t.f64, idx, 8)?))),
            DataType::Guid => Value::Guid(Guid::from_slice(df.table_slice(t.guid, idx, 16)?)),
            DataType::String => Value::String(df.text(le32(df.table_slice(t.string, idx, 4)?))),
            DataType::Locale => Value::Locale(df.text(le32(df.table_slice(t.locale, idx, 4)?))),
            DataType::Enum => Value::Enum(df.text(le32(df.table_slice(t.enum_, idx, 4)?))),
            DataType::StrongPointer => {
                let b = df.table_slice(t.strong, idx, 8)?;
                Value::StrongPointer(read_pointer(&mut Le::new(b)).expect("8 bytes"))
            }
            DataType::WeakPointer => {
                let b = df.table_slice(t.weak, idx, 8)?;
                Value::WeakPointer(read_pointer(&mut Le::new(b)).expect("8 bytes"))
            }
            DataType::Reference => {
                let b = df.table_slice(t.reference, idx, 20)?;
                Value::Reference(read_reference(&mut Le::new(b)).expect("20 bytes"))
            }
            DataType::Class => {
                Value::Class(df.instance(StructId(self.struct_index as u32), idx as u32)?)
            }
        })
    }

    /// Iterates over the elements.
    pub fn iter(&self) -> impl Iterator<Item = Result<Value<'a>>> + 'a {
        let a = *self;
        (0..a.count as usize).map(move |i| a.get(i))
    }
}

impl fmt::Debug for ArrayRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArrayRef({}[{}])", self.data_type.name(), self.count)
    }
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
