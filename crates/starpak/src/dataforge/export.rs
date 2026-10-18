//! Record export as unp4k-style XML and as JSON.
//!
//! XML follows the community `unforge`/`unp4k` conventions so dumps diff
//! cleanly against those tools: scalar properties become attributes, arrays
//! become containers of type-named elements (`<Int32 value="5"/>`), nested
//! classes and strong pointers are inlined with `__type` (plus
//! `__polymorphicType` when a pointer's target is a subtype of the declared
//! one), weak pointers are written as `<name value="Struct[XXXX]"/>`,
//! references as GUID attributes and the root element carries `__type`,
//! `__ref` and `__path`. There is no XML declaration.
//!
//! JSON mirrors the same tree with `__name`/`__type`/`__ref`/`__path`/`__tag`
//! keys on the root, `__type` on nested objects, native booleans/numbers,
//! `null` for null pointers and references and `{"__weak": "Struct",
//! "__instance": n}` for weak pointers.

use std::fmt::Write as _;

use super::{DataForge, Guid, Instance, Pointer, Record, StructId, Value};
use crate::cryxml::escape_into;
use crate::error::{Error, Result};

/// Export tuning.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Maximum nesting of pointer-resolved instances before the walk stops.
    pub max_depth: usize,
    /// Pretty-print JSON with two-space indentation.
    pub pretty: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions {
            max_depth: 100,
            pretty: true,
        }
    }
}

/// Serialises a record as unp4k-style XML.
pub fn to_xml(record: &Record<'_>, opts: &ExportOptions) -> Result<String> {
    let mut out = String::with_capacity(4096);
    let mut ctx = Ctx {
        df: record.database(),
        opts,
        stack: Vec::new(),
    };
    let root = record.instance()?;
    ctx.stack
        .push((record.struct_def().id().0, record.instance_index()));
    let name = element_name(record.name());
    let extra = [
        ("__type", record.type_name().to_string()),
        ("__ref", record.guid().to_string()),
        ("__path", record.file_name().to_string()),
    ];
    ctx.xml_element(&mut out, 0, &name, &root, &extra)?;
    Ok(out)
}

/// Serialises a record as JSON.
pub fn to_json(record: &Record<'_>, opts: &ExportOptions) -> Result<String> {
    let mut out = String::with_capacity(4096);
    let mut ctx = Ctx {
        df: record.database(),
        opts,
        stack: Vec::new(),
    };
    let root = record.instance()?;
    ctx.stack
        .push((record.struct_def().id().0, record.instance_index()));
    let mut head = vec![
        ("__name", record.name().to_string()),
        ("__type", record.type_name().to_string()),
        ("__ref", record.guid().to_string()),
        ("__path", record.file_name().to_string()),
    ];
    if !record.tag().is_empty() {
        head.push(("__tag", record.tag().to_string()));
    }
    ctx.json_object(&mut out, 0, &root, &head)?;
    if opts.pretty {
        out.push('\n');
    }
    Ok(out)
}

/// Root element name as unforge writes it: anything outside `[A-Za-z0-9.]`
/// becomes `_`.
pub fn element_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

struct Ctx<'a, 'o> {
    df: &'a DataForge,
    opts: &'o ExportOptions,
    stack: Vec<(u32, u32)>,
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn push_attr(out: &mut String, key: &str, value: &str) {
    out.push(' ');
    out.push_str(key);
    out.push_str("=\"");
    escape_into(value, true, out);
    out.push('"');
}

impl<'a> Ctx<'a, '_> {
    /// Resolves a pointer unless it would exceed the depth limit or close a
    /// cycle; a `Some` result must be paired with [`Ctx::leave`].
    fn enter(&mut self, p: Pointer) -> Result<Option<Instance<'a>>> {
        let key = (p.struct_index, p.instance_index);
        if self.stack.len() >= self.opts.max_depth || self.stack.contains(&key) {
            return Ok(None);
        }
        let inst = self
            .df
            .instance(StructId(p.struct_index), p.instance_index)?;
        self.stack.push(key);
        Ok(Some(inst))
    }

    fn leave(&mut self) {
        self.stack.pop();
    }

    fn struct_name(&self, index: u32) -> &'a str {
        self.df
            .struct_def(StructId(index))
            .map(|s| s.name())
            .unwrap_or("")
    }

    /// `__type` (and `__polymorphicType`) for an instance reached through a
    /// property declared as `declared`.
    fn type_attrs(
        &self,
        inst: &Instance<'_>,
        declared: Option<u32>,
    ) -> Vec<(&'static str, String)> {
        match declared {
            Some(d) if d != inst.struct_id().0 => vec![
                ("__type", self.struct_name(d).to_string()),
                ("__polymorphicType", inst.type_name().to_string()),
            ],
            _ => vec![("__type", inst.type_name().to_string())],
        }
    }

    // ----- XML -----

    /// Writes `<tag scalar-attrs extra>children</tag>` for an instance.
    fn xml_element(
        &mut self,
        out: &mut String,
        level: usize,
        tag: &str,
        inst: &Instance<'_>,
        extra: &[(&str, String)],
    ) -> Result<()> {
        indent(out, level);
        out.push('<');
        out.push_str(tag);
        for f in inst.fields() {
            let v = f.value()?;
            if let Some(text) = v.to_text() {
                push_attr(out, f.name(), &text);
            }
        }
        for (k, v) in extra {
            push_attr(out, k, v);
        }
        let mark = out.len();
        out.push_str(">\n");
        let mut wrote_child = false;
        for f in inst.fields() {
            let v = f.value()?;
            let declared = f.prop().target_struct().map(|s| s.id().0);
            wrote_child |= self.xml_child(out, level + 1, f.name(), declared, &v)?;
        }
        if wrote_child {
            indent(out, level);
            out.push_str("</");
            out.push_str(tag);
            out.push_str(">\n");
        } else {
            out.truncate(mark);
            out.push_str(" />\n");
        }
        Ok(())
    }

    /// Writes the child element for a non-scalar property; returns whether
    /// anything was written.
    fn xml_child(
        &mut self,
        out: &mut String,
        level: usize,
        name: &str,
        declared: Option<u32>,
        v: &Value<'_>,
    ) -> Result<bool> {
        match v {
            Value::Class(inst) => {
                let extra = [("__type", inst.type_name().to_string())];
                self.xml_element(out, level, name, inst, &extra)?;
            }
            Value::StrongPointer(Some(p)) => {
                let Some(inst) = self.enter(*p)? else {
                    return Ok(false);
                };
                indent(out, level);
                out.push('<');
                out.push_str(name);
                out.push_str(">\n");
                let extra = self.type_attrs(&inst, declared);
                let r = self.xml_element(
                    out,
                    level + 1,
                    &element_name(inst.type_name()),
                    &inst,
                    &extra,
                );
                self.leave();
                r?;
                indent(out, level);
                out.push_str("</");
                out.push_str(name);
                out.push_str(">\n");
            }
            Value::WeakPointer(Some(p)) => {
                indent(out, level);
                out.push('<');
                out.push_str(name);
                let label = format!(
                    "{}[{:04X}]",
                    self.struct_name(p.struct_index),
                    p.instance_index as u16
                );
                push_attr(out, "value", &label);
                out.push_str(" />\n");
            }
            Value::Array(arr) => {
                indent(out, level);
                out.push('<');
                out.push_str(name);
                if arr.is_empty() {
                    out.push_str(" />\n");
                    return Ok(true);
                }
                out.push_str(">\n");
                let base = arr.element_struct().map(|s| s.id().0);
                for item in arr.iter() {
                    let item = item?;
                    match &item {
                        Value::Class(inst) => {
                            let extra = [("__type", inst.type_name().to_string())];
                            self.xml_element(
                                out,
                                level + 1,
                                &element_name(inst.type_name()),
                                inst,
                                &extra,
                            )?;
                        }
                        // unp4k inlines both pointer kinds inside arrays.
                        Value::StrongPointer(Some(p)) | Value::WeakPointer(Some(p)) => {
                            if let Some(inst) = self.enter(*p)? {
                                let extra = self.type_attrs(&inst, base);
                                let r = self.xml_element(
                                    out,
                                    level + 1,
                                    &element_name(inst.type_name()),
                                    &inst,
                                    &extra,
                                );
                                self.leave();
                                r?;
                            }
                        }
                        Value::StrongPointer(None) | Value::WeakPointer(None) => {}
                        Value::Reference(r) => {
                            indent(out, level + 1);
                            out.push_str("<Reference");
                            let g = r.map(|r| r.guid).unwrap_or(Guid::NIL);
                            push_attr(out, "value", &g.to_string());
                            out.push_str(" />\n");
                        }
                        Value::Array(_) => {
                            return Err(Error::dataforge("nested arrays are not a valid layout"));
                        }
                        scalar => {
                            indent(out, level + 1);
                            out.push('<');
                            out.push_str(scalar.data_type().name());
                            push_attr(out, "value", &scalar.to_text().unwrap_or_default());
                            out.push_str(" />\n");
                        }
                    }
                }
                indent(out, level);
                out.push_str("</");
                out.push_str(name);
                out.push_str(">\n");
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    // ----- JSON -----

    fn json_object(
        &mut self,
        out: &mut String,
        level: usize,
        inst: &Instance<'_>,
        head: &[(&str, String)],
    ) -> Result<()> {
        let pretty = self.opts.pretty;
        out.push('{');
        let mut first = true;
        let sep = |out: &mut String, first: &mut bool| {
            if !*first {
                out.push(',');
            }
            *first = false;
            if pretty {
                out.push('\n');
                indent(out, level + 1);
            }
        };
        for (k, v) in head {
            sep(out, &mut first);
            json_key(out, k, pretty);
            json_string(out, v);
        }
        if head.iter().all(|(k, _)| *k != "__type") {
            sep(out, &mut first);
            json_key(out, "__type", pretty);
            json_string(out, inst.type_name());
        }
        for f in inst.fields() {
            sep(out, &mut first);
            json_key(out, f.name(), pretty);
            let declared = f.prop().target_struct().map(|s| s.id().0);
            let v = f.value()?;
            self.json_value(out, level + 1, &v, declared)?;
        }
        if pretty && !first {
            out.push('\n');
            indent(out, level);
        }
        out.push('}');
        Ok(())
    }

    fn json_value(
        &mut self,
        out: &mut String,
        level: usize,
        v: &Value<'_>,
        declared: Option<u32>,
    ) -> Result<()> {
        match v {
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::F32(f) => json_float(out, *f as f64),
            Value::F64(f) => json_float(out, *f),
            Value::U64(u) => {
                let _ = write!(out, "{u}");
            }
            Value::String(s) | Value::Locale(s) | Value::Enum(s) => json_string(out, s),
            Value::Guid(g) => json_string(out, &g.to_string()),
            Value::Reference(None) | Value::StrongPointer(None) | Value::WeakPointer(None) => {
                out.push_str("null")
            }
            Value::Reference(Some(r)) => json_string(out, &r.guid.to_string()),
            Value::Class(inst) => self.json_object(out, level, inst, &[])?,
            Value::StrongPointer(Some(p)) => match self.enter(*p)? {
                Some(inst) => {
                    let head = self.type_attrs(&inst, declared);
                    let r = self.json_object(out, level, &inst, &head);
                    self.leave();
                    r?;
                }
                None => out.push_str("null"),
            },
            Value::WeakPointer(Some(p)) => {
                out.push_str("{\"__weak\":");
                json_string(out, self.struct_name(p.struct_index));
                let _ = write!(out, ",\"__instance\":{}}}", p.instance_index);
            }
            Value::Array(arr) => {
                out.push('[');
                let base = arr.element_struct().map(|s| s.id().0);
                let mut first = true;
                for item in arr.iter() {
                    let item = item?;
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    if self.opts.pretty {
                        out.push('\n');
                        indent(out, level + 1);
                    }
                    self.json_value(out, level + 1, &item, base)?;
                }
                if self.opts.pretty && !first {
                    out.push('\n');
                    indent(out, level);
                }
                out.push(']');
            }
            other => match other.as_i64() {
                Some(i) => {
                    let _ = write!(out, "{i}");
                }
                None => out.push_str("null"),
            },
        }
        Ok(())
    }
}

fn json_key(out: &mut String, key: &str, pretty: bool) {
    json_string(out, key);
    out.push(':');
    if pretty {
        out.push(' ');
    }
}

/// Appends a JSON string literal.
pub fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_float(out: &mut String, f: f64) {
    if f.is_finite() {
        let _ = write!(out, "{f}");
    } else {
        out.push_str("null");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaping() {
        let mut s = String::new();
        json_string(&mut s, "a\"b\\c\n\t\u{1}");
        assert_eq!(s, r#""a\"b\\c\n\t\u0001""#);
        let mut f = String::new();
        json_float(&mut f, 1.5);
        json_float(&mut f, f64::NAN);
        assert_eq!(f, "1.5null");
    }

    #[test]
    fn element_names() {
        assert_eq!(element_name("Type.Name (x) [1]"), "Type.Name__x___1_");
    }
}
