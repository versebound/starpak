//! CryEngine binary XML (`CryXmlB`) decoder.
//!
//! Layout (all little-endian):
//!
//! ```text
//! 0   "CryXmlB\0"
//! 8   u32 total size
//! 12  u32 node table offset      16  u32 node count
//! 20  u32 attribute table offset 24  u32 attribute count
//! 28  u32 child table offset     32  u32 child count
//! 36  u32 string table offset    40  u32 string table size
//! ```
//!
//! A node is 28 bytes: tag string offset, content string offset, `u16`
//! attribute count, `u16` child count, `i32` parent, `i32` first attribute,
//! `i32` first child index (into the child table of `u32` node indices),
//! plus a reserved `i32`. An attribute is two string offsets (key, value).
//! String offsets are relative to the string table and NUL-terminated.

use std::io::{self, Write};

use crate::archive::Archive;
use crate::entry::{Entry, EntryId};
use crate::error::{Error, Result};
use crate::util::Le;

/// File magic.
pub const MAGIC: &[u8; 8] = b"CryXmlB\0";
const HEADER_LEN: usize = 44;
const NODE_LEN: usize = 28;
const ATTR_LEN: usize = 8;

/// True when `data` starts with the CryXmlB magic.
#[inline]
pub fn is_cryxmlb(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// True when `data` looks like text XML (optional BOM/whitespace then `<`).
pub fn looks_like_text_xml(data: &[u8]) -> bool {
    let body = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    body.iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'<')
}

#[derive(Clone, Copy, Debug)]
struct Node {
    tag: u32,
    content: u32,
    attr_count: u16,
    child_count: u16,
    parent: i32,
    first_attr: i32,
    first_child: i32,
}

/// A decoded CryXmlB document.
#[derive(Clone, Debug)]
pub struct CryXml {
    nodes: Vec<Node>,
    children: Vec<u32>,
    attrs: Vec<(u32, u32)>,
    strings: Vec<u8>,
}

impl CryXml {
    /// Parses a CryXmlB buffer, validating every table index and offset.
    pub fn parse(data: &[u8]) -> Result<CryXml> {
        if !is_cryxmlb(data) {
            return Err(Error::cryxml("missing CryXmlB magic"));
        }
        if data.len() < HEADER_LEN {
            return Err(Error::cryxml("header truncated"));
        }
        let mut r = Le::at(data, 8);
        let short = || Error::cryxml("header truncated");
        let _total = r.u32().ok_or_else(short)?;
        let node_pos = r.u32().ok_or_else(short)? as usize;
        let node_count = r.u32().ok_or_else(short)? as usize;
        let attr_pos = r.u32().ok_or_else(short)? as usize;
        let attr_count = r.u32().ok_or_else(short)? as usize;
        let child_pos = r.u32().ok_or_else(short)? as usize;
        let child_count = r.u32().ok_or_else(short)? as usize;
        let str_pos = r.u32().ok_or_else(short)? as usize;
        let str_len = r.u32().ok_or_else(short)? as usize;

        let table = |pos: usize, count: usize, width: usize, what: &str| -> Result<&[u8]> {
            let len = count
                .checked_mul(width)
                .ok_or_else(|| Error::cryxml(format!("{what} table size overflows")))?;
            let end = pos
                .checked_add(len)
                .filter(|&e| e <= data.len())
                .ok_or_else(|| Error::cryxml(format!("{what} table lies outside the buffer")))?;
            Ok(&data[pos..end])
        };
        if node_count == 0 {
            return Err(Error::cryxml("document has no nodes"));
        }
        if node_count > u32::MAX as usize / 2 || attr_count > u32::MAX as usize / 2 {
            return Err(Error::cryxml("implausible table size"));
        }
        let node_bytes = table(node_pos, node_count, NODE_LEN, "node")?;
        let attr_bytes = table(attr_pos, attr_count, ATTR_LEN, "attribute")?;
        let child_bytes = table(child_pos, child_count, 4, "child")?;
        let strings = table(str_pos, str_len, 1, "string")?.to_vec();

        let mut nodes = Vec::with_capacity(node_count);
        for (i, chunk) in node_bytes.chunks_exact(NODE_LEN).enumerate() {
            let mut c = Le::new(chunk);
            let n = Node {
                tag: c.u32().unwrap_or(0),
                content: c.u32().unwrap_or(0),
                attr_count: c.u16().unwrap_or(0),
                child_count: c.u16().unwrap_or(0),
                parent: c.i32().unwrap_or(-1),
                first_attr: c.i32().unwrap_or(0),
                first_child: c.i32().unwrap_or(0),
            };
            let bad = |what: &str| Error::cryxml(format!("node {i}: {what}"));
            if n.tag as usize >= strings.len().max(1) || n.content as usize >= strings.len().max(1)
            {
                return Err(bad("string offset out of range"));
            }
            let attr_end = (n.first_attr as i64) + n.attr_count as i64;
            if n.first_attr < 0 || attr_end > attr_count as i64 {
                return Err(bad("attribute range out of bounds"));
            }
            let child_end = (n.first_child as i64) + n.child_count as i64;
            if n.first_child < 0 || child_end > child_count as i64 {
                return Err(bad("child range out of bounds"));
            }
            if n.parent >= node_count as i32 {
                return Err(bad("parent index out of range"));
            }
            nodes.push(n);
        }
        if nodes[0].parent != -1 {
            return Err(Error::cryxml("node 0 is not a root"));
        }

        let children: Vec<u32> = child_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        if let Some(bad) = children.iter().find(|&&c| c as usize >= node_count) {
            return Err(Error::cryxml(format!("child index {bad} out of range")));
        }
        let attrs: Vec<(u32, u32)> = attr_bytes
            .chunks_exact(ATTR_LEN)
            .map(|c| {
                (
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                    u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                )
            })
            .collect();
        if let Some((k, v)) = attrs
            .iter()
            .find(|(k, v)| *k as usize >= strings.len() || *v as usize >= strings.len())
        {
            return Err(Error::cryxml(format!(
                "attribute string offset {k}/{v} out of range"
            )));
        }

        // The child lists must form a tree rooted at node 0.
        let mut seen = vec![false; node_count];
        seen[0] = true;
        let mut stack = vec![0u32];
        while let Some(n) = stack.pop() {
            let node = &nodes[n as usize];
            let s = node.first_child as usize;
            for &c in &children[s..s + node.child_count as usize] {
                if seen[c as usize] {
                    return Err(Error::cryxml(format!(
                        "node {c} is referenced twice (cycle)"
                    )));
                }
                seen[c as usize] = true;
                stack.push(c);
            }
        }

        Ok(CryXml {
            nodes,
            children,
            attrs,
            strings,
        })
    }

    /// Root element.
    pub fn root(&self) -> NodeRef<'_> {
        NodeRef { doc: self, idx: 0 }
    }

    /// Number of nodes in the document.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of attributes in the document.
    pub fn attribute_count(&self) -> usize {
        self.attrs.len()
    }

    /// Node by raw index.
    pub fn node(&self, idx: usize) -> Option<NodeRef<'_>> {
        (idx < self.nodes.len()).then_some(NodeRef {
            doc: self,
            idx: idx as u32,
        })
    }

    fn string(&self, off: u32) -> &str {
        let off = off as usize;
        if off >= self.strings.len() {
            return "";
        }
        let rest = &self.strings[off..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end]).unwrap_or("")
    }

    /// Serialises to indented XML text with a declaration.
    pub fn to_xml_string(&self) -> String {
        let mut s = String::with_capacity(self.strings.len() * 2 + self.nodes.len() * 16);
        s.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        write_node(self, 0, 0, &mut s);
        s
    }

    /// Writes indented XML text (with declaration) to `w`.
    pub fn write_xml(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(self.to_xml_string().as_bytes())
    }
}

/// A node inside a [`CryXml`] document.
#[derive(Clone, Copy)]
pub struct NodeRef<'a> {
    doc: &'a CryXml,
    idx: u32,
}

impl<'a> NodeRef<'a> {
    #[inline]
    fn node(&self) -> &'a Node {
        &self.doc.nodes[self.idx as usize]
    }

    /// Raw node index.
    pub fn index(&self) -> usize {
        self.idx as usize
    }

    /// Element name.
    pub fn tag(&self) -> &'a str {
        self.doc.string(self.node().tag)
    }

    /// Text content (empty when none).
    pub fn text(&self) -> &'a str {
        self.doc.string(self.node().content)
    }

    /// Attributes in document order.
    pub fn attributes(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        let n = self.node();
        let doc = self.doc;
        let s = n.first_attr as usize;
        doc.attrs[s..s + n.attr_count as usize]
            .iter()
            .map(move |&(k, v)| (doc.string(k), doc.string(v)))
    }

    /// Value of the attribute `name` (case-sensitive).
    pub fn attr(&self, name: &str) -> Option<&'a str> {
        self.attributes().find(|(k, _)| *k == name).map(|(_, v)| v)
    }

    /// Number of attributes.
    pub fn attribute_count(&self) -> usize {
        self.node().attr_count as usize
    }

    /// Child elements in document order.
    pub fn children(&self) -> impl Iterator<Item = NodeRef<'a>> + 'a {
        let n = self.node();
        let doc = self.doc;
        let s = n.first_child as usize;
        doc.children[s..s + n.child_count as usize]
            .iter()
            .map(move |&c| NodeRef { doc, idx: c })
    }

    /// Number of child elements.
    pub fn child_count(&self) -> usize {
        self.node().child_count as usize
    }

    /// First child with the given tag.
    pub fn child(&self, tag: &str) -> Option<NodeRef<'a>> {
        self.children().find(|c| c.tag() == tag)
    }

    /// Parent element; `None` for the root.
    pub fn parent(&self) -> Option<NodeRef<'a>> {
        let p = self.node().parent;
        (p >= 0 && (p as usize) < self.doc.nodes.len()).then_some(NodeRef {
            doc: self.doc,
            idx: p as u32,
        })
    }
}

impl std::fmt::Debug for NodeRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRef")
            .field("tag", &self.tag())
            .field("attributes", &self.attributes().collect::<Vec<_>>())
            .field("children", &self.child_count())
            .finish()
    }
}

fn write_node(doc: &CryXml, idx: u32, depth: usize, out: &mut String) {
    let n = NodeRef { doc, idx };
    for _ in 0..depth {
        out.push_str("  ");
    }
    out.push('<');
    out.push_str(n.tag());
    for (k, v) in n.attributes() {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        escape_into(v, true, out);
        out.push('"');
    }
    let text = n.text();
    if n.child_count() == 0 && text.is_empty() {
        out.push_str(" />\n");
        return;
    }
    out.push('>');
    if !text.is_empty() {
        escape_into(text, false, out);
    }
    if n.child_count() > 0 {
        out.push('\n');
        for c in n.children() {
            write_node(doc, c.idx, depth + 1, out);
        }
        for _ in 0..depth {
            out.push_str("  ");
        }
    }
    out.push_str("</");
    out.push_str(n.tag());
    out.push_str(">\n");
}

/// Appends `s` with XML escaping; quotes are escaped only for attributes.
pub fn escape_into(s: &str, attr: bool, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attr => out.push_str("&quot;"),
            '\n' if attr => out.push_str("&#10;"),
            '\t' if attr => out.push_str("&#9;"),
            '\r' if attr => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

/// Converts XML bytes from the archive to text: CryXmlB is decoded, text
/// XML passes through unchanged (lossily re-encoded as UTF-8), anything
/// else is rejected with [`Error::NotXml`].
pub fn to_xml(data: &[u8]) -> Result<String> {
    if is_cryxmlb(data) {
        return Ok(CryXml::parse(data)?.to_xml_string());
    }
    if looks_like_text_xml(data) {
        return Ok(String::from_utf8_lossy(data).into_owned());
    }
    Err(Error::NotXml)
}

impl Archive {
    /// Reads an entry by path and returns it as XML text (binary CryXmlB is
    /// decoded; text XML passes through).
    pub fn read_xml(&self, path: &str) -> Result<String> {
        let e = self.entry_by_path(path)?;
        self.read_xml_entry(&e)
    }

    /// XML text of an entry whose metadata is at hand.
    pub fn read_xml_entry(&self, e: &Entry) -> Result<String> {
        let data = self.read_entry(e)?;
        to_xml(&data)
    }

    /// Decodes an entry as a [`CryXml`] document (binary only).
    pub fn read_cryxml(&self, id: EntryId) -> Result<CryXml> {
        let data = self.read(id)?;
        CryXml::parse(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection() {
        assert!(is_cryxmlb(b"CryXmlB\0rest"));
        assert!(!is_cryxmlb(b"CryXmlB"));
        assert!(looks_like_text_xml(b"\xEF\xBB\xBF\n  <root/>"));
        assert!(!looks_like_text_xml(b"   plain"));
        assert!(!looks_like_text_xml(b""));
        assert!(matches!(to_xml(b"nope"), Err(Error::NotXml)));
        assert_eq!(to_xml(b"<a/>").unwrap(), "<a/>");
    }

    #[test]
    fn rejects_garbage_headers() {
        let mut d = MAGIC.to_vec();
        assert!(CryXml::parse(&d).is_err());
        d.extend_from_slice(&[0u8; 36]);
        // zero nodes
        assert!(CryXml::parse(&d).is_err());
        // node count 1 but table out of bounds
        d[16..20].copy_from_slice(&1u32.to_le_bytes());
        d[12..16].copy_from_slice(&1000u32.to_le_bytes());
        assert!(CryXml::parse(&d).is_err());
        // huge counts must not allocate
        d[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(CryXml::parse(&d).is_err());
    }

    #[test]
    fn escaping() {
        let mut s = String::new();
        escape_into("a<b>&\"c\"\n", true, &mut s);
        assert_eq!(s, "a&lt;b&gt;&amp;&quot;c&quot;&#10;");
        s.clear();
        escape_into("a<b>&\"c\"", false, &mut s);
        assert_eq!(s, "a&lt;b&gt;&amp;\"c\"");
    }
}
