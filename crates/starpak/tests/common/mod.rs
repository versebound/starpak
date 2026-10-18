//! Test helpers: an in-memory p4k writer that reproduces CIG's layout
//! quirks (and the plain PKWARE layout), a CryXmlB encoder and a PRNG.

#![allow(dead_code)]

use std::io::Write;

use aes::cipher::consts::U16;
use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockEncryptMut, KeyIvInit};

pub const STORE: u16 = 0;
pub const DEFLATE: u16 = 8;
pub const ZSTD: u16 = 100;

/// xorshift64* PRNG for deterministic test data.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }

    /// Compressible pseudo-text.
    pub fn text(&mut self, n: usize) -> Vec<u8> {
        const WORDS: [&str; 8] = [
            "quantum ", "drive ", "<item ", "value=\"", "\" />\n", "Stanton ", "aUEC ", "cargo ",
        ];
        let mut v = Vec::with_capacity(n + 16);
        while v.len() < n {
            v.extend_from_slice(WORDS[self.below(WORDS.len())].as_bytes());
        }
        v.truncate(n);
        v
    }
}

pub fn aes_encrypt(key: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    let pad = (16 - buf.len() % 16) % 16;
    buf.extend(std::iter::repeat_n(0u8, pad));
    let mut enc = cbc::Encryptor::<aes::Aes128>::new(key.into(), &[0u8; 16].into());
    let (blocks, _) = InOutBuf::from(&mut buf[..]).into_chunks::<U16>();
    enc.encrypt_blocks_inout_mut(blocks);
    buf
}

/// One file to be written into a fixture archive.
#[derive(Clone)]
pub struct FileSpec {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub method: u16,
    pub encrypted: bool,
    pub dos_time: u32,
    /// Replace the CRC stored in the headers.
    pub crc_override: Option<u32>,
    /// Replace the local header signature.
    pub local_sig: Option<u32>,
    /// Replace the local-header offset recorded in the central directory.
    pub local_offset_override: Option<u64>,
    /// Do not pad encrypted payloads to a block multiple (invalid archive).
    pub no_pad: bool,
    /// Append this many junk bytes after the compressed payload and count
    /// them in the compressed size.
    pub trailing_junk: usize,
}

impl FileSpec {
    pub fn new(name: &str, data: impl Into<Vec<u8>>, method: u16) -> FileSpec {
        FileSpec {
            name: name.as_bytes().to_vec(),
            data: data.into(),
            method,
            encrypted: false,
            dos_time: 0x5A42_1A4C,
            crc_override: None,
            local_sig: None,
            local_offset_override: None,
            no_pad: false,
            trailing_junk: 0,
        }
    }

    pub fn encrypted(mut self) -> FileSpec {
        self.encrypted = true;
        self
    }

    pub fn bad_crc(mut self) -> FileSpec {
        self.crc_override = Some(0xDEAD_BEEF);
        self
    }
}

/// Layout flavour of the generated archive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    /// What CIG's packer emits: ZIP64 records, header-inclusive extra sizes,
    /// `0x5002` encryption flag, 4096-aligned payloads, CIG comment and
    /// zero padding after the EOCD.
    Cig,
    /// A conventional ZIP64 archive (PKWARE extra sizes, no CIG tags).
    Pkware64,
    /// A conventional ZIP without ZIP64 records.
    Classic,
}

pub struct P4kBuilder {
    pub files: Vec<FileSpec>,
    pub flavor: Flavor,
    pub key: [u8; 16],
    pub comment: Vec<u8>,
    pub tail_padding: usize,
    /// Data alignment for the CIG flavour.
    pub align: usize,
    /// Bytes written before the first local header (e.g. a stored prefix).
    pub leading_junk: Vec<u8>,
}

impl P4kBuilder {
    pub fn new(flavor: Flavor) -> P4kBuilder {
        P4kBuilder {
            files: Vec::new(),
            flavor,
            key: starpak::crypto::P4K_KEY,
            comment: if flavor == Flavor::Cig {
                let mut c = b"CIG\0\x01\0\0\x10".to_vec();
                c.extend_from_slice(&[0xE6, 0x89, 0, 0, 0, 0, 0, 0]);
                c
            } else {
                Vec::new()
            },
            tail_padding: if flavor == Flavor::Cig { 3772 } else { 0 },
            align: if flavor == Flavor::Cig { 4096 } else { 0 },
            leading_junk: Vec::new(),
        }
    }

    pub fn file(mut self, f: FileSpec) -> P4kBuilder {
        self.files.push(f);
        self
    }

    pub fn add(mut self, name: &str, data: impl Into<Vec<u8>>, method: u16) -> P4kBuilder {
        self.files.push(FileSpec::new(name, data, method));
        self
    }

    fn zip64(&self) -> bool {
        self.flavor != Flavor::Classic
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self.leading_junk.clone();
        let mut cd = Vec::new();
        for f in &self.files {
            let (payload, crc) = self.encode(f);
            let crc = f.crc_override.unwrap_or(crc);
            let comp = payload.len() as u64;
            let uncomp = f.data.len() as u64;

            // ----- local header -----
            if self.align > 0 {
                let pad = (self.align - out.len() % self.align) % self.align;
                out.extend(std::iter::repeat_n(0u8, pad));
            }
            let local_off = out.len() as u64;
            let sig = f
                .local_sig
                .unwrap_or(if f.encrypted && self.flavor == Flavor::Cig {
                    0x1403_4b50
                } else {
                    0x0403_4b50
                });
            let mut extra = Vec::new();
            if self.zip64() {
                let body_len = 28u16;
                let declared = if self.flavor == Flavor::Cig {
                    body_len + 4
                } else {
                    body_len
                };
                extra.extend_from_slice(&1u16.to_le_bytes());
                extra.extend_from_slice(&declared.to_le_bytes());
                extra.extend_from_slice(&uncomp.to_le_bytes());
                extra.extend_from_slice(&comp.to_le_bytes());
                extra.extend_from_slice(&local_off.to_le_bytes());
                extra.extend_from_slice(&0u32.to_le_bytes());
            }
            if self.align > 0 {
                let used = 30 + f.name.len() + extra.len();
                let total = used.div_ceil(self.align) * self.align;
                let pad_total = total - used; // includes the 4-byte tag header
                assert!(pad_total >= 4, "name too long for alignment padding");
                extra.extend_from_slice(&0x0666u16.to_le_bytes());
                extra.extend_from_slice(&(pad_total as u16).to_le_bytes());
                extra.extend(std::iter::repeat_n(0u8, pad_total - 4));
            }
            out.extend_from_slice(&sig.to_le_bytes());
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&f.method.to_le_bytes());
            out.extend_from_slice(&f.dos_time.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            let (c32, u32v) = if self.zip64() {
                (u32::MAX, u32::MAX)
            } else {
                (comp as u32, uncomp as u32)
            };
            out.extend_from_slice(&c32.to_le_bytes());
            out.extend_from_slice(&u32v.to_le_bytes());
            out.extend_from_slice(&(f.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            out.extend_from_slice(&f.name);
            out.extend_from_slice(&extra);
            out.extend_from_slice(&payload);

            // ----- central directory entry -----
            let mut cextra = Vec::new();
            if self.zip64() {
                let body_len = 28u16;
                let declared = if self.flavor == Flavor::Cig {
                    body_len + 4
                } else {
                    body_len
                };
                cextra.extend_from_slice(&1u16.to_le_bytes());
                cextra.extend_from_slice(&declared.to_le_bytes());
                cextra.extend_from_slice(&uncomp.to_le_bytes());
                cextra.extend_from_slice(&comp.to_le_bytes());
                cextra
                    .extend_from_slice(&f.local_offset_override.unwrap_or(local_off).to_le_bytes());
                cextra.extend_from_slice(&0u32.to_le_bytes());
            }
            if self.flavor == Flavor::Cig {
                cextra.extend_from_slice(&0x5000u16.to_le_bytes());
                cextra.extend_from_slice(&132u16.to_le_bytes());
                cextra.extend_from_slice(&[0u8; 128]);
                cextra.extend_from_slice(&0x5002u16.to_le_bytes());
                cextra.extend_from_slice(&6u16.to_le_bytes());
                cextra.extend_from_slice(&(f.encrypted as u16).to_le_bytes());
                cextra.extend_from_slice(&0x5003u16.to_le_bytes());
                cextra.extend_from_slice(&36u16.to_le_bytes());
                cextra.extend_from_slice(&[0x11u8; 32]);
            } else {
                assert!(!f.encrypted, "encryption needs the CIG flavour");
            }
            cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            cd.extend_from_slice(&46u16.to_le_bytes());
            cd.extend_from_slice(&45u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&f.method.to_le_bytes());
            cd.extend_from_slice(&f.dos_time.to_le_bytes());
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&c32.to_le_bytes());
            cd.extend_from_slice(&u32v.to_le_bytes());
            cd.extend_from_slice(&(f.name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&(cextra.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&(if self.zip64() { u16::MAX } else { 0 }).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u32.to_le_bytes());
            let lo32 = if self.zip64() {
                u32::MAX
            } else {
                f.local_offset_override.unwrap_or(local_off) as u32
            };
            cd.extend_from_slice(&lo32.to_le_bytes());
            cd.extend_from_slice(&f.name);
            cd.extend_from_slice(&cextra);
        }

        let cd_off = out.len() as u64;
        let cd_size = cd.len() as u64;
        out.extend_from_slice(&cd);
        let n = self.files.len() as u64;

        if self.zip64() {
            let z64_off = out.len() as u64;
            out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
            out.extend_from_slice(&44u64.to_le_bytes());
            out.extend_from_slice(&46u16.to_le_bytes());
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&cd_size.to_le_bytes());
            out.extend_from_slice(&cd_off.to_le_bytes());
            out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&z64_off.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
            out.extend_from_slice(&[0xFF; 8]);
            out.extend_from_slice(&u32::MAX.to_le_bytes());
            out.extend_from_slice(&u32::MAX.to_le_bytes());
        } else {
            out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(&(cd_size as u32).to_le_bytes());
            out.extend_from_slice(&(cd_off as u32).to_le_bytes());
        }
        out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.comment);
        out.extend(std::iter::repeat_n(0u8, self.tail_padding));
        out
    }

    fn encode(&self, f: &FileSpec) -> (Vec<u8>, u32) {
        let crc = crc32c::crc32c(&f.data);
        let mut payload = match f.method {
            STORE => f.data.clone(),
            DEFLATE => {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(&f.data).unwrap();
                e.finish().unwrap()
            }
            ZSTD => zstd::encode_all(&f.data[..], 3).unwrap(),
            other => {
                // Unknown method: store the bytes so the archive stays parseable.
                let _ = other;
                f.data.clone()
            }
        };
        payload.extend(std::iter::repeat_n(0xEEu8, f.trailing_junk));
        if f.encrypted {
            if f.no_pad {
                let mut whole = aes_encrypt(&self.key, &payload);
                whole.truncate(payload.len());
                payload = whole;
            } else {
                payload = aes_encrypt(&self.key, &payload);
            }
        }
        (payload, crc)
    }
}

/// Writes `bytes` to a temp file and returns the handle keeping it alive.
pub fn temp_archive(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    f
}

/// Simple element tree used to craft CryXmlB documents.
#[derive(Clone, Debug, Default)]
pub struct Elem {
    pub tag: String,
    pub text: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Elem>,
}

impl Elem {
    pub fn new(tag: &str) -> Elem {
        Elem {
            tag: tag.into(),
            ..Default::default()
        }
    }

    pub fn attr(mut self, k: &str, v: &str) -> Elem {
        self.attrs.push((k.into(), v.into()));
        self
    }

    pub fn text(mut self, t: &str) -> Elem {
        self.text = t.into();
        self
    }

    pub fn child(mut self, c: Elem) -> Elem {
        self.children.push(c);
        self
    }
}

/// Encoder options to exercise layout variations.
#[derive(Clone, Copy, Default)]
pub struct CryXmlLayout {
    /// Put the string table before the node table.
    pub strings_first: bool,
    /// Insert junk between tables (offsets still correct).
    pub gaps: bool,
}

/// Encodes an element tree as CryXmlB.
pub fn encode_cryxml(root: &Elem, layout: CryXmlLayout) -> Vec<u8> {
    struct Node {
        tag: u32,
        content: u32,
        attr_count: u16,
        child_count: u16,
        parent: i32,
        first_attr: i32,
        first_child: i32,
    }
    let mut strings: Vec<u8> = vec![0]; // offset 0 is the empty string
    let mut intern = std::collections::HashMap::<String, u32>::new();
    intern.insert(String::new(), 0);
    let mut add_str = |s: &str| -> u32 {
        if let Some(&o) = intern.get(s) {
            return o;
        }
        let o = strings.len() as u32;
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
        intern.insert(s.to_string(), o);
        o
    };
    let mut nodes: Vec<Node> = Vec::new();
    let mut attrs: Vec<(u32, u32)> = Vec::new();
    let mut children: Vec<u32> = Vec::new();

    // Breadth-first so each node's children are contiguous in the child table.
    let mut queue: std::collections::VecDeque<(&Elem, i32)> = std::collections::VecDeque::new();
    queue.push_back((root, -1));
    let mut order: Vec<(&Elem, i32, usize)> = Vec::new();
    while let Some((e, parent)) = queue.pop_front() {
        let idx = order.len();
        order.push((e, parent, idx));
        for c in &e.children {
            queue.push_back((c, idx as i32));
        }
    }
    // Node indices follow BFS order; child lists reference them.
    let mut next_index = 1usize;
    for (e, parent, _) in &order {
        let first_attr = attrs.len() as i32;
        for (k, v) in &e.attrs {
            let ko = add_str(k);
            let vo = add_str(v);
            attrs.push((ko, vo));
        }
        let first_child = children.len() as i32;
        for _ in &e.children {
            children.push(next_index as u32);
            next_index += 1;
        }
        nodes.push(Node {
            tag: add_str(&e.tag),
            content: add_str(&e.text),
            attr_count: e.attrs.len() as u16,
            child_count: e.children.len() as u16,
            parent: *parent,
            first_attr,
            first_child,
        });
    }

    let mut node_bytes = Vec::new();
    for n in &nodes {
        node_bytes.extend_from_slice(&n.tag.to_le_bytes());
        node_bytes.extend_from_slice(&n.content.to_le_bytes());
        node_bytes.extend_from_slice(&n.attr_count.to_le_bytes());
        node_bytes.extend_from_slice(&n.child_count.to_le_bytes());
        node_bytes.extend_from_slice(&n.parent.to_le_bytes());
        node_bytes.extend_from_slice(&n.first_attr.to_le_bytes());
        node_bytes.extend_from_slice(&n.first_child.to_le_bytes());
        node_bytes.extend_from_slice(&0i32.to_le_bytes());
    }
    let mut attr_bytes = Vec::new();
    for (k, v) in &attrs {
        attr_bytes.extend_from_slice(&k.to_le_bytes());
        attr_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let mut child_bytes = Vec::new();
    for c in &children {
        child_bytes.extend_from_slice(&c.to_le_bytes());
    }

    let gap: &[u8] = if layout.gaps { b"JUNKJUNK" } else { b"" };
    let mut body = Vec::new();
    let mut place = |table: &[u8]| -> u32 {
        body.extend_from_slice(gap);
        let off = 44 + body.len() as u32;
        body.extend_from_slice(table);
        off
    };
    let (str_off, node_off, attr_off, child_off) = if layout.strings_first {
        let s = place(&strings);
        let n = place(&node_bytes);
        let a = place(&attr_bytes);
        let c = place(&child_bytes);
        (s, n, a, c)
    } else {
        let n = place(&node_bytes);
        let a = place(&attr_bytes);
        let c = place(&child_bytes);
        let s = place(&strings);
        (s, n, a, c)
    };
    let mut out = Vec::new();
    out.extend_from_slice(b"CryXmlB\0");
    out.extend_from_slice(&((44 + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(&node_off.to_le_bytes());
    out.extend_from_slice(&(nodes.len() as u32).to_le_bytes());
    out.extend_from_slice(&attr_off.to_le_bytes());
    out.extend_from_slice(&(attrs.len() as u32).to_le_bytes());
    out.extend_from_slice(&child_off.to_le_bytes());
    out.extend_from_slice(&(children.len() as u32).to_le_bytes());
    out.extend_from_slice(&str_off.to_le_bytes());
    out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

// ───────────────────────── DataForge fixtures ─────────────────────────

/// Raw DataForge type codes.
pub mod dt {
    pub const BOOL: u16 = 0x01;
    pub const I8: u16 = 0x02;
    pub const I16: u16 = 0x03;
    pub const I32: u16 = 0x04;
    pub const I64: u16 = 0x05;
    pub const U8: u16 = 0x06;
    pub const U16: u16 = 0x07;
    pub const U32: u16 = 0x08;
    pub const U64: u16 = 0x09;
    pub const STRING: u16 = 0x0A;
    pub const F32: u16 = 0x0B;
    pub const F64: u16 = 0x0C;
    pub const LOCALE: u16 = 0x0D;
    pub const GUID: u16 = 0x0E;
    pub const ENUM: u16 = 0x0F;
    pub const CLASS: u16 = 0x10;
    pub const STRONG: u16 = 0x110;
    pub const WEAK: u16 = 0x210;
    pub const REFERENCE: u16 = 0x310;
}

/// Property declaration for the fixture builder.
#[derive(Clone)]
pub struct DcbProp {
    pub name: String,
    pub ty: u16,
    /// 0 = attribute, 1 = complex array, 2 = simple array, 3 = class array.
    pub conv: u16,
    /// Struct or enum index for class/pointer/reference/enum properties.
    pub target: u16,
}

impl DcbProp {
    pub fn attr(name: &str, ty: u16) -> DcbProp {
        DcbProp {
            name: name.into(),
            ty,
            conv: 0,
            target: 0,
        }
    }

    pub fn attr_of(name: &str, ty: u16, target: usize) -> DcbProp {
        DcbProp {
            name: name.into(),
            ty,
            conv: 0,
            target: target as u16,
        }
    }

    pub fn array(name: &str, ty: u16) -> DcbProp {
        DcbProp {
            name: name.into(),
            ty,
            conv: 2,
            target: 0,
        }
    }

    pub fn array_of(name: &str, ty: u16, target: usize) -> DcbProp {
        DcbProp {
            name: name.into(),
            ty,
            conv: if ty == dt::CLASS { 3 } else { 1 },
            target: target as u16,
        }
    }
}

/// A value for one property of an instance.
#[derive(Clone, Debug)]
pub enum V {
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    Str(String),
    Loc(String),
    Enum(String),
    Guid([u8; 16]),
    /// Inline class: values of the nested struct in flattened property order.
    Class(Vec<V>),
    /// Strong pointer to `(struct, instance)`; `None` for null.
    Strong(Option<(usize, usize)>),
    /// Weak pointer to `(struct, instance)`; `None` for null.
    Weak(Option<(usize, usize)>),
    /// Reference `(guid, instance)`; `None` for null.
    Ref(Option<([u8; 16], i32)>),
    /// Array of scalar/pointer/reference values.
    Array(Vec<V>),
    /// Class array: `count` consecutive instances of the property's struct
    /// starting at `first`.
    ClassArray(usize, usize),
}

pub struct DcbStruct {
    pub name: String,
    pub parent: Option<usize>,
    pub props: Vec<DcbProp>,
}

pub struct DcbRecord {
    pub name: String,
    pub file: String,
    pub tag: Option<String>,
    pub struct_index: usize,
    pub instance: usize,
    pub guid: [u8; 16],
}

/// Builds a `.dcb` byte image.
pub struct DcbBuilder {
    pub version: u32,
    pub structs: Vec<DcbStruct>,
    pub enums: Vec<(String, Vec<String>)>,
    pub instances: Vec<Vec<Vec<V>>>,
    pub records: Vec<DcbRecord>,
    /// Emit data mappings in reverse struct order.
    pub reverse_mappings: bool,
}

#[derive(Default)]
struct Tables {
    i8: Vec<u8>,
    i16: Vec<u8>,
    i32: Vec<u8>,
    i64: Vec<u8>,
    u8: Vec<u8>,
    u16: Vec<u8>,
    u32: Vec<u8>,
    u64: Vec<u8>,
    bool: Vec<u8>,
    f32: Vec<u8>,
    f64: Vec<u8>,
    guid: Vec<u8>,
    string: Vec<u8>,
    locale: Vec<u8>,
    enum_: Vec<u8>,
    strong: Vec<u8>,
    weak: Vec<u8>,
    reference: Vec<u8>,
}

struct Strings {
    bytes: Vec<u8>,
    map: std::collections::HashMap<String, u32>,
}

impl Strings {
    fn new() -> Strings {
        Strings {
            bytes: Vec::new(),
            map: std::collections::HashMap::new(),
        }
    }

    fn add(&mut self, s: &str) -> u32 {
        if let Some(&o) = self.map.get(s) {
            return o;
        }
        let o = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        self.map.insert(s.to_string(), o);
        o
    }
}

impl DcbBuilder {
    pub fn new(version: u32) -> DcbBuilder {
        DcbBuilder {
            version,
            structs: Vec::new(),
            enums: Vec::new(),
            instances: Vec::new(),
            records: Vec::new(),
            reverse_mappings: false,
        }
    }

    pub fn struct_def(&mut self, name: &str, parent: Option<usize>, props: Vec<DcbProp>) -> usize {
        self.structs.push(DcbStruct {
            name: name.into(),
            parent,
            props,
        });
        self.instances.push(Vec::new());
        self.structs.len() - 1
    }

    pub fn enum_def(&mut self, name: &str, values: &[&str]) -> usize {
        self.enums
            .push((name.into(), values.iter().map(|s| s.to_string()).collect()));
        self.enums.len() - 1
    }

    /// Adds an instance and returns its index.
    pub fn instance(&mut self, struct_index: usize, values: Vec<V>) -> usize {
        self.instances[struct_index].push(values);
        self.instances[struct_index].len() - 1
    }

    pub fn record(
        &mut self,
        name: &str,
        file: &str,
        struct_index: usize,
        instance: usize,
        guid: [u8; 16],
    ) -> &mut Self {
        self.records.push(DcbRecord {
            name: name.into(),
            file: file.into(),
            tag: None,
            struct_index,
            instance,
            guid,
        });
        self
    }

    pub fn record_tagged(
        &mut self,
        name: &str,
        file: &str,
        tag: &str,
        struct_index: usize,
        instance: usize,
        guid: [u8; 16],
    ) -> &mut Self {
        self.record(name, file, struct_index, instance, guid);
        self.records.last_mut().unwrap().tag = Some(tag.into());
        self
    }

    fn flat_props(&self, si: usize) -> Vec<DcbProp> {
        let mut chain = Vec::new();
        let mut cur = Some(si);
        while let Some(s) = cur {
            chain.push(s);
            cur = self.structs[s].parent;
        }
        let mut out = Vec::new();
        for &s in chain.iter().rev() {
            out.extend(self.structs[s].props.iter().cloned());
        }
        out
    }

    fn struct_size(&self, si: usize) -> u32 {
        self.flat_props(si)
            .iter()
            .map(|p| {
                if p.conv != 0 {
                    8
                } else if p.ty == dt::CLASS {
                    self.struct_size(p.target as usize)
                } else {
                    scalar_size(p.ty)
                }
            })
            .sum()
    }

    fn write_values(
        &self,
        props: &[DcbProp],
        values: &[V],
        out: &mut Vec<u8>,
        t: &mut Tables,
        text: &mut Strings,
    ) {
        assert_eq!(
            props.len(),
            values.len(),
            "value count must match property count"
        );
        for (p, v) in props.iter().zip(values) {
            if p.conv != 0 {
                let (first, count) = match v {
                    V::ClassArray(first, count) => (*first as i32, *count as i32),
                    V::Array(items) => {
                        let first = table_len(t, p.ty);
                        for item in items {
                            write_table_value(p.ty, item, t, text);
                        }
                        (first as i32, items.len() as i32)
                    }
                    other => panic!(
                        "array property {} needs an array value, got {other:?}",
                        p.name
                    ),
                };
                out.extend_from_slice(&count.to_le_bytes());
                out.extend_from_slice(&first.to_le_bytes());
                continue;
            }
            match (p.ty, v) {
                (dt::CLASS, V::Class(inner)) => {
                    let inner_props = self.flat_props(p.target as usize);
                    self.write_values(&inner_props, inner, out, t, text);
                }
                (dt::CLASS, other) => {
                    panic!("class property {} needs V::Class, got {other:?}", p.name)
                }
                _ => write_scalar(p.ty, v, out, text),
            }
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let mut text = Strings::new();
        let mut names = Strings::new();
        let two_tables = self.version >= 6;
        let mut t = Tables::default();

        // Struct / property / enum tables.
        let mut struct_bytes = Vec::new();
        let mut prop_bytes = Vec::new();
        let mut first_attr = 0u16;
        for s in &self.structs {
            let name_off = if two_tables {
                names.add(&s.name)
            } else {
                text.add(&s.name)
            };
            struct_bytes.extend_from_slice(&name_off.to_le_bytes());
            struct_bytes.extend_from_slice(&s.parent.map(|p| p as i32).unwrap_or(-1).to_le_bytes());
            struct_bytes.extend_from_slice(&(s.props.len() as u16).to_le_bytes());
            struct_bytes.extend_from_slice(&first_attr.to_le_bytes());
            struct_bytes.extend_from_slice(
                &self
                    .struct_size(
                        self.structs
                            .iter()
                            .position(|x| std::ptr::eq(x, s))
                            .unwrap(),
                    )
                    .to_le_bytes(),
            );
            for p in &s.props {
                let n = if two_tables {
                    names.add(&p.name)
                } else {
                    text.add(&p.name)
                };
                prop_bytes.extend_from_slice(&n.to_le_bytes());
                prop_bytes.extend_from_slice(&p.target.to_le_bytes());
                prop_bytes.extend_from_slice(&p.ty.to_le_bytes());
                prop_bytes.extend_from_slice(&p.conv.to_le_bytes());
                prop_bytes.extend_from_slice(&0u16.to_le_bytes());
                first_attr += 1;
            }
        }
        let mut enum_bytes = Vec::new();
        let mut enum_opt_bytes = Vec::new();
        let mut first_val = 0u16;
        for (name, values) in &self.enums {
            let n = if two_tables {
                names.add(name)
            } else {
                text.add(name)
            };
            enum_bytes.extend_from_slice(&n.to_le_bytes());
            enum_bytes.extend_from_slice(&(values.len() as u16).to_le_bytes());
            enum_bytes.extend_from_slice(&first_val.to_le_bytes());
            for v in values {
                let o = if two_tables {
                    names.add(v)
                } else {
                    text.add(v)
                };
                enum_opt_bytes.extend_from_slice(&o.to_le_bytes());
                first_val += 1;
            }
        }

        // Instances (in mapping order) and mappings.
        let order: Vec<usize> = if self.reverse_mappings {
            (0..self.structs.len()).rev().collect()
        } else {
            (0..self.structs.len()).collect()
        };
        let mut mapping_bytes = Vec::new();
        let mut data = Vec::new();
        for &si in &order {
            let insts = &self.instances[si];
            if insts.is_empty() {
                continue;
            }
            mapping_bytes.extend_from_slice(&(insts.len() as u32).to_le_bytes());
            mapping_bytes.extend_from_slice(&(si as i32).to_le_bytes());
            let props = self.flat_props(si);
            for values in insts {
                let before = data.len();
                self.write_values(&props, values, &mut data, &mut t, &mut text);
                assert_eq!(
                    (data.len() - before) as u32,
                    self.struct_size(si),
                    "instance size for struct {si}"
                );
            }
        }

        // Records.
        let mut record_bytes = Vec::new();
        for r in &self.records {
            let n = if two_tables {
                names.add(&r.name)
            } else {
                text.add(&r.name)
            };
            record_bytes.extend_from_slice(&n.to_le_bytes());
            record_bytes.extend_from_slice(&text.add(&r.file).to_le_bytes());
            if self.version >= 8 {
                let tag = match &r.tag {
                    Some(t) => names.add(t),
                    None => u32::MAX,
                };
                record_bytes.extend_from_slice(&tag.to_le_bytes());
            }
            record_bytes.extend_from_slice(&(r.struct_index as i32).to_le_bytes());
            record_bytes.extend_from_slice(&r.guid);
            record_bytes.extend_from_slice(&(r.instance as u16).to_le_bytes());
            record_bytes
                .extend_from_slice(&(self.struct_size(r.struct_index) as u16).to_le_bytes());
        }

        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let mapping_count = mapping_bytes.len() / 8;
        let counts: [usize; 24] = [
            self.structs.len(),
            prop_bytes.len() / 12,
            self.enums.len(),
            mapping_count,
            self.records.len(),
            t.bool.len(),
            t.i8.len(),
            t.i16.len() / 2,
            t.i32.len() / 4,
            t.i64.len() / 8,
            t.u8.len(),
            t.u16.len() / 2,
            t.u32.len() / 4,
            t.u64.len() / 8,
            t.f32.len() / 4,
            t.f64.len() / 8,
            t.guid.len() / 16,
            t.string.len() / 4,
            t.locale.len() / 4,
            t.enum_.len() / 4,
            t.strong.len() / 8,
            t.weak.len() / 8,
            t.reference.len() / 20,
            enum_opt_bytes.len() / 4,
        ];
        for c in counts {
            out.extend_from_slice(&(c as u32).to_le_bytes());
        }
        let (text1, text2) = if two_tables {
            (text.bytes, names.bytes)
        } else {
            (text.bytes, Vec::new())
        };
        out.extend_from_slice(&(text1.len() as u32).to_le_bytes());
        out.extend_from_slice(&(text2.len() as u32).to_le_bytes());
        out.extend_from_slice(&struct_bytes);
        out.extend_from_slice(&prop_bytes);
        out.extend_from_slice(&enum_bytes);
        out.extend_from_slice(&mapping_bytes);
        out.extend_from_slice(&record_bytes);
        for tb in [
            &t.i8,
            &t.i16,
            &t.i32,
            &t.i64,
            &t.u8,
            &t.u16,
            &t.u32,
            &t.u64,
            &t.bool,
            &t.f32,
            &t.f64,
            &t.guid,
            &t.string,
            &t.locale,
            &t.enum_,
            &t.strong,
            &t.weak,
            &t.reference,
        ] {
            out.extend_from_slice(tb);
        }
        out.extend_from_slice(&enum_opt_bytes);
        out.extend_from_slice(&text1);
        out.extend_from_slice(&text2);
        out.extend_from_slice(&data);
        out
    }
}

fn scalar_size(ty: u16) -> u32 {
    match ty {
        dt::BOOL | dt::I8 | dt::U8 => 1,
        dt::I16 | dt::U16 => 2,
        dt::I32 | dt::U32 | dt::F32 | dt::STRING | dt::LOCALE | dt::ENUM => 4,
        dt::I64 | dt::U64 | dt::F64 | dt::STRONG | dt::WEAK => 8,
        dt::GUID => 16,
        dt::REFERENCE => 20,
        other => panic!("no scalar size for type {other:#x}"),
    }
}

fn table_len(t: &Tables, ty: u16) -> usize {
    match ty {
        dt::BOOL => t.bool.len(),
        dt::I8 => t.i8.len(),
        dt::U8 => t.u8.len(),
        dt::I16 => t.i16.len() / 2,
        dt::U16 => t.u16.len() / 2,
        dt::I32 => t.i32.len() / 4,
        dt::U32 => t.u32.len() / 4,
        dt::F32 => t.f32.len() / 4,
        dt::I64 => t.i64.len() / 8,
        dt::U64 => t.u64.len() / 8,
        dt::F64 => t.f64.len() / 8,
        dt::GUID => t.guid.len() / 16,
        dt::STRING => t.string.len() / 4,
        dt::LOCALE => t.locale.len() / 4,
        dt::ENUM => t.enum_.len() / 4,
        dt::STRONG => t.strong.len() / 8,
        dt::WEAK => t.weak.len() / 8,
        dt::REFERENCE => t.reference.len() / 20,
        other => panic!("no table for type {other:#x}"),
    }
}

fn write_table_value(ty: u16, v: &V, t: &mut Tables, text: &mut Strings) {
    let buf = match ty {
        dt::BOOL => &mut t.bool,
        dt::I8 => &mut t.i8,
        dt::U8 => &mut t.u8,
        dt::I16 => &mut t.i16,
        dt::U16 => &mut t.u16,
        dt::I32 => &mut t.i32,
        dt::U32 => &mut t.u32,
        dt::F32 => &mut t.f32,
        dt::I64 => &mut t.i64,
        dt::U64 => &mut t.u64,
        dt::F64 => &mut t.f64,
        dt::GUID => &mut t.guid,
        dt::STRING => &mut t.string,
        dt::LOCALE => &mut t.locale,
        dt::ENUM => &mut t.enum_,
        dt::STRONG => &mut t.strong,
        dt::WEAK => &mut t.weak,
        dt::REFERENCE => &mut t.reference,
        other => panic!("no table for type {other:#x}"),
    };
    write_scalar(ty, v, buf, text);
}

fn write_scalar(ty: u16, v: &V, out: &mut Vec<u8>, text: &mut Strings) {
    match (ty, v) {
        (dt::BOOL, V::Bool(b)) => out.push(*b as u8),
        (dt::I8, V::I8(x)) => out.push(*x as u8),
        (dt::U8, V::U8(x)) => out.push(*x),
        (dt::I16, V::I16(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::U16, V::U16(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::I32, V::I32(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::U32, V::U32(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::I64, V::I64(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::U64, V::U64(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::F32, V::F32(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::F64, V::F64(x)) => out.extend_from_slice(&x.to_le_bytes()),
        (dt::STRING, V::Str(s)) | (dt::LOCALE, V::Loc(s)) | (dt::ENUM, V::Enum(s)) => {
            out.extend_from_slice(&text.add(s).to_le_bytes())
        }
        (dt::GUID, V::Guid(g)) => out.extend_from_slice(g),
        (dt::STRONG, V::Strong(p)) | (dt::WEAK, V::Weak(p)) => {
            let (s, i) = p.map(|(s, i)| (s as i32, i as i32)).unwrap_or((-1, -1));
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&i.to_le_bytes());
        }
        (dt::REFERENCE, V::Ref(r)) => match r {
            Some((g, i)) => {
                out.extend_from_slice(&i.to_le_bytes());
                out.extend_from_slice(g);
            }
            None => {
                out.extend_from_slice(&(-1i32).to_le_bytes());
                out.extend_from_slice(&[0u8; 16]);
            }
        },
        (ty, v) => panic!("value {v:?} does not match type {ty:#x}"),
    }
}

/// GUID bytes for a small integer, readable in dumps.
pub fn guid(n: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0] = n;
    g[15] = 0xAA;
    g
}
