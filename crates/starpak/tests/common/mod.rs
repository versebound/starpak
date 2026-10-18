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
