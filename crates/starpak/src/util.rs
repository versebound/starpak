//! Small byte-level helpers: little-endian readers, positional I/O and
//! case/separator-insensitive path handling.

use std::fs::File;
use std::io;

/// Little-endian cursor over a byte slice with bounds checking.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct Le<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

#[allow(dead_code)]
impl<'a> Le<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Le { buf, pos: 0 }
    }

    pub fn at(buf: &'a [u8], pos: usize) -> Self {
        Le { buf, pos }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn has(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if !self.has(n) {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.bytes(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }

    pub fn u64(&mut self) -> Option<u64> {
        self.bytes(8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}

/// Reads `buf.len()` bytes at absolute `offset` without touching the file
/// cursor, so concurrent readers never interfere with each other.
pub(crate) fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of file",
                ));
            }
            done += n;
        }
        Ok(())
    }
}

/// Positional read that may return fewer bytes than requested.
pub(crate) fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buf, offset)
    }
}

/// Normalises one path byte for lookups: `\` becomes `/` and ASCII upper
/// case becomes lower case.
#[inline]
pub(crate) fn norm_byte(b: u8) -> u8 {
    match b {
        b'\\' => b'/',
        b'A'..=b'Z' => b | 0x20,
        _ => b,
    }
}

/// SWAR normalisation of eight path bytes at once (see [`norm_byte`]).
#[inline]
fn norm_word(w: u64) -> u64 {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    const LOW7: u64 = 0x7F7F_7F7F_7F7F_7F7F;
    // Lower-case: bytes in 'A'..='Z' get bit 5 set. Arithmetic runs on the
    // low seven bits so no carry can leak into a neighbouring byte.
    let w7 = w & LOW7;
    let ge_a = w7.wrapping_add(ONES * (0x80 - b'A' as u64)); // high bit where byte >= 'A'
    let gt_z = w7.wrapping_add(ONES * (0x80 - b'Z' as u64 - 1)); // high bit where byte > 'Z'
    let upper = ge_a & !gt_z & !w & HIGH;
    let lowered = w | (upper >> 2);
    // Backslash -> slash: exact per-byte zero test on `byte ^ '\\'`.
    let x = lowered ^ (ONES * b'\\' as u64);
    let zero = !((x & LOW7).wrapping_add(LOW7) | x | LOW7); // 0x80 where byte == '\\'
    lowered ^ ((zero >> 7) * (b'\\' ^ b'/') as u64)
}

/// Hashes a path in its normalised form (case-insensitive, separator
/// agnostic) without allocating.
#[inline]
pub(crate) fn hash_path(bytes: &[u8]) -> u64 {
    const K: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut h: u64 = bytes.len() as u64 ^ K;
    let mut chunks = bytes.chunks_exact(8);
    for c in &mut chunks {
        let w = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        h = (h.rotate_left(29) ^ norm_word(w)).wrapping_mul(K);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let mut tmp = [0u8; 8];
        tmp[..rest.len()].copy_from_slice(rest);
        let w = u64::from_le_bytes(tmp);
        h = (h.rotate_left(29) ^ norm_word(w)).wrapping_mul(K);
    }
    h ^ (h >> 32)
}

/// Compares two paths in normalised form.
#[inline]
pub(crate) fn path_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut ca = a.chunks_exact(8);
    let mut cb = b.chunks_exact(8);
    for (x, y) in (&mut ca).zip(&mut cb) {
        let wx = u64::from_le_bytes([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]]);
        let wy = u64::from_le_bytes([y[0], y[1], y[2], y[3], y[4], y[5], y[6], y[7]]);
        if norm_word(wx) != norm_word(wy) {
            return false;
        }
    }
    ca.remainder()
        .iter()
        .zip(cb.remainder())
        .all(|(&x, &y)| norm_byte(x) == norm_byte(y))
}

/// True when `name` starts with `prefix` in normalised form.
#[inline]
pub(crate) fn path_starts_with(name: &[u8], prefix: &[u8]) -> bool {
    name.len() >= prefix.len() && path_eq(&name[..prefix.len()], prefix)
}

/// Strips leading separators and `./` segments from a lookup path.
pub(crate) fn trim_lookup_path(path: &str) -> &str {
    let mut p = path;
    loop {
        if let Some(rest) = p.strip_prefix('/').or_else(|| p.strip_prefix('\\')) {
            p = rest;
        } else if let Some(rest) = p.strip_prefix("./").or_else(|| p.strip_prefix(".\\")) {
            p = rest;
        } else {
            return p;
        }
    }
}

/// Writes `name` into `out` in normalised form (lower-case, `/` separators).
pub(crate) fn normalize_into(name: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend(name.iter().map(|&b| norm_byte(b)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swar_normalisation_matches_scalar() {
        let samples: &[&[u8]] = &[
            b"Data\\Scripts\\Entities\\Vehicles.XML",
            b"abc/DEF\\gHi",
            b"\\\\\\\\\\\\\\\\",
            b"AZ[`az{@",
            b"\x00\xff\x7f\x80ABCZ",
            b"\\\x01\\\x01\x5b\x5d\xc1\xda",
            b"@[`{\x40\x5a\x41\x7a",
        ];
        for s in samples {
            let scalar: Vec<u8> = s.iter().map(|&b| norm_byte(b)).collect();
            let mut swar = Vec::new();
            for c in s.chunks(8) {
                let mut tmp = [0u8; 8];
                tmp[..c.len()].copy_from_slice(c);
                let w = norm_word(u64::from_le_bytes(tmp));
                swar.extend_from_slice(&w.to_le_bytes()[..c.len()]);
            }
            assert_eq!(scalar, swar, "{:?}", String::from_utf8_lossy(s));
        }
    }

    #[test]
    fn hash_and_eq_are_normalisation_invariant() {
        assert_eq!(
            hash_path(b"Data\\Scripts\\A.xml"),
            hash_path(b"data/scripts/a.XML")
        );
        assert!(path_eq(b"Data\\Scripts\\A.xml", b"data/scripts/a.XML"));
        assert!(!path_eq(b"Data\\Scripts\\A.xml", b"data/scripts/b.XML"));
        assert!(!path_eq(b"abc", b"abcd"));
        assert_ne!(hash_path(b"abc"), hash_path(b"abd"));
        assert!(path_starts_with(b"Data\\Scripts\\A.xml", b"data/scripts/"));
        assert!(!path_starts_with(b"Data", b"data/scripts/"));
    }

    #[test]
    fn trim_lookup() {
        assert_eq!(trim_lookup_path("/Data/x"), "Data/x");
        assert_eq!(trim_lookup_path("./\\Data"), "Data");
        assert_eq!(trim_lookup_path("Data"), "Data");
    }

    #[test]
    fn le_cursor_bounds() {
        let mut c = Le::new(&[1, 0, 2, 0, 0, 0]);
        assert_eq!(c.u16(), Some(1));
        assert_eq!(c.u32(), Some(2));
        assert_eq!(c.u8(), None);
        assert_eq!(c.remaining(), 0);
    }
}
