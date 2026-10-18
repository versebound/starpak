//! AES-128-CBC decryption of encrypted p4k payloads.
//!
//! Encrypted entries use a fixed, publicly known key, an all-zero IV and no
//! padding scheme: the writer zero-fills the last block and relies on the
//! uncompressed size (or the zstd frame header) to delimit real data.

use std::io::{self, Read};

use aes::cipher::consts::U16;
use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockDecryptMut, KeyIvInit};

type Decryptor = cbc::Decryptor<aes::Aes128>;

/// Key used by every known Star Citizen `Data.p4k`.
pub const P4K_KEY: [u8; 16] = [
    0x5E, 0x7A, 0x20, 0x02, 0x30, 0x2E, 0xEB, 0x1A, 0x3B, 0xB6, 0x17, 0xC3, 0x0F, 0xDE, 0x1E, 0x47,
];

/// AES block size in bytes.
pub const BLOCK: usize = 16;

fn decryptor(key: &[u8; 16]) -> Decryptor {
    Decryptor::new(key.into(), &[0u8; BLOCK].into())
}

fn decrypt_blocks(dec: &mut Decryptor, buf: &mut [u8]) {
    debug_assert_eq!(buf.len() % BLOCK, 0);
    let (blocks, tail) = InOutBuf::from(buf).into_chunks::<U16>();
    debug_assert!(tail.is_empty());
    dec.decrypt_blocks_inout_mut(blocks);
}

/// Decrypts `buf` in place. `buf.len()` must be a multiple of 16.
pub fn decrypt_in_place(key: &[u8; 16], buf: &mut [u8]) {
    let mut dec = decryptor(key);
    decrypt_blocks(&mut dec, buf);
}

/// Streaming CBC decryptor over any `Read`.
pub struct CbcReader<R> {
    inner: R,
    dec: Decryptor,
    buf: Vec<u8>,
    /// Bytes `buf[pos..len]` are decrypted and ready to serve.
    pos: usize,
    len: usize,
    /// Undecrypted tail bytes (fewer than one block) kept for the next fill.
    carry: usize,
    eof: bool,
}

impl<R: Read> CbcReader<R> {
    /// Wraps `inner`, decrypting with `key` in chunks of `chunk` bytes
    /// (rounded up to a block multiple).
    pub fn new(inner: R, key: &[u8; 16], chunk: usize) -> Self {
        let cap = chunk.max(BLOCK).div_ceil(BLOCK) * BLOCK;
        CbcReader {
            inner,
            dec: decryptor(key),
            buf: vec![0u8; cap],
            pos: 0,
            len: 0,
            carry: 0,
            eof: false,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        // Move any undecrypted partial block to the front.
        let carry = self.carry;
        if carry > 0 {
            let start = self.len;
            self.buf.copy_within(start..start + carry, 0);
        }
        let mut filled = carry;
        while filled < self.buf.len() {
            match self.inner.read(&mut self.buf[filled..]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let whole = filled / BLOCK * BLOCK;
        let rest = filled - whole;
        if self.eof && rest != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encrypted payload is not a multiple of the AES block size",
            ));
        }
        decrypt_blocks(&mut self.dec, &mut self.buf[..whole]);
        self.pos = 0;
        self.len = whole;
        self.carry = rest;
        Ok(())
    }
}

impl<R: Read> Read for CbcReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos == self.len {
            if self.eof {
                return Ok(0);
            }
            self.fill()?;
            if self.len == 0 {
                return Ok(0);
            }
        }
        let n = (self.len - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncryptMut;

    pub(crate) fn encrypt(key: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        let mut buf = plain.to_vec();
        let pad = (BLOCK - buf.len() % BLOCK) % BLOCK;
        buf.extend(std::iter::repeat_n(0u8, pad));
        let mut enc = cbc::Encryptor::<aes::Aes128>::new(key.into(), &[0u8; BLOCK].into());
        let (blocks, _) = InOutBuf::from(&mut buf[..]).into_chunks::<U16>();
        enc.encrypt_blocks_inout_mut(blocks);
        buf
    }

    #[test]
    fn roundtrip_bulk_and_stream() {
        let plain: Vec<u8> = (0..100_003u32).map(|i| (i * 7 % 251) as u8).collect();
        let cipher = encrypt(&P4K_KEY, &plain);
        assert_eq!(cipher.len() % BLOCK, 0);

        let mut bulk = cipher.clone();
        decrypt_in_place(&P4K_KEY, &mut bulk);
        assert_eq!(&bulk[..plain.len()], &plain[..]);

        for chunk in [16usize, 17, 1000, 65536, 1 << 20] {
            let mut r = CbcReader::new(&cipher[..], &P4K_KEY, chunk);
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            assert_eq!(&out[..plain.len()], &plain[..], "chunk {chunk}");
            assert_eq!(out.len(), cipher.len());
        }
    }

    #[test]
    fn stream_rejects_partial_block() {
        let cipher = encrypt(&P4K_KEY, b"hello world, this is longer than one block");
        let mut r = CbcReader::new(&cipher[..cipher.len() - 3], &P4K_KEY, 16);
        let mut out = Vec::new();
        let err = r.read_to_end(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stream_small_reads() {
        let plain = vec![0xABu8; 4096 + 16];
        let cipher = encrypt(&P4K_KEY, &plain);
        let mut r = CbcReader::new(&cipher[..], &P4K_KEY, 48);
        let mut out = Vec::new();
        let mut tmp = [0u8; 7];
        loop {
            let n = r.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(out, plain);
        assert_eq!(r.read(&mut []).unwrap(), 0);
    }
}
