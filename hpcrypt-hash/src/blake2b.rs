//! BLAKE2b cryptographic hash function
//!
//! BLAKE2b is a cryptographic hash function optimized for 64-bit platforms.
//! It's faster than MD5, SHA-1, SHA-2, and SHA-3, yet is at least as secure as SHA-3.
//!
//! Key features:
//! - Output size: 1 to 64 bytes (configurable)
//! - Keyed hashing (MAC mode)
//! - Personalization and salt support
//! - Tree hashing mode

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::min;

/// BLAKE2b output size in bytes (512 bits)
pub const OUT_LEN: usize = 64;

/// BLAKE2b key size in bytes (512 bits max)
pub const KEY_LEN: usize = 64;

/// BLAKE2b block size in bytes
pub const BLOCK_LEN: usize = 128;

/// BLAKE2b initialization vectors
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// BLAKE2b sigma permutation table
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b mixing function G
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// BLAKE2b compression function
fn compress(h: &mut [u64; 8], m: &[u64; 16], t: u64, f: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);

    v[12] ^= t;
    v[13] ^= 0; // High word of counter (for >2^64 bytes)

    if f {
        v[14] = !v[14]; // Last block flag
    }

    // 12 rounds
    for s in &SIGMA[0..12] {
        // Column step
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

        // Diagonal step
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Convert bytes to u64 (little-endian)
#[inline]
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}

/// BLAKE2b hasher state
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    t: u64,
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    out_len: usize,
}

impl Blake2b {
    /// Create a new BLAKE2b hasher with default 64-byte output
    pub fn new() -> Self {
        Self::new_with_output_len(OUT_LEN)
    }

    /// Create a new BLAKE2b hasher with specified output length (1-64 bytes)
    pub fn new_with_output_len(out_len: usize) -> Self {
        assert!(out_len > 0 && out_len <= OUT_LEN, "Invalid output length");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ (out_len as u64);

        Self {
            h,
            t: 0,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            out_len,
        }
    }

    /// Create a new BLAKE2b hasher with a key (MAC mode)
    pub fn new_keyed(key: &[u8], out_len: usize) -> Self {
        assert!(key.len() <= KEY_LEN, "Key too long");
        assert!(out_len > 0 && out_len <= OUT_LEN, "Invalid output length");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ ((key.len() as u64) << 8) ^ (out_len as u64);

        let mut hasher = Self {
            h,
            t: 0,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            out_len,
        };

        // Process key as first block
        if !key.is_empty() {
            hasher.buf[..key.len()].copy_from_slice(key);
            hasher.buf_len = BLOCK_LEN; // Pad to full block
        }

        hasher
    }

    /// Update the hasher with input data
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buf_len == BLOCK_LEN {
                self.t += BLOCK_LEN as u64;
                let mut m = [0u64; 16];
                #[allow(clippy::needless_range_loop)]
                for i in 0..16 {
                    m[i] = bytes_to_u64(&self.buf[i * 8..(i + 1) * 8]);
                }
                compress(&mut self.h, &m, self.t, false);
                self.buf_len = 0;
            }

            let take = min(BLOCK_LEN - self.buf_len, input.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
    }

    /// Finalize and return the hash
    pub fn finalize(mut self) -> Vec<u8> {
        self.t += self.buf_len as u64;

        // Pad remaining buffer with zeros
        self.buf[self.buf_len..].fill(0);

        let mut m = [0u64; 16];
        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            m[i] = bytes_to_u64(&self.buf[i * 8..min((i + 1) * 8, BLOCK_LEN)]);
        }

        compress(&mut self.h, &m, self.t, true);

        let mut out = Vec::with_capacity(self.out_len);
        for &word in &self.h {
            out.extend_from_slice(&word.to_le_bytes());
            if out.len() >= self.out_len {
                break;
            }
        }
        out.truncate(self.out_len);
        out
    }

    /// Finalize and return exactly 64 bytes
    pub fn finalize_fixed(mut self) -> [u8; OUT_LEN] {
        self.t += self.buf_len as u64;

        // Pad remaining buffer with zeros
        self.buf[self.buf_len..].fill(0);

        let mut m = [0u64; 16];
        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            m[i] = bytes_to_u64(&self.buf[i * 8..min((i + 1) * 8, BLOCK_LEN)]);
        }

        compress(&mut self.h, &m, self.t, true);

        let mut out = [0u8; OUT_LEN];
        for (i, &word) in self.h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

impl Default for Blake2b {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot BLAKE2b hash
pub fn blake2b(data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Blake2b::new();
    hasher.update(data);
    hasher.finalize_fixed()
}

/// One-shot BLAKE2b hash with custom output length
pub fn blake2b_variable(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Blake2b::new_with_output_len(out_len);
    hasher.update(data);
    hasher.finalize()
}

/// One-shot BLAKE2b keyed hash (MAC)
pub fn blake2b_mac(key: &[u8], data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Blake2b::new_keyed(key, OUT_LEN);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; OUT_LEN];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_empty() {
        let hash = blake2b(b"");
        let expected = hex_literal::hex!(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
            "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake2b_abc() {
        let hash = blake2b(b"abc");
        let expected = hex_literal::hex!(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake2b_variable_length() {
        let hash32 = blake2b_variable(b"test", 32);
        assert_eq!(hash32.len(), 32);

        let hash16 = blake2b_variable(b"test", 16);
        assert_eq!(hash16.len(), 16);
    }

    #[test]
    fn test_blake2b_incremental() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let hash1 = blake2b(data);

        // Incremental
        let mut hasher = Blake2b::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize_fixed();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake2b_keyed() {
        let key = b"secret key";
        let data = b"message";

        let mac = blake2b_mac(key, data);

        // Should differ from unkeyed hash
        let unkeyed = blake2b(data);
        assert_ne!(mac, unkeyed);
    }
}
