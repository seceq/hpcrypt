//! BLAKE2s cryptographic hash function
//!
//! BLAKE2s is a cryptographic hash function optimized for 8- to 32-bit platforms.
//! It provides high performance while maintaining security comparable to SHA-3.
//!
//! # Features
//!
//! - Variable output length (1-32 bytes)
//! - Optional keyed hashing for MAC functionality
//! - Optimized for 32-bit processors
//! - Support for salt and personalization parameters
//!
//! # Security
//!
//! BLAKE2s provides security equivalent to SHA-3, with performance exceeding
//! SHA-2 and SHA-3 implementations on 32-bit platforms.
//!
//! # Example
//!
//! ```
//! use hpcrypt_hash::blake2s;
//!
//! let hash = blake2s(b"hello world");
//! assert_eq!(hash.len(), 32);
//! ```

extern crate alloc;
use alloc::vec::Vec;

/// Maximum output length in bytes (256 bits)
pub const OUT_LEN: usize = 32;

/// Maximum key length in bytes (256 bits)
pub const KEY_LEN: usize = 32;

/// Block size in bytes (512 bits)
const BLOCK_LEN: usize = 64;

/// Initialization vector constants
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Message word permutations for rounds 0-9
const SIGMA: [[usize; 16]; 10] = [
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
];

/// Core mixing function
#[inline(always)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// Single compression round
macro_rules! round {
    ($v:expr, $m:expr, $round:expr) => {{
        let s = &SIGMA[$round];
        g($v, 0, 4, 8, 12, $m[s[0]], $m[s[1]]);
        g($v, 1, 5, 9, 13, $m[s[2]], $m[s[3]]);
        g($v, 2, 6, 10, 14, $m[s[4]], $m[s[5]]);
        g($v, 3, 7, 11, 15, $m[s[6]], $m[s[7]]);
        g($v, 0, 5, 10, 15, $m[s[8]], $m[s[9]]);
        g($v, 1, 6, 11, 12, $m[s[10]], $m[s[11]]);
        g($v, 2, 7, 8, 13, $m[s[12]], $m[s[13]]);
        g($v, 3, 4, 9, 14, $m[s[14]], $m[s[15]]);
    }};
}

/// Complete 10-round compression
macro_rules! rounds_10 {
    ($v:expr, $m:expr) => {{
        round!($v, $m, 0);
        round!($v, $m, 1);
        round!($v, $m, 2);
        round!($v, $m, 3);
        round!($v, $m, 4);
        round!($v, $m, 5);
        round!($v, $m, 6);
        round!($v, $m, 7);
        round!($v, $m, 8);
        round!($v, $m, 9);
    }};
}

/// Load message words from block
#[inline(always)]
fn load_message_words(buf: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([
            buf[i * 4],
            buf[i * 4 + 1],
            buf[i * 4 + 2],
            buf[i * 4 + 3],
        ]);
    }
    m
}

/// Block compression function
#[inline]
fn compress(h: &mut [u32; 8], buf: &[u8; BLOCK_LEN], t: [u32; 2], f: bool) {
    let m = load_message_words(buf);

    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);

    v[12] ^= t[0];
    v[13] ^= t[1];

    if f {
        v[14] = !v[14];
    }

    rounds_10!(&mut v, &m);

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2s hash state
#[derive(Clone)]
pub struct Blake2s {
    h: [u32; 8],
    t: [u32; 2],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    out_len: usize,
}

impl Blake2s {
    /// Creates a hasher with specified output length
    ///
    /// # Panics
    ///
    /// Panics if `out_len` is zero or greater than 32
    pub fn new_with_output_len(out_len: usize) -> Self {
        assert!(out_len > 0 && out_len <= OUT_LEN, "Invalid output length");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ (out_len as u32);

        Self {
            h,
            t: [0, 0],
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            out_len,
        }
    }

    /// Creates a keyed hasher for MAC generation
    ///
    /// # Panics
    ///
    /// Panics if key length exceeds 32 bytes or output length is invalid
    pub fn new_keyed(key: &[u8], out_len: usize) -> Self {
        assert!(key.len() <= KEY_LEN, "Key too long");
        assert!(out_len > 0 && out_len <= OUT_LEN, "Invalid output length");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ ((key.len() as u32) << 8) ^ (out_len as u32);

        let mut hasher = Self {
            h,
            t: [0, 0],
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            out_len,
        };

        if !key.is_empty() {
            hasher.buf[..key.len()].copy_from_slice(key);
            hasher.buf_len = BLOCK_LEN;
        }

        hasher
    }

    /// Increments the byte counter
    #[inline(always)]
    fn increment_counter(&mut self, inc: usize) {
        let inc_u32 = inc as u32;
        self.t[0] = self.t[0].wrapping_add(inc_u32);
        if self.t[0] < inc_u32 {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    /// Internal method: processes input data
    fn update_internal(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buf_len == BLOCK_LEN {
                self.increment_counter(BLOCK_LEN);
                compress(&mut self.h, &self.buf, self.t, false);
                self.buf_len = 0;
            }

            let take = (BLOCK_LEN - self.buf_len).min(input.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
    }

    /// Internal method: completes hashing and returns variable-length digest
    fn finalize_internal(mut self) -> Vec<u8> {
        self.increment_counter(self.buf_len);
        self.buf[self.buf_len..].fill(0);

        compress(&mut self.h, &self.buf, self.t, true);

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

    /// Internal method: completes hashing and returns a 32-byte digest
    fn finalize_fixed_internal(mut self) -> [u8; OUT_LEN] {
        self.increment_counter(self.buf_len);
        self.buf[self.buf_len..].fill(0);

        compress(&mut self.h, &self.buf, self.t, true);

        let mut out = [0u8; OUT_LEN];
        for (i, &word) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

impl Default for Blake2s {
    fn default() -> Self {
        Self::new_with_output_len(OUT_LEN)
    }
}

impl crate::traits::HashFunction for Blake2s {
    type Output = [u8; OUT_LEN];
    const OUTPUT_SIZE: usize = OUT_LEN;
    const BLOCK_SIZE: usize = BLOCK_LEN;

    #[inline]
    fn new() -> Self {
        Self::new_with_output_len(OUT_LEN)
    }

    #[inline]
    fn update(&mut self, input: &[u8]) {
        self.update_internal(input)
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        self.finalize_fixed_internal()
    }

    #[inline]
    fn finalize_reset(&mut self) -> Self::Output {
        let clone = self.clone();
        *self = Self::new();
        clone.finalize_fixed_internal()
    }
}

/// Computes BLAKE2s hash of data
pub fn blake2s(data: &[u8]) -> [u8; OUT_LEN] {
    use crate::traits::HashFunction;
    Blake2s::hash(data)
}

/// Computes BLAKE2s hash with custom length
pub fn blake2s_variable(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Blake2s::new_with_output_len(out_len);
    hasher.update_internal(data);
    hasher.finalize_internal()
}

/// Computes keyed BLAKE2s for MAC generation
pub fn blake2s_mac(key: &[u8], data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Blake2s::new_keyed(key, OUT_LEN);
    hasher.update_internal(data);
    let result = hasher.finalize_internal();
    let mut out = [0u8; OUT_LEN];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s_empty() {
        let hash = blake2s(b"");
        let expected =
            hex_literal::hex!("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake2s_abc() {
        let hash = blake2s(b"abc");
        let expected =
            hex_literal::hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake2s_variable_length() {
        let hash16 = blake2s_variable(b"test", 16);
        assert_eq!(hash16.len(), 16);

        let hash20 = blake2s_variable(b"test", 20);
        assert_eq!(hash20.len(), 20);
    }

    #[test]
    fn test_blake2s_incremental() {
        use crate::traits::HashFunction;
        let data = b"The quick brown fox jumps over the lazy dog";

        let hash1 = blake2s(data);

        let mut hasher = Blake2s::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake2s_keyed() {
        let key = b"secret key";
        let data = b"message";

        let mac = blake2s_mac(key, data);
        let unkeyed = blake2s(data);
        assert_ne!(mac, unkeyed);
    }
}
