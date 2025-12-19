//! BLAKE2b cryptographic hash function
//!
//! BLAKE2b is a cryptographic hash function optimized for 64-bit platforms.
//! It provides high performance while maintaining security comparable to SHA-3.
//!
//! # Features
//!
//! - Variable output length (1-64 bytes)
//! - Optional keyed hashing for MAC functionality
//! - Optimized for modern 64-bit processors
//! - No padding requirements for arbitrary-length inputs
//!
//! # Security
//!
//! BLAKE2b provides security equivalent to SHA-3, with performance exceeding
//! SHA-2 and SHA-3 implementations. It is suitable for general-purpose
//! cryptographic hashing, message authentication, and key derivation.
//!
//! # Example
//!
//! ```
//! use hpcrypt_hash::blake2b;
//!
//! let hash = blake2b(b"hello world");
//! assert_eq!(hash.len(), 64);
//! ```

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::min;

/// Maximum output length in bytes (512 bits)
pub const OUT_LEN: usize = 64;

/// Maximum key length in bytes (512 bits)
pub const KEY_LEN: usize = 64;

/// Block size in bytes (1024 bits)
pub const BLOCK_LEN: usize = 128;

/// Initialization vector constants
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

/// Message word permutations for rounds 0-11
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

/// Core mixing function
#[inline(always)]
fn g<const A: usize, const B: usize, const C: usize, const D: usize>(
    v: &mut [u64; 16],
    x: u64,
    y: u64,
) {
    v[A] = v[A].wrapping_add(v[B]).wrapping_add(x);
    v[D] = (v[D] ^ v[A]).rotate_right(32);
    v[C] = v[C].wrapping_add(v[D]);
    v[B] = (v[B] ^ v[C]).rotate_right(24);
    v[A] = v[A].wrapping_add(v[B]).wrapping_add(y);
    v[D] = (v[D] ^ v[A]).rotate_right(16);
    v[C] = v[C].wrapping_add(v[D]);
    v[B] = (v[B] ^ v[C]).rotate_right(63);
}

/// Single compression round
macro_rules! round {
    ($v:expr, $m:expr, $round:expr) => {{
        let s = &SIGMA[$round];
        let m0 = $m[s[0]];
        let m1 = $m[s[1]];
        let m2 = $m[s[2]];
        let m3 = $m[s[3]];
        let m4 = $m[s[4]];
        let m5 = $m[s[5]];
        let m6 = $m[s[6]];
        let m7 = $m[s[7]];
        let m8 = $m[s[8]];
        let m9 = $m[s[9]];
        let m10 = $m[s[10]];
        let m11 = $m[s[11]];
        let m12 = $m[s[12]];
        let m13 = $m[s[13]];
        let m14 = $m[s[14]];
        let m15 = $m[s[15]];

        g::<0, 4, 8, 12>($v, m0, m1);
        g::<1, 5, 9, 13>($v, m2, m3);
        g::<2, 6, 10, 14>($v, m4, m5);
        g::<3, 7, 11, 15>($v, m6, m7);
        g::<0, 5, 10, 15>($v, m8, m9);
        g::<1, 6, 11, 12>($v, m10, m11);
        g::<2, 7, 8, 13>($v, m12, m13);
        g::<3, 4, 9, 14>($v, m14, m15);
    }};
}

/// Complete 12-round compression
macro_rules! rounds_12 {
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
        round!($v, $m, 10);
        round!($v, $m, 11);
    }};
}

/// Load message words from block
#[inline(always)]
fn load_message_words(buf: &[u8; BLOCK_LEN]) -> [u64; 16] {
    [
        u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]),
        u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]),
        u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]),
        u64::from_le_bytes([buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]]),
        u64::from_le_bytes([buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39]]),
        u64::from_le_bytes([buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47]]),
        u64::from_le_bytes([buf[48], buf[49], buf[50], buf[51], buf[52], buf[53], buf[54], buf[55]]),
        u64::from_le_bytes([buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63]]),
        u64::from_le_bytes([buf[64], buf[65], buf[66], buf[67], buf[68], buf[69], buf[70], buf[71]]),
        u64::from_le_bytes([buf[72], buf[73], buf[74], buf[75], buf[76], buf[77], buf[78], buf[79]]),
        u64::from_le_bytes([buf[80], buf[81], buf[82], buf[83], buf[84], buf[85], buf[86], buf[87]]),
        u64::from_le_bytes([buf[88], buf[89], buf[90], buf[91], buf[92], buf[93], buf[94], buf[95]]),
        u64::from_le_bytes([buf[96], buf[97], buf[98], buf[99], buf[100], buf[101], buf[102], buf[103]]),
        u64::from_le_bytes([buf[104], buf[105], buf[106], buf[107], buf[108], buf[109], buf[110], buf[111]]),
        u64::from_le_bytes([buf[112], buf[113], buf[114], buf[115], buf[116], buf[117], buf[118], buf[119]]),
        u64::from_le_bytes([buf[120], buf[121], buf[122], buf[123], buf[124], buf[125], buf[126], buf[127]]),
    ]
}

/// Block compression function
#[inline(always)]
fn compress(h: &mut [u64; 8], m: &[u64; 16], t: [u64; 2], f: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);

    v[12] ^= t[0];
    v[13] ^= t[1];

    if f {
        v[14] = !v[14];
    }

    rounds_12!(&mut v, m);

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b hash state
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    t: [u64; 2],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    out_len: usize,
}

impl Blake2b {
    /// Creates a hasher with specified output length
    ///
    /// # Panics
    ///
    /// Panics if `out_len` is zero or greater than 64
    pub fn new_with_output_len(out_len: usize) -> Self {
        assert!(out_len > 0 && out_len <= OUT_LEN, "Invalid output length");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ (out_len as u64);

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
    /// Panics if key length exceeds 64 bytes or output length is invalid
    pub fn new_keyed(key: &[u8], out_len: usize) -> Self {
        assert!(key.len() <= KEY_LEN, "Key too long");
        assert!(out_len > 0 && out_len <= OUT_LEN, "Invalid output length");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ ((key.len() as u64) << 8) ^ (out_len as u64);

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
        let inc_u64 = inc as u64;
        self.t[0] = self.t[0].wrapping_add(inc_u64);
        if self.t[0] < inc_u64 {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    /// Internal method: processes input data
    fn update_internal(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buf_len == BLOCK_LEN {
                self.increment_counter(BLOCK_LEN);
                let m = load_message_words(&self.buf);
                compress(&mut self.h, &m, self.t, false);
                self.buf_len = 0;
            }

            let take = min(BLOCK_LEN - self.buf_len, input.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
    }

    /// Internal method: completes hashing and returns variable-length digest
    fn finalize_internal(mut self) -> Vec<u8> {
        self.increment_counter(self.buf_len);
        self.buf[self.buf_len..].fill(0);

        let m = load_message_words(&self.buf);
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

    /// Internal method: completes hashing and returns a 64-byte digest
    fn finalize_fixed_internal(mut self) -> [u8; OUT_LEN] {
        self.increment_counter(self.buf_len);
        self.buf[self.buf_len..].fill(0);

        let m = load_message_words(&self.buf);
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
        Self::new_with_output_len(OUT_LEN)
    }
}

impl crate::traits::HashFunction for Blake2b {
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

/// Computes BLAKE2b hash of data
pub fn blake2b(data: &[u8]) -> [u8; OUT_LEN] {
    use crate::traits::HashFunction;
    Blake2b::hash(data)
}

/// Computes BLAKE2b hash with custom length
pub fn blake2b_variable(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Blake2b::new_with_output_len(out_len);
    hasher.update_internal(data);
    hasher.finalize_internal()
}

/// Computes keyed BLAKE2b for MAC generation
pub fn blake2b_mac(key: &[u8], data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Blake2b::new_keyed(key, OUT_LEN);
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
        use crate::traits::HashFunction;
        let data = b"The quick brown fox jumps over the lazy dog";

        let hash1 = blake2b(data);

        let mut hasher = Blake2b::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake2b_keyed() {
        let key = b"secret key";
        let data = b"message";

        let mac = blake2b_mac(key, data);
        let unkeyed = blake2b(data);
        assert_ne!(mac, unkeyed);
    }
}
