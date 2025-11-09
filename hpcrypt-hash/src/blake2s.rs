//! BLAKE2s cryptographic hash function
//!
//! BLAKE2s is a cryptographic hash function optimized for 8- to 32-bit platforms.
//! It produces digests of any size between 1 and 32 bytes.
//!
//! Specified in RFC 7693: <https://tools.ietf.org/html/rfc7693>
//! Target performance: ~5-7 cycles/byte on 32-bit platforms
//!
//! Features:
//! - Arbitrary output length (1-32 bytes)

#![allow(clippy::needless_range_loop)]
//! - Keyed hashing (MAC mode)
//! - Personalization and salt support

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_core::utils::{read_u32_le, write_u32_le, rotr32};

/// BLAKE2s output size (default: 256 bits = 32 bytes)
pub const OUT_LEN: usize = 32;

/// BLAKE2s key size (max: 32 bytes)
pub const KEY_LEN: usize = 32;

/// BLAKE2s block size in bytes
const BLOCK_LEN: usize = 64;

/// BLAKE2s initialization vector
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// BLAKE2s sigma permutation table (same as BLAKE2b)
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

/// BLAKE2s rotation constants
const R1: u32 = 16;
const R2: u32 = 12;
const R3: u32 = 8;
const R4: u32 = 7;

/// BLAKE2s parameters
#[derive(Clone, Debug)]
pub struct Blake2sParams {
    digest_length: u8,
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: u32,
    node_offset: u32,
    node_depth: u16,
    inner_length: u16,
    salt: [u8; 8],
    personalization: [u8; 8],
}

impl Default for Blake2sParams {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sParams {
    pub fn new() -> Self {
        Self {
            digest_length: OUT_LEN as u8,
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_length: 0,
            salt: [0; 8],
            personalization: [0; 8],
        }
    }

    pub fn digest_length(mut self, length: u8) -> Self {
        assert!(length > 0 && length <= OUT_LEN as u8);
        self.digest_length = length;
        self
    }

    pub fn key_length(mut self, length: u8) -> Self {
        assert!(length <= KEY_LEN as u8);
        self.key_length = length;
        self
    }

    pub fn salt(mut self, salt: &[u8]) -> Self {
        assert!(salt.len() <= 8);
        self.salt[..salt.len()].copy_from_slice(salt);
        self
    }

    pub fn personalization(mut self, p: &[u8]) -> Self {
        assert!(p.len() <= 8);
        self.personalization[..p.len()].copy_from_slice(p);
        self
    }

    fn to_iv(&self) -> [u32; 8] {
        let mut iv = IV;

        iv[0] ^= u32::from(self.digest_length)
            | (u32::from(self.key_length) << 8)
            | (u32::from(self.fanout) << 16)
            | (u32::from(self.depth) << 24);

        iv[1] ^= self.leaf_length;
        iv[2] ^= self.node_offset;
        iv[3] ^= u32::from(self.node_depth) | (u32::from(self.inner_length) << 16);

        iv[4] ^= read_u32_le(&self.salt[0..4]);
        iv[5] ^= read_u32_le(&self.salt[4..8]);
        iv[6] ^= read_u32_le(&self.personalization[0..4]);
        iv[7] ^= read_u32_le(&self.personalization[4..8]);

        iv
    }
}

/// BLAKE2s hash state
#[derive(Clone)]
pub struct Blake2s {
    h: [u32; 8],
    t: [u32; 2],
    buf: [u8; BLOCK_LEN],
    buflen: usize,
    digest_length: usize,
}

impl Blake2s {
    pub fn new() -> Self {
        Self::with_params(&Blake2sParams::new())
    }

    pub fn new_with_size(size: usize) -> Self {
        assert!(size > 0 && size <= OUT_LEN);
        Self::with_params(&Blake2sParams::new().digest_length(size as u8))
    }

    pub fn new_keyed(key: &[u8]) -> Self {
        assert!(!key.is_empty() && key.len() <= KEY_LEN);

        let params = Blake2sParams::new().key_length(key.len() as u8);
        let mut hasher = Self::with_params(&params);

        let mut key_block = [0u8; BLOCK_LEN];
        key_block[..key.len()].copy_from_slice(key);
        hasher.update(&key_block);

        hasher
    }

    pub fn with_params(params: &Blake2sParams) -> Self {
        Self {
            h: params.to_iv(),
            t: [0, 0],
            buf: [0; BLOCK_LEN],
            buflen: 0,
            digest_length: params.digest_length as usize,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buflen == BLOCK_LEN {
                self.increment_counter(BLOCK_LEN);
                self.compress(false);
                self.buflen = 0;
            }

            let take = (BLOCK_LEN - self.buflen).min(input.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&input[..take]);
            self.buflen += take;
            input = &input[take..];
        }
    }

    pub fn finalize(mut self) -> Vec<u8> {
        self.increment_counter(self.buflen);

        for i in self.buflen..BLOCK_LEN {
            self.buf[i] = 0;
        }

        self.compress(true);

        let mut out = vec![0u8; self.digest_length];
        let full_bytes = self.digest_length.min(OUT_LEN);

        for i in 0..(full_bytes + 3) / 4 {
            let start = i * 4;
            let end = (start + 4).min(full_bytes);
            let len = end - start;

            let mut word_bytes = [0u8; 4];
            write_u32_le(&mut word_bytes, self.h[i]);
            out[start..end].copy_from_slice(&word_bytes[..len]);
        }

        out
    }

    fn increment_counter(&mut self, inc: usize) {
        self.t[0] = self.t[0].wrapping_add(inc as u32);
        if self.t[0] < inc as u32 {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compress(&mut self, is_last: bool) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = read_u32_le(&self.buf[i * 4..(i + 1) * 4]);
        }

        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&IV);

        v[12] ^= self.t[0];
        v[13] ^= self.t[1];

        if is_last {
            v[14] = !v[14];
        }

        // 10 rounds for BLAKE2s
        for round in 0..10 {
            let s = &SIGMA[round];

            Self::g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

            Self::g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            Self::g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            Self::g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            Self::g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    #[inline(always)]
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = rotr32(v[d] ^ v[a], R1);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = rotr32(v[b] ^ v[c], R2);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = rotr32(v[d] ^ v[a], R3);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = rotr32(v[b] ^ v[c], R4);
    }
}

impl Default for Blake2s {
    fn default() -> Self {
        Self::new()
    }
}

pub fn blake2s(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn blake2s_sized(size: usize, data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s::new_with_size(size);
    hasher.update(data);
    hasher.finalize()
}

pub fn blake2s_keyed(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s::new_keyed(key);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s_empty() {
        let hash = blake2s(b"");
        let expected = hex_literal::hex!(
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
        assert_eq!(hash.as_slice(), &expected[..]);
    }

    #[test]
    fn test_blake2s_abc() {
        let hash = blake2s(b"abc");
        let expected = hex_literal::hex!(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        assert_eq!(hash.as_slice(), &expected[..]);
    }

    #[test]
    fn test_blake2s_custom_size() {
        let hash = blake2s_sized(16, b"test");
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_blake2s_incremental() {
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

        let mac = blake2s_keyed(key, data);
        assert_eq!(mac.len(), 32);

        let unkeyed = blake2s(data);
        assert_ne!(mac, unkeyed);
    }
}
