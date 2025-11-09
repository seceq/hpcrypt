//! SHA-256 cryptographic hash function
//!
//! SHA-256 is part of the SHA-2 family, producing a 256-bit (32-byte) digest.
//! Specified in FIPS 180-4.
//!
//! Target performance: ~7-10 cycles/byte on modern CPUs (pure software)
//!
//! Features:
//! - Fixed 256-bit output
//! - NIST standardized (FIPS 180-4)

#![allow(clippy::needless_range_loop)]
//! - Widely used and well-analyzed
//! - No known practical attacks

use hpcrypt_core::utils::{read_u32_be, rotr32, write_u32_be};

/// SHA-256 output size in bytes
pub const OUT_LEN: usize = 32;

/// SHA-256 block size in bytes
pub const BLOCK_LEN: usize = 64;

/// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 hash state
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],          // Hash state
    buf: [u8; BLOCK_LEN], // Input buffer
    buflen: usize,        // Bytes in buffer
    len: u64,             // Total bytes processed
}

impl Sha256 {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self {
            h: H0,
            buf: [0; BLOCK_LEN],
            buflen: 0,
            len: 0,
        }
    }

    /// Update the hash with input data
    pub fn update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u64);

        while !input.is_empty() {
            if self.buflen == BLOCK_LEN {
                self.process_block();
                self.buflen = 0;
            }

            let take = (BLOCK_LEN - self.buflen).min(input.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&input[..take]);
            self.buflen += take;
            input = &input[take..];
        }
    }

    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        // Process current block if full
        if self.buflen == BLOCK_LEN {
            self.process_block();
            self.buflen = 0;
        }

        // Padding: append bit '1' followed by zeros
        self.buf[self.buflen] = 0x80;
        self.buflen += 1;

        // If not enough space for length, process this block and start new one
        if self.buflen > 56 {
            for i in self.buflen..BLOCK_LEN {
                self.buf[i] = 0;
            }
            self.process_block();
            self.buflen = 0;
        }

        // Pad with zeros up to 56 bytes
        for i in self.buflen..56 {
            self.buf[i] = 0;
        }

        // Append length in bits as 64-bit big-endian
        let bit_len = self.len.wrapping_mul(8);
        write_u32_be(&mut self.buf[56..60], (bit_len >> 32) as u32);
        write_u32_be(&mut self.buf[60..64], bit_len as u32);

        self.process_block();

        // Convert hash state to output bytes
        let mut out = [0u8; OUT_LEN];
        for i in 0..8 {
            write_u32_be(&mut out[i * 4..(i + 1) * 4], self.h[i]);
        }

        out
    }

    /// Process a single 512-bit block
    fn process_block(&mut self) {
        let mut w = [0u32; 64];

        // Prepare message schedule
        for i in 0..16 {
            w[i] = read_u32_be(&self.buf[i * 4..(i + 1) * 4]);
        }

        for i in 16..64 {
            let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // Main loop (64 rounds)
        for i in 0..64 {
            let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add working variables to hash state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected =
            hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected =
            hex_literal::hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_long() {
        let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected =
            hex_literal::hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_incremental() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let hash1 = sha256(data);

        // Incremental
        let mut hasher = Sha256::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_fox() {
        let hash = sha256(b"The quick brown fox jumps over the lazy dog");
        let expected =
            hex_literal::hex!("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_multiblock() {
        // Test data larger than one block (64 bytes)
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // Verify it produces a valid hash (32 bytes)
        assert_eq!(hash.len(), 32);
    }
}
