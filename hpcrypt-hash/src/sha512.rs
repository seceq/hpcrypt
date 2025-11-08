//! SHA-512 cryptographic hash function

#![allow(clippy::needless_range_loop)]
//!
//! SHA-512 is part of the SHA-2 family, producing a 512-bit (64-byte) digest.
//! Specified in FIPS 180-4.
//!
//! Target performance: ~7-10 cycles/byte on 64-bit platforms
//!
//! Features:
//! - Fixed 512-bit output
//! - NIST standardized (FIPS 180-4)
//! - Optimized for 64-bit platforms

use hpcrypt_core::utils::{read_u64_be, rotr64, write_u64_be};

/// SHA-512 output size in bytes
pub const OUT_LEN: usize = 64;

/// SHA-512 block size in bytes
pub const BLOCK_LEN: usize = 128;

/// SHA-512 initial hash values
const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// SHA-512 round constants
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 hash state
#[derive(Clone)]
pub struct Sha512 {
    h: [u64; 8],
    buf: [u8; BLOCK_LEN],
    buflen: usize,
    len: u128, // Use u128 to support larger messages
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            h: H0,
            buf: [0; BLOCK_LEN],
            buflen: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u128);

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

    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        // Process current block if full
        if self.buflen == BLOCK_LEN {
            self.process_block();
            self.buflen = 0;
        }

        // Padding: append bit '1' followed by zeros
        self.buf[self.buflen] = 0x80;
        self.buflen += 1;

        // If not enough space for length (16 bytes), process this block and start new one
        if self.buflen > 112 {
            for i in self.buflen..BLOCK_LEN {
                self.buf[i] = 0;
            }
            self.process_block();
            self.buflen = 0;
        }

        // Pad with zeros up to 112 bytes
        for i in self.buflen..112 {
            self.buf[i] = 0;
        }

        // Append length in bits as 128-bit big-endian
        let bit_len = self.len.wrapping_mul(8);
        write_u64_be(&mut self.buf[112..120], (bit_len >> 64) as u64);
        write_u64_be(&mut self.buf[120..128], bit_len as u64);

        self.process_block();

        // Convert hash state to output bytes
        let mut out = [0u8; OUT_LEN];
        for i in 0..8 {
            write_u64_be(&mut out[i * 8..(i + 1) * 8], self.h[i]);
        }

        out
    }

    fn process_block(&mut self) {
        let mut w = [0u64; 80];

        // Prepare message schedule
        for i in 0..16 {
            w[i] = read_u64_be(&self.buf[i * 8..(i + 1) * 8]);
        }

        for i in 16..80 {
            let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
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

        // Main loop (80 rounds)
        for i in 0..80 {
            let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
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

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha512(data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_empty() {
        let hash = sha512(b"");
        let expected = hex_literal::hex!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha512_abc() {
        let hash = sha512(b"abc");
        let expected = hex_literal::hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha512_long() {
        let hash = sha512(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let expected = hex_literal::hex!(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha512_incremental() {
        let data = b"The quick brown fox jumps over the lazy dog";

        let hash1 = sha512(data);

        let mut hasher = Sha512::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha512_fox() {
        let hash = sha512(b"The quick brown fox jumps over the lazy dog");
        let expected = hex_literal::hex!(
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64"
            "2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
        );
        assert_eq!(hash, expected);
    }
}
