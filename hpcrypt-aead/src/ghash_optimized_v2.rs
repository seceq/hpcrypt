//! Optimized GHASH - Software-only optimizations
//!
//! Implements:
//! 1. Table-free carry-less multiplication (BearSSL approach)
//! 2. Karatsuba algorithm (3 muls vs 4)
//! 3. Barrett reduction
//! 4. Powers of H for parallelism

mod ctmul;

use core::convert::TryInto;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const BLOCK_SIZE: usize = 16;
const REDUCTION_CONST: u64 = 0xc200000000000000;

// Re-export from ctmul module
use ctmul::carryless_mul_64;

/// Karatsuba: Multiply 128x128 -> 256 bits using only 3 64x64 multiplications
#[inline]
fn karatsuba_mul_128(a: [u64; 2], b: [u64; 2]) -> [u64; 4] {
    let a0 = a[1];
    let a1 = a[0];
    let b0 = b[1];
    let b1 = b[0];

    let z0 = carryless_mul_64(a0, b0);
    let z2 = carryless_mul_64(a1, b1);
    let z1 = carryless_mul_64(a0 ^ a1, b0 ^ b1);

    let z1_corrected = [z1[0] ^ z0[0] ^ z2[0], z1[1] ^ z0[1] ^ z2[1]];

    [z2[1], z2[0] ^ z1_corrected[1], z1_corrected[0] ^ z0[1], z0[0]]
}

/// Barrett reduction: 256 bits -> 128 bits mod GCM polynomial
#[inline]
fn barrett_reduce(z: [u64; 4]) -> [u64; 2] {
    let t = carryless_mul_64(z[1], REDUCTION_CONST);
    let mid = [z[1] ^ t[1], z[0] ^ t[0]];
    let t2 = carryless_mul_64(mid[0], REDUCTION_CONST);

    [mid[1] ^ t2[1], z[2] ^ mid[0] ^ t2[0]]
}

/// GF(2^128) multiplication using Karatsuba + Barrett
#[inline]
fn gf_mul_optimized(x: [u64; 2], y: [u64; 2]) -> [u64; 2] {
    let product = karatsuba_mul_128(x, y);
    barrett_reduce(product)
}

/// Optimized GHASH with powers of H
#[derive(Debug)]
pub struct GHashOptimized {
    h_powers: Vec<[u64; 2]>,
    acc: [u64; 2],
}

impl GHashOptimized {
    pub fn new(h: &[u8; 16], degree: usize) -> Self {
        let h_int = bytes_to_u64x2(h);
        let mut h_powers = vec![h_int];

        for i in 1..degree {
            h_powers.push(gf_mul_optimized(h_powers[i - 1], h_int));
        }

        Self { h_powers, acc: [0, 0] }
    }

    pub fn new_default(h: &[u8; 16]) -> Self {
        Self::new(h, 4)
    }

    #[inline]
    pub fn update(&mut self, block: &[u8; 16]) {
        let block_int = bytes_to_u64x2(block);
        self.acc[0] ^= block_int[0];
        self.acc[1] ^= block_int[1];
        self.acc = gf_mul_optimized(self.acc, self.h_powers[0]);
    }

    pub fn update_batch(&mut self, blocks: &[[u8; 16]]) {
        for chunk in blocks.chunks(self.h_powers.len()) {
            self.process_chunk(chunk);
        }
    }

    fn process_chunk(&mut self, blocks: &[[u8; 16]]) {
        let n = blocks.len();
        let first_block = bytes_to_u64x2(&blocks[0]);
        let mut result = [first_block[0] ^ self.acc[0], first_block[1] ^ self.acc[1]];
        
        result = gf_mul_optimized(result, self.h_powers[n.saturating_sub(1).min(self.h_powers.len() - 1)]);

        for i in 1..n {
            let block = bytes_to_u64x2(&blocks[i]);
            let power_idx = (n - 1 - i).min(self.h_powers.len() - 1);
            let product = gf_mul_optimized(block, self.h_powers[power_idx]);
            result[0] ^= product[0];
            result[1] ^= product[1];
        }

        self.acc = result;
    }

    pub fn update_padded(&mut self, data: &[u8]) {
        let blocks: Vec<[u8; 16]> = data
            .chunks(BLOCK_SIZE)
            .map(|chunk| {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                block
            })
            .collect();

        if !blocks.is_empty() {
            self.update_batch(&blocks);
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        u64x2_to_bytes(self.acc)
    }

    pub fn reset(&mut self) {
        self.acc = [0, 0];
    }
}

#[inline(always)]
fn bytes_to_u64x2(bytes: &[u8; 16]) -> [u64; 2] {
    [
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
    ]
}

#[inline(always)]
fn u64x2_to_bytes(words: [u64; 2]) -> [u8; 16] {
    let mut result = [0u8; 16];
    result[0..8].copy_from_slice(&words[0].to_be_bytes());
    result[8..16].copy_from_slice(&words[1].to_be_bytes());
    result
}

pub fn ghash_optimized(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut hasher = GHashOptimized::new_default(h);
    hasher.update_padded(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghash_zero() {
        let h = [0u8; 16];
        let data = [0u8; 16];
        let tag = ghash_optimized(&h, &data);
        assert_eq!(tag, [0u8; 16]);
    }

    #[test]
    fn test_ghash_incremental() {
        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        
        let block1 = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                      0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];
        
        let block2 = [0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                      0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf];

        let mut hasher1 = GHashOptimized::new_default(&h);
        hasher1.update(&block1);
        hasher1.update(&block2);
        let tag1 = hasher1.finalize();

        let mut data = Vec::new();
        data.extend_from_slice(&block1);
        data.extend_from_slice(&block2);
        let tag2 = ghash_optimized(&h, &data);

        assert_eq!(tag1, tag2);
    }
}
