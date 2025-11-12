//! Working GHASH Optimizations
//!
//! This uses the correct GF multiplication from the baseline implementation
//! but adds key optimizations:
//! 1. Powers of H precomputation for parallelism
//! 2. Batch processing
//! 3. Better algorithm structure

use core::convert::TryInto;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const BLOCK_SIZE: usize = 16;

/// GF(2^128) multiplication - using the correct baseline algorithm
/// This is the SAME as in ghash.rs but extracted for reuse
#[inline]
fn gf_mul(x: [u64; 2], y: [u64; 2]) -> [u64; 2] {
    let mut z = [0u64; 2];
    let mut v = x;

    // Process each bit of Y, from MSB to LSB
    for i in 0..64 {
        // Process high word bits (from MSB to LSB)
        if (y[0] & (1u64 << (63 - i))) != 0 {
            z[0] ^= v[0];
            z[1] ^= v[1];
        }

        // Save LSB before shifting
        let lsb = v[1] & 1;

        // Right shift V
        v[1] = (v[1] >> 1) | (v[0] << 63);
        v[0] >>= 1;

        // If old LSB was 1, XOR with R
        if lsb != 0 {
            v[0] ^= 0xE100000000000000;
        }
    }

    // Process low word bits
    for i in 0..64 {
        if (y[1] & (1u64 << (63 - i))) != 0 {
            z[0] ^= v[0];
            z[1] ^= v[1];
        }

        let lsb = v[1] & 1;
        v[1] = (v[1] >> 1) | (v[0] << 63);
        v[0] >>= 1;

        if lsb != 0 {
            v[0] ^= 0xE100000000000000;
        }
    }

    z
}

/// OPTIMIZATION 1: Powers of H Precomputation
///
/// By precomputing H, H^2, H^3, ..., H^n, we can process multiple blocks
/// in parallel (instruction-level parallelism) instead of sequentially.
#[derive(Debug)]
pub struct GHashOptimized {
    h_powers: Vec<[u64; 2]>, // H, H^2, H^3, H^4, ...
    acc: [u64; 2],
}

impl GHashOptimized {
    /// Create with specified parallelism degree
    pub fn new(h: &[u8; 16], degree: usize) -> Self {
        let h_int = bytes_to_u64x2(h);
        let mut h_powers = vec![h_int];

        // Precompute powers of H
        for i in 1..degree {
            h_powers.push(gf_mul(h_powers[i - 1], h_int));
        }

        Self {
            h_powers,
            acc: [0, 0],
        }
    }

    pub fn new_default(h: &[u8; 16]) -> Self {
        Self::new(h, 4) // Default 4-way parallelism
    }

    #[inline]
    pub fn update(&mut self, block: &[u8; 16]) {
        let block_int = bytes_to_u64x2(block);
        self.acc[0] ^= block_int[0];
        self.acc[1] ^= block_int[1];
        self.acc = gf_mul(self.acc, self.h_powers[0]);
    }

    /// OPTIMIZATION 2: Batch Processing with Powers
    ///
    /// Process multiple blocks using precomputed powers
    /// This enables instruction-level parallelism
    pub fn update_batch(&mut self, blocks: &[[u8; 16]]) {
        for chunk in blocks.chunks(self.h_powers.len()) {
            self.process_chunk(chunk);
        }
    }

    #[inline(always)]
    fn process_chunk(&mut self, blocks: &[[u8; 16]]) {
        let n = blocks.len();
        if n == 0 {
            return;
        }

        // XOR first block with accumulator
        let first_block = bytes_to_u64x2(&blocks[0]);
        let mut acc_with_first = [
            first_block[0] ^ self.acc[0],
            first_block[1] ^ self.acc[1],
        ];

        // Multiply by appropriate power of H
        let power_idx = n.saturating_sub(1).min(self.h_powers.len() - 1);
        acc_with_first = gf_mul(acc_with_first, self.h_powers[power_idx]);

        // Process remaining blocks independently
        let mut result = acc_with_first;
        for i in 1..n {
            let block = bytes_to_u64x2(&blocks[i]);
            let pow_idx = (n - 1 - i).min(self.h_powers.len() - 1);
            let product = gf_mul(block, self.h_powers[pow_idx]);
            result[0] ^= product[0];
            result[1] ^= product[1];
        }

        self.acc = result;
    }

    pub fn update_padded(&mut self, data: &[u8]) {
        // Process complete blocks
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

// Helper functions
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

/// Aggregated variant (currently same as optimized, placeholder for future)
#[derive(Debug)]
pub struct GHashAggregated {
    inner: GHashOptimized,
}

impl GHashAggregated {
    pub fn new(h: &[u8; 16], degree: usize, _reduction_interval: usize) -> Self {
        Self {
            inner: GHashOptimized::new(h, degree),
        }
    }

    pub fn update(&mut self, block: &[u8; 16]) {
        self.inner.update(block);
    }

    pub fn finalize(self) -> [u8; 16] {
        self.inner.finalize()
    }
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
    fn test_ghash_vs_baseline() {
        use crate::ghash::ghash;

        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        let data = b"Hello, World! This is a test message for GHASH.";

        let baseline = ghash(&h, data);
        let optimized = ghash_optimized(&h, data);

        assert_eq!(baseline, optimized, "Optimized should match baseline");
    }

    #[test]
    fn test_ghash_incremental() {
        use crate::ghash::GHash;

        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        
        let block1 = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                      0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];
        
        let block2 = [0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                      0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf];

        // Baseline
        let mut hasher_baseline = GHash::new(&h);
        hasher_baseline.update(&block1);
        hasher_baseline.update(&block2);
        let tag_baseline = hasher_baseline.finalize();

        // Optimized
        let mut hasher_opt = GHashOptimized::new_default(&h);
        hasher_opt.update(&block1);
        hasher_opt.update(&block2);
        let tag_opt = hasher_opt.finalize();

        assert_eq!(tag_baseline, tag_opt);
    }

    #[test]
    fn test_different_degrees() {
        use crate::ghash::ghash;

        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        let data = vec![0x42u8; 128];

        let baseline = ghash(&h, &data);

        for degree in [1, 2, 4, 8, 16] {
            let mut hasher = GHashOptimized::new(&h, degree);
            hasher.update_padded(&data);
            let tag = hasher.finalize();
            assert_eq!(baseline, tag, "Degree {} should match baseline", degree);
        }
    }
}
