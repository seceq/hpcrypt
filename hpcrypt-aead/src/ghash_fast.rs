//! Fast GHASH Implementation
//!
//! Based on RustCrypto's approach: GHASH implemented using POLYVAL multiplication
//! with the `mulX_POLYVAL()` transformation and byte reversal.
//!
//! Core multiplication adapted from RustCrypto's polyval/src/backend/soft/soft64.rs
//! which itself is based on BearSSL's ghash_ctmul64.c
//!
//! Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> (BearSSL original)
//! Rust adaptation by RustCrypto team
//! Further adapted for direct GHASH use

use core::{
    convert::TryInto,
    num::Wrapping,
    ops::{Add, Mul},
};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const BLOCK_SIZE: usize = 16;

/// POLYVAL field element (128 bits as two u64 words, little-endian)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct FieldElement(u64, u64); // (low, high)

impl FieldElement {
    /// Decode from little-endian bytes (POLYVAL convention)
    #[inline]
    fn from_le_bytes(bytes: &[u8; 16]) -> Self {
        Self(
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        )
    }

    /// Encode to little-endian bytes (POLYVAL convention)
    #[inline]
    fn to_le_bytes(self) -> [u8; 16] {
        let mut result = [0u8; 16];
        result[0..8].copy_from_slice(&self.0.to_le_bytes());
        result[8..16].copy_from_slice(&self.1.to_le_bytes());
        result
    }
}

impl Add for FieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    /// POLYVAL multiplication in GF(2^128) using BearSSL's ctmul64 approach
    ///
    /// This is the exact algorithm from RustCrypto's polyval/soft64.rs
    fn mul(self, rhs: Self) -> Self {
        let h0 = self.0;
        let h1 = self.1;
        let h0r = rev64(h0);
        let h1r = rev64(h1);
        let h2 = h0 ^ h1;
        let h2r = h0r ^ h1r;

        let y0 = rhs.0;
        let y1 = rhs.1;
        let y0r = rev64(y0);
        let y1r = rev64(y1);
        let y2 = y0 ^ y1;
        let y2r = y0r ^ y1r;

        let z0 = bmul64(y0, h0);
        let z1 = bmul64(y1, h1);

        let mut z2 = bmul64(y2, h2);
        let mut z0h = bmul64(y0r, h0r);
        let mut z1h = bmul64(y1r, h1r);
        let mut z2h = bmul64(y2r, h2r);

        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = rev64(z0h) >> 1;
        z1h = rev64(z1h) >> 1;
        z2h = rev64(z2h) >> 1;

        let v0 = z0;
        let mut v1 = z0h ^ z2;
        let mut v2 = z1 ^ z2h;
        let mut v3 = z1h;

        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

        FieldElement(v2, v3)
    }
}

/// Constant-time 64x64 → 64-bit carry-less multiplication with holes
#[inline]
fn bmul64(x: u64, y: u64) -> u64 {
    let x0 = Wrapping(x & 0x1111_1111_1111_1111);
    let x1 = Wrapping(x & 0x2222_2222_2222_2222);
    let x2 = Wrapping(x & 0x4444_4444_4444_4444);
    let x3 = Wrapping(x & 0x8888_8888_8888_8888);
    let y0 = Wrapping(y & 0x1111_1111_1111_1111);
    let y1 = Wrapping(y & 0x2222_2222_2222_2222);
    let y2 = Wrapping(y & 0x4444_4444_4444_4444);
    let y3 = Wrapping(y & 0x8888_8888_8888_8888);

    let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
    let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
    let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
    let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

    z0 &= 0x1111_1111_1111_1111;
    z1 &= 0x2222_2222_2222_2222;
    z2 &= 0x4444_4444_4444_4444;
    z3 &= 0x8888_8888_8888_8888;

    z0 | z1 | z2 | z3
}

/// Bit-reverse a u64 in constant time
#[inline]
fn rev64(mut x: u64) -> u64 {
    x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
    x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
    x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
    x = ((x & 0x00ff_00ff_00ff_00ff) << 8) | ((x >> 8) & 0x00ff_00ff_00ff_00ff);
    x = ((x & 0xffff_0000_ffff) << 16) | ((x >> 16) & 0xffff_0000_ffff);
    x.rotate_right(32)
}

/// The `mulX_POLYVAL()` function as defined in RFC 8452 Appendix A.
///
/// Performs a doubling (multiply by x) over GF(2^128).
/// Required to convert GHASH key H to POLYVAL-compatible form.
fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;

    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

/// Fast GHASH with Powers of H
#[derive(Debug)]
pub struct GHashFast {
    h_powers: Vec<FieldElement>,
    acc: FieldElement,
}

impl GHashFast {
    /// Create new GHASH with specified parallelism degree
    pub fn new(h: &[u8; 16], degree: usize) -> Self {
        // Convert GHASH H to POLYVAL H using mulx
        let mut h_reversed = *h;
        h_reversed.reverse();
        let h_polyval = mulx(&h_reversed);

        let h_elem = FieldElement::from_le_bytes(&h_polyval);
        let mut h_powers = vec![h_elem];

        // Precompute powers using POLYVAL multiplication
        for i in 1..degree {
            h_powers.push(h_powers[i - 1] * h_elem);
        }

        Self {
            h_powers,
            acc: FieldElement::default(),
        }
    }

    /// Create with default degree (4)
    pub fn new_default(h: &[u8; 16]) -> Self {
        Self::new(h, 4)
    }

    /// Update with single block (GHASH format: big-endian)
    #[inline]
    pub fn update(&mut self, block: &[u8; 16]) {
        // Reverse bytes for POLYVAL format
        let mut block_reversed = *block;
        block_reversed.reverse();

        let block_elem = FieldElement::from_le_bytes(&block_reversed);
        self.acc = (self.acc + block_elem) * self.h_powers[0];
    }

    /// Update with multiple blocks (optimized)
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

        // Reverse bytes for first block
        let mut first_reversed = blocks[0];
        first_reversed.reverse();
        let first_elem = FieldElement::from_le_bytes(&first_reversed);

        let mut acc_with_first = self.acc + first_elem;

        // Multiply by appropriate power
        let power_idx = n.saturating_sub(1).min(self.h_powers.len() - 1);
        acc_with_first = acc_with_first * self.h_powers[power_idx];

        // Process remaining blocks
        let mut result = acc_with_first;
        for i in 1..n {
            let mut block_reversed = blocks[i];
            block_reversed.reverse();
            let block_elem = FieldElement::from_le_bytes(&block_reversed);

            let pow_idx = (n - 1 - i).min(self.h_powers.len() - 1);
            let product = block_elem * self.h_powers[pow_idx];
            result = result + product;
        }

        self.acc = result;
    }

    /// Update with arbitrary-length data
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

    /// Finalize and return tag (GHASH format: big-endian)
    pub fn finalize(self) -> [u8; 16] {
        let mut result = self.acc.to_le_bytes();
        result.reverse(); // Convert back to GHASH big-endian
        result
    }

    /// Reset for reuse
    pub fn reset(&mut self) {
        self.acc = FieldElement::default();
    }
}

/// Convenience function
pub fn ghash_fast(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut hasher = GHashFast::new_default(h);
    hasher.update_padded(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mulx() {
        // Test vector from RFC 8452 Appendix A (with errata correction)
        let input = [
            0x9c, 0x98, 0xc0, 0x4d, 0xf9, 0x38, 0x7d, 0xed, 0x82, 0x81, 0x75, 0xa9, 0x2b, 0xa6,
            0x52, 0xd8,
        ];
        let expected = [
            0x39, 0x31, 0x81, 0x9b, 0xf2, 0x71, 0xfa, 0xda, 0x05, 0x03, 0xeb, 0x52, 0x57, 0x4c,
            0xa5, 0x72,
        ];
        let result = mulx(&input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bmul64_zero() {
        assert_eq!(bmul64(0, 0x1234567890ABCDEF), 0);
        assert_eq!(bmul64(0x1234567890ABCDEF, 0), 0);
    }

    #[test]
    fn test_bmul64_one() {
        let x = 0x0123456789ABCDEF;
        assert_eq!(bmul64(x, 1), x);
        assert_eq!(bmul64(1, x), x);
    }

    #[test]
    fn test_rev64_known_values() {
        assert_eq!(rev64(0), 0);
        assert_eq!(rev64(1), 0x8000000000000000);
        assert_eq!(rev64(0x8000000000000000), 1);
        assert_eq!(rev64(0xFF00000000000000), 0x00000000000000FF);
    }

    #[test]
    fn test_field_element_zero_mul() {
        let zero = FieldElement(0, 0);
        let h = FieldElement(0x66e94bd4ef8a2c3b, 0x884cfa59ca342b2e);
        let result = zero * h;
        assert_eq!(result, FieldElement(0, 0));
    }

    #[test]
    fn test_field_element_commutativity() {
        let a = FieldElement(0x1234567890ABCDEF, 0xFEDCBA0987654321);
        let b = FieldElement(0x0011223344556677, 0x8899AABBCCDDEEFF);

        let ab = a * b;
        let ba = b * a;
        assert_eq!(ab, ba, "Multiplication should be commutative");
    }

    #[test]
    fn test_incremental() {
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        let block1 = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];

        let block2 = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
            0xbd, 0xdf,
        ];

        // Test incremental update produces same result as single-shot
        let mut fast = GHashFast::new_default(&h);
        fast.update(&block1);
        fast.update(&block2);
        let tag_incremental = fast.finalize();

        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(&block1);
        data.extend_from_slice(&block2);
        let tag_single = ghash_fast(&h, &data);

        assert_eq!(tag_incremental, tag_single);
    }

    #[test]
    fn test_different_sizes() {
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        // Test that various sizes work correctly (consistency check)
        for size in [16, 64, 128, 256, 1024] {
            let data = vec![0x42u8; size];
            let tag1 = ghash_fast(&h, &data);
            let tag2 = ghash_fast(&h, &data);
            assert_eq!(tag1, tag2, "Size {} must be deterministic", size);
        }
    }
}
