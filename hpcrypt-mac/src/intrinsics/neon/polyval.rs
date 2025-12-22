//! ARM NEON + PMULL optimized POLYVAL implementation using R/F Algorithm
//!
//! This implementation uses the R/F (Reduction/Field) algorithm:
//! - 4 PMULL per block for R and F terms
//! - PMULL-based reduction (1 PMULL) instead of scalar shifts
//! - 4-block aggregated processing with single reduction
//!
//! Key equations:
//! - D = swap(H) ⊕ (H0 × P1)
//! - R = M0×D1 ⊕ M1×H1
//! - F = M0×D0 ⊕ M1×H0
//! - Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
//!
//! POLYVAL operates in GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1
//! Unlike GHASH, POLYVAL uses little-endian byte ordering (no byte swap needed).

use core::arch::aarch64::*;
use core::convert::TryInto;

/// Block size in bytes
const BLOCK_SIZE: usize = 16;

/// P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
const P1: u64 = 0xC200000000000000;

/// Precomputed key material for POLYVAL using R/F algorithm
///
/// Stores H and D values for each power, where D = swap(H) ⊕ (H0 × P1)
#[derive(Clone)]
pub struct PolyvalNeonKey {
    /// H^1 packed as [h1_hi : h1_lo]
    h1: uint64x2_t,
    /// D^1 = computed from H^1
    d1: uint64x2_t,
    /// H^2
    h2: uint64x2_t,
    /// D^2
    d2: uint64x2_t,
    /// H^3
    h3: uint64x2_t,
    /// D^3
    d3: uint64x2_t,
    /// H^4
    h4: uint64x2_t,
    /// D^4
    d4: uint64x2_t,
}

/// POLYVAL state using ARM NEON + PMULL with R/F algorithm
pub struct PolyvalNeon {
    key: PolyvalNeonKey,
    /// Current accumulator
    acc: uint64x2_t,
    /// Buffer for incomplete blocks
    buffer: [u8; 16],
    /// Number of bytes in buffer
    buffer_len: usize,
}

/// Compute D from H using R/F algorithm
///
/// D = swap(H) ⊕ (H0 × P1)
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn compute_d(h: uint64x2_t) -> uint64x2_t {
    // Swap halves: [H1 : H0] -> [H0 : H1]
    let h_swap = vextq_u64(h, h, 1);

    // T = H0 × P1 (polynomial multiply)
    let h0 = vgetq_lane_u64(h, 0);
    let t: u128 = vmull_p64(h0, P1);
    let t_vec: uint64x2_t = core::mem::transmute(t);

    // D = swap(H) ⊕ T
    veorq_u64(h_swap, t_vec)
}

/// R/F multiplication: compute R and F terms (4 PMULLs)
///
/// R = M0×D1 ⊕ M1×H1
/// F = M0×D0 ⊕ M1×H0
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn rf_mul_unreduced(m: uint64x2_t, h: uint64x2_t, d: uint64x2_t) -> (uint64x2_t, uint64x2_t) {
    let m0 = vgetq_lane_u64(m, 0);
    let m1 = vgetq_lane_u64(m, 1);
    let h0 = vgetq_lane_u64(h, 0);
    let h1 = vgetq_lane_u64(h, 1);
    let d0 = vgetq_lane_u64(d, 0);
    let d1 = vgetq_lane_u64(d, 1);

    // R = M0×D1 ⊕ M1×H1
    let r0: u128 = vmull_p64(m0, d1);
    let r1: u128 = vmull_p64(m1, h1);
    let r0_vec: uint64x2_t = core::mem::transmute(r0);
    let r1_vec: uint64x2_t = core::mem::transmute(r1);
    let r = veorq_u64(r0_vec, r1_vec);

    // F = M0×D0 ⊕ M1×H0
    let f0: u128 = vmull_p64(m0, d0);
    let f1: u128 = vmull_p64(m1, h0);
    let f0_vec: uint64x2_t = core::mem::transmute(f0);
    let f1_vec: uint64x2_t = core::mem::transmute(f1);
    let f = veorq_u64(f0_vec, f1_vec);

    (r, f)
}

/// Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
///
/// Uses 1 PMULL for reduction
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn reduce_rf(r: uint64x2_t, f: uint64x2_t) -> uint64x2_t {
    // F1 (high 64 bits of f)
    let f1 = vgetq_lane_u64(f, 1);
    let f1_vec = vcombine_u64(vcreate_u64(f1), vcreate_u64(0));

    // x^64×F0 (shift F0 to high position)
    let f0 = vgetq_lane_u64(f, 0);
    let f0_shifted = vcombine_u64(vcreate_u64(0), vcreate_u64(f0));

    // P1×F0
    let p1_f0: u128 = vmull_p64(f0, P1);
    let p1_f0_vec: uint64x2_t = core::mem::transmute(p1_f0);

    // Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
    let result = veorq_u64(r, f1_vec);
    let result = veorq_u64(result, f0_shifted);
    veorq_u64(result, p1_f0_vec)
}

/// Complete R/F multiplication with reduction (5 PMULLs total)
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn gf128_mul_rf(m: uint64x2_t, h: uint64x2_t, d: uint64x2_t) -> uint64x2_t {
    let (r, f) = rf_mul_unreduced(m, h, d);
    reduce_rf(r, f)
}

impl PolyvalNeonKey {
    /// Create a new POLYVAL key with R/F algorithm
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub unsafe fn new(h: &[u8; 16]) -> Self {
        // Load H directly (POLYVAL uses little-endian, no byte swap needed)
        let h1 = vreinterpretq_u64_u8(vld1q_u8(h.as_ptr()));
        let d1 = compute_d(h1);

        // Compute powers using R/F multiplication (same as GHASH)
        let h2 = gf128_mul_rf(h1, h1, d1);
        let d2 = compute_d(h2);

        let h3 = gf128_mul_rf(h2, h1, d1);
        let d3 = compute_d(h3);

        let h4 = gf128_mul_rf(h2, h2, d2);
        let d4 = compute_d(h4);

        Self {
            h1, d1,
            h2, d2,
            h3, d3,
            h4, d4,
        }
    }
}

impl PolyvalNeon {
    /// Create a new POLYVAL instance
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub unsafe fn new(h: &[u8; 16]) -> Self {
        Self {
            key: PolyvalNeonKey::new(h),
            acc: vdupq_n_u64(0),
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    /// Create from pre-computed key
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub unsafe fn from_key(key: PolyvalNeonKey) -> Self {
        Self {
            key,
            acc: vdupq_n_u64(0),
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    /// Update with a single block (5 PMULLs)
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    #[inline]
    pub unsafe fn update_block(&mut self, block: &[u8; 16]) {
        // Load directly (POLYVAL uses little-endian, no byte swap)
        let data = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr()));

        // XOR with accumulator
        self.acc = veorq_u64(self.acc, data);

        // Multiply by H using R/F algorithm
        self.acc = gf128_mul_rf(self.acc, self.key.h1, self.key.d1);
    }

    /// Update with arbitrary-length data
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub unsafe fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Handle buffered data
        if self.buffer_len > 0 {
            let needed = 16 - self.buffer_len;
            let available = core::cmp::min(needed, data.len());

            self.buffer[self.buffer_len..self.buffer_len + available]
                .copy_from_slice(&data[..available]);
            self.buffer_len += available;
            offset += available;

            if self.buffer_len == 16 {
                let block = self.buffer;
                self.update_block(&block);
                self.buffer_len = 0;
            }
        }

        self.update_blocks(&data[offset..]);
    }

    /// Update with multiple blocks
    #[target_feature(enable = "neon", enable = "aes")]
    unsafe fn update_blocks(&mut self, data: &[u8]) {
        let num_full_blocks = data.len() / BLOCK_SIZE;
        let full_block_bytes = num_full_blocks * BLOCK_SIZE;

        let mut offset = 0;

        // Process 4 blocks at a time (17 PMULLs per 64 bytes)
        while offset + 64 <= full_block_bytes {
            self.process_4_blocks(&data[offset..offset + 64]);
            offset += 64;
        }

        // Process remaining blocks one at a time
        while offset + 16 <= full_block_bytes {
            let block: &[u8; 16] = data[offset..offset + 16].try_into().unwrap();
            self.update_block(block);
            offset += 16;
        }

        // Buffer remaining bytes
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Process 4 blocks with R/F algorithm and aggregated reduction
    ///
    /// Uses 16 PMULLs for multiplication (4 per block) + 1 PMULL for reduction = 17 PMULLs total
    #[target_feature(enable = "neon", enable = "aes")]
    #[inline]
    unsafe fn process_4_blocks(&mut self, data: &[u8]) {
        debug_assert!(data.len() == 64);

        // Load all 4 blocks (no byte swap for POLYVAL)
        let m0 = vreinterpretq_u64_u8(vld1q_u8(data.as_ptr()));
        let m1 = vreinterpretq_u64_u8(vld1q_u8(data[16..].as_ptr()));
        let m2 = vreinterpretq_u64_u8(vld1q_u8(data[32..].as_ptr()));
        let m3 = vreinterpretq_u64_u8(vld1q_u8(data[48..].as_ptr()));

        // XOR first block with accumulator
        let y0 = veorq_u64(self.acc, m0);

        // R/F multiply all 4 blocks (16 PMULLs)
        let (r0, f0) = rf_mul_unreduced(y0, self.key.h4, self.key.d4);
        let (r1, f1) = rf_mul_unreduced(m1, self.key.h3, self.key.d3);
        let (r2, f2) = rf_mul_unreduced(m2, self.key.h2, self.key.d2);
        let (r3, f3) = rf_mul_unreduced(m3, self.key.h1, self.key.d1);

        // Aggregate R and F values
        let r = veorq_u64(
            veorq_u64(r0, r1),
            veorq_u64(r2, r3)
        );
        let f = veorq_u64(
            veorq_u64(f0, f1),
            veorq_u64(f2, f3)
        );

        // Single reduction (1 PMULL)
        self.acc = reduce_rf(r, f);
    }

    /// Finalize and return the POLYVAL tag
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub unsafe fn finalize(mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.update_block(&block);
        }

        // Output directly (POLYVAL uses little-endian, no byte swap)
        let mut output = [0u8; 16];
        vst1q_u8(output.as_mut_ptr(), vreinterpretq_u8_u64(self.acc));
        output
    }

    /// Reset for reuse with the same key
    ///
    /// # Safety
    /// Requires NEON and AES/PMULL support
    #[target_feature(enable = "neon", enable = "aes")]
    pub unsafe fn reset(&mut self) {
        self.acc = vdupq_n_u64(0);
        self.buffer = [0u8; 16];
        self.buffer_len = 0;
    }
}

/// Convenience function to compute POLYVAL using NEON
///
/// # Safety
/// Requires NEON and AES/PMULL support
#[target_feature(enable = "neon", enable = "aes")]
pub unsafe fn polyval_neon(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut hasher = PolyvalNeon::new(h);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyval_neon_empty() {
        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];

        unsafe {
            let tag = polyval_neon(&h, &[]);
            assert_eq!(tag, [0u8; 16], "Empty input should produce zero tag");
        }
    }

    #[test]
    fn test_polyval_neon_vs_software() {
        use crate::polyval::polyval as polyval_software;

        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];

        let full_data = [0x42u8; 1024];

        for size in [16, 32, 48, 64, 80, 128, 256, 512, 1024] {
            let data = &full_data[..size];
            let expected = polyval_software(&h, data);

            unsafe {
                let result = polyval_neon(&h, data);
                assert_eq!(result, expected,
                    "NEON should match software for size {}", size);
            }
        }
    }

    #[test]
    fn test_polyval_neon_partial_blocks() {
        use crate::polyval::polyval as polyval_software;

        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];

        let full_data = [0xabu8; 256];

        for size in [1, 7, 15, 17, 31, 33, 47, 49, 63, 65, 100] {
            let data = &full_data[..size];
            let expected = polyval_software(&h, data);

            unsafe {
                let result = polyval_neon(&h, data);
                assert_eq!(result, expected,
                    "NEON should match software for partial size {}", size);
            }
        }
    }

    #[test]
    fn test_polyval_neon_deterministic() {
        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];
        let data = [0x42u8; 64];

        unsafe {
            let tag1 = polyval_neon(&h, &data);
            let tag2 = polyval_neon(&h, &data);
            assert_eq!(tag1, tag2, "POLYVAL should be deterministic");
        }
    }
}
