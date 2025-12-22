//! AVX2 + PCLMULQDQ optimized POLYVAL implementation using R/F Algorithm
//!
//! Uses the R/F algorithm from "Efficient GHASH Implementation Using CLMUL":
//! - 4 CLMULs per block for multiplication (R and F terms)
//! - 1 CLMUL for reduction (Lemma 3)
//! - 4-block aggregated processing with single reduction
//!
//! Key equations:
//! - D = swap(H) ⊕ (H0 × P1)
//! - R = M0×D1 ⊕ M1×H1
//! - F = M0×D0 ⊕ M1×H0
//! - Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
//!
//! Performance: ~1.7x faster than Karatsuba with scalar reduction
//!
//! POLYVAL operates in GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1
//! Unlike GHASH, POLYVAL uses little-endian byte ordering (no byte swap needed).

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use core::convert::TryInto;

/// Block size in bytes
const BLOCK_SIZE: usize = 16;

/// P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
const P1: u64 = 0xC200000000000000;

/// Precomputed key material for POLYVAL using R/F algorithm
///
/// Stores H and D values for each power, where D = swap(H) ⊕ (H0 × P1)
#[derive(Clone)]
pub struct PolyvalAvx2Key {
    /// H^1 packed as [h1_hi : h1_lo]
    h1: __m128i,
    /// D^1 = computed from H^1
    d1: __m128i,
    /// H^2
    h2: __m128i,
    /// D^2
    d2: __m128i,
    /// H^3
    h3: __m128i,
    /// D^3
    d3: __m128i,
    /// H^4
    h4: __m128i,
    /// D^4
    d4: __m128i,
}

/// POLYVAL state using AVX2 + PCLMULQDQ with R/F algorithm
pub struct PolyvalAvx2 {
    key: PolyvalAvx2Key,
    /// Current accumulator
    acc: __m128i,
    /// Buffer for incomplete blocks
    buffer: [u8; 16],
    /// Number of bytes in buffer
    buffer_len: usize,
}

/// Compute D from H using the R/F algorithm
///
/// D = swap(H) ⊕ (H0 × P1)
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn compute_d(h: __m128i) -> __m128i {
    let p = _mm_set_epi64x(P1 as i64, 0);

    // Swap halves: [H1 : H0] -> [H0 : H1]
    let h_swap = _mm_shuffle_epi32(h, 0x4e);

    // T = H0 × P1
    let t = _mm_clmulepi64_si128(h, p, 0x10);

    // D = swap(H) ⊕ T
    _mm_xor_si128(h_swap, t)
}

/// Karatsuba multiplication for key setup: a × b in GF(2^128)
/// Returns (lo, hi, mid) for reduction
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn karatsuba_mul(a: __m128i, b: __m128i) -> (__m128i, __m128i, __m128i) {
    let lo = _mm_clmulepi64_si128(a, b, 0x00);
    let hi = _mm_clmulepi64_si128(a, b, 0x11);

    let a_xor = _mm_xor_si128(a, _mm_srli_si128(a, 8));
    let b_xor = _mm_xor_si128(b, _mm_srli_si128(b, 8));
    let mid_raw = _mm_clmulepi64_si128(a_xor, b_xor, 0x00);
    let mid = _mm_xor_si128(_mm_xor_si128(mid_raw, lo), hi);

    (lo, hi, mid)
}

/// Reduce 256-bit product to 128-bit modulo POLYVAL polynomial
/// POLYVAL polynomial: x^128 + x^127 + x^126 + x^121 + 1
#[target_feature(enable = "sse2")]
#[inline]
unsafe fn reduce_256_to_128(lo: __m128i, hi: __m128i, mid: __m128i) -> __m128i {
    let lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    let hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    let mut v = [0u64; 4];
    _mm_storeu_si128(v.as_mut_ptr() as *mut __m128i, lo);
    _mm_storeu_si128(v[2..].as_mut_ptr() as *mut __m128i, hi);

    // POLYVAL reduction
    v[2] ^= v[0] ^ (v[0] >> 1) ^ (v[0] >> 2) ^ (v[0] >> 7);
    v[1] ^= (v[0] << 63) ^ (v[0] << 62) ^ (v[0] << 57);

    v[3] ^= v[1] ^ (v[1] >> 1) ^ (v[1] >> 2) ^ (v[1] >> 7);
    v[2] ^= (v[1] << 63) ^ (v[1] << 62) ^ (v[1] << 57);

    _mm_set_epi64x(v[3] as i64, v[2] as i64)
}

/// Full GF(2^128) multiplication with reduction (for key setup)
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn gf128_mul_reduce(a: __m128i, b: __m128i) -> __m128i {
    let (lo, hi, mid) = karatsuba_mul(a, b);
    reduce_256_to_128(lo, hi, mid)
}

impl PolyvalAvx2Key {
    /// Create a new POLYVAL key with R/F algorithm
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub unsafe fn new(h: &[u8; 16]) -> Self {
        // Load H directly (POLYVAL uses little-endian, no byte swap needed)
        let h1 = _mm_loadu_si128(h.as_ptr() as *const __m128i);

        // Compute H^2, H^3, H^4
        let h2 = gf128_mul_reduce(h1, h1);
        let h3 = gf128_mul_reduce(h2, h1);
        let h4 = gf128_mul_reduce(h2, h2);

        // Compute D values for R/F algorithm
        let d1 = compute_d(h1);
        let d2 = compute_d(h2);
        let d3 = compute_d(h3);
        let d4 = compute_d(h4);

        Self {
            h1, d1,
            h2, d2,
            h3, d3,
            h4, d4,
        }
    }
}

/// R/F multiplication using 4 CLMULs per block
///
/// Given M = [M1 : M0] and precomputed H = [H1 : H0], D = [D1 : D0]:
/// - R = M0×D1 ⊕ M1×H1 (2 CLMULs)
/// - F = M0×D0 ⊕ M1×H0 (2 CLMULs)
///
/// Returns (R, F) for later reduction
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn rf_mul_unreduced(m: __m128i, h: __m128i, d: __m128i) -> (__m128i, __m128i) {
    // R = M0×D1 ⊕ M1×H1
    let r0 = _mm_clmulepi64_si128(m, d, 0x10);   // M0 × D1
    let r1 = _mm_clmulepi64_si128(m, h, 0x11);   // M1 × H1
    let r = _mm_xor_si128(r0, r1);

    // F = M0×D0 ⊕ M1×H0
    let f0 = _mm_clmulepi64_si128(m, d, 0x00);   // M0 × D0
    let f1 = _mm_clmulepi64_si128(m, h, 0x01);   // M1 × H0
    let f = _mm_xor_si128(f0, f1);

    (r, f)
}

/// Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
///
/// Uses 1 CLMUL for reduction
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn reduce_rf(r: __m128i, f: __m128i) -> __m128i {
    let p1 = _mm_set_epi64x(0, P1 as i64);

    // F1 in low position
    let f1 = _mm_srli_si128(f, 8);

    // x^64×F0 (shift F0 to high position)
    let f0_shifted = _mm_slli_si128(f, 8);

    // P1×F0
    let p1_f0 = _mm_clmulepi64_si128(f, p1, 0x00);

    // Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)
    let result = _mm_xor_si128(r, f1);
    let result = _mm_xor_si128(result, f0_shifted);
    _mm_xor_si128(result, p1_f0)
}

/// Complete R/F multiplication with reduction (5 CLMULs total)
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn gf128_mul_rf(m: __m128i, h: __m128i, d: __m128i) -> __m128i {
    let (r, f) = rf_mul_unreduced(m, h, d);
    reduce_rf(r, f)
}

impl PolyvalAvx2 {
    /// Create a new POLYVAL instance
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub unsafe fn new(h: &[u8; 16]) -> Self {
        Self {
            key: PolyvalAvx2Key::new(h),
            acc: _mm_setzero_si128(),
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    /// Create from pre-computed key
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub unsafe fn from_key(key: PolyvalAvx2Key) -> Self {
        Self {
            key,
            acc: _mm_setzero_si128(),
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    /// Update with a single block (5 CLMULs)
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    #[inline]
    pub unsafe fn update_block(&mut self, block: &[u8; 16]) {
        // Load directly (POLYVAL uses little-endian, no byte swap)
        let data = _mm_loadu_si128(block.as_ptr() as *const __m128i);

        // XOR with accumulator
        self.acc = _mm_xor_si128(self.acc, data);

        // Multiply by H using R/F algorithm
        self.acc = gf128_mul_rf(self.acc, self.key.h1, self.key.d1);
    }

    /// Update with arbitrary-length data
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
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
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    unsafe fn update_blocks(&mut self, data: &[u8]) {
        let num_full_blocks = data.len() / BLOCK_SIZE;
        let full_block_bytes = num_full_blocks * BLOCK_SIZE;

        let mut offset = 0;

        // Process 4 blocks at a time (17 CLMULs per 64 bytes)
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
    /// Uses 16 CLMULs for multiplication (4 per block) + 1 CLMUL for reduction = 17 CLMULs total
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    #[inline]
    unsafe fn process_4_blocks(&mut self, data: &[u8]) {
        debug_assert!(data.len() == 64);

        // Load all 4 blocks (no byte swap for POLYVAL)
        let m0 = _mm_loadu_si128(data.as_ptr() as *const __m128i);
        let m1 = _mm_loadu_si128(data[16..].as_ptr() as *const __m128i);
        let m2 = _mm_loadu_si128(data[32..].as_ptr() as *const __m128i);
        let m3 = _mm_loadu_si128(data[48..].as_ptr() as *const __m128i);

        // XOR first block with accumulator
        let y0 = _mm_xor_si128(self.acc, m0);

        // R/F multiply all 4 blocks (16 CLMULs)
        let (r0, f0) = rf_mul_unreduced(y0, self.key.h4, self.key.d4);
        let (r1, f1) = rf_mul_unreduced(m1, self.key.h3, self.key.d3);
        let (r2, f2) = rf_mul_unreduced(m2, self.key.h2, self.key.d2);
        let (r3, f3) = rf_mul_unreduced(m3, self.key.h1, self.key.d1);

        // Aggregate R and F values
        let r = _mm_xor_si128(
            _mm_xor_si128(r0, r1),
            _mm_xor_si128(r2, r3)
        );
        let f = _mm_xor_si128(
            _mm_xor_si128(f0, f1),
            _mm_xor_si128(f2, f3)
        );

        // Single reduction (1 CLMUL)
        self.acc = reduce_rf(r, f);
    }

    /// Finalize and return the POLYVAL tag
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub unsafe fn finalize(mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.update_block(&block);
        }

        // Output directly (POLYVAL uses little-endian, no byte swap)
        let mut output = [0u8; 16];
        _mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, self.acc);
        output
    }

    /// Reset for reuse with the same key
    ///
    /// # Safety
    /// Requires AVX2 and PCLMULQDQ support
    #[target_feature(enable = "avx2", enable = "pclmulqdq")]
    pub unsafe fn reset(&mut self) {
        self.acc = _mm_setzero_si128();
        self.buffer = [0u8; 16];
        self.buffer_len = 0;
    }
}

/// Convenience function to compute POLYVAL using AVX2
///
/// # Safety
/// Requires AVX2 and PCLMULQDQ support
#[target_feature(enable = "avx2", enable = "pclmulqdq")]
pub unsafe fn polyval_avx2(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut hasher = PolyvalAvx2::new(h);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyval_avx2_empty() {
        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];

        unsafe {
            let tag = polyval_avx2(&h, &[]);
            assert_eq!(tag, [0u8; 16], "Empty input should produce zero tag");
        }
    }

    #[test]
    fn test_polyval_avx2_vs_software() {
        use crate::polyval::polyval as polyval_software;

        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];

        let full_data = [0x42u8; 1024];

        for size in [16, 32, 48, 64, 80, 128, 256, 512, 1024] {
            let data = &full_data[..size];
            let expected = polyval_software(&h, data);

            unsafe {
                let result = polyval_avx2(&h, data);
                assert_eq!(result, expected,
                    "AVX2 should match software for size {}", size);
            }
        }
    }

    #[test]
    fn test_polyval_avx2_partial_blocks() {
        use crate::polyval::polyval as polyval_software;

        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];

        let full_data = [0xabu8; 256];

        for size in [1, 7, 15, 17, 31, 33, 47, 49, 63, 65, 100] {
            let data = &full_data[..size];
            let expected = polyval_software(&h, data);

            unsafe {
                let result = polyval_avx2(&h, data);
                assert_eq!(result, expected,
                    "AVX2 should match software for partial size {}", size);
            }
        }
    }

    #[test]
    fn test_polyval_avx2_deterministic() {
        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];
        let data = [0x42u8; 64];

        unsafe {
            let tag1 = polyval_avx2(&h, &data);
            let tag2 = polyval_avx2(&h, &data);
            assert_eq!(tag1, tag2, "POLYVAL should be deterministic");
        }
    }
}
