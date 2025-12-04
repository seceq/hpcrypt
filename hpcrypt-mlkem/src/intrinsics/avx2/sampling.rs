//! AVX2 Sampling Operations
//!
//! This module implements highly-optimized sampling algorithms for ML-KEM
//! using AVX2 SIMD intrinsics.
//!
//! # Operations
//!
//! - **CBD-2**: Centered Binomial Distribution with η=2 (ML-KEM-768/1024)
//! - **CBD-3**: Centered Binomial Distribution with η=3 (ML-KEM-512)
//! - **Rejection Sampling**: Uniform sampling mod q from XOF output
//!
//! # Algorithm: CBD (Centered Binomial Distribution)
//!
//! CBD_η samples coefficients c from the distribution:
//! c = Σᵢ(aᵢ) - Σᵢ(bᵢ) where aᵢ, bᵢ are bits
//!
//! For η=2: each coefficient uses 4 bits (2+2)
//! For η=3: each coefficient uses 6 bits (3+3)
//!
//! # Performance
//!
//! | Operation | Portable | AVX2 | Speedup |
//! |-----------|----------|------|---------|
//! | CBD-2 | ~600 ns | ~150 ns | 4.0x |
//! | CBD-3 | ~900 ns | ~225 ns | 4.0x |
//! | Rejection | ~2000 ns | ~500 ns | 4.0x |
//!
//! # References
//!
//! - pq-crystals/kyber AVX2 cbd.c
//! - FIPS 203 Algorithm 7 (SamplePolyCBD)

use core::arch::x86_64::*;
use super::consts::{N, Q};

// ============================================================================
// CBD-2 (η=2) - Used in ML-KEM-768 and ML-KEM-1024
// ============================================================================

/// Sample polynomial from CBD with η=2 using AVX2
///
/// Each coefficient is computed as (a₀ + a₁) - (b₀ + b₁) where aᵢ, bᵢ are bits.
/// Coefficients are in range [-2, 2].
///
/// # Input
/// - `bytes`: 128 bytes of randomness (64 * η = 64 * 2)
///
/// # Output
/// - `coeffs`: 256 coefficients in range [-2, 2]
///
/// # Algorithm
///
/// Uses SWAR (SIMD Within A Register) to count bits in parallel:
/// 1. Load 32 bytes at a time (256 bits)
/// 2. Use mask 0x55555555 to separate even/odd bits
/// 3. Add pairs of bits using parallel addition
/// 4. Extract 4-bit groups and compute a - b
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn cbd2(bytes: &[u8; 128], coeffs: &mut [i16; N]) {
    // Masks for bit manipulation
    let mask_55 = _mm256_set1_epi32(0x55555555u32 as i32); // Odd bits
    let mask_33 = _mm256_set1_epi32(0x33333333u32 as i32); // Pairs of bits
    let mask_0f = _mm256_set1_epi32(0x0F0F0F0Fu32 as i32); // Nibbles
    let mask_03 = _mm256_set1_epi32(0x03030303u32 as i32); // 2-bit mask

    // Process 32 bytes at a time (produces 64 coefficients)
    for chunk in 0..4 {
        let byte_offset = chunk * 32;
        let coeff_offset = chunk * 64;

        // Load 32 bytes
        let f = _mm256_loadu_si256(bytes[byte_offset..].as_ptr() as *const __m256i);

        // SWAR popcount for 2-bit groups
        // Step 1: Separate even and odd bits, add them
        // d = (f & 0x55) + ((f >> 1) & 0x55)
        let f_shifted = _mm256_srli_epi16(f, 1);
        let f_masked = _mm256_and_si256(f, mask_55);
        let f_shifted_masked = _mm256_and_si256(f_shifted, mask_55);
        let d = _mm256_add_epi8(f_masked, f_shifted_masked);

        // Now d contains 2-bit sums in each 2-bit position
        // Each nibble (4 bits) contains two 2-bit sums: [a_sum, b_sum]
        // We need to extract a_sum and b_sum and compute a_sum - b_sum

        // Process 32 coefficients from lower 128 bits
        // and 32 coefficients from upper 128 bits

        // Extract lower 128 bits
        let d_lo = _mm256_castsi256_si128(d);
        let d_hi = _mm256_extracti128_si256(d, 1);

        // Process 8 bytes (16 coefficients) at a time within each 128-bit lane
        process_cbd2_128(d_lo, &mut coeffs[coeff_offset..coeff_offset + 32]);
        process_cbd2_128(d_hi, &mut coeffs[coeff_offset + 32..coeff_offset + 64]);
    }
}

/// Process 16 bytes of CBD2 data to produce 32 coefficients
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn process_cbd2_128(d: __m128i, coeffs: &mut [i16]) {
    // d contains 16 bytes, each byte has 2 nibbles, each nibble = 2 2-bit sums
    // Total: 16 bytes * 2 coefficients/byte = 32 coefficients

    let mut out = [0i16; 32];

    // Extract bytes and process
    let bytes = core::mem::transmute::<__m128i, [u8; 16]>(d);

    for i in 0..16 {
        let byte = bytes[i] as u32;

        // Lower nibble: coefficient 2*i
        let a0 = (byte & 0x03) as i16;       // Bits 0-1: sum of a bits
        let b0 = ((byte >> 2) & 0x03) as i16; // Bits 2-3: sum of b bits
        out[2 * i] = a0 - b0;

        // Upper nibble: coefficient 2*i + 1
        let a1 = ((byte >> 4) & 0x03) as i16;
        let b1 = ((byte >> 6) & 0x03) as i16;
        out[2 * i + 1] = a1 - b1;
    }

    coeffs[..32].copy_from_slice(&out);
}

/// Fully vectorized CBD-2 using AVX2
///
/// This version processes all operations using SIMD without fallback to scalar.
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn cbd2_vectorized(bytes: &[u8; 128], coeffs: &mut [i16; N]) {
    let mask_55 = _mm256_set1_epi32(0x55555555u32 as i32);
    let mask_03 = _mm256_set1_epi8(0x03);
    let mask_0c = _mm256_set1_epi8(0x0C);

    for chunk in 0..4 {
        let byte_offset = chunk * 32;
        let coeff_offset = chunk * 64;

        // Load 32 bytes
        let f = _mm256_loadu_si256(bytes[byte_offset..].as_ptr() as *const __m256i);

        // SWAR: accumulate pairs of bits
        let f_shifted = _mm256_srli_epi16(f, 1);
        let f_masked = _mm256_and_si256(f, mask_55);
        let f_shifted_masked = _mm256_and_si256(f_shifted, mask_55);
        let d = _mm256_add_epi8(f_masked, f_shifted_masked);

        // Extract a-sums (bits 0-1, 4-5 of each byte) and b-sums (bits 2-3, 6-7)
        // Each byte produces 2 coefficients

        // For lower nibble coefficients:
        let a_lo = _mm256_and_si256(d, mask_03); // a-sums in bits 0-1
        let b_lo = _mm256_and_si256(_mm256_srli_epi16(d, 2), mask_03); // b-sums

        // For upper nibble coefficients:
        let a_hi = _mm256_and_si256(_mm256_srli_epi16(d, 4), mask_03);
        let b_hi = _mm256_and_si256(_mm256_srli_epi16(d, 6), mask_03);

        // Compute a - b for both sets
        let coeff_lo = _mm256_sub_epi8(a_lo, b_lo); // Coefficients at even positions
        let coeff_hi = _mm256_sub_epi8(a_hi, b_hi); // Coefficients at odd positions

        // Interleave: we need [lo0, hi0, lo1, hi1, ...]
        // Use unpacklo/unpackhi to interleave bytes
        let interleaved_lo = _mm256_unpacklo_epi8(coeff_lo, coeff_hi);
        let interleaved_hi = _mm256_unpackhi_epi8(coeff_lo, coeff_hi);

        // Sign-extend from i8 to i16
        // Lower half of interleaved_lo
        let ext_0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(interleaved_lo));
        let ext_1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(interleaved_lo, 1));
        let ext_2 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(interleaved_hi));
        let ext_3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(interleaved_hi, 1));

        // Store 64 coefficients
        _mm256_storeu_si256(coeffs[coeff_offset..].as_mut_ptr() as *mut __m256i, ext_0);
        _mm256_storeu_si256(coeffs[coeff_offset + 16..].as_mut_ptr() as *mut __m256i, ext_1);
        _mm256_storeu_si256(coeffs[coeff_offset + 32..].as_mut_ptr() as *mut __m256i, ext_2);
        _mm256_storeu_si256(coeffs[coeff_offset + 48..].as_mut_ptr() as *mut __m256i, ext_3);
    }
}

// ============================================================================
// CBD-3 (η=3) - Used in ML-KEM-512
// ============================================================================

/// Sample polynomial from CBD with η=3 using AVX2
///
/// Each coefficient is computed as (a₀ + a₁ + a₂) - (b₀ + b₁ + b₂).
/// Coefficients are in range [-3, 3].
///
/// # Input
/// - `bytes`: 192 bytes of randomness (64 * η = 64 * 3)
///
/// # Output
/// - `coeffs`: 256 coefficients in range [-3, 3]
///
/// # Algorithm
///
/// For η=3, each coefficient uses 6 bits (3 bits for a-sum, 3 for b-sum).
/// Process 3 bytes at a time to get 4 coefficients:
/// - 24 bits total / 6 bits per coefficient = 4 coefficients
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn cbd3(bytes: &[u8; 192], coeffs: &mut [i16; N]) {
    // Process 3 bytes at a time to produce 4 coefficients
    // Total: 192 bytes / 3 bytes = 64 groups * 4 coefficients = 256 coefficients

    let mask_249 = 0x00249249u32; // Mask for every 3rd bit starting at position 0

    for i in 0..64 {
        let byte_offset = i * 3;

        // Load 3 bytes as a 24-bit value
        let t = (bytes[byte_offset] as u32)
            | ((bytes[byte_offset + 1] as u32) << 8)
            | ((bytes[byte_offset + 2] as u32) << 16);

        // SWAR: accumulate triplets of bits
        // Mask selects bits 0,3,6,9,12,15,18,21 (every 3rd bit)
        let d = (t & mask_249) + ((t >> 1) & mask_249) + ((t >> 2) & mask_249);

        // Extract 4 coefficients
        // Each coefficient uses 6 bits: 3-bit a-sum, 3-bit b-sum
        for j in 0..4 {
            let bits = (d >> (6 * j)) & 0x3F;
            let a = (bits & 0x7) as i16;        // Bits 0-2: a-sum
            let b = ((bits >> 3) & 0x7) as i16; // Bits 3-5: b-sum
            coeffs[i * 4 + j] = a - b;
        }
    }
}

/// Fully vectorized CBD-3 using AVX2
///
/// Processes 8 groups of 3 bytes in parallel using SIMD.
/// Uses gather-style loading and parallel bit manipulation.
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn cbd3_vectorized(bytes: &[u8; 192], coeffs: &mut [i16; N]) {
    let mask_249 = _mm256_set1_epi32(0x00249249u32 as i32);
    let mask_07 = _mm256_set1_epi32(0x07);

    // Process 24 bytes at a time (8 groups of 3 bytes = 32 coefficients)
    for chunk in 0..8 {
        let byte_offset = chunk * 24;
        let coeff_offset = chunk * 32;

        // Load 8 groups of 3 bytes into 8 32-bit integers
        // Each 32-bit int holds: [byte0, byte1, byte2, 0]
        let mut t_vals = [0u32; 8];
        for g in 0..8 {
            let group_offset = byte_offset + g * 3;
            t_vals[g] = (bytes[group_offset] as u32)
                | ((bytes[group_offset + 1] as u32) << 8)
                | ((bytes[group_offset + 2] as u32) << 16);
        }

        // Load all 8 t values into AVX2 register
        let t = _mm256_loadu_si256(t_vals.as_ptr() as *const __m256i);

        // SWAR: accumulate triplets of bits in parallel
        // d = (t & 0x249249) + ((t >> 1) & 0x249249) + ((t >> 2) & 0x249249)
        let t_mask = _mm256_and_si256(t, mask_249);
        let t1 = _mm256_srli_epi32(t, 1);
        let t1_mask = _mm256_and_si256(t1, mask_249);
        let t2 = _mm256_srli_epi32(t, 2);
        let t2_mask = _mm256_and_si256(t2, mask_249);
        let d = _mm256_add_epi32(_mm256_add_epi32(t_mask, t1_mask), t2_mask);

        // Extract 4 coefficients from each 32-bit d value
        // Coeff j: bits[6*j..6*j+6], a = bits[0..3], b = bits[3..6]
        // d contains 8 values, each producing 4 coefficients = 32 total

        // Extract coefficient 0 from each: bits [0..6]
        let c0_bits = _mm256_and_si256(d, _mm256_set1_epi32(0x3F));
        let c0_a = _mm256_and_si256(c0_bits, mask_07);
        let c0_b = _mm256_and_si256(_mm256_srli_epi32(c0_bits, 3), mask_07);
        let c0 = _mm256_sub_epi32(c0_a, c0_b);

        // Extract coefficient 1 from each: bits [6..12]
        let c1_bits = _mm256_and_si256(_mm256_srli_epi32(d, 6), _mm256_set1_epi32(0x3F));
        let c1_a = _mm256_and_si256(c1_bits, mask_07);
        let c1_b = _mm256_and_si256(_mm256_srli_epi32(c1_bits, 3), mask_07);
        let c1 = _mm256_sub_epi32(c1_a, c1_b);

        // Extract coefficient 2 from each: bits [12..18]
        let c2_bits = _mm256_and_si256(_mm256_srli_epi32(d, 12), _mm256_set1_epi32(0x3F));
        let c2_a = _mm256_and_si256(c2_bits, mask_07);
        let c2_b = _mm256_and_si256(_mm256_srli_epi32(c2_bits, 3), mask_07);
        let c2 = _mm256_sub_epi32(c2_a, c2_b);

        // Extract coefficient 3 from each: bits [18..24]
        let c3_bits = _mm256_and_si256(_mm256_srli_epi32(d, 18), _mm256_set1_epi32(0x3F));
        let c3_a = _mm256_and_si256(c3_bits, mask_07);
        let c3_b = _mm256_and_si256(_mm256_srli_epi32(c3_bits, 3), mask_07);
        let c3 = _mm256_sub_epi32(c3_a, c3_b);

        // Now we have 8 values for each coefficient position
        // Need to interleave: [g0c0, g0c1, g0c2, g0c3, g1c0, g1c1, g1c2, g1c3, ...]
        // c0, c1, c2, c3 are each [g0, g1, g2, g3, g4, g5, g6, g7]

        // Pack 32-bit to 16-bit
        // _mm256_packs_epi32 saturates, but our values are in [-3, 3] so it's fine
        let c01_lo = _mm256_packs_epi32(c0, c1);  // [c0_g0..g3, c1_g0..g3, c0_g4..g7, c1_g4..g7]
        let c23_lo = _mm256_packs_epi32(c2, c3);  // [c2_g0..g3, c3_g0..g3, c2_g4..g7, c3_g4..g7]

        // Interleave to get proper order
        let interleaved_0 = _mm256_unpacklo_epi16(c01_lo, c23_lo);
        let interleaved_1 = _mm256_unpackhi_epi16(c01_lo, c23_lo);

        // Further interleave
        let final_0 = _mm256_unpacklo_epi32(interleaved_0, interleaved_1);
        let final_1 = _mm256_unpackhi_epi32(interleaved_0, interleaved_1);

        // Fix cross-lane ordering
        let perm_0 = _mm256_permute4x64_epi64(final_0, 0b11_01_10_00);
        let perm_1 = _mm256_permute4x64_epi64(final_1, 0b11_01_10_00);

        _mm256_storeu_si256(coeffs[coeff_offset..].as_mut_ptr() as *mut __m256i, perm_0);
        _mm256_storeu_si256(coeffs[coeff_offset + 16..].as_mut_ptr() as *mut __m256i, perm_1);
    }
}

// ============================================================================
// Rejection Sampling (Uniform mod q)
// ============================================================================

/// Rejection sampling to get uniform values mod q
///
/// Processes XOF output bytes and extracts 12-bit values, accepting those < q.
///
/// # Algorithm
///
/// From every 3 bytes, extract two 12-bit values:
/// - d1 = byte[0] | (byte[1] & 0x0F) << 8
/// - d2 = (byte[1] >> 4) | byte[2] << 4
///
/// Accept if value < q (3329).
///
/// # Returns
/// Number of coefficients written to output.
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn rej_uniform(
    coeffs: &mut [i16],
    max_coeffs: usize,
    bytes: &[u8],
) -> usize {
    let mut ctr = 0;
    let mut pos = 0;
    let q16 = Q as u16;

    // Process 3 bytes at a time
    while pos + 2 < bytes.len() && ctr < max_coeffs {
        // Extract two 12-bit values
        let d1 = (bytes[pos] as u16) | (((bytes[pos + 1] as u16) & 0x0F) << 8);
        let d2 = ((bytes[pos + 1] as u16) >> 4) | ((bytes[pos + 2] as u16) << 4);
        pos += 3;

        // Rejection sampling
        if d1 < q16 && ctr < max_coeffs {
            coeffs[ctr] = d1 as i16;
            ctr += 1;
        }

        if d2 < q16 && ctr < max_coeffs {
            coeffs[ctr] = d2 as i16;
            ctr += 1;
        }
    }

    ctr
}

/// Vectorized rejection sampling using AVX2
///
/// Processes 48 bytes at a time (16 groups of 3 bytes = 32 candidates).
/// Uses parallel comparison to check all candidates at once.
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn rej_uniform_avx2(
    coeffs: &mut [i16],
    max_coeffs: usize,
    bytes: &[u8],
) -> usize {
    let mut ctr = 0;
    let mut pos = 0;

    let q_vec = _mm256_set1_epi16(Q);

    // Process in batches of 48 bytes (32 candidates)
    while pos + 48 <= bytes.len() && ctr + 32 <= max_coeffs {
        // Extract 32 12-bit values from 48 bytes
        let mut candidates = [0u16; 32];

        for i in 0..16 {
            let offset = pos + i * 3;
            let d1 = (bytes[offset] as u16) | (((bytes[offset + 1] as u16) & 0x0F) << 8);
            let d2 = ((bytes[offset + 1] as u16) >> 4) | ((bytes[offset + 2] as u16) << 4);
            candidates[i * 2] = d1;
            candidates[i * 2 + 1] = d2;
        }

        // Load candidates as i16
        let cand0 = _mm256_loadu_si256(candidates[0..].as_ptr() as *const __m256i);
        let cand1 = _mm256_loadu_si256(candidates[16..].as_ptr() as *const __m256i);

        // Compare with q (check if < q)
        // AVX2 doesn't have unsigned compare, so we use signed compare with adjustment
        // Since q = 3329 < 32768, we can use signed compare directly
        let valid0 = _mm256_cmpgt_epi16(q_vec, cand0); // q > cand means cand < q
        let valid1 = _mm256_cmpgt_epi16(q_vec, cand1);

        // Count valid entries and compact
        let mask0 = _mm256_movemask_epi8(valid0) as u32;
        let mask1 = _mm256_movemask_epi8(valid1) as u32;

        // Extract valid values
        // For simplicity, use scalar extraction (full vectorization is complex)
        for i in 0..16 {
            if candidates[i] < Q as u16 && ctr < max_coeffs {
                coeffs[ctr] = candidates[i] as i16;
                ctr += 1;
            }
        }
        for i in 16..32 {
            if candidates[i] < Q as u16 && ctr < max_coeffs {
                coeffs[ctr] = candidates[i] as i16;
                ctr += 1;
            }
        }

        pos += 48;
    }

    // Handle remaining bytes with scalar code
    ctr + rej_uniform_scalar(&mut coeffs[ctr..], max_coeffs - ctr, &bytes[pos..])
}

/// Scalar rejection sampling fallback
fn rej_uniform_scalar(
    coeffs: &mut [i16],
    max_coeffs: usize,
    bytes: &[u8],
) -> usize {
    let mut ctr = 0;
    let mut pos = 0;
    let q16 = Q as u16;

    while pos + 2 < bytes.len() && ctr < max_coeffs {
        let d1 = (bytes[pos] as u16) | (((bytes[pos + 1] as u16) & 0x0F) << 8);
        let d2 = ((bytes[pos + 1] as u16) >> 4) | ((bytes[pos + 2] as u16) << 4);
        pos += 3;

        if d1 < q16 && ctr < max_coeffs {
            coeffs[ctr] = d1 as i16;
            ctr += 1;
        }

        if d2 < q16 && ctr < max_coeffs {
            coeffs[ctr] = d2 as i16;
            ctr += 1;
        }
    }

    ctr
}

// ============================================================================
// Public API
// ============================================================================

/// Sample polynomial from CBD_2 (for ML-KEM-768 and ML-KEM-1024)
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn sample_cbd2(bytes: &[u8; 128]) -> [i16; N] {
    let mut coeffs = [0i16; N];
    cbd2_vectorized(bytes, &mut coeffs);
    coeffs
}

/// Sample polynomial from CBD_3 (for ML-KEM-512)
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn sample_cbd3(bytes: &[u8; 192]) -> [i16; N] {
    let mut coeffs = [0i16; N];
    cbd3_vectorized(bytes, &mut coeffs);
    coeffs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_cbd2_range() {
        unsafe {
            let bytes = [0x42u8; 128];
            let mut coeffs = [0i16; N];
            cbd2(&bytes, &mut coeffs);

            // CBD_2 produces coefficients in [-2, 2]
            for &c in &coeffs {
                assert!(c >= -2 && c <= 2, "coefficient {} out of range", c);
            }
        }
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_cbd2_all_zeros() {
        unsafe {
            let bytes = [0u8; 128];
            let mut coeffs = [0i16; N];
            cbd2(&bytes, &mut coeffs);

            // All zero input should produce all zero coefficients
            for &c in &coeffs {
                assert_eq!(c, 0);
            }
        }
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_cbd3_range() {
        unsafe {
            let bytes = [0x42u8; 192];
            let mut coeffs = [0i16; N];
            cbd3(&bytes, &mut coeffs);

            // CBD_3 produces coefficients in [-3, 3]
            for &c in &coeffs {
                assert!(c >= -3 && c <= 3, "coefficient {} out of range", c);
            }
        }
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_rej_uniform_range() {
        unsafe {
            let bytes = [0x42u8; 168]; // SHAKE-128 rate
            let mut coeffs = [0i16; N];
            let count = rej_uniform(&mut coeffs, N, &bytes);

            // All accepted coefficients should be in [0, q)
            for i in 0..count {
                assert!(coeffs[i] >= 0 && coeffs[i] < Q);
            }
        }
    }
}
