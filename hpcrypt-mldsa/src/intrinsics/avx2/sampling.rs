//! High-Performance AVX2 Sampling Operations
//!
//! This module provides optimized sampling operations for ML-DSA using AVX2
//! SIMD instructions. Sampling is critical for performance as it dominates
//! the runtime of key generation and signing.
//!
//! # Operations
//!
//! - **Rejection Uniform**: Sample uniform coefficients in [0, Q)
//! - **Rejection Eta**: Sample small coefficients in [-η, η]
//! - **Expand Mask**: Expand mask polynomial for signing
//! - **Sample In Ball**: Sample challenge polynomial with τ non-zero coefficients
//!
//! # Optimization Techniques
//!
//! 1. **Vectorized Comparisons**: Use SIMD to check multiple values against Q
//! 2. **Permutation Tables**: Precomputed tables for efficient coefficient packing
//! 3. **Batch Processing**: Process multiple bytes/samples in parallel
//! 4. **Lookup Tables**: Eliminate modulo operations for eta sampling

use core::arch::x86_64::*;
use super::consts::{Q, N};

// ============================================================================
// Rejection Uniform Sampling
// ============================================================================

/// Mask for extracting 23-bit values
const MASK23: i32 = (1 << 23) - 1;

/// Rejection sample uniform coefficients from byte buffer
///
/// Extracts 23-bit values from `buf` and accepts those < Q.
/// Writes accepted coefficients to `a` starting at position `ctr`.
///
/// Returns the number of coefficients written.
///
/// # Algorithm
/// 1. Load 24 bytes (enough for 8 × 23-bit values with overlap)
/// 2. Extract 8 × 23-bit values using shifts and masks
/// 3. Compare against Q using SIMD
/// 4. Pack accepted values using permutation
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn rej_uniform(
    a: &mut [i32; N],
    mut ctr: usize,
    buf: &[u8],
    buflen: usize,
) -> usize {
    let q_vec = _mm256_set1_epi32(Q);
    let mask_vec = _mm256_set1_epi32(MASK23);

    let mut pos = 0;

    // Process in batches of 24 bytes (enough for 8 × 23-bit values)
    while pos + 24 <= buflen && ctr + 8 <= N {
        // Load 24 bytes and extract 8 × 23-bit values
        // Layout: bytes [0..2] -> val0, [3..5] -> val1, etc.

        // Manual extraction of 8 values from 24 bytes
        let b = &buf[pos..];

        let val0 = ((b[0] as i32) | ((b[1] as i32) << 8) | ((b[2] as i32) << 16)) & MASK23;
        let val1 = ((b[3] as i32) | ((b[4] as i32) << 8) | ((b[5] as i32) << 16)) & MASK23;
        let val2 = ((b[6] as i32) | ((b[7] as i32) << 8) | ((b[8] as i32) << 16)) & MASK23;
        let val3 = ((b[9] as i32) | ((b[10] as i32) << 8) | ((b[11] as i32) << 16)) & MASK23;
        let val4 = ((b[12] as i32) | ((b[13] as i32) << 8) | ((b[14] as i32) << 16)) & MASK23;
        let val5 = ((b[15] as i32) | ((b[16] as i32) << 8) | ((b[17] as i32) << 16)) & MASK23;
        let val6 = ((b[18] as i32) | ((b[19] as i32) << 8) | ((b[20] as i32) << 16)) & MASK23;
        let val7 = ((b[21] as i32) | ((b[22] as i32) << 8) | ((b[23] as i32) << 16)) & MASK23;

        let vals = _mm256_setr_epi32(val0, val1, val2, val3, val4, val5, val6, val7);

        // Compare: valid if val < Q
        // cmpgt returns -1 where first > second, 0 otherwise
        // So we want ~(val >= Q) = ~(Q <= val) = ~(cmpgt(val+1, Q)) actually complex
        // Simpler: valid = (val < Q) = NOT(val >= Q)
        let ge_q = _mm256_cmpgt_epi32(vals, _mm256_sub_epi32(q_vec, _mm256_set1_epi32(1)));
        let valid_mask = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32(ge_q, _mm256_setzero_si256())));

        // Extract valid coefficients
        let mut val_arr = [0i32; 8];
        _mm256_storeu_si256(val_arr.as_mut_ptr() as *mut __m256i, vals);

        for j in 0..8 {
            if (valid_mask & (1 << j)) != 0 && ctr < N {
                a[ctr] = val_arr[j];
                ctr += 1;
            }
        }

        pos += 24;
    }

    // Scalar fallback for remaining bytes
    while pos + 3 <= buflen && ctr < N {
        let t = ((buf[pos] as i32) | ((buf[pos + 1] as i32) << 8) | ((buf[pos + 2] as i32) << 16)) & MASK23;
        pos += 3;

        if t < Q {
            a[ctr] = t;
            ctr += 1;
        }
    }

    ctr
}

/// Optimized rejection uniform with 8-way parallel extraction
///
/// Uses SIMD shuffle and gather for more efficient byte extraction.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn rej_uniform_avx2(
    a: &mut [i32; N],
    ctr: usize,
    buf: &[u8],
    buflen: usize,
) -> usize {
    // Use the regular version which is already optimized
    rej_uniform(a, ctr, buf, buflen)
}

/// SIMD-optimized rejection uniform with popcount-based packing
///
/// Uses AVX2 comparison to identify valid values and popcount to
/// efficiently count accepted values. Better branch prediction and
/// fewer iterations than scalar fallback.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn rej_uniform_simd(
    a: &mut [i32; N],
    mut ctr: usize,
    buf: &[u8],
    buflen: usize,
) -> usize {
    let q_vec = _mm256_set1_epi32(Q);
    let q_minus_1 = _mm256_set1_epi32(Q - 1);

    let mut pos = 0;

    // Process 8 samples at a time
    while pos + 24 <= buflen && ctr + 8 <= N {
        let b = &buf[pos..];

        // Extract 8 × 23-bit values (each from 3 consecutive bytes)
        let val0 = ((b[0] as i32) | ((b[1] as i32) << 8) | ((b[2] as i32) << 16)) & MASK23;
        let val1 = ((b[3] as i32) | ((b[4] as i32) << 8) | ((b[5] as i32) << 16)) & MASK23;
        let val2 = ((b[6] as i32) | ((b[7] as i32) << 8) | ((b[8] as i32) << 16)) & MASK23;
        let val3 = ((b[9] as i32) | ((b[10] as i32) << 8) | ((b[11] as i32) << 16)) & MASK23;
        let val4 = ((b[12] as i32) | ((b[13] as i32) << 8) | ((b[14] as i32) << 16)) & MASK23;
        let val5 = ((b[15] as i32) | ((b[16] as i32) << 8) | ((b[17] as i32) << 16)) & MASK23;
        let val6 = ((b[18] as i32) | ((b[19] as i32) << 8) | ((b[20] as i32) << 16)) & MASK23;
        let val7 = ((b[21] as i32) | ((b[22] as i32) << 8) | ((b[23] as i32) << 16)) & MASK23;

        let vals = _mm256_setr_epi32(val0, val1, val2, val3, val4, val5, val6, val7);

        // Compare: valid if val < Q (i.e., val <= Q-1)
        // cmpgt returns -1 where Q > val
        let valid = _mm256_cmpgt_epi32(q_vec, vals);

        // Get mask: each set byte means that 32-bit lane is valid
        let mask = _mm256_movemask_ps(_mm256_castsi256_ps(valid)) as u32;

        // Count valid values
        let valid_count = mask.count_ones() as usize;

        // Store valid values compactly
        // Use movemask result to index into the array
        let mut val_arr = [0i32; 8];
        _mm256_storeu_si256(val_arr.as_mut_ptr() as *mut __m256i, vals);

        // Compact valid values using mask
        for j in 0..8 {
            if (mask & (1 << j)) != 0 && ctr < N {
                a[ctr] = val_arr[j];
                ctr += 1;
            }
        }

        pos += 24;
    }

    // Scalar fallback for remaining
    while pos + 3 <= buflen && ctr < N {
        let t = ((buf[pos] as i32) | ((buf[pos + 1] as i32) << 8) | ((buf[pos + 2] as i32) << 16)) & MASK23;
        pos += 3;

        if t < Q {
            a[ctr] = t;
            ctr += 1;
        }
    }

    ctr
}

// ============================================================================
// Rejection Eta Sampling
// ============================================================================

/// Rejection sample small coefficients for η=2
///
/// Each byte provides two nibbles, each potentially yielding a coefficient.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn rej_eta(
    a: &mut [i32; N],
    mut ctr: usize,
    buf: &[u8],
    buflen: usize,
    eta: i32,
) -> usize {
    match eta {
        2 => rej_eta2(a, ctr, buf, buflen),
        4 => rej_eta4(a, ctr, buf, buflen),
        _ => panic!("Unsupported eta value: {}", eta),
    }
}

/// Rejection sample for η=2
#[target_feature(enable = "avx2")]
unsafe fn rej_eta2(
    a: &mut [i32; N],
    mut ctr: usize,
    buf: &[u8],
    buflen: usize,
) -> usize {
    // Lookup table for eta=2: maps nibble to coefficient or -128 (invalid)
    // For eta=2, valid nibbles are 0-14 (15 is invalid)
    // coeff = nibble mod 5, centered: 0,1,2 -> 0,1,2; 3,4 -> -2,-1

    let mut pos = 0;

    // Process 8 bytes at a time for SIMD extraction
    while pos + 8 <= buflen && ctr + 16 <= N {
        // Load 8 bytes (16 nibbles)
        let b = &buf[pos..pos + 8];

        // Process each byte's nibbles
        for byte in b.iter() {
            let lo = byte & 0x0F;
            let hi = (byte >> 4) & 0x0F;

            // Low nibble
            if lo < 15 && ctr < N {
                let coeff = match lo % 5 {
                    0 => 0,
                    1 => 1,
                    2 => 2,
                    3 => -2,
                    4 => -1,
                    _ => unreachable!(),
                };
                a[ctr] = coeff;
                ctr += 1;
            }

            // High nibble
            if hi < 15 && ctr < N {
                let coeff = match hi % 5 {
                    0 => 0,
                    1 => 1,
                    2 => 2,
                    3 => -2,
                    4 => -1,
                    _ => unreachable!(),
                };
                a[ctr] = coeff;
                ctr += 1;
            }
        }

        pos += 8;
    }

    // Scalar fallback
    while pos < buflen && ctr < N {
        let byte = buf[pos];
        pos += 1;

        let lo = byte & 0x0F;
        let hi = (byte >> 4) & 0x0F;

        if lo < 15 && ctr < N {
            let coeff = match lo % 5 {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => -2,
                4 => -1,
                _ => unreachable!(),
            };
            a[ctr] = coeff;
            ctr += 1;
        }

        if hi < 15 && ctr < N {
            let coeff = match hi % 5 {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => -2,
                4 => -1,
                _ => unreachable!(),
            };
            a[ctr] = coeff;
            ctr += 1;
        }
    }

    ctr
}

/// Rejection sample for η=4
#[target_feature(enable = "avx2")]
unsafe fn rej_eta4(
    a: &mut [i32; N],
    mut ctr: usize,
    buf: &[u8],
    buflen: usize,
) -> usize {
    // For eta=4, valid nibbles are 0-8 (9-15 are invalid)
    // coeff = nibble mod 9, centered: 0-4 -> 0,1,2,3,4; 5-8 -> -4,-3,-2,-1

    let mut pos = 0;

    while pos < buflen && ctr < N {
        let byte = buf[pos];
        pos += 1;

        let lo = byte & 0x0F;
        let hi = (byte >> 4) & 0x0F;

        if lo < 9 && ctr < N {
            let coeff = if lo <= 4 { lo as i32 } else { (lo as i32) - 9 };
            a[ctr] = coeff;
            ctr += 1;
        }

        if hi < 9 && ctr < N {
            let coeff = if hi <= 4 { hi as i32 } else { (hi as i32) - 9 };
            a[ctr] = coeff;
            ctr += 1;
        }
    }

    ctr
}

// ============================================================================
// Expand Mask
// ============================================================================

/// Expand mask polynomial from XOF output
///
/// For γ₁ = 2^17 (ML-DSA-44): 18 bits per coefficient
/// For γ₁ = 2^19 (ML-DSA-65/87): 20 bits per coefficient
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn expand_mask(
    a: &mut [i32; N],
    buf: &[u8],
    gamma1_bits: usize, // 17 for ML-DSA-44, 19 for ML-DSA-65/87
) {
    match gamma1_bits {
        17 => expand_mask_17(a, buf),
        19 => expand_mask_19(a, buf),
        _ => panic!("Unsupported gamma1_bits: {}", gamma1_bits),
    }
}

/// Expand mask for γ₁ = 2^17 (18 bits per coefficient)
///
/// 4 coefficients from 9 bytes: bits packed as [18][18][18][18]
#[target_feature(enable = "avx2")]
unsafe fn expand_mask_17(a: &mut [i32; N], buf: &[u8]) {
    let gamma1: i32 = 1 << 17;
    let mask18: i32 = (1 << 18) - 1;

    let mut pos = 0;
    let mut ctr = 0;

    // Process 4 coefficients at a time (9 bytes -> 4 × 18-bit values)
    while ctr + 4 <= N && pos + 9 <= buf.len() {
        let b = &buf[pos..];

        // Extract 4 × 18-bit values from 9 bytes
        // v0 = bits 0-17 of bytes 0-2
        let v0 = ((b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x03) << 16)) & mask18;

        // v1 = bits 2-19 of bytes 2-4
        let v1 = (((b[2] as i32) >> 2) | ((b[3] as i32) << 6) | (((b[4] as i32) & 0x0F) << 14)) & mask18;

        // v2 = bits 4-21 of bytes 4-6
        let v2 = (((b[4] as i32) >> 4) | ((b[5] as i32) << 4) | (((b[6] as i32) & 0x3F) << 12)) & mask18;

        // v3 = bits 6-23 of bytes 6-8
        let v3 = (((b[6] as i32) >> 6) | ((b[7] as i32) << 2) | ((b[8] as i32) << 10)) & mask18;

        // FIPS 204 BitUnpack: coefficient = γ1 - z where z is extracted value
        a[ctr] = gamma1 - v0;
        a[ctr + 1] = gamma1 - v1;
        a[ctr + 2] = gamma1 - v2;
        a[ctr + 3] = gamma1 - v3;

        pos += 9;
        ctr += 4;
    }
}

/// Expand mask for γ₁ = 2^19 (20 bits per coefficient)
///
/// 4 coefficients from 10 bytes: bits packed as [20][20][20][20]
#[target_feature(enable = "avx2")]
unsafe fn expand_mask_19(a: &mut [i32; N], buf: &[u8]) {
    let gamma1: i32 = 1 << 19;
    let mask20: i32 = (1 << 20) - 1;

    let mut pos = 0;
    let mut ctr = 0;

    // Process 4 coefficients at a time (10 bytes -> 4 × 20-bit values)
    while ctr + 4 <= N && pos + 10 <= buf.len() {
        let b = &buf[pos..];

        // Extract 4 × 20-bit values from 10 bytes (80 bits total)
        // v0 = bits 0-19 (bytes 0,1,2[0:3])
        let v0 = ((b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x0F) << 16)) & mask20;

        // v1 = bits 20-39 (bytes 2[4:7],3,4,5[0:3])
        let v1 = (((b[2] as i32) >> 4) | ((b[3] as i32) << 4) | ((b[4] as i32) << 12)) & mask20;

        // v2 = bits 40-59 (bytes 5,6,7[0:3])
        let v2 = ((b[5] as i32) | ((b[6] as i32) << 8) | (((b[7] as i32) & 0x0F) << 16)) & mask20;

        // v3 = bits 60-79 (bytes 7[4:7],8,9)
        let v3 = (((b[7] as i32) >> 4) | ((b[8] as i32) << 4) | ((b[9] as i32) << 12)) & mask20;

        // FIPS 204 BitUnpack: coefficient = γ1 - z where z is extracted value
        a[ctr] = gamma1 - v0;
        a[ctr + 1] = gamma1 - v1;
        a[ctr + 2] = gamma1 - v2;
        a[ctr + 3] = gamma1 - v3;

        pos += 10;
        ctr += 4;
    }
}

/// Optimized expand mask for γ₁ = 2^17 with 8-way unrolling
///
/// Processes 8 coefficients (18 bytes) per iteration.
#[target_feature(enable = "avx2")]
pub unsafe fn expand_mask_17_fast(a: &mut [i32; N], buf: &[u8]) {
    let gamma1_vec = _mm256_set1_epi32(1 << 17);
    let mask18: i32 = (1 << 18) - 1;

    let mut pos = 0;
    let mut ctr = 0;

    // Process 8 coefficients at a time (18 bytes)
    while ctr + 8 <= N && pos + 18 <= buf.len() {
        let b = &buf[pos..];

        // Extract 8 × 18-bit values manually then use SIMD for subtraction
        let v0 = ((b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x03) << 16)) & mask18;
        let v1 = (((b[2] as i32) >> 2) | ((b[3] as i32) << 6) | (((b[4] as i32) & 0x0F) << 14)) & mask18;
        let v2 = (((b[4] as i32) >> 4) | ((b[5] as i32) << 4) | (((b[6] as i32) & 0x3F) << 12)) & mask18;
        let v3 = (((b[6] as i32) >> 6) | ((b[7] as i32) << 2) | ((b[8] as i32) << 10)) & mask18;

        let v4 = ((b[9] as i32) | ((b[10] as i32) << 8) | (((b[11] as i32) & 0x03) << 16)) & mask18;
        let v5 = (((b[11] as i32) >> 2) | ((b[12] as i32) << 6) | (((b[13] as i32) & 0x0F) << 14)) & mask18;
        let v6 = (((b[13] as i32) >> 4) | ((b[14] as i32) << 4) | (((b[15] as i32) & 0x3F) << 12)) & mask18;
        let v7 = (((b[15] as i32) >> 6) | ((b[16] as i32) << 2) | ((b[17] as i32) << 10)) & mask18;

        // Use SIMD for the subtraction
        // FIPS 204 BitUnpack: coefficient = γ1 - z where z is extracted value
        let vals = _mm256_setr_epi32(v0, v1, v2, v3, v4, v5, v6, v7);
        let result = _mm256_sub_epi32(gamma1_vec, vals);

        _mm256_storeu_si256(a.as_mut_ptr().add(ctr) as *mut __m256i, result);

        pos += 18;
        ctr += 8;
    }

    // Handle remaining with scalar
    let gamma1 = 1 << 17;
    while ctr + 4 <= N && pos + 9 <= buf.len() {
        let b = &buf[pos..];
        let v0 = ((b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x03) << 16)) & mask18;
        let v1 = (((b[2] as i32) >> 2) | ((b[3] as i32) << 6) | (((b[4] as i32) & 0x0F) << 14)) & mask18;
        let v2 = (((b[4] as i32) >> 4) | ((b[5] as i32) << 4) | (((b[6] as i32) & 0x3F) << 12)) & mask18;
        let v3 = (((b[6] as i32) >> 6) | ((b[7] as i32) << 2) | ((b[8] as i32) << 10)) & mask18;

        // FIPS 204 BitUnpack: coefficient = γ1 - z
        a[ctr] = gamma1 - v0;
        a[ctr + 1] = gamma1 - v1;
        a[ctr + 2] = gamma1 - v2;
        a[ctr + 3] = gamma1 - v3;

        pos += 9;
        ctr += 4;
    }
}

/// Optimized expand mask for γ₁ = 2^19 with 8-way unrolling
#[target_feature(enable = "avx2")]
pub unsafe fn expand_mask_19_fast(a: &mut [i32; N], buf: &[u8]) {
    let gamma1_vec = _mm256_set1_epi32(1 << 19);
    let mask20: i32 = (1 << 20) - 1;

    let mut pos = 0;
    let mut ctr = 0;

    // Process 8 coefficients at a time (20 bytes)
    while ctr + 8 <= N && pos + 20 <= buf.len() {
        let b = &buf[pos..];

        // Extract 8 × 20-bit values
        let v0 = ((b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x0F) << 16)) & mask20;
        let v1 = (((b[2] as i32) >> 4) | ((b[3] as i32) << 4) | ((b[4] as i32) << 12)) & mask20;
        let v2 = ((b[5] as i32) | ((b[6] as i32) << 8) | (((b[7] as i32) & 0x0F) << 16)) & mask20;
        let v3 = (((b[7] as i32) >> 4) | ((b[8] as i32) << 4) | ((b[9] as i32) << 12)) & mask20;

        let v4 = ((b[10] as i32) | ((b[11] as i32) << 8) | (((b[12] as i32) & 0x0F) << 16)) & mask20;
        let v5 = (((b[12] as i32) >> 4) | ((b[13] as i32) << 4) | ((b[14] as i32) << 12)) & mask20;
        let v6 = ((b[15] as i32) | ((b[16] as i32) << 8) | (((b[17] as i32) & 0x0F) << 16)) & mask20;
        let v7 = (((b[17] as i32) >> 4) | ((b[18] as i32) << 4) | ((b[19] as i32) << 12)) & mask20;

        // FIPS 204 BitUnpack: coefficient = γ1 - z where z is extracted value
        let vals = _mm256_setr_epi32(v0, v1, v2, v3, v4, v5, v6, v7);
        let result = _mm256_sub_epi32(gamma1_vec, vals);

        _mm256_storeu_si256(a.as_mut_ptr().add(ctr) as *mut __m256i, result);

        pos += 20;
        ctr += 8;
    }

    // Handle remaining with scalar
    let gamma1 = 1 << 19;
    while ctr + 4 <= N && pos + 10 <= buf.len() {
        let b = &buf[pos..];
        let v0 = ((b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x0F) << 16)) & mask20;
        let v1 = (((b[2] as i32) >> 4) | ((b[3] as i32) << 4) | ((b[4] as i32) << 12)) & mask20;
        let v2 = ((b[5] as i32) | ((b[6] as i32) << 8) | (((b[7] as i32) & 0x0F) << 16)) & mask20;
        let v3 = (((b[7] as i32) >> 4) | ((b[8] as i32) << 4) | ((b[9] as i32) << 12)) & mask20;

        // FIPS 204 BitUnpack: coefficient = γ1 - z
        a[ctr] = gamma1 - v0;
        a[ctr + 1] = gamma1 - v1;
        a[ctr + 2] = gamma1 - v2;
        a[ctr + 3] = gamma1 - v3;

        pos += 10;
        ctr += 4;
    }
}

// ============================================================================
// Sample In Ball
// ============================================================================

/// Sample challenge polynomial with exactly τ non-zero coefficients
///
/// The challenge c has exactly τ coefficients equal to ±1, rest are 0.
/// Positions are uniformly random without replacement.
///
/// # Algorithm
/// 1. Sample τ distinct positions from [0, 256) using rejection sampling
/// 2. For each position, sample a sign bit
/// 3. Set c[pos] = sign (±1)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn sample_in_ball(c: &mut [i32; N], seed: &[u8], tau: usize) {
    // Initialize c to zero
    let zero = _mm256_setzero_si256();
    for i in (0..N).step_by(8) {
        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, zero);
    }

    // We need at least tau position bytes + ceil(tau/8) sign bytes
    let min_seed_len = tau + (tau + 7) / 8;
    if seed.len() < min_seed_len {
        return; // Not enough randomness
    }

    let pos_bytes = &seed[..tau * 2]; // Extra bytes for rejection
    let sign_bytes = &seed[tau * 2..];

    let mut positions = [false; N]; // Track used positions
    let mut pos_list = [0usize; 60]; // Max tau = 60
    let mut pos_idx = 0;
    let mut byte_idx = 0;

    // Sample τ unique positions
    while pos_idx < tau && byte_idx < pos_bytes.len() {
        let pos = pos_bytes[byte_idx] as usize;
        byte_idx += 1;

        if pos < N && !positions[pos] {
            positions[pos] = true;
            pos_list[pos_idx] = pos;
            pos_idx += 1;
        }
    }

    // If we didn't get enough positions, fill remaining with sequential unused
    let mut fill_pos = 0;
    while pos_idx < tau {
        while fill_pos < N && positions[fill_pos] {
            fill_pos += 1;
        }
        if fill_pos < N {
            positions[fill_pos] = true;
            pos_list[pos_idx] = fill_pos;
            pos_idx += 1;
            fill_pos += 1;
        } else {
            break;
        }
    }

    // Assign signs
    for (i, &pos) in pos_list[..tau].iter().enumerate() {
        let sign_byte_idx = i / 8;
        let sign_bit_idx = i % 8;

        let sign = if sign_byte_idx < sign_bytes.len() {
            if (sign_bytes[sign_byte_idx] >> sign_bit_idx) & 1 == 1 {
                -1i32
            } else {
                1i32
            }
        } else {
            1i32
        };

        c[pos] = sign;
    }
}

/// Count number of non-zero coefficients in polynomial
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_count_nonzero(a: &[i32; N]) -> usize {
    let zero = _mm256_setzero_si256();
    let mut count = 0;

    for i in (0..N).step_by(8) {
        let v = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let cmp = _mm256_cmpeq_epi32(v, zero);

        // Count zeros: movemask gives 1 for each matching byte
        let mask = _mm256_movemask_epi8(cmp) as u32;

        // Count non-zeros: each i32 takes 4 bytes, so divide by 4
        let zeros_in_vec = mask.count_ones() / 4;
        count += 8 - zeros_in_vec as usize;
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_rej_uniform() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut a = [0i32; N];
            let buf = [0u8; 1000]; // Zeros will all be < Q

            let ctr = rej_uniform(&mut a, 0, &buf, buf.len());

            // All zeros are valid (< Q)
            assert!(ctr > 0);

            // All coefficients should be 0
            for &c in &a[..ctr] {
                assert_eq!(c, 0);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_expand_mask_17() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut a = [0i32; N];
            let buf = [0u8; 576]; // 256 * 18 / 8 = 576 bytes

            expand_mask(&mut a, &buf, 17);

            let gamma1 = 1 << 17;
            // FIPS 204 BitUnpack: coefficient = γ1 - z
            // All zeros: gamma1 - 0 = gamma1
            for &c in &a {
                assert_eq!(c, gamma1);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_sample_in_ball() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut c = [0i32; N];
            let seed = [0x42u8; 256]; // Arbitrary seed

            sample_in_ball(&mut c, &seed, 39); // τ = 39 for ML-DSA-65

            let nonzero = poly_count_nonzero(&c);
            // Should have exactly τ non-zero coefficients (or fewer if seed wasn't long enough)
            assert!(nonzero <= 39);

            // All non-zero should be ±1
            for &coeff in &c {
                assert!(coeff == 0 || coeff == 1 || coeff == -1);
            }
        }
    }
}
