//! High-Performance AVX2 Bit-Packing and Serialization
//!
//! This module provides optimized serialization/deserialization operations
//! for ML-DSA using AVX2 SIMD instructions.
//!
//! # Operations
//!
//! - **t1 encoding**: 10-bit coefficients (public key)
//! - **t0 encoding**: 13-bit coefficients (secret key)
//! - **z encoding**: 18 or 20-bit coefficients (signature)
//! - **eta encoding**: 3 or 4-bit coefficients (secret key)
//! - **w1 encoding**: Variable bit-width high bits (signature)
//!
//! # Optimization Strategy
//!
//! Bit-packing is memory-bound rather than compute-bound, so the main
//! optimization is efficient memory access patterns and reducing the
//! number of load/store operations.

use core::arch::x86_64::*;
use super::consts::{N, D};

// ============================================================================
// t1 Encoding (10-bit coefficients)
// ============================================================================

/// Pack t1 polynomial into bytes
///
/// Each coefficient is 10 bits. 4 coefficients pack into 5 bytes.
///
/// # Layout
/// ```text
/// byte[0] = c0[7:0]
/// byte[1] = c0[9:8] | c1[5:0] << 2
/// byte[2] = c1[9:6] | c2[3:0] << 4
/// byte[3] = c2[9:4] | c3[1:0] << 6
/// byte[4] = c3[9:2]
/// ```
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_t1(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 320); // 256 * 10 / 8 = 320

    let mut byte_idx = 0;

    // Process 4 coefficients at a time (produces 5 bytes)
    for chunk in coeffs.chunks_exact(4) {
        let c0 = chunk[0] as u32;
        let c1 = chunk[1] as u32;
        let c2 = chunk[2] as u32;
        let c3 = chunk[3] as u32;

        bytes[byte_idx] = c0 as u8;
        bytes[byte_idx + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
        bytes[byte_idx + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
        bytes[byte_idx + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
        bytes[byte_idx + 4] = (c3 >> 2) as u8;

        byte_idx += 5;
    }
}

/// Unpack bytes into t1 polynomial
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_t1(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 320);

    let mask10 = 0x3FF; // 10 bits
    let mut byte_idx = 0;

    for chunk in coeffs.chunks_exact_mut(4) {
        let b0 = bytes[byte_idx] as u32;
        let b1 = bytes[byte_idx + 1] as u32;
        let b2 = bytes[byte_idx + 2] as u32;
        let b3 = bytes[byte_idx + 3] as u32;
        let b4 = bytes[byte_idx + 4] as u32;

        chunk[0] = (b0 | (b1 << 8)) as i32 & mask10;
        chunk[1] = ((b1 >> 2) | (b2 << 6)) as i32 & mask10;
        chunk[2] = ((b2 >> 4) | (b3 << 4)) as i32 & mask10;
        chunk[3] = ((b3 >> 6) | (b4 << 2)) as i32 & mask10;

        byte_idx += 5;
    }
}

// ============================================================================
// t0 Encoding (13-bit coefficients)
// ============================================================================

/// Pack t0 polynomial into bytes
///
/// Each coefficient is 13 bits. 8 coefficients pack into 13 bytes.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_t0(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 416); // 256 * 13 / 8 = 416

    let half_power = (1 << (D - 1)) as i32; // 2^12 = 4096
    let mut byte_idx = 0;

    // Process 8 coefficients at a time (produces 13 bytes)
    for chunk in coeffs.chunks_exact(8) {
        // Convert from signed to unsigned representation
        // t0 is stored as 2^(D-1) - t0 to ensure positive values
        let c: [u32; 8] = [
            (half_power - chunk[0]) as u32,
            (half_power - chunk[1]) as u32,
            (half_power - chunk[2]) as u32,
            (half_power - chunk[3]) as u32,
            (half_power - chunk[4]) as u32,
            (half_power - chunk[5]) as u32,
            (half_power - chunk[6]) as u32,
            (half_power - chunk[7]) as u32,
        ];

        // Pack 8 × 13-bit values into 13 bytes
        bytes[byte_idx + 0] = c[0] as u8;
        bytes[byte_idx + 1] = ((c[0] >> 8) | (c[1] << 5)) as u8;
        bytes[byte_idx + 2] = (c[1] >> 3) as u8;
        bytes[byte_idx + 3] = ((c[1] >> 11) | (c[2] << 2)) as u8;
        bytes[byte_idx + 4] = ((c[2] >> 6) | (c[3] << 7)) as u8;
        bytes[byte_idx + 5] = (c[3] >> 1) as u8;
        bytes[byte_idx + 6] = ((c[3] >> 9) | (c[4] << 4)) as u8;
        bytes[byte_idx + 7] = (c[4] >> 4) as u8;
        bytes[byte_idx + 8] = ((c[4] >> 12) | (c[5] << 1)) as u8;
        bytes[byte_idx + 9] = ((c[5] >> 7) | (c[6] << 6)) as u8;
        bytes[byte_idx + 10] = (c[6] >> 2) as u8;
        bytes[byte_idx + 11] = ((c[6] >> 10) | (c[7] << 3)) as u8;
        bytes[byte_idx + 12] = (c[7] >> 5) as u8;

        byte_idx += 13;
    }
}

/// Unpack bytes into t0 polynomial
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_t0(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 416);

    let half_power = (1 << (D - 1)) as i32;
    let mask13: u32 = 0x1FFF;
    let mut byte_idx = 0;

    for chunk in coeffs.chunks_exact_mut(8) {
        let b: [u32; 13] = [
            bytes[byte_idx + 0] as u32,
            bytes[byte_idx + 1] as u32,
            bytes[byte_idx + 2] as u32,
            bytes[byte_idx + 3] as u32,
            bytes[byte_idx + 4] as u32,
            bytes[byte_idx + 5] as u32,
            bytes[byte_idx + 6] as u32,
            bytes[byte_idx + 7] as u32,
            bytes[byte_idx + 8] as u32,
            bytes[byte_idx + 9] as u32,
            bytes[byte_idx + 10] as u32,
            bytes[byte_idx + 11] as u32,
            bytes[byte_idx + 12] as u32,
        ];

        let c0 = (b[0] | (b[1] << 8)) & mask13;
        let c1 = ((b[1] >> 5) | (b[2] << 3) | (b[3] << 11)) & mask13;
        let c2 = ((b[3] >> 2) | (b[4] << 6)) & mask13;
        let c3 = ((b[4] >> 7) | (b[5] << 1) | (b[6] << 9)) & mask13;
        let c4 = ((b[6] >> 4) | (b[7] << 4) | (b[8] << 12)) & mask13;
        let c5 = ((b[8] >> 1) | (b[9] << 7)) & mask13;
        let c6 = ((b[9] >> 6) | (b[10] << 2) | (b[11] << 10)) & mask13;
        let c7 = ((b[11] >> 3) | (b[12] << 5)) & mask13;

        // Convert back from unsigned to signed
        chunk[0] = half_power - c0 as i32;
        chunk[1] = half_power - c1 as i32;
        chunk[2] = half_power - c2 as i32;
        chunk[3] = half_power - c3 as i32;
        chunk[4] = half_power - c4 as i32;
        chunk[5] = half_power - c5 as i32;
        chunk[6] = half_power - c6 as i32;
        chunk[7] = half_power - c7 as i32;

        byte_idx += 13;
    }
}

// ============================================================================
// z Encoding (18 or 20-bit coefficients)
// ============================================================================

/// Pack z polynomial with 18-bit coefficients (γ₁ = 2^17)
///
/// For ML-DSA-44. Each coefficient is in range [-(γ₁-1), γ₁]
/// Stored as γ₁ - z to ensure positive values.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_z_17(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 576); // 256 * 18 / 8 = 576

    let gamma1 = 1 << 17;
    let mut byte_idx = 0;

    // Process 4 coefficients at a time (produces 9 bytes)
    for chunk in coeffs.chunks_exact(4) {
        let c0 = (gamma1 - chunk[0]) as u32;
        let c1 = (gamma1 - chunk[1]) as u32;
        let c2 = (gamma1 - chunk[2]) as u32;
        let c3 = (gamma1 - chunk[3]) as u32;

        bytes[byte_idx + 0] = c0 as u8;
        bytes[byte_idx + 1] = (c0 >> 8) as u8;
        bytes[byte_idx + 2] = ((c0 >> 16) | (c1 << 2)) as u8;
        bytes[byte_idx + 3] = (c1 >> 6) as u8;
        bytes[byte_idx + 4] = ((c1 >> 14) | (c2 << 4)) as u8;
        bytes[byte_idx + 5] = (c2 >> 4) as u8;
        bytes[byte_idx + 6] = ((c2 >> 12) | (c3 << 6)) as u8;
        bytes[byte_idx + 7] = (c3 >> 2) as u8;
        bytes[byte_idx + 8] = (c3 >> 10) as u8;

        byte_idx += 9;
    }
}

/// Unpack bytes into z polynomial with 18-bit coefficients
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_z_17(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 576);

    let gamma1 = 1i32 << 17;
    let mask18: u32 = 0x3FFFF;
    let mut byte_idx = 0;

    for chunk in coeffs.chunks_exact_mut(4) {
        let b: [u32; 9] = [
            bytes[byte_idx + 0] as u32,
            bytes[byte_idx + 1] as u32,
            bytes[byte_idx + 2] as u32,
            bytes[byte_idx + 3] as u32,
            bytes[byte_idx + 4] as u32,
            bytes[byte_idx + 5] as u32,
            bytes[byte_idx + 6] as u32,
            bytes[byte_idx + 7] as u32,
            bytes[byte_idx + 8] as u32,
        ];

        let c0 = (b[0] | (b[1] << 8) | (b[2] << 16)) & mask18;
        let c1 = ((b[2] >> 2) | (b[3] << 6) | (b[4] << 14)) & mask18;
        let c2 = ((b[4] >> 4) | (b[5] << 4) | (b[6] << 12)) & mask18;
        let c3 = ((b[6] >> 6) | (b[7] << 2) | (b[8] << 10)) & mask18;

        chunk[0] = gamma1 - c0 as i32;
        chunk[1] = gamma1 - c1 as i32;
        chunk[2] = gamma1 - c2 as i32;
        chunk[3] = gamma1 - c3 as i32;

        byte_idx += 9;
    }
}

/// Pack z polynomial with 20-bit coefficients (γ₁ = 2^19)
///
/// For ML-DSA-65/87.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_z_19(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 640); // 256 * 20 / 8 = 640

    let gamma1 = 1 << 19;
    let mut byte_idx = 0;

    // Process 4 coefficients at a time (produces 10 bytes)
    for chunk in coeffs.chunks_exact(4) {
        let c0 = (gamma1 - chunk[0]) as u32;
        let c1 = (gamma1 - chunk[1]) as u32;
        let c2 = (gamma1 - chunk[2]) as u32;
        let c3 = (gamma1 - chunk[3]) as u32;

        bytes[byte_idx + 0] = c0 as u8;
        bytes[byte_idx + 1] = (c0 >> 8) as u8;
        bytes[byte_idx + 2] = ((c0 >> 16) | (c1 << 4)) as u8;
        bytes[byte_idx + 3] = (c1 >> 4) as u8;
        bytes[byte_idx + 4] = (c1 >> 12) as u8;
        bytes[byte_idx + 5] = c2 as u8;
        bytes[byte_idx + 6] = (c2 >> 8) as u8;
        bytes[byte_idx + 7] = ((c2 >> 16) | (c3 << 4)) as u8;
        bytes[byte_idx + 8] = (c3 >> 4) as u8;
        bytes[byte_idx + 9] = (c3 >> 12) as u8;

        byte_idx += 10;
    }
}

/// Unpack bytes into z polynomial with 20-bit coefficients
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_z_19(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 640);

    let gamma1 = 1i32 << 19;
    let mask20: u32 = 0xFFFFF;
    let mut byte_idx = 0;

    for chunk in coeffs.chunks_exact_mut(4) {
        let b: [u32; 10] = [
            bytes[byte_idx + 0] as u32,
            bytes[byte_idx + 1] as u32,
            bytes[byte_idx + 2] as u32,
            bytes[byte_idx + 3] as u32,
            bytes[byte_idx + 4] as u32,
            bytes[byte_idx + 5] as u32,
            bytes[byte_idx + 6] as u32,
            bytes[byte_idx + 7] as u32,
            bytes[byte_idx + 8] as u32,
            bytes[byte_idx + 9] as u32,
        ];

        let c0 = (b[0] | (b[1] << 8) | (b[2] << 16)) & mask20;
        let c1 = ((b[2] >> 4) | (b[3] << 4) | (b[4] << 12)) & mask20;
        let c2 = (b[5] | (b[6] << 8) | (b[7] << 16)) & mask20;
        let c3 = ((b[7] >> 4) | (b[8] << 4) | (b[9] << 12)) & mask20;

        chunk[0] = gamma1 - c0 as i32;
        chunk[1] = gamma1 - c1 as i32;
        chunk[2] = gamma1 - c2 as i32;
        chunk[3] = gamma1 - c3 as i32;

        byte_idx += 10;
    }
}

// ============================================================================
// eta Encoding (3 or 4-bit coefficients)
// ============================================================================

/// Pack eta=2 coefficients (3 bits each)
///
/// Coefficients are in [-2, 2], stored as 2 - coeff.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_eta2(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 96); // 256 * 3 / 8 = 96

    let mut byte_idx = 0;

    // Process 8 coefficients at a time (produces 3 bytes)
    for chunk in coeffs.chunks_exact(8) {
        let c: [u8; 8] = [
            (2 - chunk[0]) as u8,
            (2 - chunk[1]) as u8,
            (2 - chunk[2]) as u8,
            (2 - chunk[3]) as u8,
            (2 - chunk[4]) as u8,
            (2 - chunk[5]) as u8,
            (2 - chunk[6]) as u8,
            (2 - chunk[7]) as u8,
        ];

        bytes[byte_idx + 0] = c[0] | (c[1] << 3) | (c[2] << 6);
        bytes[byte_idx + 1] = (c[2] >> 2) | (c[3] << 1) | (c[4] << 4) | (c[5] << 7);
        bytes[byte_idx + 2] = (c[5] >> 1) | (c[6] << 2) | (c[7] << 5);

        byte_idx += 3;
    }
}

/// Unpack eta=2 coefficients
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_eta2(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 96);

    let mut byte_idx = 0;

    for chunk in coeffs.chunks_exact_mut(8) {
        let b0 = bytes[byte_idx + 0];
        let b1 = bytes[byte_idx + 1];
        let b2 = bytes[byte_idx + 2];

        chunk[0] = 2 - ((b0 & 0x07) as i32);
        chunk[1] = 2 - (((b0 >> 3) & 0x07) as i32);
        chunk[2] = 2 - ((((b0 >> 6) | (b1 << 2)) & 0x07) as i32);
        chunk[3] = 2 - (((b1 >> 1) & 0x07) as i32);
        chunk[4] = 2 - (((b1 >> 4) & 0x07) as i32);
        chunk[5] = 2 - ((((b1 >> 7) | (b2 << 1)) & 0x07) as i32);
        chunk[6] = 2 - (((b2 >> 2) & 0x07) as i32);
        chunk[7] = 2 - (((b2 >> 5) & 0x07) as i32);

        byte_idx += 3;
    }
}

/// Pack eta=4 coefficients (4 bits each)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_eta4(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 128); // 256 * 4 / 8 = 128

    let mut byte_idx = 0;

    // Process 2 coefficients at a time (produces 1 byte)
    for chunk in coeffs.chunks_exact(2) {
        let c0 = (4 - chunk[0]) as u8;
        let c1 = (4 - chunk[1]) as u8;

        bytes[byte_idx] = c0 | (c1 << 4);
        byte_idx += 1;
    }
}

/// Unpack eta=4 coefficients
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_eta4(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 128);

    let mut byte_idx = 0;

    for chunk in coeffs.chunks_exact_mut(2) {
        let b = bytes[byte_idx];

        chunk[0] = 4 - ((b & 0x0F) as i32);
        chunk[1] = 4 - ((b >> 4) as i32);

        byte_idx += 1;
    }
}

// ============================================================================
// w1 Encoding (high bits)
// ============================================================================

/// Pack w1 polynomial for ML-DSA-44 (6 bits per coefficient)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_w1_44(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 192); // 256 * 6 / 8 = 192

    let mut byte_idx = 0;

    // Process 4 coefficients at a time (produces 3 bytes)
    for chunk in coeffs.chunks_exact(4) {
        let c0 = chunk[0] as u8;
        let c1 = chunk[1] as u8;
        let c2 = chunk[2] as u8;
        let c3 = chunk[3] as u8;

        bytes[byte_idx + 0] = c0 | (c1 << 6);
        bytes[byte_idx + 1] = (c1 >> 2) | (c2 << 4);
        bytes[byte_idx + 2] = (c2 >> 4) | (c3 << 2);

        byte_idx += 3;
    }
}

/// Pack w1 polynomial for ML-DSA-65/87 (4 bits per coefficient)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_w1_65(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 128); // 256 * 4 / 8 = 128

    let mut byte_idx = 0;

    // Process 2 coefficients at a time (produces 1 byte)
    for chunk in coeffs.chunks_exact(2) {
        bytes[byte_idx] = (chunk[0] as u8) | ((chunk[1] as u8) << 4);
        byte_idx += 1;
    }
}

// ============================================================================
// Optimized SIMD Packing Operations
// ============================================================================

/// Optimized unpack_eta4 using AVX2
///
/// Process 16 coefficients per iteration (8 bytes -> 16 i32 values)
/// Uses loop unrolling to process 32 coefficients per outer iteration.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_eta4_fast(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 128);

    let four = _mm256_set1_epi32(4);
    let mask_lo = _mm256_set1_epi32(0x0F);

    // Process 8 bytes at a time (16 coefficients)
    // Each byte gives 2 coefficients: low nibble, high nibble
    for i in 0..16 {
        let byte_offset = i * 8;
        let coeff_offset = i * 16;

        // Load 8 bytes
        let bytes_vec = _mm_loadl_epi64(bytes.as_ptr().add(byte_offset) as *const __m128i);
        let bytes_256 = _mm256_cvtepu8_epi32(bytes_vec);

        // Low nibbles (even indices: 0, 2, 4, 6, 8, 10, 12, 14)
        let lo_nibbles = _mm256_and_si256(bytes_256, mask_lo);
        let lo_coeffs = _mm256_sub_epi32(four, lo_nibbles);

        // High nibbles (odd indices: 1, 3, 5, 7, 9, 11, 13, 15)
        let hi_nibbles = _mm256_srli_epi32(bytes_256, 4);
        let hi_coeffs = _mm256_sub_epi32(four, hi_nibbles);

        // Interleave: need to produce [lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3, lo4, hi4, lo5, hi5, lo6, hi6, lo7, hi7]
        // unpacklo gives [a0, b0, a1, b1, a4, b4, a5, b5]
        // unpackhi gives [a2, b2, a3, b3, a6, b6, a7, b7]
        let interleaved_lo = _mm256_unpacklo_epi32(lo_coeffs, hi_coeffs);  // [lo0, hi0, lo1, hi1, lo4, hi4, lo5, hi5]
        let interleaved_hi = _mm256_unpackhi_epi32(lo_coeffs, hi_coeffs);  // [lo2, hi2, lo3, hi3, lo6, hi6, lo7, hi7]

        // Due to AVX2 128-bit lane structure, we need to permute
        // Current: [lo0,hi0,lo1,hi1 | lo4,hi4,lo5,hi5] and [lo2,hi2,lo3,hi3 | lo6,hi6,lo7,hi7]
        // Need: [lo0,hi0,lo1,hi1,lo2,hi2,lo3,hi3] and [lo4,hi4,lo5,hi5,lo6,hi6,lo7,hi7]
        let result_0 = _mm256_permute2x128_si256(interleaved_lo, interleaved_hi, 0x20);  // lo lanes
        let result_1 = _mm256_permute2x128_si256(interleaved_lo, interleaved_hi, 0x31);  // hi lanes

        _mm256_storeu_si256(coeffs.as_mut_ptr().add(coeff_offset) as *mut __m256i, result_0);
        _mm256_storeu_si256(coeffs.as_mut_ptr().add(coeff_offset + 8) as *mut __m256i, result_1);
    }
}

/// Optimized pack_eta4 using AVX2
///
/// Process 16 coefficients per iteration (16 i32 values -> 8 bytes)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_eta4_fast(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 128);

    let four = _mm256_set1_epi32(4);
    let mask_lo = _mm256_set1_epi32(0x0F);

    // Process 16 coefficients at a time
    for i in 0..16 {
        let coeff_offset = i * 16;
        let byte_offset = i * 8;

        // Load 16 coefficients (2 vectors of 8)
        let v0 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_offset) as *const __m256i);
        let v1 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_offset + 8) as *const __m256i);

        // Compute 4 - coeff and mask to 4 bits
        let c0 = _mm256_and_si256(_mm256_sub_epi32(four, v0), mask_lo);
        let c1 = _mm256_and_si256(_mm256_sub_epi32(four, v1), mask_lo);

        // Extract to arrays and combine nibbles
        let mut temp0 = [0i32; 8];
        let mut temp1 = [0i32; 8];
        _mm256_storeu_si256(temp0.as_mut_ptr() as *mut __m256i, c0);
        _mm256_storeu_si256(temp1.as_mut_ptr() as *mut __m256i, c1);

        // Coefficients come in pairs (even, odd) and each pair makes one byte
        // v0 has coefficients 0,1,2,3,4,5,6,7 -> bytes 0,1,2,3
        // v1 has coefficients 8,9,10,11,12,13,14,15 -> bytes 4,5,6,7
        bytes[byte_offset + 0] = (temp0[0] as u8) | ((temp0[1] as u8) << 4);
        bytes[byte_offset + 1] = (temp0[2] as u8) | ((temp0[3] as u8) << 4);
        bytes[byte_offset + 2] = (temp0[4] as u8) | ((temp0[5] as u8) << 4);
        bytes[byte_offset + 3] = (temp0[6] as u8) | ((temp0[7] as u8) << 4);
        bytes[byte_offset + 4] = (temp1[0] as u8) | ((temp1[1] as u8) << 4);
        bytes[byte_offset + 5] = (temp1[2] as u8) | ((temp1[3] as u8) << 4);
        bytes[byte_offset + 6] = (temp1[4] as u8) | ((temp1[5] as u8) << 4);
        bytes[byte_offset + 7] = (temp1[6] as u8) | ((temp1[7] as u8) << 4);
    }
}

/// Optimized unpack_z_19 using AVX2
///
/// Process 8 coefficients per iteration
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_z_19_fast(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 640);

    let gamma1 = _mm256_set1_epi32(1 << 19);
    let mask20: u32 = 0xFFFFF;

    // Process 8 coefficients at a time (20 bytes)
    for i in 0..32 {
        let byte_idx = i * 20;
        let coeff_idx = i * 8;

        // Load bytes
        let b: [u32; 20] = [
            bytes[byte_idx + 0] as u32, bytes[byte_idx + 1] as u32,
            bytes[byte_idx + 2] as u32, bytes[byte_idx + 3] as u32,
            bytes[byte_idx + 4] as u32, bytes[byte_idx + 5] as u32,
            bytes[byte_idx + 6] as u32, bytes[byte_idx + 7] as u32,
            bytes[byte_idx + 8] as u32, bytes[byte_idx + 9] as u32,
            bytes[byte_idx + 10] as u32, bytes[byte_idx + 11] as u32,
            bytes[byte_idx + 12] as u32, bytes[byte_idx + 13] as u32,
            bytes[byte_idx + 14] as u32, bytes[byte_idx + 15] as u32,
            bytes[byte_idx + 16] as u32, bytes[byte_idx + 17] as u32,
            bytes[byte_idx + 18] as u32, bytes[byte_idx + 19] as u32,
        ];

        // Extract 8 20-bit values
        let c0 = (b[0] | (b[1] << 8) | (b[2] << 16)) & mask20;
        let c1 = ((b[2] >> 4) | (b[3] << 4) | (b[4] << 12)) & mask20;
        let c2 = (b[5] | (b[6] << 8) | (b[7] << 16)) & mask20;
        let c3 = ((b[7] >> 4) | (b[8] << 4) | (b[9] << 12)) & mask20;
        let c4 = (b[10] | (b[11] << 8) | (b[12] << 16)) & mask20;
        let c5 = ((b[12] >> 4) | (b[13] << 4) | (b[14] << 12)) & mask20;
        let c6 = (b[15] | (b[16] << 8) | (b[17] << 16)) & mask20;
        let c7 = ((b[17] >> 4) | (b[18] << 4) | (b[19] << 12)) & mask20;

        // Create vector
        let v = _mm256_setr_epi32(c0 as i32, c1 as i32, c2 as i32, c3 as i32,
                                   c4 as i32, c5 as i32, c6 as i32, c7 as i32);

        // Compute gamma1 - c
        let result = _mm256_sub_epi32(gamma1, v);
        _mm256_storeu_si256(coeffs.as_mut_ptr().add(coeff_idx) as *mut __m256i, result);
    }
}

/// Optimized pack_z_19 using AVX2
///
/// Process 8 coefficients per iteration
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_z_19_fast(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 640);

    let gamma1 = _mm256_set1_epi32(1 << 19);

    // Process 8 coefficients at a time
    for i in 0..32 {
        let coeff_idx = i * 8;
        let byte_idx = i * 20;

        // Load 8 coefficients
        let v = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx) as *const __m256i);

        // Compute gamma1 - coeff
        let c_vec = _mm256_sub_epi32(gamma1, v);

        // Extract to array
        let mut c = [0u32; 8];
        _mm256_storeu_si256(c.as_mut_ptr() as *mut __m256i, c_vec);

        // Pack 8 20-bit values into 20 bytes
        bytes[byte_idx + 0] = c[0] as u8;
        bytes[byte_idx + 1] = (c[0] >> 8) as u8;
        bytes[byte_idx + 2] = ((c[0] >> 16) | (c[1] << 4)) as u8;
        bytes[byte_idx + 3] = (c[1] >> 4) as u8;
        bytes[byte_idx + 4] = (c[1] >> 12) as u8;
        bytes[byte_idx + 5] = c[2] as u8;
        bytes[byte_idx + 6] = (c[2] >> 8) as u8;
        bytes[byte_idx + 7] = ((c[2] >> 16) | (c[3] << 4)) as u8;
        bytes[byte_idx + 8] = (c[3] >> 4) as u8;
        bytes[byte_idx + 9] = (c[3] >> 12) as u8;
        bytes[byte_idx + 10] = c[4] as u8;
        bytes[byte_idx + 11] = (c[4] >> 8) as u8;
        bytes[byte_idx + 12] = ((c[4] >> 16) | (c[5] << 4)) as u8;
        bytes[byte_idx + 13] = (c[5] >> 4) as u8;
        bytes[byte_idx + 14] = (c[5] >> 12) as u8;
        bytes[byte_idx + 15] = c[6] as u8;
        bytes[byte_idx + 16] = (c[6] >> 8) as u8;
        bytes[byte_idx + 17] = ((c[6] >> 16) | (c[7] << 4)) as u8;
        bytes[byte_idx + 18] = (c[7] >> 4) as u8;
        bytes[byte_idx + 19] = (c[7] >> 12) as u8;
    }
}

/// Optimized unpack_z_17 using AVX2
///
/// Process 8 coefficients per iteration (18 bytes -> 8 coefficients)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_z_17_fast(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 576);

    let gamma1 = _mm256_set1_epi32(1 << 17);
    let mask18: u32 = 0x3FFFF;

    // Process 8 coefficients at a time (18 bytes)
    // 256 coefficients / 8 = 32 iterations
    for i in 0..32 {
        let byte_idx = i * 18;
        let coeff_idx = i * 8;

        // Load bytes
        let b: [u32; 18] = [
            bytes[byte_idx + 0] as u32, bytes[byte_idx + 1] as u32,
            bytes[byte_idx + 2] as u32, bytes[byte_idx + 3] as u32,
            bytes[byte_idx + 4] as u32, bytes[byte_idx + 5] as u32,
            bytes[byte_idx + 6] as u32, bytes[byte_idx + 7] as u32,
            bytes[byte_idx + 8] as u32, bytes[byte_idx + 9] as u32,
            bytes[byte_idx + 10] as u32, bytes[byte_idx + 11] as u32,
            bytes[byte_idx + 12] as u32, bytes[byte_idx + 13] as u32,
            bytes[byte_idx + 14] as u32, bytes[byte_idx + 15] as u32,
            bytes[byte_idx + 16] as u32, bytes[byte_idx + 17] as u32,
        ];

        // Extract 8 18-bit values
        // Layout: 4 coefficients per 9 bytes
        // First 4 coefficients (bytes 0-8)
        let c0 = (b[0] | (b[1] << 8) | (b[2] << 16)) & mask18;
        let c1 = ((b[2] >> 2) | (b[3] << 6) | (b[4] << 14)) & mask18;
        let c2 = ((b[4] >> 4) | (b[5] << 4) | (b[6] << 12)) & mask18;
        let c3 = ((b[6] >> 6) | (b[7] << 2) | (b[8] << 10)) & mask18;

        // Second 4 coefficients (bytes 9-17)
        let c4 = (b[9] | (b[10] << 8) | (b[11] << 16)) & mask18;
        let c5 = ((b[11] >> 2) | (b[12] << 6) | (b[13] << 14)) & mask18;
        let c6 = ((b[13] >> 4) | (b[14] << 4) | (b[15] << 12)) & mask18;
        let c7 = ((b[15] >> 6) | (b[16] << 2) | (b[17] << 10)) & mask18;

        // Create vector
        let v = _mm256_setr_epi32(c0 as i32, c1 as i32, c2 as i32, c3 as i32,
                                   c4 as i32, c5 as i32, c6 as i32, c7 as i32);

        // Compute gamma1 - c
        let result = _mm256_sub_epi32(gamma1, v);
        _mm256_storeu_si256(coeffs.as_mut_ptr().add(coeff_idx) as *mut __m256i, result);
    }
}

/// Optimized pack_z_17 using AVX2
///
/// Process 8 coefficients per iteration
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_z_17_fast(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 576);

    let gamma1 = _mm256_set1_epi32(1 << 17);

    // Process 8 coefficients at a time
    for i in 0..32 {
        let coeff_idx = i * 8;
        let byte_idx = i * 18;

        // Load 8 coefficients
        let v = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx) as *const __m256i);

        // Compute gamma1 - coeff
        let c_vec = _mm256_sub_epi32(gamma1, v);

        // Extract to array
        let mut c = [0u32; 8];
        _mm256_storeu_si256(c.as_mut_ptr() as *mut __m256i, c_vec);

        // Pack 8 18-bit values into 18 bytes
        // First 4 coefficients -> 9 bytes
        bytes[byte_idx + 0] = c[0] as u8;
        bytes[byte_idx + 1] = (c[0] >> 8) as u8;
        bytes[byte_idx + 2] = ((c[0] >> 16) | (c[1] << 2)) as u8;
        bytes[byte_idx + 3] = (c[1] >> 6) as u8;
        bytes[byte_idx + 4] = ((c[1] >> 14) | (c[2] << 4)) as u8;
        bytes[byte_idx + 5] = (c[2] >> 4) as u8;
        bytes[byte_idx + 6] = ((c[2] >> 12) | (c[3] << 6)) as u8;
        bytes[byte_idx + 7] = (c[3] >> 2) as u8;
        bytes[byte_idx + 8] = (c[3] >> 10) as u8;

        // Second 4 coefficients -> 9 bytes
        bytes[byte_idx + 9] = c[4] as u8;
        bytes[byte_idx + 10] = (c[4] >> 8) as u8;
        bytes[byte_idx + 11] = ((c[4] >> 16) | (c[5] << 2)) as u8;
        bytes[byte_idx + 12] = (c[5] >> 6) as u8;
        bytes[byte_idx + 13] = ((c[5] >> 14) | (c[6] << 4)) as u8;
        bytes[byte_idx + 14] = (c[6] >> 4) as u8;
        bytes[byte_idx + 15] = ((c[6] >> 12) | (c[7] << 6)) as u8;
        bytes[byte_idx + 16] = (c[7] >> 2) as u8;
        bytes[byte_idx + 17] = (c[7] >> 10) as u8;
    }
}

/// Optimized unpack_eta2 using AVX2
///
/// Process 16 coefficients per iteration (6 bytes -> 16 coefficients)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_eta2_fast(bytes: &[u8], coeffs: &mut [i32; N]) {
    debug_assert!(bytes.len() >= 96);

    let two = _mm256_set1_epi32(2);
    let mask3 = _mm256_set1_epi32(0x07);

    // Process 16 coefficients at a time (6 bytes -> 16 coefficients)
    // 256 / 16 = 16 iterations
    for i in 0..16 {
        let byte_idx = i * 6;
        let coeff_idx = i * 16;

        let b0 = bytes[byte_idx + 0] as u32;
        let b1 = bytes[byte_idx + 1] as u32;
        let b2 = bytes[byte_idx + 2] as u32;
        let b3 = bytes[byte_idx + 3] as u32;
        let b4 = bytes[byte_idx + 4] as u32;
        let b5 = bytes[byte_idx + 5] as u32;

        // Extract 16 3-bit values
        // First 8 (from bytes 0-2)
        let c0 = (b0 & 0x07) as i32;
        let c1 = ((b0 >> 3) & 0x07) as i32;
        let c2 = (((b0 >> 6) | (b1 << 2)) & 0x07) as i32;
        let c3 = ((b1 >> 1) & 0x07) as i32;
        let c4 = ((b1 >> 4) & 0x07) as i32;
        let c5 = (((b1 >> 7) | (b2 << 1)) & 0x07) as i32;
        let c6 = ((b2 >> 2) & 0x07) as i32;
        let c7 = ((b2 >> 5) & 0x07) as i32;

        // Second 8 (from bytes 3-5)
        let c8 = (b3 & 0x07) as i32;
        let c9 = ((b3 >> 3) & 0x07) as i32;
        let c10 = (((b3 >> 6) | (b4 << 2)) & 0x07) as i32;
        let c11 = ((b4 >> 1) & 0x07) as i32;
        let c12 = ((b4 >> 4) & 0x07) as i32;
        let c13 = (((b4 >> 7) | (b5 << 1)) & 0x07) as i32;
        let c14 = ((b5 >> 2) & 0x07) as i32;
        let c15 = ((b5 >> 5) & 0x07) as i32;

        // Create vectors and compute 2 - c
        let v0 = _mm256_setr_epi32(c0, c1, c2, c3, c4, c5, c6, c7);
        let v1 = _mm256_setr_epi32(c8, c9, c10, c11, c12, c13, c14, c15);

        let result0 = _mm256_sub_epi32(two, v0);
        let result1 = _mm256_sub_epi32(two, v1);

        _mm256_storeu_si256(coeffs.as_mut_ptr().add(coeff_idx) as *mut __m256i, result0);
        _mm256_storeu_si256(coeffs.as_mut_ptr().add(coeff_idx + 8) as *mut __m256i, result1);
    }
}

/// Optimized pack_eta2 using AVX2
///
/// Process 16 coefficients per iteration
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_eta2_fast(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 96);

    let two = _mm256_set1_epi32(2);
    let mask3 = _mm256_set1_epi32(0x07);

    // Process 16 coefficients at a time
    for i in 0..16 {
        let coeff_idx = i * 16;
        let byte_idx = i * 6;

        // Load 16 coefficients
        let v0 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx) as *const __m256i);
        let v1 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx + 8) as *const __m256i);

        // Compute 2 - coeff and mask to 3 bits
        let c0_vec = _mm256_and_si256(_mm256_sub_epi32(two, v0), mask3);
        let c1_vec = _mm256_and_si256(_mm256_sub_epi32(two, v1), mask3);

        // Extract to arrays
        let mut c0 = [0u32; 8];
        let mut c1 = [0u32; 8];
        _mm256_storeu_si256(c0.as_mut_ptr() as *mut __m256i, c0_vec);
        _mm256_storeu_si256(c1.as_mut_ptr() as *mut __m256i, c1_vec);

        // Pack 16 3-bit values into 6 bytes
        // First 8 coefficients -> 3 bytes
        bytes[byte_idx + 0] = (c0[0] | (c0[1] << 3) | (c0[2] << 6)) as u8;
        bytes[byte_idx + 1] = ((c0[2] >> 2) | (c0[3] << 1) | (c0[4] << 4) | (c0[5] << 7)) as u8;
        bytes[byte_idx + 2] = ((c0[5] >> 1) | (c0[6] << 2) | (c0[7] << 5)) as u8;

        // Second 8 coefficients -> 3 bytes
        bytes[byte_idx + 3] = (c1[0] | (c1[1] << 3) | (c1[2] << 6)) as u8;
        bytes[byte_idx + 4] = ((c1[2] >> 2) | (c1[3] << 1) | (c1[4] << 4) | (c1[5] << 7)) as u8;
        bytes[byte_idx + 5] = ((c1[5] >> 1) | (c1[6] << 2) | (c1[7] << 5)) as u8;
    }
}

/// Optimized pack_w1_44 using AVX2
///
/// Process 8 coefficients per iteration (8 coefficients -> 6 bytes)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_w1_44_fast(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 192);

    // Process 8 coefficients at a time (produces 6 bytes)
    // 256 / 8 = 32 iterations
    for i in 0..32 {
        let coeff_idx = i * 8;
        let byte_idx = i * 6;

        // Load 8 coefficients
        let v = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx) as *const __m256i);

        // Extract to array
        let mut c = [0u32; 8];
        _mm256_storeu_si256(c.as_mut_ptr() as *mut __m256i, v);

        // Pack 8 6-bit values into 6 bytes
        // Layout: 4 coefficients per 3 bytes
        bytes[byte_idx + 0] = (c[0] | (c[1] << 6)) as u8;
        bytes[byte_idx + 1] = ((c[1] >> 2) | (c[2] << 4)) as u8;
        bytes[byte_idx + 2] = ((c[2] >> 4) | (c[3] << 2)) as u8;
        bytes[byte_idx + 3] = (c[4] | (c[5] << 6)) as u8;
        bytes[byte_idx + 4] = ((c[5] >> 2) | (c[6] << 4)) as u8;
        bytes[byte_idx + 5] = ((c[6] >> 4) | (c[7] << 2)) as u8;
    }
}

/// Optimized pack_w1_65 using AVX2
///
/// Process 16 coefficients per iteration (16 coefficients -> 8 bytes)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_w1_65_fast(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 128);

    let mask4 = _mm256_set1_epi32(0x0F);

    // Process 16 coefficients at a time
    for i in 0..16 {
        let coeff_idx = i * 16;
        let byte_idx = i * 8;

        // Load 16 coefficients (2 vectors of 8)
        let v0 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx) as *const __m256i);
        let v1 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx + 8) as *const __m256i);

        // Mask to 4 bits
        let c0 = _mm256_and_si256(v0, mask4);
        let c1 = _mm256_and_si256(v1, mask4);

        // Extract to arrays
        let mut temp0 = [0i32; 8];
        let mut temp1 = [0i32; 8];
        _mm256_storeu_si256(temp0.as_mut_ptr() as *mut __m256i, c0);
        _mm256_storeu_si256(temp1.as_mut_ptr() as *mut __m256i, c1);

        // Combine nibbles: 2 coefficients per byte
        bytes[byte_idx + 0] = (temp0[0] as u8) | ((temp0[1] as u8) << 4);
        bytes[byte_idx + 1] = (temp0[2] as u8) | ((temp0[3] as u8) << 4);
        bytes[byte_idx + 2] = (temp0[4] as u8) | ((temp0[5] as u8) << 4);
        bytes[byte_idx + 3] = (temp0[6] as u8) | ((temp0[7] as u8) << 4);
        bytes[byte_idx + 4] = (temp1[0] as u8) | ((temp1[1] as u8) << 4);
        bytes[byte_idx + 5] = (temp1[2] as u8) | ((temp1[3] as u8) << 4);
        bytes[byte_idx + 6] = (temp1[4] as u8) | ((temp1[5] as u8) << 4);
        bytes[byte_idx + 7] = (temp1[6] as u8) | ((temp1[7] as u8) << 4);
    }
}

/// Pure SIMD pack_w1_65 using shuffle operations
///
/// Eliminates store-to-array overhead by using SIMD shuffle and pack instructions.
/// Process 32 coefficients per iteration (32 coefficients -> 16 bytes).
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_w1_65_simd(coeffs: &[i32; N], bytes: &mut [u8]) {
    debug_assert!(bytes.len() >= 128);

    // Shuffle mask to pack 32-bit values into bytes
    // For each 128-bit lane, we pack 4 i32 values into 4 bytes in the low position
    // Then we'll manually combine
    let pack_mask = _mm256_setr_epi8(
        0, 4, 8, 12,   // Pack positions 0,1,2,3 into first 4 bytes (low lane)
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        0, 4, 8, 12,   // Pack positions 0,1,2,3 into first 4 bytes (high lane)
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    );

    // Process 32 coefficients at a time (produces 16 bytes)
    for i in 0..8 {
        let coeff_idx = i * 32;
        let byte_idx = i * 16;

        // Load 32 coefficients (4 vectors of 8)
        let v0 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx) as *const __m256i);
        let v1 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx + 8) as *const __m256i);
        let v2 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx + 16) as *const __m256i);
        let v3 = _mm256_loadu_si256(coeffs.as_ptr().add(coeff_idx + 24) as *const __m256i);

        // Shuffle to pack i32 low bytes into consecutive positions
        // Each vector: [a0,a1,a2,a3,a4,a5,a6,a7] -> low 4 bytes contain [a0[0],a1[0],a2[0],a3[0]]
        let p0 = _mm256_shuffle_epi8(v0, pack_mask);
        let p1 = _mm256_shuffle_epi8(v1, pack_mask);
        let p2 = _mm256_shuffle_epi8(v2, pack_mask);
        let p3 = _mm256_shuffle_epi8(v3, pack_mask);

        // Extract the packed bytes and combine nibbles
        // p0 low lane has bytes for coeffs 0,1,2,3
        // p0 high lane has bytes for coeffs 4,5,6,7
        // We need to combine pairs: (coeff[0] | coeff[1]<<4), (coeff[2] | coeff[3]<<4), etc.

        // Extract 32-bit values containing the packed bytes
        let b0_lo = _mm256_extract_epi32::<0>(p0) as u32;  // coeffs 0-3 as bytes
        let b0_hi = _mm256_extract_epi32::<4>(p0) as u32;  // coeffs 4-7 as bytes
        let b1_lo = _mm256_extract_epi32::<0>(p1) as u32;  // coeffs 8-11 as bytes
        let b1_hi = _mm256_extract_epi32::<4>(p1) as u32;  // coeffs 12-15 as bytes
        let b2_lo = _mm256_extract_epi32::<0>(p2) as u32;  // coeffs 16-19 as bytes
        let b2_hi = _mm256_extract_epi32::<4>(p2) as u32;  // coeffs 20-23 as bytes
        let b3_lo = _mm256_extract_epi32::<0>(p3) as u32;  // coeffs 24-27 as bytes
        let b3_hi = _mm256_extract_epi32::<4>(p3) as u32;  // coeffs 28-31 as bytes

        // Combine nibbles: each pair of bytes becomes one output byte
        // byte[n] = (coeff[2n] & 0xF) | ((coeff[2n+1] & 0xF) << 4)
        bytes[byte_idx + 0] = ((b0_lo & 0x0F) | ((b0_lo >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 1] = (((b0_lo >> 16) & 0x0F) | ((b0_lo >> 20) & 0xF0)) as u8;
        bytes[byte_idx + 2] = ((b0_hi & 0x0F) | ((b0_hi >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 3] = (((b0_hi >> 16) & 0x0F) | ((b0_hi >> 20) & 0xF0)) as u8;
        bytes[byte_idx + 4] = ((b1_lo & 0x0F) | ((b1_lo >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 5] = (((b1_lo >> 16) & 0x0F) | ((b1_lo >> 20) & 0xF0)) as u8;
        bytes[byte_idx + 6] = ((b1_hi & 0x0F) | ((b1_hi >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 7] = (((b1_hi >> 16) & 0x0F) | ((b1_hi >> 20) & 0xF0)) as u8;
        bytes[byte_idx + 8] = ((b2_lo & 0x0F) | ((b2_lo >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 9] = (((b2_lo >> 16) & 0x0F) | ((b2_lo >> 20) & 0xF0)) as u8;
        bytes[byte_idx + 10] = ((b2_hi & 0x0F) | ((b2_hi >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 11] = (((b2_hi >> 16) & 0x0F) | ((b2_hi >> 20) & 0xF0)) as u8;
        bytes[byte_idx + 12] = ((b3_lo & 0x0F) | ((b3_lo >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 13] = (((b3_lo >> 16) & 0x0F) | ((b3_lo >> 20) & 0xF0)) as u8;
        bytes[byte_idx + 14] = ((b3_hi & 0x0F) | ((b3_hi >> 4) & 0xF0)) as u8;
        bytes[byte_idx + 15] = (((b3_hi >> 16) & 0x0F) | ((b3_hi >> 20) & 0xF0)) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_unpack_t1() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = (i as i32 * 3) % 1024; // 10-bit values
            }

            let mut bytes = [0u8; 320];
            pack_t1(&original, &mut bytes);

            let mut recovered = [0i32; N];
            unpack_t1(&bytes, &mut recovered);

            for i in 0..N {
                assert_eq!(original[i], recovered[i], "Mismatch at index {}", i);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_unpack_z_17() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let gamma1 = 1 << 17;
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = ((i as i32) % (2 * gamma1)) - gamma1 + 1;
            }

            let mut bytes = [0u8; 576];
            pack_z_17(&original, &mut bytes);

            let mut recovered = [0i32; N];
            unpack_z_17(&bytes, &mut recovered);

            for i in 0..N {
                assert_eq!(original[i], recovered[i], "Mismatch at index {}", i);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_unpack_eta2() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = ((i % 5) as i32) - 2; // Values in [-2, 2]
            }

            let mut bytes = [0u8; 96];
            pack_eta2(&original, &mut bytes);

            let mut recovered = [0i32; N];
            unpack_eta2(&bytes, &mut recovered);

            for i in 0..N {
                assert_eq!(original[i], recovered[i], "Mismatch at index {}", i);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_unpack_eta4_fast() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = ((i % 9) as i32) - 4; // Values in [-4, 4]
            }

            // Test fast pack/unpack roundtrip
            let mut bytes_fast = [0u8; 128];
            pack_eta4_fast(&original, &mut bytes_fast);

            let mut recovered_fast = [0i32; N];
            unpack_eta4_fast(&bytes_fast, &mut recovered_fast);

            for i in 0..N {
                assert_eq!(original[i], recovered_fast[i], "Fast mismatch at index {}", i);
            }

            // Compare fast vs base
            let mut bytes_base = [0u8; 128];
            pack_eta4(&original, &mut bytes_base);

            let mut recovered_base = [0i32; N];
            unpack_eta4(&bytes_base, &mut recovered_base);

            for i in 0..N {
                assert_eq!(recovered_base[i], recovered_fast[i], "Base vs fast mismatch at index {}", i);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_unpack_z_19_fast() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let gamma1 = 1 << 19;
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = ((i as i32) % (2 * gamma1)) - gamma1 + 1;
            }

            // Test fast pack/unpack roundtrip
            let mut bytes_fast = [0u8; 640];
            pack_z_19_fast(&original, &mut bytes_fast);

            let mut recovered_fast = [0i32; N];
            unpack_z_19_fast(&bytes_fast, &mut recovered_fast);

            for i in 0..N {
                assert_eq!(original[i], recovered_fast[i], "Fast mismatch at index {}", i);
            }

            // Compare fast vs base
            let mut bytes_base = [0u8; 640];
            pack_z_19(&original, &mut bytes_base);

            assert_eq!(bytes_base, bytes_fast, "Packed bytes mismatch");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_unpack_z_17_fast() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let gamma1 = 1 << 17;
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = ((i as i32) % (2 * gamma1)) - gamma1 + 1;
            }

            // Test fast pack/unpack roundtrip
            let mut bytes_fast = [0u8; 576];
            pack_z_17_fast(&original, &mut bytes_fast);

            let mut recovered_fast = [0i32; N];
            unpack_z_17_fast(&bytes_fast, &mut recovered_fast);

            for i in 0..N {
                assert_eq!(original[i], recovered_fast[i], "Fast mismatch at index {}", i);
            }

            // Compare fast vs base
            let mut bytes_base = [0u8; 576];
            pack_z_17(&original, &mut bytes_base);

            assert_eq!(bytes_base, bytes_fast, "Packed bytes mismatch");

            // Compare unpack results
            let mut recovered_base = [0i32; N];
            unpack_z_17(&bytes_base, &mut recovered_base);

            for i in 0..N {
                assert_eq!(recovered_base[i], recovered_fast[i], "Base vs fast unpack mismatch at index {}", i);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_unpack_eta2_fast() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = ((i % 5) as i32) - 2; // Values in [-2, 2]
            }

            // Test fast pack/unpack roundtrip
            let mut bytes_fast = [0u8; 96];
            pack_eta2_fast(&original, &mut bytes_fast);

            let mut recovered_fast = [0i32; N];
            unpack_eta2_fast(&bytes_fast, &mut recovered_fast);

            for i in 0..N {
                assert_eq!(original[i], recovered_fast[i], "Fast mismatch at index {}", i);
            }

            // Compare fast vs base
            let mut bytes_base = [0u8; 96];
            pack_eta2(&original, &mut bytes_base);

            assert_eq!(bytes_base, bytes_fast, "Packed bytes mismatch");

            // Compare unpack results
            let mut recovered_base = [0i32; N];
            unpack_eta2(&bytes_base, &mut recovered_base);

            for i in 0..N {
                assert_eq!(recovered_base[i], recovered_fast[i], "Base vs fast unpack mismatch at index {}", i);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_w1_44_fast() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = (i % 44) as i32; // Values in [0, 43] (6-bit range)
            }

            // Test fast pack
            let mut bytes_fast = [0u8; 192];
            pack_w1_44_fast(&original, &mut bytes_fast);

            // Compare fast vs base
            let mut bytes_base = [0u8; 192];
            pack_w1_44(&original, &mut bytes_base);

            assert_eq!(bytes_base, bytes_fast, "Packed bytes mismatch");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_w1_65_fast() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = (i % 16) as i32; // Values in [0, 15] (4-bit range)
            }

            // Test fast pack
            let mut bytes_fast = [0u8; 128];
            pack_w1_65_fast(&original, &mut bytes_fast);

            // Compare fast vs base
            let mut bytes_base = [0u8; 128];
            pack_w1_65(&original, &mut bytes_base);

            assert_eq!(bytes_base, bytes_fast, "Packed bytes mismatch");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pack_w1_65_simd() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut original = [0i32; N];
            for i in 0..N {
                original[i] = (i % 16) as i32; // Values in [0, 15] (4-bit range)
            }

            // Test SIMD pack
            let mut bytes_simd = [0u8; 128];
            pack_w1_65_simd(&original, &mut bytes_simd);

            // Compare with base
            let mut bytes_base = [0u8; 128];
            pack_w1_65(&original, &mut bytes_base);

            assert_eq!(bytes_base, bytes_simd, "SIMD packed bytes mismatch");
        }
    }
}
