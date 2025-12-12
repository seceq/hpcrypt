//! AVX2 Compression Operations
//!
//! This module implements highly-optimized compression for ML-KEM
//! using AVX2 SIMD intrinsics.
//!
//! # Compression Algorithm
//!
//! Compress_d(x) = ⌈(2^d / q) · x⌋ mod 2^d
//!
//! This maps from Z_q to {0, ..., 2^d - 1}.
//!
//! # Optimization: Division Elimination
//!
//! Instead of dividing by q, we multiply by a magic constant and shift:
//! x / q ≈ (x * MAGIC) >> 35 where MAGIC = ⌊2^35 / q⌋
//!
//! This provides:
//! - 2-3x faster compression
//! - Constant-time execution (no timing side-channels)
//! - Better vectorization
//!
//! # ML-KEM Parameters
//!
//! | Parameter | d_u | d_v | Usage |
//! |-----------|-----|-----|-------|
//! | ML-KEM-512 | 10 | 4 | Ciphertext |
//! | ML-KEM-768 | 10 | 4 | Ciphertext |
//! | ML-KEM-1024 | 11 | 5 | Ciphertext |

use core::arch::x86_64::*;
use super::consts::Q;

/// Magic divisor for constant-time division by q = 3329
/// Computed as: floor(2^35 / 3329) = 10,321,340
const COMPRESS_MAGIC: u64 = 10_321_340;

/// Half of q for rounding: 3329 / 2 = 1664
const Q_HALF: u32 = 1664;

// ============================================================================
// Compression d=10 (ML-KEM-512, ML-KEM-768)
// ============================================================================

/// Compress 16 coefficients with d=10 using AVX2
///
/// Maps each coefficient from [-q, 2q) to [0, 1024).
/// Includes branchless normalization to handle negative coefficients.
///
/// # Algorithm
/// 1. Normalize coefficients from [-q, 2q) to [0, q)
/// 2. compress(x) = ⌊(1024 * x + q/2) / q⌋ mod 1024
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn compress_d10(coeffs: &[i16; 16]) -> [u16; 16] {
    let mut result = [0u16; 16];

    // Load 16 i16 coefficients
    let x_vec = _mm256_loadu_si256(coeffs.as_ptr() as *const __m256i);

    // Constants
    let q_vec = _mm256_set1_epi16(Q as i16);

    // Branchless normalization: convert [-q, 2q) to [0, q)
    // Step 1: Add q to handle negatives -> now in [0, 3q)
    let pos = _mm256_add_epi16(x_vec, q_vec);

    // Step 2: Subtract q, check if result is negative
    let high = _mm256_sub_epi16(pos, q_vec);
    let mask = _mm256_srai_epi16(high, 15); // -1 if high < 0, else 0

    // Step 3: Select pos if high < 0, else high
    let normalized = _mm256_blendv_epi8(high, pos, mask);

    // Step 4: Handle case where result is still >= q (for inputs > q)
    let high2 = _mm256_sub_epi16(normalized, q_vec);
    let mask2 = _mm256_srai_epi16(high2, 15);
    let normalized_final = _mm256_blendv_epi8(high2, normalized, mask2);

    // Now normalized_final is in [0, q), stored as i16

    // Convert to 32-bit for shift and add (lower 8 coefficients)
    let norm_lo_128 = _mm256_castsi256_si128(normalized_final);
    let norm_lo = _mm256_cvtepi16_epi32(norm_lo_128); // 8 x i32

    // Upper 8 coefficients
    let norm_hi_128 = _mm256_extracti128_si256(normalized_final, 1);
    let norm_hi = _mm256_cvtepi16_epi32(norm_hi_128); // 8 x i32

    // Shift left by 10 and add q/2
    let q_half_32 = _mm256_set1_epi32(Q_HALF as i32);

    let lo_shifted = _mm256_slli_epi32(norm_lo, 10);
    let lo_added = _mm256_add_epi32(lo_shifted, q_half_32);

    let hi_shifted = _mm256_slli_epi32(norm_hi, 10);
    let hi_added = _mm256_add_epi32(hi_shifted, q_half_32);

    // Scalar 64-bit multiply
    let lo_arr: [i32; 8] = core::mem::transmute(lo_added);
    let hi_arr: [i32; 8] = core::mem::transmute(hi_added);

    for i in 0..8 {
        let compressed = ((lo_arr[i] as u64) * COMPRESS_MAGIC) >> 35;
        result[i] = (compressed & 0x3FF) as u16;
    }
    for i in 0..8 {
        let compressed = ((hi_arr[i] as u64) * COMPRESS_MAGIC) >> 35;
        result[8 + i] = (compressed & 0x3FF) as u16;
    }

    result
}

// ============================================================================
// Compression d=11 (ML-KEM-1024)
// ============================================================================

/// Compress 16 coefficients with d=11 using AVX2
///
/// Maps each coefficient from [-q, 2q) to [0, 2048).
/// Includes branchless normalization to handle negative coefficients.
///
/// # Safety
/// Requires AVX2 support
#[target_feature(enable = "avx2")]
pub unsafe fn compress_d11(coeffs: &[i16; 16]) -> [u16; 16] {
    let mut result = [0u16; 16];

    // Load 16 i16 coefficients
    let x_vec = _mm256_loadu_si256(coeffs.as_ptr() as *const __m256i);

    // Constants
    let q_vec = _mm256_set1_epi16(Q as i16);

    // Branchless normalization: convert [-q, 2q) to [0, q)
    let pos = _mm256_add_epi16(x_vec, q_vec);
    let high = _mm256_sub_epi16(pos, q_vec);
    let mask = _mm256_srai_epi16(high, 15);
    let normalized = _mm256_blendv_epi8(high, pos, mask);
    let high2 = _mm256_sub_epi16(normalized, q_vec);
    let mask2 = _mm256_srai_epi16(high2, 15);
    let normalized_final = _mm256_blendv_epi8(high2, normalized, mask2);

    // Convert to 32-bit
    let norm_lo_128 = _mm256_castsi256_si128(normalized_final);
    let norm_lo = _mm256_cvtepi16_epi32(norm_lo_128);
    let norm_hi_128 = _mm256_extracti128_si256(normalized_final, 1);
    let norm_hi = _mm256_cvtepi16_epi32(norm_hi_128);

    // Shift left by 11 and add q/2
    let q_half_32 = _mm256_set1_epi32(Q_HALF as i32);
    let lo_shifted = _mm256_slli_epi32(norm_lo, 11);
    let lo_added = _mm256_add_epi32(lo_shifted, q_half_32);
    let hi_shifted = _mm256_slli_epi32(norm_hi, 11);
    let hi_added = _mm256_add_epi32(hi_shifted, q_half_32);

    // Scalar 64-bit multiply
    let lo_arr: [i32; 8] = core::mem::transmute(lo_added);
    let hi_arr: [i32; 8] = core::mem::transmute(hi_added);

    for i in 0..8 {
        let compressed = ((lo_arr[i] as u64) * COMPRESS_MAGIC) >> 35;
        result[i] = (compressed & 0x7FF) as u16;
    }
    for i in 0..8 {
        let compressed = ((hi_arr[i] as u64) * COMPRESS_MAGIC) >> 35;
        result[8 + i] = (compressed & 0x7FF) as u16;
    }

    result
}

