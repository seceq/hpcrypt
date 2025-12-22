//! High-Performance AVX2 Rounding Operations
//!
//! This module provides optimized rounding operations for ML-DSA using AVX2
//! SIMD instructions. These operations are critical for signature generation
//! and verification.
//!
//! # Operations
//!
//! - **Power2Round**: Split coefficient into high and low bits
//! - **Decompose**: Decompose coefficient into high and low parts modulo α
//! - **HighBits**: Extract high bits from decomposition
//! - **LowBits**: Extract low bits from decomposition
//!
//! # Magic Multiplication Optimization
//!
//! Division operations are replaced with magic multiplication followed by
//! shift, which is significantly faster than hardware division:
//!
//! ```text
//! x / α ≈ (x * magic) >> shift
//! ```
//!
//! where `magic = ceil(2^shift / α)`

use core::arch::x86_64::*;
use super::consts::{
    Q, N, D, POWER2D, HALF_POWER2D,
    ALPHA_44, ALPHA_65,
    MAGIC_DIV_190464, MAGIC_DIV_523776,
};

// ============================================================================
// Power2Round
// ============================================================================

/// Power2Round: split r into (r1, r0) such that r ≡ r1*2^D + r0 (mod Q)
///
/// # Algorithm
/// ```text
/// r1 = (r + 2^(D-1) - 1) >> D
/// r0 = r - r1 * 2^D
/// ```
///
/// # Parameters
/// - D = 13 for ML-DSA (fixed)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn power2round(r: &[i32; N], r1: &mut [i32; N], r0: &mut [i32; N]) {
    let half_d = _mm256_set1_epi32(HALF_POWER2D - 1); // 2^(D-1) - 1 = 4095
    let power_d = _mm256_set1_epi32(POWER2D);          // 2^D = 8192

    for i in (0..N).step_by(8) {
        let vr = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);

        // r1 = (r + 2^(D-1) - 1) >> D
        let r_plus_half = _mm256_add_epi32(vr, half_d);
        let vr1 = _mm256_srai_epi32(r_plus_half, D as i32);

        // r0 = r - r1 * 2^D
        let r1_shifted = _mm256_slli_epi32(vr1, D as i32);
        let vr0 = _mm256_sub_epi32(vr, r1_shifted);

        _mm256_storeu_si256(r1.as_mut_ptr().add(i) as *mut __m256i, vr1);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i) as *mut __m256i, vr0);
    }
}

/// Power2Round in-place: compute r1, overwrite r with r0
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn power2round_inplace(r: &mut [i32; N], r1: &mut [i32; N]) {
    let half_d = _mm256_set1_epi32(HALF_POWER2D - 1);

    for i in (0..N).step_by(8) {
        let vr = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);

        let r_plus_half = _mm256_add_epi32(vr, half_d);
        let vr1 = _mm256_srai_epi32(r_plus_half, D as i32);

        let r1_shifted = _mm256_slli_epi32(vr1, D as i32);
        let vr0 = _mm256_sub_epi32(vr, r1_shifted);

        _mm256_storeu_si256(r1.as_mut_ptr().add(i) as *mut __m256i, vr1);
        _mm256_storeu_si256(r.as_mut_ptr().add(i) as *mut __m256i, vr0);
    }
}

/// Optimized Power2Round with unrolled loop
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn power2round_fast(r: &[i32; N], r1: &mut [i32; N], r0: &mut [i32; N]) {
    let half_d = _mm256_set1_epi32(HALF_POWER2D - 1);

    // Process 4 vectors (32 elements) per iteration
    for i in (0..N).step_by(32) {
        let vr0 = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);
        let vr1 = _mm256_loadu_si256(r.as_ptr().add(i + 8) as *const __m256i);
        let vr2 = _mm256_loadu_si256(r.as_ptr().add(i + 16) as *const __m256i);
        let vr3 = _mm256_loadu_si256(r.as_ptr().add(i + 24) as *const __m256i);

        // r1 = (r + 2^(D-1) - 1) >> D
        let rh0 = _mm256_add_epi32(vr0, half_d);
        let rh1 = _mm256_add_epi32(vr1, half_d);
        let rh2 = _mm256_add_epi32(vr2, half_d);
        let rh3 = _mm256_add_epi32(vr3, half_d);

        let hi0 = _mm256_srai_epi32(rh0, D as i32);
        let hi1 = _mm256_srai_epi32(rh1, D as i32);
        let hi2 = _mm256_srai_epi32(rh2, D as i32);
        let hi3 = _mm256_srai_epi32(rh3, D as i32);

        // r0 = r - r1 * 2^D
        let hi_shift0 = _mm256_slli_epi32(hi0, D as i32);
        let hi_shift1 = _mm256_slli_epi32(hi1, D as i32);
        let hi_shift2 = _mm256_slli_epi32(hi2, D as i32);
        let hi_shift3 = _mm256_slli_epi32(hi3, D as i32);

        let lo0 = _mm256_sub_epi32(vr0, hi_shift0);
        let lo1 = _mm256_sub_epi32(vr1, hi_shift1);
        let lo2 = _mm256_sub_epi32(vr2, hi_shift2);
        let lo3 = _mm256_sub_epi32(vr3, hi_shift3);

        _mm256_storeu_si256(r1.as_mut_ptr().add(i) as *mut __m256i, hi0);
        _mm256_storeu_si256(r1.as_mut_ptr().add(i + 8) as *mut __m256i, hi1);
        _mm256_storeu_si256(r1.as_mut_ptr().add(i + 16) as *mut __m256i, hi2);
        _mm256_storeu_si256(r1.as_mut_ptr().add(i + 24) as *mut __m256i, hi3);

        _mm256_storeu_si256(r0.as_mut_ptr().add(i) as *mut __m256i, lo0);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i + 8) as *mut __m256i, lo1);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i + 16) as *mut __m256i, lo2);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i + 24) as *mut __m256i, lo3);
    }
}

// ============================================================================
// Decompose
// ============================================================================

/// Decompose: split r into (r1, r0) such that r ≡ r1*α + r0 (mod Q)
///
/// # Algorithm
/// ```text
/// r1 = (r + 127) / α  (using magic multiplication)
/// r0 = r - r1 * α
/// if r0 > α/2: r1++; r0 -= α
/// if r1 == (Q-1)/α: r1 = 0; r0 -= 1
/// ```
///
/// # Parameters
/// - α = 2*γ₂ where γ₂ = (Q-1)/88 (ML-DSA-44) or (Q-1)/32 (ML-DSA-65/87)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn decompose(
    r: &[i32; N],
    r1: &mut [i32; N],
    r0: &mut [i32; N],
    alpha: i32,
) {
    match alpha {
        ALPHA_44 => decompose_alpha44(r, r1, r0),
        ALPHA_65 => decompose_alpha65(r, r1, r0),
        _ => decompose_generic(r, r1, r0, alpha),
    }
}

/// Decompose for ML-DSA-44 (α = 190464)
///
/// Uses 2x unrolling for better instruction-level parallelism.
#[target_feature(enable = "avx2")]
unsafe fn decompose_alpha44(r: &[i32; N], r1: &mut [i32; N], r0: &mut [i32; N]) {
    const ALPHA: i32 = ALPHA_44;        // 190464
    const ALPHA_HALF: i32 = ALPHA / 2;  // 95232
    const MAGIC: i64 = MAGIC_DIV_190464 as i64;
    const M: i32 = (Q - 1) / ALPHA;     // 43

    // Process 16 elements per iteration (2x unrolled)
    for i in (0..N).step_by(16) {
        // Load first 8 elements
        let r0_val = r[i];
        let r1_val = r[i + 1];
        let r2_val = r[i + 2];
        let r3_val = r[i + 3];
        let r4_val = r[i + 4];
        let r5_val = r[i + 5];
        let r6_val = r[i + 6];
        let r7_val = r[i + 7];

        // Load second 8 elements
        let r8_val = r[i + 8];
        let r9_val = r[i + 9];
        let r10_val = r[i + 10];
        let r11_val = r[i + 11];
        let r12_val = r[i + 12];
        let r13_val = r[i + 13];
        let r14_val = r[i + 14];
        let r15_val = r[i + 15];

        // Magic division for first 8 (can pipeline)
        let mut h0 = (((r0_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h1 = (((r1_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h2 = (((r2_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h3 = (((r3_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h4 = (((r4_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h5 = (((r5_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h6 = (((r6_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h7 = (((r7_val + 127) as i64 * MAGIC) >> 32) as i32;

        // Magic division for second 8
        let mut h8 = (((r8_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h9 = (((r9_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h10 = (((r10_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h11 = (((r11_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h12 = (((r12_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h13 = (((r13_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h14 = (((r14_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h15 = (((r15_val + 127) as i64 * MAGIC) >> 32) as i32;

        // Compute r0 = r - h * alpha for first 8
        let mut l0 = r0_val - h0 * ALPHA;
        let mut l1 = r1_val - h1 * ALPHA;
        let mut l2 = r2_val - h2 * ALPHA;
        let mut l3 = r3_val - h3 * ALPHA;
        let mut l4 = r4_val - h4 * ALPHA;
        let mut l5 = r5_val - h5 * ALPHA;
        let mut l6 = r6_val - h6 * ALPHA;
        let mut l7 = r7_val - h7 * ALPHA;

        // Compute r0 for second 8
        let mut l8 = r8_val - h8 * ALPHA;
        let mut l9 = r9_val - h9 * ALPHA;
        let mut l10 = r10_val - h10 * ALPHA;
        let mut l11 = r11_val - h11 * ALPHA;
        let mut l12 = r12_val - h12 * ALPHA;
        let mut l13 = r13_val - h13 * ALPHA;
        let mut l14 = r14_val - h14 * ALPHA;
        let mut l15 = r15_val - h15 * ALPHA;

        // Conditional corrections for first 8
        if l0 > ALPHA_HALF { h0 += 1; l0 -= ALPHA; }
        if l1 > ALPHA_HALF { h1 += 1; l1 -= ALPHA; }
        if l2 > ALPHA_HALF { h2 += 1; l2 -= ALPHA; }
        if l3 > ALPHA_HALF { h3 += 1; l3 -= ALPHA; }
        if l4 > ALPHA_HALF { h4 += 1; l4 -= ALPHA; }
        if l5 > ALPHA_HALF { h5 += 1; l5 -= ALPHA; }
        if l6 > ALPHA_HALF { h6 += 1; l6 -= ALPHA; }
        if l7 > ALPHA_HALF { h7 += 1; l7 -= ALPHA; }

        // Conditional corrections for second 8
        if l8 > ALPHA_HALF { h8 += 1; l8 -= ALPHA; }
        if l9 > ALPHA_HALF { h9 += 1; l9 -= ALPHA; }
        if l10 > ALPHA_HALF { h10 += 1; l10 -= ALPHA; }
        if l11 > ALPHA_HALF { h11 += 1; l11 -= ALPHA; }
        if l12 > ALPHA_HALF { h12 += 1; l12 -= ALPHA; }
        if l13 > ALPHA_HALF { h13 += 1; l13 -= ALPHA; }
        if l14 > ALPHA_HALF { h14 += 1; l14 -= ALPHA; }
        if l15 > ALPHA_HALF { h15 += 1; l15 -= ALPHA; }

        // Wrap-around corrections for first 8
        if h0 == M { h0 = 0; l0 -= 1; }
        if h1 == M { h1 = 0; l1 -= 1; }
        if h2 == M { h2 = 0; l2 -= 1; }
        if h3 == M { h3 = 0; l3 -= 1; }
        if h4 == M { h4 = 0; l4 -= 1; }
        if h5 == M { h5 = 0; l5 -= 1; }
        if h6 == M { h6 = 0; l6 -= 1; }
        if h7 == M { h7 = 0; l7 -= 1; }

        // Wrap-around corrections for second 8
        if h8 == M { h8 = 0; l8 -= 1; }
        if h9 == M { h9 = 0; l9 -= 1; }
        if h10 == M { h10 = 0; l10 -= 1; }
        if h11 == M { h11 = 0; l11 -= 1; }
        if h12 == M { h12 = 0; l12 -= 1; }
        if h13 == M { h13 = 0; l13 -= 1; }
        if h14 == M { h14 = 0; l14 -= 1; }
        if h15 == M { h15 = 0; l15 -= 1; }

        // Store using SIMD
        let vh0 = _mm256_setr_epi32(h0, h1, h2, h3, h4, h5, h6, h7);
        let vh1 = _mm256_setr_epi32(h8, h9, h10, h11, h12, h13, h14, h15);
        let vl0 = _mm256_setr_epi32(l0, l1, l2, l3, l4, l5, l6, l7);
        let vl1 = _mm256_setr_epi32(l8, l9, l10, l11, l12, l13, l14, l15);

        _mm256_storeu_si256(r1.as_mut_ptr().add(i) as *mut __m256i, vh0);
        _mm256_storeu_si256(r1.as_mut_ptr().add(i + 8) as *mut __m256i, vh1);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i) as *mut __m256i, vl0);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i + 8) as *mut __m256i, vl1);
    }
}

/// Decompose for ML-DSA-65/87 (α = 523776)
///
/// Uses 2x unrolling for better instruction-level parallelism.
#[target_feature(enable = "avx2")]
unsafe fn decompose_alpha65(r: &[i32; N], r1: &mut [i32; N], r0: &mut [i32; N]) {
    const ALPHA: i32 = ALPHA_65;        // 523776
    const ALPHA_HALF: i32 = ALPHA / 2;  // 261888
    const MAGIC: i64 = MAGIC_DIV_523776 as i64;
    const M: i32 = (Q - 1) / ALPHA;     // 15

    // Process 16 elements per iteration (2x unrolled)
    for i in (0..N).step_by(16) {
        // Compute first 8 elements
        let r0_val = r[i];
        let r1_val = r[i + 1];
        let r2_val = r[i + 2];
        let r3_val = r[i + 3];
        let r4_val = r[i + 4];
        let r5_val = r[i + 5];
        let r6_val = r[i + 6];
        let r7_val = r[i + 7];

        // Compute second 8 elements
        let r8_val = r[i + 8];
        let r9_val = r[i + 9];
        let r10_val = r[i + 10];
        let r11_val = r[i + 11];
        let r12_val = r[i + 12];
        let r13_val = r[i + 13];
        let r14_val = r[i + 14];
        let r15_val = r[i + 15];

        // Magic division for first 8 (can pipeline)
        let mut h0 = (((r0_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h1 = (((r1_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h2 = (((r2_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h3 = (((r3_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h4 = (((r4_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h5 = (((r5_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h6 = (((r6_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h7 = (((r7_val + 127) as i64 * MAGIC) >> 32) as i32;

        // Magic division for second 8
        let mut h8 = (((r8_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h9 = (((r9_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h10 = (((r10_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h11 = (((r11_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h12 = (((r12_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h13 = (((r13_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h14 = (((r14_val + 127) as i64 * MAGIC) >> 32) as i32;
        let mut h15 = (((r15_val + 127) as i64 * MAGIC) >> 32) as i32;

        // Compute r0 = r - h * alpha for first 8
        let mut l0 = r0_val - h0 * ALPHA;
        let mut l1 = r1_val - h1 * ALPHA;
        let mut l2 = r2_val - h2 * ALPHA;
        let mut l3 = r3_val - h3 * ALPHA;
        let mut l4 = r4_val - h4 * ALPHA;
        let mut l5 = r5_val - h5 * ALPHA;
        let mut l6 = r6_val - h6 * ALPHA;
        let mut l7 = r7_val - h7 * ALPHA;

        // Compute r0 for second 8
        let mut l8 = r8_val - h8 * ALPHA;
        let mut l9 = r9_val - h9 * ALPHA;
        let mut l10 = r10_val - h10 * ALPHA;
        let mut l11 = r11_val - h11 * ALPHA;
        let mut l12 = r12_val - h12 * ALPHA;
        let mut l13 = r13_val - h13 * ALPHA;
        let mut l14 = r14_val - h14 * ALPHA;
        let mut l15 = r15_val - h15 * ALPHA;

        // Conditional corrections for first 8
        if l0 > ALPHA_HALF { h0 += 1; l0 -= ALPHA; }
        if l1 > ALPHA_HALF { h1 += 1; l1 -= ALPHA; }
        if l2 > ALPHA_HALF { h2 += 1; l2 -= ALPHA; }
        if l3 > ALPHA_HALF { h3 += 1; l3 -= ALPHA; }
        if l4 > ALPHA_HALF { h4 += 1; l4 -= ALPHA; }
        if l5 > ALPHA_HALF { h5 += 1; l5 -= ALPHA; }
        if l6 > ALPHA_HALF { h6 += 1; l6 -= ALPHA; }
        if l7 > ALPHA_HALF { h7 += 1; l7 -= ALPHA; }

        // Conditional corrections for second 8
        if l8 > ALPHA_HALF { h8 += 1; l8 -= ALPHA; }
        if l9 > ALPHA_HALF { h9 += 1; l9 -= ALPHA; }
        if l10 > ALPHA_HALF { h10 += 1; l10 -= ALPHA; }
        if l11 > ALPHA_HALF { h11 += 1; l11 -= ALPHA; }
        if l12 > ALPHA_HALF { h12 += 1; l12 -= ALPHA; }
        if l13 > ALPHA_HALF { h13 += 1; l13 -= ALPHA; }
        if l14 > ALPHA_HALF { h14 += 1; l14 -= ALPHA; }
        if l15 > ALPHA_HALF { h15 += 1; l15 -= ALPHA; }

        // Wrap-around corrections for first 8
        if h0 == M { h0 = 0; l0 -= 1; }
        if h1 == M { h1 = 0; l1 -= 1; }
        if h2 == M { h2 = 0; l2 -= 1; }
        if h3 == M { h3 = 0; l3 -= 1; }
        if h4 == M { h4 = 0; l4 -= 1; }
        if h5 == M { h5 = 0; l5 -= 1; }
        if h6 == M { h6 = 0; l6 -= 1; }
        if h7 == M { h7 = 0; l7 -= 1; }

        // Wrap-around corrections for second 8
        if h8 == M { h8 = 0; l8 -= 1; }
        if h9 == M { h9 = 0; l9 -= 1; }
        if h10 == M { h10 = 0; l10 -= 1; }
        if h11 == M { h11 = 0; l11 -= 1; }
        if h12 == M { h12 = 0; l12 -= 1; }
        if h13 == M { h13 = 0; l13 -= 1; }
        if h14 == M { h14 = 0; l14 -= 1; }
        if h15 == M { h15 = 0; l15 -= 1; }

        // Store using SIMD
        let vh0 = _mm256_setr_epi32(h0, h1, h2, h3, h4, h5, h6, h7);
        let vh1 = _mm256_setr_epi32(h8, h9, h10, h11, h12, h13, h14, h15);
        let vl0 = _mm256_setr_epi32(l0, l1, l2, l3, l4, l5, l6, l7);
        let vl1 = _mm256_setr_epi32(l8, l9, l10, l11, l12, l13, l14, l15);

        _mm256_storeu_si256(r1.as_mut_ptr().add(i) as *mut __m256i, vh0);
        _mm256_storeu_si256(r1.as_mut_ptr().add(i + 8) as *mut __m256i, vh1);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i) as *mut __m256i, vl0);
        _mm256_storeu_si256(r0.as_mut_ptr().add(i + 8) as *mut __m256i, vl1);
    }
}

/// Generic decompose for arbitrary alpha
#[target_feature(enable = "avx2")]
unsafe fn decompose_generic(
    r: &[i32; N],
    r1: &mut [i32; N],
    r0: &mut [i32; N],
    alpha: i32,
) {
    let alpha_half = alpha / 2;
    let m = (Q - 1) / alpha;

    for i in 0..N {
        let r_val = r[i];

        let mut r1_val = (r_val + 127) / alpha;
        let mut r0_val = r_val - r1_val * alpha;

        if r0_val > alpha_half {
            r1_val += 1;
            r0_val -= alpha;
        }

        if r1_val == m {
            r1_val = 0;
            r0_val -= 1;
        }

        r1[i] = r1_val;
        r0[i] = r0_val;
    }
}

// ============================================================================
// HighBits and LowBits
// ============================================================================

/// Extract high bits from decomposition
///
/// Returns r1 from Decompose(r, α)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn highbits(r: &[i32; N], out: &mut [i32; N], alpha: i32) {
    let mut r0 = [0i32; N];
    decompose(r, out, &mut r0, alpha);
}

/// Extract low bits from decomposition
///
/// Returns r0 from Decompose(r, α)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn lowbits(r: &[i32; N], out: &mut [i32; N], alpha: i32) {
    let mut r1 = [0i32; N];
    decompose(r, &mut r1, out, alpha);
}

/// Optimized high bits extraction
///
/// Directly computes r1 without storing r0.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn highbits_fast(r: &[i32; N], out: &mut [i32; N], alpha: i32) {
    match alpha {
        ALPHA_44 => highbits_fast_alpha44(r, out),
        ALPHA_65 => highbits_fast_alpha65(r, out),
        _ => highbits(r, out, alpha), // Fallback
    }
}

#[target_feature(enable = "avx2")]
unsafe fn highbits_fast_alpha44(r: &[i32; N], out: &mut [i32; N]) {
    const ALPHA: i32 = ALPHA_44;
    const ALPHA_HALF: i32 = ALPHA / 2;
    const MAGIC: i64 = MAGIC_DIV_190464 as i64;
    const M: i32 = (Q - 1) / ALPHA;

    for i in (0..N).step_by(8) {
        let vr = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);

        let mut r_arr = [0i32; 8];
        let mut r1_arr = [0i32; 8];

        _mm256_storeu_si256(r_arr.as_mut_ptr() as *mut __m256i, vr);

        for j in 0..8 {
            let r_val = r_arr[j];
            let mut r1_val = (((r_val + 127) as i64 * MAGIC) >> 32) as i32;
            let r0_val = r_val - r1_val * ALPHA;

            if r0_val > ALPHA_HALF {
                r1_val += 1;
            }

            if r1_val == M {
                r1_val = 0;
            }

            r1_arr[j] = r1_val;
        }

        let vr1 = _mm256_loadu_si256(r1_arr.as_ptr() as *const __m256i);
        _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr1);
    }
}

#[target_feature(enable = "avx2")]
unsafe fn highbits_fast_alpha65(r: &[i32; N], out: &mut [i32; N]) {
    const ALPHA: i32 = ALPHA_65;
    const ALPHA_HALF: i32 = ALPHA / 2;
    const MAGIC: i64 = MAGIC_DIV_523776 as i64;
    const M: i32 = (Q - 1) / ALPHA;

    for i in (0..N).step_by(8) {
        let vr = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);

        let mut r_arr = [0i32; 8];
        let mut r1_arr = [0i32; 8];

        _mm256_storeu_si256(r_arr.as_mut_ptr() as *mut __m256i, vr);

        for j in 0..8 {
            let r_val = r_arr[j];
            let mut r1_val = (((r_val + 127) as i64 * MAGIC) >> 32) as i32;
            let r0_val = r_val - r1_val * ALPHA;

            if r0_val > ALPHA_HALF {
                r1_val += 1;
            }

            if r1_val == M {
                r1_val = 0;
            }

            r1_arr[j] = r1_val;
        }

        let vr1 = _mm256_loadu_si256(r1_arr.as_ptr() as *const __m256i);
        _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr1);
    }
}

/// Optimized low bits extraction
///
/// Directly computes r0 without storing r1.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn lowbits_fast(r: &[i32; N], out: &mut [i32; N], alpha: i32) {
    match alpha {
        ALPHA_44 => lowbits_fast_alpha44(r, out),
        ALPHA_65 => lowbits_fast_alpha65(r, out),
        _ => lowbits(r, out, alpha),
    }
}

#[target_feature(enable = "avx2")]
unsafe fn lowbits_fast_alpha44(r: &[i32; N], out: &mut [i32; N]) {
    const ALPHA: i32 = ALPHA_44;
    const ALPHA_HALF: i32 = ALPHA / 2;
    const MAGIC: i64 = MAGIC_DIV_190464 as i64;
    const M: i32 = (Q - 1) / ALPHA;

    for i in (0..N).step_by(8) {
        let vr = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);

        let mut r_arr = [0i32; 8];
        let mut r0_arr = [0i32; 8];

        _mm256_storeu_si256(r_arr.as_mut_ptr() as *mut __m256i, vr);

        for j in 0..8 {
            let r_val = r_arr[j];
            let mut r1_val = (((r_val + 127) as i64 * MAGIC) >> 32) as i32;
            let mut r0_val = r_val - r1_val * ALPHA;

            if r0_val > ALPHA_HALF {
                r1_val += 1;
                r0_val -= ALPHA;
            }

            if r1_val == M {
                r0_val -= 1;
            }

            r0_arr[j] = r0_val;
        }

        let vr0 = _mm256_loadu_si256(r0_arr.as_ptr() as *const __m256i);
        _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr0);
    }
}

#[target_feature(enable = "avx2")]
unsafe fn lowbits_fast_alpha65(r: &[i32; N], out: &mut [i32; N]) {
    const ALPHA: i32 = ALPHA_65;
    const ALPHA_HALF: i32 = ALPHA / 2;
    const MAGIC: i64 = MAGIC_DIV_523776 as i64;
    const M: i32 = (Q - 1) / ALPHA;

    for i in (0..N).step_by(8) {
        let vr = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);

        let mut r_arr = [0i32; 8];
        let mut r0_arr = [0i32; 8];

        _mm256_storeu_si256(r_arr.as_mut_ptr() as *mut __m256i, vr);

        for j in 0..8 {
            let r_val = r_arr[j];
            let mut r1_val = (((r_val + 127) as i64 * MAGIC) >> 32) as i32;
            let mut r0_val = r_val - r1_val * ALPHA;

            if r0_val > ALPHA_HALF {
                r1_val += 1;
                r0_val -= ALPHA;
            }

            if r1_val == M {
                r0_val -= 1;
            }

            r0_arr[j] = r0_val;
        }

        let vr0 = _mm256_loadu_si256(r0_arr.as_ptr() as *const __m256i);
        _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, vr0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_power2round() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut r = [0i32; N];
            let mut r1 = [0i32; N];
            let mut r0 = [0i32; N];

            // Test value
            for i in 0..N {
                r[i] = (i as i32 * 12345) % Q;
            }

            power2round(&r, &mut r1, &mut r0);

            // Verify: r ≡ r1 * 2^D + r0
            for i in 0..N {
                let reconstructed = (r1[i] << D) + r0[i];
                assert_eq!(
                    reconstructed, r[i],
                    "Power2Round mismatch at {}: {} != {}",
                    i, reconstructed, r[i]
                );
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_decompose_alpha44() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut r = [0i32; N];
            let mut r1 = [0i32; N];
            let mut r0 = [0i32; N];

            for i in 0..N {
                r[i] = (i as i32 * 12345) % Q;
            }

            decompose(&r, &mut r1, &mut r0, ALPHA_44);

            // Verify r1 is in valid range
            for i in 0..N {
                assert!(
                    r1[i] >= 0 && r1[i] < 44,
                    "r1[{}] = {} out of range",
                    i,
                    r1[i]
                );
            }

            // Verify r0 is in valid range
            for i in 0..N {
                assert!(
                    r0[i] >= -ALPHA_44 / 2 && r0[i] <= ALPHA_44 / 2,
                    "r0[{}] = {} out of range",
                    i,
                    r0[i]
                );
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_decompose_alpha65() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut r = [0i32; N];
            let mut r1 = [0i32; N];
            let mut r0 = [0i32; N];

            for i in 0..N {
                r[i] = (i as i32 * 12345) % Q;
            }

            decompose(&r, &mut r1, &mut r0, ALPHA_65);

            // Verify r1 is in valid range (0..16 for alpha65)
            for i in 0..N {
                assert!(
                    r1[i] >= 0 && r1[i] < 16,
                    "r1[{}] = {} out of range",
                    i,
                    r1[i]
                );
            }

            // Verify r0 is in valid range
            for i in 0..N {
                assert!(
                    r0[i] >= -ALPHA_65 / 2 && r0[i] <= ALPHA_65 / 2,
                    "r0[{}] = {} out of range",
                    i,
                    r0[i]
                );
            }
        }
    }
}
