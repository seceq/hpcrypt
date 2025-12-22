//! High-Performance ARM NEON Number Theoretic Transform (NTT)
//!
//! This module provides a fully vectorized NTT implementation for ML-DSA,
//! processing all 8 levels with NEON SIMD instructions.
//!
//! # Algorithm Overview
//!
//! ## Forward NTT (Cooley-Tukey, Decimation-in-Time)
//!
//! Transforms polynomial from coefficient domain to NTT domain.
//! Uses bit-reversal ordering with in-place butterflies:
//!
//! ```text
//! For level k = 0 to 7:
//!     For each butterfly group:
//!         (a, b) <- (a + ζ*b, a - ζ*b)
//! ```
//!
//! ## Inverse NTT (Gentleman-Sande, Decimation-in-Frequency)
//!
//! Transforms from NTT domain back to coefficient domain.
//!
//! # Vectorization Strategy
//!
//! - **NEON uses 128-bit registers (4 × i32)** vs AVX2's 256-bit (8 × i32)
//! - **64 vectors per polynomial** instead of 32 for AVX2
//! - **Levels 0-5** (inter-vector): Butterflies between different int32x4_t registers
//! - **Levels 6-7** (intra-vector): Butterflies within single register using shuffles
//!
//! # Optimization Techniques
//!
//! - **4x unrolled load/store**: Better memory bandwidth utilization
//! - **2x unrolled butterflies**: Improved instruction-level parallelism
//! - **Merged levels 6+7**: Reduces intermediate stores
//! - **Shoup's Montgomery**: Precomputed constants for parallel execution
//! - **Rolling macros**: Clean, maintainable code without sacrificing performance

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::consts::{Q, QINV, F, N, ZETAS, ZETAS_SHOUP, VECS_PER_POLY};
use super::reduce::{fqmul_neon, fqmul_shoup_neon, montgomery_reduce_scalar};

// ============================================================================
// Butterfly Operations
// ============================================================================

/// Cooley-Tukey butterfly for forward NTT
///
/// Computes: (a0 + t, a0 - t) where t = a1 * zeta
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn butterfly_ct(
    a0: int32x4_t,
    a1: int32x4_t,
    zeta: int32x4_t,
    zeta_shoup: int32x4_t,
) -> (int32x4_t, int32x4_t) {
    // t = a1 * zeta (Shoup's optimized Montgomery multiplication)
    let t = fqmul_shoup_neon(a1, zeta, zeta_shoup);

    // new_a0 = a0 + t, new_a1 = a0 - t
    let new_a0 = vaddq_s32(a0, t);
    let new_a1 = vsubq_s32(a0, t);

    (new_a0, new_a1)
}

/// Gentleman-Sande butterfly for inverse NTT
///
/// Computes: (a0 + a1, (a0 - a1) * zeta)
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn butterfly_gs(
    a0: int32x4_t,
    a1: int32x4_t,
    zeta: int32x4_t,
    zeta_shoup: int32x4_t,
) -> (int32x4_t, int32x4_t) {
    // new_a0 = a0 + a1
    let new_a0 = vaddq_s32(a0, a1);

    // diff = a0 - a1
    let diff = vsubq_s32(a0, a1);

    // new_a1 = diff * zeta (Shoup's optimized Montgomery multiplication)
    let new_a1 = fqmul_shoup_neon(diff, zeta, zeta_shoup);

    (new_a0, new_a1)
}

// ============================================================================
// Forward NTT - Fully Vectorized
// ============================================================================

/// Forward Number Theoretic Transform
///
/// Transforms a 256-coefficient polynomial from coefficient domain to NTT domain
/// using Cooley-Tukey decimation-in-time algorithm.
///
/// All 8 levels are fully vectorized using NEON.
///
/// # Input/Output
/// - Input: polynomial in coefficient representation
/// - Output: polynomial in NTT representation (bitreversed order)
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn ntt(coeffs: &mut [i32; N]) {
    // Load all 64 vectors using 4x unrolled macro
    let mut v: [int32x4_t; VECS_PER_POLY] = [vdupq_n_s32(0); VECS_PER_POLY];
    load_poly_4x!(v, coeffs);

    let mut k = 1usize; // Zeta index

    // =========================================================================
    // Level 0: distance = 128 (1 butterfly group, spans entire polynomial)
    // Butterflies between v[i] and v[i+32] for i in 0..32
    // OPTIMIZED: 2x loop unrolling for better ILP
    // =========================================================================
    {
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);
        k += 1;

        // 2x unrolled loop for better instruction-level parallelism
        let mut i = 0;
        while i < 32 {
            // Process two butterflies in parallel (independent operations)
            let (new_lo0, new_hi0) = butterfly_ct(v[i], v[i + 32], zeta, zeta_shoup);
            let (new_lo1, new_hi1) = butterfly_ct(v[i + 1], v[i + 33], zeta, zeta_shoup);
            v[i] = new_lo0;
            v[i + 32] = new_hi0;
            v[i + 1] = new_lo1;
            v[i + 33] = new_hi1;
            i += 2;
        }
    }

    // =========================================================================
    // Level 1: distance = 64 (2 butterfly groups)
    // OPTIMIZED: 2x loop unrolling
    // =========================================================================
    for group in 0..2 {
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);
        k += 1;

        let base = group * 32;
        let mut i = 0;
        while i < 16 {
            let (new_lo0, new_hi0) = butterfly_ct(v[base + i], v[base + i + 16], zeta, zeta_shoup);
            let (new_lo1, new_hi1) = butterfly_ct(v[base + i + 1], v[base + i + 17], zeta, zeta_shoup);
            v[base + i] = new_lo0;
            v[base + i + 16] = new_hi0;
            v[base + i + 1] = new_lo1;
            v[base + i + 17] = new_hi1;
            i += 2;
        }
    }

    // =========================================================================
    // Level 2: distance = 32 (4 butterfly groups)
    // OPTIMIZED: 2x unrolled inner loop
    // =========================================================================
    for group in 0..4 {
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);
        k += 1;

        let base = group * 16;
        let mut i = 0;
        while i < 8 {
            let (new_lo0, new_hi0) = butterfly_ct(v[base + i], v[base + i + 8], zeta, zeta_shoup);
            let (new_lo1, new_hi1) = butterfly_ct(v[base + i + 1], v[base + i + 9], zeta, zeta_shoup);
            v[base + i] = new_lo0;
            v[base + i + 8] = new_hi0;
            v[base + i + 1] = new_lo1;
            v[base + i + 9] = new_hi1;
            i += 2;
        }
    }

    // =========================================================================
    // Level 3: distance = 16 (8 butterfly groups)
    // OPTIMIZED: 2x unrolled inner loop
    // =========================================================================
    for group in 0..8 {
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);
        k += 1;

        let base = group * 8;
        // Unrolled: process all 4 pairs at once (2x2)
        let (new_lo0, new_hi0) = butterfly_ct(v[base], v[base + 4], zeta, zeta_shoup);
        let (new_lo1, new_hi1) = butterfly_ct(v[base + 1], v[base + 5], zeta, zeta_shoup);
        let (new_lo2, new_hi2) = butterfly_ct(v[base + 2], v[base + 6], zeta, zeta_shoup);
        let (new_lo3, new_hi3) = butterfly_ct(v[base + 3], v[base + 7], zeta, zeta_shoup);
        v[base] = new_lo0;
        v[base + 4] = new_hi0;
        v[base + 1] = new_lo1;
        v[base + 5] = new_hi1;
        v[base + 2] = new_lo2;
        v[base + 6] = new_hi2;
        v[base + 3] = new_lo3;
        v[base + 7] = new_hi3;
    }

    // =========================================================================
    // Level 4: distance = 8 (16 butterfly groups)
    // OPTIMIZED: 2x unrolled
    // =========================================================================
    for group in 0..16 {
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);
        k += 1;

        let base = group * 4;
        // Unrolled: process both pairs together
        let (new_lo0, new_hi0) = butterfly_ct(v[base], v[base + 2], zeta, zeta_shoup);
        let (new_lo1, new_hi1) = butterfly_ct(v[base + 1], v[base + 3], zeta, zeta_shoup);
        v[base] = new_lo0;
        v[base + 2] = new_hi0;
        v[base + 1] = new_lo1;
        v[base + 3] = new_hi1;
    }

    // =========================================================================
    // Level 5: distance = 4 (32 butterfly groups)
    // OPTIMIZED: 2x unrolled
    // =========================================================================
    let mut group = 0;
    while group < 32 {
        let zeta0 = vdupq_n_s32(ZETAS[k]);
        let zeta0_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);
        let zeta1 = vdupq_n_s32(ZETAS[k + 1]);
        let zeta1_shoup = vdupq_n_s32(ZETAS_SHOUP[k + 1]);
        k += 2;

        let base0 = group * 2;
        let base1 = (group + 1) * 2;

        // Process two groups in parallel
        let (new_lo0, new_hi0) = butterfly_ct(v[base0], v[base0 + 1], zeta0, zeta0_shoup);
        let (new_lo1, new_hi1) = butterfly_ct(v[base1], v[base1 + 1], zeta1, zeta1_shoup);

        v[base0] = new_lo0;
        v[base0 + 1] = new_hi0;
        v[base1] = new_lo1;
        v[base1 + 1] = new_hi1;

        group += 2;
    }

    // =========================================================================
    // MERGED Levels 6+7: Process both intra-vector levels in one pass
    // This eliminates intermediate store/load and improves register usage
    // Level 6: butterflies on (c0,c2) and (c1,c3)
    // Level 7: butterflies on (c0,c1) and (c2,c3)
    // =========================================================================
    let k6_base = k;  // Level 6 zetas start here
    let k7_base = k + VECS_PER_POLY;  // Level 7 zetas start here

    for i in 0..VECS_PER_POLY {
        // ===================== Level 6 =====================
        // Zeta for level 6 (same zeta for both pairs in vector)
        let zeta6 = vdupq_n_s32(ZETAS[k6_base + i]);
        let zeta6_shoup = vdupq_n_s32(ZETAS_SHOUP[k6_base + i]);

        // v[i] = [c0, c1, c2, c3]
        // Level 6 butterflies: (c0, c2) and (c1, c3)
        let lo = vget_low_s32(v[i]);   // [c0, c1]
        let hi = vget_high_s32(v[i]);  // [c2, c3]
        let a6 = vcombine_s32(lo, lo);  // [c0, c1, c0, c1]
        let b6 = vcombine_s32(hi, hi);  // [c2, c3, c2, c3]

        // t6 = b6 * zeta6 (Shoup's optimized Montgomery multiplication)
        let t6 = fqmul_shoup_neon(b6, zeta6, zeta6_shoup);

        // After level 6: new_lo = [c0+t, c1+t], new_hi = [c0-t, c1-t]
        let sum6 = vaddq_s32(a6, t6);   // [c0', c1', c0', c1'] where ' = +t
        let diff6 = vsubq_s32(a6, t6);  // [c0'', c1'', c0'', c1''] where '' = -t

        // Level 6 output (before level 7): [c0', c1', c0'', c1'']
        let l6_lo = vget_low_s32(sum6);   // [c0', c1']
        let l6_hi = vget_low_s32(diff6);  // [c0'', c1'']
        let l6_out = vcombine_s32(l6_lo, l6_hi);  // [c0', c1', c0'', c1'']

        // ===================== Level 7 =====================
        // Two different zetas for level 7: zeta7_a for (c0', c1'), zeta7_b for (c0'', c1'')
        let zeta7_a = ZETAS[k7_base + 2 * i];
        let zeta7_b = ZETAS[k7_base + 2 * i + 1];
        let zeta7_vec = vcombine_s32(
            vdup_n_s32(zeta7_a),
            vdup_n_s32(zeta7_b)
        );  // [z7a, z7a, z7b, z7b]
        let zeta7_shoup_vec = vcombine_s32(
            vdup_n_s32(ZETAS_SHOUP[k7_base + 2 * i]),
            vdup_n_s32(ZETAS_SHOUP[k7_base + 2 * i + 1])
        );

        // l6_out = [c0', c1', c0'', c1'']
        // Level 7 butterflies: (c0', c1') with zeta7_a, (c0'', c1'') with zeta7_b
        let trn = vtrnq_s32(l6_out, l6_out);
        let evens = trn.0;  // [c0', c0', c0'', c0'']
        let odds = trn.1;   // [c1', c1', c1'', c1'']

        // t7 = odds * zeta7 (Shoup's optimized Montgomery multiplication)
        let t7 = fqmul_shoup_neon(odds, zeta7_vec, zeta7_shoup_vec);

        // Final output
        let sum7 = vaddq_s32(evens, t7);
        let diff7 = vsubq_s32(evens, t7);

        // Interleave back: [sum7[0], diff7[0], sum7[2], diff7[2]]
        let result = vtrnq_s32(sum7, diff7);
        // result.0 = [sum7[0], diff7[0], sum7[2], diff7[2]]
        v[i] = result.0;
    }

    // Store results using 4x unrolled macro
    store_poly_4x!(coeffs, v);
}

// ============================================================================
// Inverse NTT - Fully Vectorized
// ============================================================================

/// Inverse Number Theoretic Transform
///
/// Transforms a polynomial from NTT domain back to coefficient domain
/// using Gentleman-Sande decimation-in-frequency algorithm.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn invntt(coeffs: &mut [i32; N]) {
    // Load all 64 vectors using 4x unrolled macro
    let mut v: [int32x4_t; VECS_PER_POLY] = [vdupq_n_s32(0); VECS_PER_POLY];
    load_poly_4x!(v, coeffs);

    // =========================================================================
    // MERGED Levels 7+6: Process both intra-vector levels in one pass
    // This eliminates intermediate store/load and improves register usage
    // Level 7: butterflies on (c0,c1) and (c2,c3) - GS style
    // Level 6: butterflies on (c0,c2) and (c1,c3) - GS style
    // =========================================================================
    // Zeta indices for inverse NTT:
    // Level 7 uses zetas[128..256] (2 per vector, 128 total)
    // Level 6 uses zetas[64..128] (1 per vector, 64 total)
    let k7_base = 128;  // Level 7 zetas: indices 128-255
    let k6_base = 64;   // Level 6 zetas: indices 64-127

    for i in 0..VECS_PER_POLY {
        // ===================== Level 7 =====================
        // Two different zetas per vector (for pairs (c0,c1) and (c2,c3))
        let zeta7_0 = ZETAS[k7_base + 2 * i];      // for pair (c0, c1)
        let zeta7_1 = ZETAS[k7_base + 2 * i + 1];  // for pair (c2, c3)

        let zeta7_vec = vcombine_s32(
            vdup_n_s32(zeta7_0),
            vdup_n_s32(zeta7_1)
        );
        let zeta7_shoup_vec = vcombine_s32(
            vdup_n_s32(ZETAS_SHOUP[k7_base + 2 * i]),
            vdup_n_s32(ZETAS_SHOUP[k7_base + 2 * i + 1])
        );

        // v[i] = [c0, c1, c2, c3]
        // GS butterfly: (a, b) -> (a+b, (a-b)*zeta)
        // For (c0,c1): new_c0 = c0+c1, new_c1 = (c0-c1)*zeta7_0
        // For (c2,c3): new_c2 = c2+c3, new_c3 = (c2-c3)*zeta7_1

        let trn7 = vtrnq_s32(v[i], v[i]);
        let evens7 = trn7.0;  // [c0, c0, c2, c2]
        let odds7 = trn7.1;   // [c1, c1, c3, c3]

        let sum7 = vaddq_s32(evens7, odds7);   // [c0+c1, c0+c1, c2+c3, c2+c3]
        let diff7 = vsubq_s32(evens7, odds7);  // [c0-c1, c0-c1, c2-c3, c2-c3]
        let diff7_mul = fqmul_shoup_neon(diff7, zeta7_vec, zeta7_shoup_vec);

        // Interleave: [sum7[0], diff7_mul[0], sum7[2], diff7_mul[2]]
        let result7 = vtrnq_s32(sum7, diff7_mul);
        let l7_out = result7.0;  // [c0', c1', c2', c3'] after level 7

        // ===================== Level 6 (immediately after, no intermediate store) =====================
        let zeta6 = vdupq_n_s32(ZETAS[k6_base + i]);
        let zeta6_shoup = vdupq_n_s32(ZETAS_SHOUP[k6_base + i]);

        // l7_out = [c0', c1', c2', c3']
        // GS butterflies: (c0', c2') and (c1', c3')
        let lo6 = vget_low_s32(l7_out);   // [c0', c1']
        let hi6 = vget_high_s32(l7_out);  // [c2', c3']

        let a6 = vcombine_s32(lo6, lo6);  // [c0', c1', c0', c1']
        let b6 = vcombine_s32(hi6, hi6);  // [c2', c3', c2', c3']

        let sum6 = vaddq_s32(a6, b6);     // [c0'+c2', c1'+c3', ...]
        let diff6 = vsubq_s32(a6, b6);    // [c0'-c2', c1'-c3', ...]
        let diff6_mul = fqmul_shoup_neon(diff6, zeta6, zeta6_shoup);

        // Recombine: [c0'+c2', c1'+c3', (c0'-c2')*z, (c1'-c3')*z]
        let result_lo6 = vget_low_s32(sum6);
        let result_hi6 = vget_low_s32(diff6_mul);
        v[i] = vcombine_s32(result_lo6, result_hi6);
    }

    // k tracks position for remaining levels
    let mut k = k6_base;  // Start at 64 for level 5

    // =========================================================================
    // Level 5: distance = 4 (32 butterfly groups)
    // OPTIMIZED: 2x unrolled, processing groups in reverse order
    // =========================================================================
    let mut group_idx: i32 = 30;  // Process pairs (30,31), (28,29), ... down to (0,1)
    while group_idx >= 0 {
        k -= 2;
        let zeta0 = vdupq_n_s32(ZETAS[k + 1]);
        let zeta0_shoup = vdupq_n_s32(ZETAS_SHOUP[k + 1]);
        let zeta1 = vdupq_n_s32(ZETAS[k]);
        let zeta1_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);

        let base0 = ((group_idx + 1) * 2) as usize;  // Higher group
        let base1 = (group_idx * 2) as usize;        // Lower group

        let (new_lo0, new_hi0) = butterfly_gs(v[base0], v[base0 + 1], zeta0, zeta0_shoup);
        let (new_lo1, new_hi1) = butterfly_gs(v[base1], v[base1 + 1], zeta1, zeta1_shoup);

        v[base0] = new_lo0;
        v[base0 + 1] = new_hi0;
        v[base1] = new_lo1;
        v[base1 + 1] = new_hi1;

        group_idx -= 2;
    }

    // =========================================================================
    // Level 4: distance = 8 (16 butterfly groups)
    // OPTIMIZED: 2x unrolled inner loop
    // =========================================================================
    for group in (0..16).rev() {
        k -= 1;
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);

        let base = group * 4;
        // Unrolled: process both pairs together
        let (new_lo0, new_hi0) = butterfly_gs(v[base], v[base + 2], zeta, zeta_shoup);
        let (new_lo1, new_hi1) = butterfly_gs(v[base + 1], v[base + 3], zeta, zeta_shoup);
        v[base] = new_lo0;
        v[base + 2] = new_hi0;
        v[base + 1] = new_lo1;
        v[base + 3] = new_hi1;
    }

    // =========================================================================
    // Level 3: distance = 16 (8 butterfly groups)
    // OPTIMIZED: Fully unrolled inner loop (4 butterflies)
    // =========================================================================
    for group in (0..8).rev() {
        k -= 1;
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);

        let base = group * 8;
        // Fully unrolled: all 4 pairs
        let (new_lo0, new_hi0) = butterfly_gs(v[base], v[base + 4], zeta, zeta_shoup);
        let (new_lo1, new_hi1) = butterfly_gs(v[base + 1], v[base + 5], zeta, zeta_shoup);
        let (new_lo2, new_hi2) = butterfly_gs(v[base + 2], v[base + 6], zeta, zeta_shoup);
        let (new_lo3, new_hi3) = butterfly_gs(v[base + 3], v[base + 7], zeta, zeta_shoup);
        v[base] = new_lo0;
        v[base + 4] = new_hi0;
        v[base + 1] = new_lo1;
        v[base + 5] = new_hi1;
        v[base + 2] = new_lo2;
        v[base + 6] = new_hi2;
        v[base + 3] = new_lo3;
        v[base + 7] = new_hi3;
    }

    // =========================================================================
    // Level 2: distance = 32 (4 butterfly groups)
    // OPTIMIZED: 2x unrolled inner loop
    // =========================================================================
    for group in (0..4).rev() {
        k -= 1;
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);

        let base = group * 16;
        let mut i = 0;
        while i < 8 {
            let (new_lo0, new_hi0) = butterfly_gs(v[base + i], v[base + i + 8], zeta, zeta_shoup);
            let (new_lo1, new_hi1) = butterfly_gs(v[base + i + 1], v[base + i + 9], zeta, zeta_shoup);
            v[base + i] = new_lo0;
            v[base + i + 8] = new_hi0;
            v[base + i + 1] = new_lo1;
            v[base + i + 9] = new_hi1;
            i += 2;
        }
    }

    // =========================================================================
    // Level 1: distance = 64 (2 butterfly groups)
    // OPTIMIZED: 2x unrolled inner loop
    // =========================================================================
    for group in (0..2).rev() {
        k -= 1;
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);

        let base = group * 32;
        let mut i = 0;
        while i < 16 {
            let (new_lo0, new_hi0) = butterfly_gs(v[base + i], v[base + i + 16], zeta, zeta_shoup);
            let (new_lo1, new_hi1) = butterfly_gs(v[base + i + 1], v[base + i + 17], zeta, zeta_shoup);
            v[base + i] = new_lo0;
            v[base + i + 16] = new_hi0;
            v[base + i + 1] = new_lo1;
            v[base + i + 17] = new_hi1;
            i += 2;
        }
    }

    // =========================================================================
    // Level 0: distance = 128 (1 butterfly group)
    // OPTIMIZED: 2x unrolled
    // =========================================================================
    {
        k -= 1;
        let zeta = vdupq_n_s32(ZETAS[k]);
        let zeta_shoup = vdupq_n_s32(ZETAS_SHOUP[k]);

        let mut i = 0;
        while i < 32 {
            let (new_lo0, new_hi0) = butterfly_gs(v[i], v[i + 32], zeta, zeta_shoup);
            let (new_lo1, new_hi1) = butterfly_gs(v[i + 1], v[i + 33], zeta, zeta_shoup);
            v[i] = new_lo0;
            v[i + 32] = new_hi0;
            v[i + 1] = new_lo1;
            v[i + 33] = new_hi1;
            i += 2;
        }
    }

    // =========================================================================
    // Scale by F = 1/256 in Montgomery form AND store (fused)
    // Uses scale_store_4x! macro for clean 4x unrolled code
    // =========================================================================
    let f_vec = vdupq_n_s32(F);
    let f_shoup = vdupq_n_s32(super::consts::F_SHOUP);

    let mut i = 0;
    while i < VECS_PER_POLY {
        scale_store_4x!(coeffs, v, i, f_vec, f_shoup, fqmul_shoup_neon);
        i += 4;
    }
}

// ============================================================================
// Pointwise Multiplication in NTT Domain
// ============================================================================

/// Pointwise multiplication of two polynomials in NTT domain
///
/// Computes c[i] = a[i] * b[i] (Montgomery) for all coefficients.
/// OPTIMIZED: 4x unrolling for better ILP and memory bandwidth utilization.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn ntt_multiply(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    // 4x unrolled loop for maximum throughput
    let mut i = 0;
    while i < VECS_PER_POLY {
        // Load 4 vectors from each input (16 coefficients)
        let a0 = vld1q_s32(a.as_ptr().add(i * 4));
        let a1 = vld1q_s32(a.as_ptr().add((i + 1) * 4));
        let a2 = vld1q_s32(a.as_ptr().add((i + 2) * 4));
        let a3 = vld1q_s32(a.as_ptr().add((i + 3) * 4));

        let b0 = vld1q_s32(b.as_ptr().add(i * 4));
        let b1 = vld1q_s32(b.as_ptr().add((i + 1) * 4));
        let b2 = vld1q_s32(b.as_ptr().add((i + 2) * 4));
        let b3 = vld1q_s32(b.as_ptr().add((i + 3) * 4));

        // Compute 4 multiplications (can execute in parallel)
        let c0 = fqmul_neon(a0, b0);
        let c1 = fqmul_neon(a1, b1);
        let c2 = fqmul_neon(a2, b2);
        let c3 = fqmul_neon(a3, b3);

        // Store results
        vst1q_s32(c.as_mut_ptr().add(i * 4), c0);
        vst1q_s32(c.as_mut_ptr().add((i + 1) * 4), c1);
        vst1q_s32(c.as_mut_ptr().add((i + 2) * 4), c2);
        vst1q_s32(c.as_mut_ptr().add((i + 3) * 4), c3);

        i += 4;
    }
}

/// Pointwise multiply-accumulate: c += a * b (Montgomery)
/// OPTIMIZED: 4x unrolling for better ILP.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn ntt_multiply_add(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    // 4x unrolled for maximum throughput
    let mut i = 0;
    while i < VECS_PER_POLY {
        // Load from all three arrays
        let a0 = vld1q_s32(a.as_ptr().add(i * 4));
        let a1 = vld1q_s32(a.as_ptr().add((i + 1) * 4));
        let a2 = vld1q_s32(a.as_ptr().add((i + 2) * 4));
        let a3 = vld1q_s32(a.as_ptr().add((i + 3) * 4));

        let b0 = vld1q_s32(b.as_ptr().add(i * 4));
        let b1 = vld1q_s32(b.as_ptr().add((i + 1) * 4));
        let b2 = vld1q_s32(b.as_ptr().add((i + 2) * 4));
        let b3 = vld1q_s32(b.as_ptr().add((i + 3) * 4));

        let c0 = vld1q_s32(c.as_ptr().add(i * 4));
        let c1 = vld1q_s32(c.as_ptr().add((i + 1) * 4));
        let c2 = vld1q_s32(c.as_ptr().add((i + 2) * 4));
        let c3 = vld1q_s32(c.as_ptr().add((i + 3) * 4));

        // Multiply and accumulate
        let r0 = vaddq_s32(c0, fqmul_neon(a0, b0));
        let r1 = vaddq_s32(c1, fqmul_neon(a1, b1));
        let r2 = vaddq_s32(c2, fqmul_neon(a2, b2));
        let r3 = vaddq_s32(c3, fqmul_neon(a3, b3));

        // Store results
        vst1q_s32(c.as_mut_ptr().add(i * 4), r0);
        vst1q_s32(c.as_mut_ptr().add((i + 1) * 4), r1);
        vst1q_s32(c.as_mut_ptr().add((i + 2) * 4), r2);
        vst1q_s32(c.as_mut_ptr().add((i + 3) * 4), r3);

        i += 4;
    }
}

// ============================================================================
// Public API Aliases
// ============================================================================

/// Forward NTT - alias for consistent naming across modules
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
pub unsafe fn ntt_neon(coeffs: &mut [i32; N]) {
    ntt(coeffs);
}

/// Inverse NTT - alias for consistent naming across modules
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
pub unsafe fn inv_ntt_neon(coeffs: &mut [i32; N]) {
    invntt(coeffs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_ntt_invntt_roundtrip() {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = (i as i32 * 1234) % Q;
        }
        let original = coeffs;

        unsafe {
            ntt(&mut coeffs);
            invntt(&mut coeffs);
        }

        // Check roundtrip (values should match after reducing)
        for i in 0..N {
            let expected = original[i];
            let mut got = coeffs[i];
            // Normalize to [0, Q)
            while got < 0 {
                got += Q;
            }
            while got >= Q {
                got -= Q;
            }
            // Allow for Montgomery domain differences
            let diff = (expected - got).abs();
            assert!(diff == 0 || diff == Q, "Mismatch at {}: expected {}, got {}", i, expected, got);
        }
    }
}
