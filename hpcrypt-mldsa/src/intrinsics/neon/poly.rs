//! ARM NEON Polynomial Operations - Faster Functions Only
//!
//! This module contains only the NEON polynomial operations that have been
//! benchmarked to be FASTER than their portable counterparts on ARM Neoverse-N1.
//!
//! # Benchmark Results (ARM Neoverse-N1)
//!
//! Functions included (all faster with NEON):
//! - pointwise_montgomery: ~2x faster
//! - infinity_norm variants: faster
//! - infinity_norm_threshold: ~3.65x faster (with early exit)
//!
//! Functions NOT included (slower than portable):
//! - poly_add: 1.70x slower (use scalar instead)
//! - poly_sub: 1.69x slower (use scalar instead)
//! - poly_reduce: 1.26x slower (use scalar instead)

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::consts::{Q, N, VECS_PER_POLY};
use super::reduce::fqmul_neon;

// ============================================================================
// Pointwise Montgomery Multiplication - ~2x FASTER than portable
// ============================================================================

/// Pointwise multiply: c = a * b (Montgomery domain)
/// OPTIMIZED: 4x unrolled using macro
///
/// # Performance (ARM Neoverse-N1)
/// ~2x faster than portable implementation.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_pointwise_montgomery(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    unroll_4x_binary!(a, b, c, fqmul_neon);
}

// ============================================================================
// Infinity Norm - FASTER than portable
// ============================================================================

/// Compute infinity norm (max absolute value) of polynomial
/// OPTIMIZED: 4x unrolled with proper NEON absolute value
///
/// For coefficients in [-Q/2, Q/2), returns max|a[i]|
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_infinity_norm(a: &[i32; N]) -> i32 {
    let mut max_vec = vdupq_n_s32(0);

    let mut i = 0;
    while i < VECS_PER_POLY {
        // Load 4 vectors
        let v0 = vld1q_s32(a.as_ptr().add(i * 4));
        let v1 = vld1q_s32(a.as_ptr().add((i + 1) * 4));
        let v2 = vld1q_s32(a.as_ptr().add((i + 2) * 4));
        let v3 = vld1q_s32(a.as_ptr().add((i + 3) * 4));

        // Compute absolute values using vabsq_s32
        let abs0 = vabsq_s32(v0);
        let abs1 = vabsq_s32(v1);
        let abs2 = vabsq_s32(v2);
        let abs3 = vabsq_s32(v3);

        // Update running maximum (tree reduction for better ILP)
        let max01 = vmaxq_s32(abs0, abs1);
        let max23 = vmaxq_s32(abs2, abs3);
        let max0123 = vmaxq_s32(max01, max23);
        max_vec = vmaxq_s32(max_vec, max0123);

        i += 4;
    }

    // Horizontal max reduction
    let max_low = vget_low_s32(max_vec);
    let max_high = vget_high_s32(max_vec);
    let max_pair = vmax_s32(max_low, max_high);
    let a0 = vget_lane_s32(max_pair, 0);
    let a1 = vget_lane_s32(max_pair, 1);

    if a0 > a1 { a0 } else { a1 }
}

/// Compute infinity norm with centering (for coefficients in [0, Q))
/// OPTIMIZED: 4x unrolled with tree reduction
///
/// For coefficients in [0, Q), first center to [-Q/2, Q/2) then compute max|a[i]|.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_infinity_norm_centered(a: &[i32; N]) -> i32 {
    let q_vec = vdupq_n_s32(Q);
    let q_half = vdupq_n_s32((Q - 1) / 2);
    let mut max_vec = vdupq_n_s32(0);

    let mut i = 0;
    while i < VECS_PER_POLY {
        // Load 4 vectors
        let v0 = vld1q_s32(a.as_ptr().add(i * 4));
        let v1 = vld1q_s32(a.as_ptr().add((i + 1) * 4));
        let v2 = vld1q_s32(a.as_ptr().add((i + 2) * 4));
        let v3 = vld1q_s32(a.as_ptr().add((i + 3) * 4));

        // Center: if v > Q/2, v -= Q
        let mask0 = vcgtq_s32(v0, q_half);
        let mask1 = vcgtq_s32(v1, q_half);
        let mask2 = vcgtq_s32(v2, q_half);
        let mask3 = vcgtq_s32(v3, q_half);

        let c0 = vsubq_s32(v0, vandq_s32(vreinterpretq_s32_u32(mask0), q_vec));
        let c1 = vsubq_s32(v1, vandq_s32(vreinterpretq_s32_u32(mask1), q_vec));
        let c2 = vsubq_s32(v2, vandq_s32(vreinterpretq_s32_u32(mask2), q_vec));
        let c3 = vsubq_s32(v3, vandq_s32(vreinterpretq_s32_u32(mask3), q_vec));

        // Absolute values
        let abs0 = vabsq_s32(c0);
        let abs1 = vabsq_s32(c1);
        let abs2 = vabsq_s32(c2);
        let abs3 = vabsq_s32(c3);

        // Tree reduction for max
        let max01 = vmaxq_s32(abs0, abs1);
        let max23 = vmaxq_s32(abs2, abs3);
        let max0123 = vmaxq_s32(max01, max23);
        max_vec = vmaxq_s32(max_vec, max0123);

        i += 4;
    }

    // Horizontal max
    let max_low = vget_low_s32(max_vec);
    let max_high = vget_high_s32(max_vec);
    let max_pair = vmax_s32(max_low, max_high);
    let a0 = vget_lane_s32(max_pair, 0);
    let a1 = vget_lane_s32(max_pair, 1);

    if a0 > a1 { a0 } else { a1 }
}

// ============================================================================
// Infinity Norm with Threshold - ~3.65x FASTER than portable (with early exit)
// ============================================================================

/// Check norm with centering (for coefficients in [0, Q))
/// OPTIMIZED: 4x unrolled with early termination
///
/// Returns true if any |a[i]| >= threshold
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_chknorm_centered(a: &[i32; N], threshold: i32) -> bool {
    let q_vec = vdupq_n_s32(Q);
    let q_half = vdupq_n_s32((Q - 1) / 2);
    let thresh_vec = vdupq_n_s32(threshold);
    let neg_thresh = vdupq_n_s32(-threshold);

    let mut i = 0;
    while i < VECS_PER_POLY {
        // Load 4 vectors
        let v0 = vld1q_s32(a.as_ptr().add(i * 4));
        let v1 = vld1q_s32(a.as_ptr().add((i + 1) * 4));
        let v2 = vld1q_s32(a.as_ptr().add((i + 2) * 4));
        let v3 = vld1q_s32(a.as_ptr().add((i + 3) * 4));

        // Center: if v > Q/2, v -= Q
        let mask0 = vcgtq_s32(v0, q_half);
        let mask1 = vcgtq_s32(v1, q_half);
        let mask2 = vcgtq_s32(v2, q_half);
        let mask3 = vcgtq_s32(v3, q_half);

        let c0 = vsubq_s32(v0, vandq_s32(vreinterpretq_s32_u32(mask0), q_vec));
        let c1 = vsubq_s32(v1, vandq_s32(vreinterpretq_s32_u32(mask1), q_vec));
        let c2 = vsubq_s32(v2, vandq_s32(vreinterpretq_s32_u32(mask2), q_vec));
        let c3 = vsubq_s32(v3, vandq_s32(vreinterpretq_s32_u32(mask3), q_vec));

        // Check bounds
        let fail0 = vorrq_u32(vcgeq_s32(c0, thresh_vec), vcltq_s32(c0, neg_thresh));
        let fail1 = vorrq_u32(vcgeq_s32(c1, thresh_vec), vcltq_s32(c1, neg_thresh));
        let fail2 = vorrq_u32(vcgeq_s32(c2, thresh_vec), vcltq_s32(c2, neg_thresh));
        let fail3 = vorrq_u32(vcgeq_s32(c3, thresh_vec), vcltq_s32(c3, neg_thresh));

        // Combine and check
        let fail01 = vorrq_u32(fail0, fail1);
        let fail23 = vorrq_u32(fail2, fail3);
        let fail_all = vorrq_u32(fail01, fail23);

        if vmaxvq_u32(fail_all) != 0 {
            return true;
        }

        i += 4;
    }

    false
}

/// Compute infinity norm with early exit if threshold exceeded
/// OPTIMIZED: 4x unrolled with early termination + running max
///
/// Returns Some(norm) if all |a[i]| < threshold, None otherwise (early exit).
/// This is optimized for rejection sampling where most attempts fail early.
///
/// For coefficients already in centered representation [-Q/2, Q/2).
///
/// # Performance (ARM Neoverse-N1)
/// ~3.65x faster than portable (63ns vs 230ns when passing)
/// ~2.97x faster on early exit (3.7ns vs 11ns when failing)
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_infinity_norm_threshold(a: &[i32; N], threshold: i32) -> Option<i32> {
    let thresh_vec = vdupq_n_s32(threshold);
    let neg_thresh = vdupq_n_s32(-threshold);
    let mut max_vec = vdupq_n_s32(0);

    let mut i = 0;
    while i < VECS_PER_POLY {
        // Load 4 vectors
        let v0 = vld1q_s32(a.as_ptr().add(i * 4));
        let v1 = vld1q_s32(a.as_ptr().add((i + 1) * 4));
        let v2 = vld1q_s32(a.as_ptr().add((i + 2) * 4));
        let v3 = vld1q_s32(a.as_ptr().add((i + 3) * 4));

        // Early exit check: if any |v[i]| >= threshold
        let fail0 = vorrq_u32(vcgeq_s32(v0, thresh_vec), vcltq_s32(v0, neg_thresh));
        let fail1 = vorrq_u32(vcgeq_s32(v1, thresh_vec), vcltq_s32(v1, neg_thresh));
        let fail2 = vorrq_u32(vcgeq_s32(v2, thresh_vec), vcltq_s32(v2, neg_thresh));
        let fail3 = vorrq_u32(vcgeq_s32(v3, thresh_vec), vcltq_s32(v3, neg_thresh));

        let fail01 = vorrq_u32(fail0, fail1);
        let fail23 = vorrq_u32(fail2, fail3);
        let fail_all = vorrq_u32(fail01, fail23);

        if vmaxvq_u32(fail_all) != 0 {
            return None; // Early exit - threshold exceeded
        }

        // Compute absolute values and track max
        let abs0 = vabsq_s32(v0);
        let abs1 = vabsq_s32(v1);
        let abs2 = vabsq_s32(v2);
        let abs3 = vabsq_s32(v3);

        let max01 = vmaxq_s32(abs0, abs1);
        let max23 = vmaxq_s32(abs2, abs3);
        let max0123 = vmaxq_s32(max01, max23);
        max_vec = vmaxq_s32(max_vec, max0123);

        i += 4;
    }

    // Horizontal max reduction
    let max_low = vget_low_s32(max_vec);
    let max_high = vget_high_s32(max_vec);
    let max_pair = vmax_s32(max_low, max_high);
    let a0 = vget_lane_s32(max_pair, 0);
    let a1 = vget_lane_s32(max_pair, 1);

    Some(if a0 > a1 { a0 } else { a1 })
}

/// Compute infinity norm with early exit if threshold exceeded (centered)
/// OPTIMIZED: 4x unrolled with early termination + running max
///
/// Returns Some(norm) if all coefficients pass, None otherwise (early exit).
/// For coefficients in [0, Q) - centers them first.
///
/// # Performance (ARM Neoverse-N1)
/// ~3.65x faster than portable implementation.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_infinity_norm_threshold_centered(a: &[i32; N], threshold: i32) -> Option<i32> {
    let q_vec = vdupq_n_s32(Q);
    let q_half = vdupq_n_s32((Q - 1) / 2);
    let thresh_vec = vdupq_n_s32(threshold);
    let neg_thresh = vdupq_n_s32(-threshold);
    let mut max_vec = vdupq_n_s32(0);

    let mut i = 0;
    while i < VECS_PER_POLY {
        // Load 4 vectors
        let v0 = vld1q_s32(a.as_ptr().add(i * 4));
        let v1 = vld1q_s32(a.as_ptr().add((i + 1) * 4));
        let v2 = vld1q_s32(a.as_ptr().add((i + 2) * 4));
        let v3 = vld1q_s32(a.as_ptr().add((i + 3) * 4));

        // Center: if v > Q/2, v -= Q
        let mask0 = vcgtq_s32(v0, q_half);
        let mask1 = vcgtq_s32(v1, q_half);
        let mask2 = vcgtq_s32(v2, q_half);
        let mask3 = vcgtq_s32(v3, q_half);

        let c0 = vsubq_s32(v0, vandq_s32(vreinterpretq_s32_u32(mask0), q_vec));
        let c1 = vsubq_s32(v1, vandq_s32(vreinterpretq_s32_u32(mask1), q_vec));
        let c2 = vsubq_s32(v2, vandq_s32(vreinterpretq_s32_u32(mask2), q_vec));
        let c3 = vsubq_s32(v3, vandq_s32(vreinterpretq_s32_u32(mask3), q_vec));

        // Early exit check
        let fail0 = vorrq_u32(vcgeq_s32(c0, thresh_vec), vcltq_s32(c0, neg_thresh));
        let fail1 = vorrq_u32(vcgeq_s32(c1, thresh_vec), vcltq_s32(c1, neg_thresh));
        let fail2 = vorrq_u32(vcgeq_s32(c2, thresh_vec), vcltq_s32(c2, neg_thresh));
        let fail3 = vorrq_u32(vcgeq_s32(c3, thresh_vec), vcltq_s32(c3, neg_thresh));

        let fail01 = vorrq_u32(fail0, fail1);
        let fail23 = vorrq_u32(fail2, fail3);
        let fail_all = vorrq_u32(fail01, fail23);

        if vmaxvq_u32(fail_all) != 0 {
            return None; // Early exit
        }

        // Track max (centered values)
        let abs0 = vabsq_s32(c0);
        let abs1 = vabsq_s32(c1);
        let abs2 = vabsq_s32(c2);
        let abs3 = vabsq_s32(c3);

        let max01 = vmaxq_s32(abs0, abs1);
        let max23 = vmaxq_s32(abs2, abs3);
        let max0123 = vmaxq_s32(max01, max23);
        max_vec = vmaxq_s32(max_vec, max0123);

        i += 4;
    }

    // Horizontal max
    let max_low = vget_low_s32(max_vec);
    let max_high = vget_high_s32(max_vec);
    let max_pair = vmax_s32(max_low, max_high);
    let a0 = vget_lane_s32(max_pair, 0);
    let a1 = vget_lane_s32(max_pair, 1);

    Some(if a0 > a1 { a0 } else { a1 })
}
