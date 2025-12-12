//! ARM NEON Modular Arithmetic Primitives
//!
//! This module implements highly-optimized modular arithmetic operations
//! using ARM NEON SIMD intrinsics. All operations process 8 i16 coefficients
//! in parallel using 128-bit vector registers.
//!
//! # Key Operations
//!
//! - **Montgomery Reduction**: O(1) modular reduction using Seiler's technique
//! - **Montgomery Multiplication**: Fused multiply + reduce
//! - **Barrett Reduction**: Fast approximate reduction for coefficient normalization
//! - **Conditional Subtraction**: Branchless reduction to [0, q)
//!
//! # NEON vs AVX2
//!
//! - NEON uses 128-bit vectors (8 x i16) vs AVX2's 256-bit (16 x i16)
//! - NEON has different multiply-high instruction semantics
//! - ARM has better branch prediction, but we still use branchless for CT
//!
//! # Performance Characteristics
//!
//! | Operation | Cycles (typical) | Throughput |
//! |-----------|-----------------|------------|
//! | Montgomery mul | ~8 | 1 coeff/cycle |
//! | Barrett reduce | ~4 | 2 coeffs/cycle |
//! | Add/Sub | ~1 | 8 coeffs/cycle |
//!
//! # Mathematical Background
//!
//! Montgomery representation: a' = a * R mod q where R = 2^16
//!
//! Montgomery multiplication: MontyMul(a', b') = a' * b' * R^-1 mod q = (a*b) * R mod q

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

#[cfg(target_arch = "arm")]
use core::arch::arm::*;

use super::consts::{Q, QINV, BARRETT_V};

// ============================================================================
// Montgomery Arithmetic
// ============================================================================

/// Montgomery reduction for 8 coefficients (NEON)
///
/// Computes a * R^-1 mod q where R = 2^16
///
/// # Algorithm (Seiler's modified Montgomery)
///
/// For each 32-bit input a:
/// 1. t = a_lo * QINV (mod 2^16)
/// 2. result = (a - t * q) >> 16 = a_hi - (t * q)_hi
///
/// # Input Range
/// a must be in range [-q * 2^15, q * 2^15] for correct results
///
/// # Output Range
/// Result is in range [-q, q]
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn montgomery_reduce(a_lo: int16x8_t, a_hi: int16x8_t) -> int16x8_t {
    let q_vec = vdupq_n_s16(Q);
    let qinv_vec = vdupq_n_s16(QINV);

    // t = a_lo * QINV (only low 16 bits matter)
    let t = vmulq_s16(a_lo, qinv_vec);

    // (t * q)_hi - using NEON's vqdmulhq_s16 would double, so we use different approach
    // Compute t * q as widening multiply, then take high part
    let t_lo = vget_low_s16(t);
    let t_hi = vget_high_s16(t);
    let q_lo = vget_low_s16(q_vec);
    let q_hi = vget_high_s16(q_vec);

    // Widening multiply: t * q (32-bit result)
    let tq_lo = vmull_s16(t_lo, q_lo);
    let tq_hi = vmull_s16(t_hi, q_hi);

    // Extract high 16 bits (shift right by 16)
    let tq_hi_lo = vshrn_n_s32(tq_lo, 16);
    let tq_hi_hi = vshrn_n_s32(tq_hi, 16);
    let tq_high = vcombine_s16(tq_hi_lo, tq_hi_hi);

    // result = a_hi - tq_high
    vsubq_s16(a_hi, tq_high)
}

/// Montgomery multiplication for 8 coefficient pairs (NEON)
///
/// Computes (a * b * R^-1) mod q for 8 coefficient pairs simultaneously.
/// This is the core operation for NTT butterfly multiplications.
///
/// # Algorithm
///
/// 1. Compute 32-bit products a * b (split into low and high halves)
/// 2. Apply Montgomery reduction to get result in [-q, q]
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn montgomery_mul(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    let q_vec = vdupq_n_s16(Q);
    let qinv_vec = vdupq_n_s16(QINV);

    // Split into low and high halves for widening multiply
    let a_lo = vget_low_s16(a);
    let a_hi = vget_high_s16(a);
    let b_lo = vget_low_s16(b);
    let b_hi = vget_high_s16(b);

    // Widening multiply: a * b (32-bit products)
    let ab_lo_32 = vmull_s16(a_lo, b_lo);  // 4 x i32
    let ab_hi_32 = vmull_s16(a_hi, b_hi);  // 4 x i32

    // Extract low 16 bits (for Montgomery quotient)
    let ab_lo_16_lo = vmovn_s32(ab_lo_32);  // 4 x i16
    let ab_lo_16_hi = vmovn_s32(ab_hi_32);  // 4 x i16
    let ab_lo = vcombine_s16(ab_lo_16_lo, ab_lo_16_hi);

    // Extract high 16 bits
    let ab_hi_16_lo = vshrn_n_s32(ab_lo_32, 16);  // 4 x i16
    let ab_hi_16_hi = vshrn_n_s32(ab_hi_32, 16);  // 4 x i16
    let ab_hi = vcombine_s16(ab_hi_16_lo, ab_hi_16_hi);

    // Montgomery reduction
    // t = ab_lo * QINV (mod 2^16)
    let t = vmulq_s16(ab_lo, qinv_vec);

    // (t * q)_hi
    let t_lo = vget_low_s16(t);
    let t_hi = vget_high_s16(t);
    let q_lo = vget_low_s16(q_vec);
    let q_hi = vget_high_s16(q_vec);

    let tq_lo_32 = vmull_s16(t_lo, q_lo);
    let tq_hi_32 = vmull_s16(t_hi, q_hi);

    let tq_hi_lo = vshrn_n_s32(tq_lo_32, 16);
    let tq_hi_hi = vshrn_n_s32(tq_hi_32, 16);
    let tq_high = vcombine_s16(tq_hi_lo, tq_hi_hi);

    // result = ab_hi - tq_high
    vsubq_s16(ab_hi, tq_high)
}

/// Fused multiply-add with Montgomery reduction
///
/// Computes acc + (a * b * R^-1) mod q for 8 coefficients.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn montgomery_mul_add(a: int16x8_t, b: int16x8_t, acc: int16x8_t) -> int16x8_t {
    let product = montgomery_mul(a, b);
    vaddq_s16(acc, product)
}

// ============================================================================
// Optimized fqmulprecomp (3-multiply Montgomery)
// ============================================================================

/// Optimized Montgomery multiplication with precomputed twiddle factor
///
/// Uses only 3 multiplications instead of 4 by precomputing:
/// - zl = zeta * QINV mod 2^16
/// - zh = zeta
///
/// # Algorithm
///
/// Standard Montgomery: result = (coeff * zeta * R^-1) mod q
/// 1. x = coeff * zl (mod 2^16)  -- this is coeff * zeta * QINV mod R
/// 2. b = (coeff * zh) >> 16     -- high half of coeff * zeta
/// 3. x = (x * Q) >> 16          -- high half of x * Q
/// 4. result = b - x
///
/// # Performance
///
/// Saves one widening multiply compared to standard Montgomery:
/// - Standard: 4 multiplies (a*b for lo+hi, ab_lo*QINV, t*q)
/// - Precomp: 3 multiplies (coeff*zl, coeff*zh, x*q)
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn fqmulprecomp(coeff: int16x8_t, zl: int16x8_t, zh: int16x8_t) -> int16x8_t {
    let q_vec = vdupq_n_s16(Q);

    // Step 1: x = coeff * zl (mod 2^16) - only low bits needed
    let x = vmulq_s16(coeff, zl);

    // Step 2: b = (coeff * zh) >> 16 - need high 16 bits
    let coeff_lo = vget_low_s16(coeff);
    let coeff_hi = vget_high_s16(coeff);
    let zh_lo = vget_low_s16(zh);
    let zh_hi = vget_high_s16(zh);

    let prod_lo = vmull_s16(coeff_lo, zh_lo);
    let prod_hi = vmull_s16(coeff_hi, zh_hi);

    let b_lo = vshrn_n_s32(prod_lo, 16);
    let b_hi = vshrn_n_s32(prod_hi, 16);
    let b = vcombine_s16(b_lo, b_hi);

    // Step 3: x = (x * Q) >> 16 - need high 16 bits
    let x_lo = vget_low_s16(x);
    let x_hi = vget_high_s16(x);
    let q_lo = vget_low_s16(q_vec);
    let q_hi = vget_high_s16(q_vec);

    let xq_lo = vmull_s16(x_lo, q_lo);
    let xq_hi = vmull_s16(x_hi, q_hi);

    let xq_high_lo = vshrn_n_s32(xq_lo, 16);
    let xq_high_hi = vshrn_n_s32(xq_hi, 16);
    let xq_high = vcombine_s16(xq_high_lo, xq_high_hi);

    // Step 4: result = b - xq_high
    vsubq_s16(b, xq_high)
}

/// fqmulprecomp with pre-loaded Q vector
///
/// Optimized version that takes pre-loaded Q vector to avoid
/// redundant broadcasts in hot NTT loops.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn fqmulprecomp_preloaded(
    coeff: int16x8_t,
    zl: int16x8_t,
    zh: int16x8_t,
    q_vec: int16x8_t,
) -> int16x8_t {
    // Step 1: x = coeff * zl (mod 2^16)
    let x = vmulq_s16(coeff, zl);

    // Step 2: b = (coeff * zh) >> 16
    let coeff_lo = vget_low_s16(coeff);
    let coeff_hi = vget_high_s16(coeff);
    let zh_lo = vget_low_s16(zh);
    let zh_hi = vget_high_s16(zh);

    let prod_lo = vmull_s16(coeff_lo, zh_lo);
    let prod_hi = vmull_s16(coeff_hi, zh_hi);

    let b_lo = vshrn_n_s32(prod_lo, 16);
    let b_hi = vshrn_n_s32(prod_hi, 16);
    let b = vcombine_s16(b_lo, b_hi);

    // Step 3: x = (x * Q) >> 16
    let x_lo = vget_low_s16(x);
    let x_hi = vget_high_s16(x);
    let q_lo = vget_low_s16(q_vec);
    let q_hi = vget_high_s16(q_vec);

    let xq_lo = vmull_s16(x_lo, q_lo);
    let xq_hi = vmull_s16(x_hi, q_hi);

    let xq_high_lo = vshrn_n_s32(xq_lo, 16);
    let xq_high_hi = vshrn_n_s32(xq_hi, 16);
    let xq_high = vcombine_s16(xq_high_lo, xq_high_hi);

    // Step 4: result = b - xq_high
    vsubq_s16(b, xq_high)
}

/// Cooley-Tukey butterfly using fqmulprecomp (forward NTT)
///
/// Optimized butterfly that uses precomputed twiddle factors.
///
/// # Returns
/// (a', b') = (a + zeta*b, a - zeta*b)
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn butterfly_ct_precomp(
    a: int16x8_t,
    b: int16x8_t,
    zl: int16x8_t,
    zh: int16x8_t,
    q_vec: int16x8_t,
) -> (int16x8_t, int16x8_t) {
    let t = fqmulprecomp_preloaded(b, zl, zh, q_vec);
    let a_new = vaddq_s16(a, t);
    let b_new = vsubq_s16(a, t);
    (a_new, b_new)
}

/// Montgomery multiplication with pre-loaded constants
///
/// Optimized version that takes pre-loaded q and qinv vectors
/// to avoid redundant broadcasts in hot loops.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn montgomery_mul_preloaded(
    a: int16x8_t,
    b: int16x8_t,
    q_vec: int16x8_t,
    qinv_vec: int16x8_t,
) -> int16x8_t {
    // Split into low and high halves for widening multiply
    let a_lo = vget_low_s16(a);
    let a_hi = vget_high_s16(a);
    let b_lo = vget_low_s16(b);
    let b_hi = vget_high_s16(b);

    // Widening multiply
    let ab_lo_32 = vmull_s16(a_lo, b_lo);
    let ab_hi_32 = vmull_s16(a_hi, b_hi);

    // Extract low 16 bits
    let ab_lo_16_lo = vmovn_s32(ab_lo_32);
    let ab_lo_16_hi = vmovn_s32(ab_hi_32);
    let ab_lo = vcombine_s16(ab_lo_16_lo, ab_lo_16_hi);

    // Extract high 16 bits
    let ab_hi_16_lo = vshrn_n_s32(ab_lo_32, 16);
    let ab_hi_16_hi = vshrn_n_s32(ab_hi_32, 16);
    let ab_hi = vcombine_s16(ab_hi_16_lo, ab_hi_16_hi);

    // Montgomery reduction
    let t = vmulq_s16(ab_lo, qinv_vec);

    let t_lo = vget_low_s16(t);
    let t_hi = vget_high_s16(t);
    let q_lo = vget_low_s16(q_vec);
    let q_hi = vget_high_s16(q_vec);

    let tq_lo_32 = vmull_s16(t_lo, q_lo);
    let tq_hi_32 = vmull_s16(t_hi, q_hi);

    let tq_hi_lo = vshrn_n_s32(tq_lo_32, 16);
    let tq_hi_hi = vshrn_n_s32(tq_hi_32, 16);
    let tq_high = vcombine_s16(tq_hi_lo, tq_hi_hi);

    vsubq_s16(ab_hi, tq_high)
}

// ============================================================================
// Barrett Reduction
// ============================================================================

/// Barrett reduction for 8 coefficients
///
/// Reduces coefficients to approximately [-q, q] range.
/// Uses the formula: r = a - ⌊a * v / 2^26⌋ * q
///
/// # Input Range
/// Works correctly for a in range [-2^15, 2^15]
///
/// # Output Range
/// Result is approximately in range [-q, 2q], but typically [-q, q]
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn barrett_reduce(a: int16x8_t) -> int16x8_t {
    let q_vec = vdupq_n_s16(Q);
    let v_vec = vdupq_n_s16(BARRETT_V);

    // t = (a * v) >> 16 (using high multiply)
    // Note: NEON's vqdmulhq_s16 doubles, so we need different approach
    let a_lo = vget_low_s16(a);
    let a_hi = vget_high_s16(a);
    let v_lo = vget_low_s16(v_vec);
    let v_hi = vget_high_s16(v_vec);

    let av_lo = vmull_s16(a_lo, v_lo);  // 4 x i32
    let av_hi = vmull_s16(a_hi, v_hi);  // 4 x i32

    // Shift right by 26 (16 from narrowing + 10 additional)
    // First narrow by 16, then shift by 10
    let av_hi_16_lo = vshrn_n_s32(av_lo, 16);
    let av_hi_16_hi = vshrn_n_s32(av_hi, 16);
    let av_hi_16 = vcombine_s16(av_hi_16_lo, av_hi_16_hi);

    // Shift right by 10 more
    let t = vshrq_n_s16(av_hi_16, 10);

    // r = a - t * q
    let tq = vmulq_s16(t, q_vec);
    vsubq_s16(a, tq)
}

/// Barrett reduction with pre-loaded constants
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn barrett_reduce_preloaded(
    a: int16x8_t,
    q_vec: int16x8_t,
    v_vec: int16x8_t,
) -> int16x8_t {
    let a_lo = vget_low_s16(a);
    let a_hi = vget_high_s16(a);
    let v_lo = vget_low_s16(v_vec);
    let v_hi = vget_high_s16(v_vec);

    let av_lo = vmull_s16(a_lo, v_lo);
    let av_hi = vmull_s16(a_hi, v_hi);

    let av_hi_16_lo = vshrn_n_s32(av_lo, 16);
    let av_hi_16_hi = vshrn_n_s32(av_hi, 16);
    let av_hi_16 = vcombine_s16(av_hi_16_lo, av_hi_16_hi);

    let t = vshrq_n_s16(av_hi_16, 10);
    let tq = vmulq_s16(t, q_vec);
    vsubq_s16(a, tq)
}

// ============================================================================
// Conditional Operations (Constant-Time)
// ============================================================================

/// Conditionally subtract q (constant-time)
///
/// If a >= q, returns a - q; otherwise returns a.
/// Used for final normalization to [0, q) range.
///
/// # Algorithm (branchless)
/// 1. Compute a - q
/// 2. If original a < q, the result would be negative
/// 3. Use sign bit to create mask
/// 4. Blend original and subtracted values based on mask
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn conditional_sub_q(a: int16x8_t) -> int16x8_t {
    let q_vec = vdupq_n_s16(Q);

    // Compute a - q
    let a_minus_q = vsubq_s16(a, q_vec);

    // Create mask: 0xFFFF if a < q (a - q is negative), 0x0000 otherwise
    // Arithmetic right shift by 15 propagates sign bit
    let mask = vshrq_n_s16(a_minus_q, 15);

    // result = (a & mask) | (a_minus_q & ~mask)
    // Using: result = a_minus_q + (a - a_minus_q) & mask = a_minus_q + q & mask
    // Simplified: select a if mask=-1, else a_minus_q
    let q_masked = vandq_s16(mask, q_vec);
    vaddq_s16(a_minus_q, q_masked)
}

/// Conditionally add q (constant-time)
///
/// If a < 0, returns a + q; otherwise returns a.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn conditional_add_q(a: int16x8_t) -> int16x8_t {
    let q_vec = vdupq_n_s16(Q);

    // Create mask from sign bit: 0xFFFF if negative, 0x0000 if non-negative
    let mask = vshrq_n_s16(a, 15);

    // Add q if negative
    let q_masked = vandq_s16(mask, q_vec);
    vaddq_s16(a, q_masked)
}

/// Full normalization to [0, q) range (constant-time)
///
/// Handles both negative values and values >= q.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn normalize_to_positive(a: int16x8_t) -> int16x8_t {
    let a = conditional_add_q(a);
    conditional_sub_q(a)
}

// ============================================================================
// Vector Arithmetic Operations
// ============================================================================

/// Add two vectors of 8 coefficients
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn add(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    vaddq_s16(a, b)
}

/// Subtract two vectors of 8 coefficients
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn sub(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    vsubq_s16(a, b)
}

/// Add with Barrett reduction
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn add_reduce(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    let sum = vaddq_s16(a, b);
    barrett_reduce(sum)
}

/// Subtract with Barrett reduction
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn sub_reduce(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    let diff = vsubq_s16(a, b);
    barrett_reduce(diff)
}

/// Negate a vector of coefficients
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn negate(a: int16x8_t) -> int16x8_t {
    vnegq_s16(a)
}

// ============================================================================
// Butterfly Operations for NTT
// ============================================================================

/// Cooley-Tukey butterfly operation (forward NTT)
///
/// Computes:
/// - a' = a + t where t = zeta * b
/// - b' = a - t
///
/// # Returns
/// (a', b') = (a + zeta*b, a - zeta*b)
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn butterfly_ct(
    a: int16x8_t,
    b: int16x8_t,
    zeta: int16x8_t,
) -> (int16x8_t, int16x8_t) {
    let t = montgomery_mul(zeta, b);
    let a_new = vaddq_s16(a, t);
    let b_new = vsubq_s16(a, t);
    (a_new, b_new)
}

/// Gentleman-Sande butterfly operation (inverse NTT)
///
/// Computes:
/// - a' = a + b (with Barrett reduction)
/// - b' = (a - b) * zeta
///
/// # Returns
/// (a', b') = (a + b, (a - b) * zeta)
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn butterfly_gs(
    a: int16x8_t,
    b: int16x8_t,
    zeta: int16x8_t,
) -> (int16x8_t, int16x8_t) {
    let a_new = barrett_reduce(vaddq_s16(a, b));
    let diff = vsubq_s16(b, a);  // Note: b - a for correct sign
    let b_new = montgomery_mul(zeta, diff);
    (a_new, b_new)
}

/// Lazy Gentleman-Sande butterfly (no reduction on sum)
///
/// Used in lazy INTT where reduction is deferred.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn butterfly_gs_lazy(
    a: int16x8_t,
    b: int16x8_t,
    zeta: int16x8_t,
) -> (int16x8_t, int16x8_t) {
    let a_new = vaddq_s16(a, b);  // No reduction
    let diff = vsubq_s16(b, a);
    let b_new = montgomery_mul(zeta, diff);
    (a_new, b_new)
}

/// Cooley-Tukey butterfly with pre-loaded constants
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn butterfly_ct_preloaded(
    a: int16x8_t,
    b: int16x8_t,
    zeta: int16x8_t,
    q_vec: int16x8_t,
    qinv_vec: int16x8_t,
) -> (int16x8_t, int16x8_t) {
    let t = montgomery_mul_preloaded(zeta, b, q_vec, qinv_vec);
    let a_new = vaddq_s16(a, t);
    let b_new = vsubq_s16(a, t);
    (a_new, b_new)
}

// ============================================================================
// Specialized Operations
// ============================================================================

/// Multiply by constant F (INTT scaling factor)
///
/// Used in the final step of inverse NTT to scale by n^-1 in Montgomery form.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn mul_f(a: int16x8_t) -> int16x8_t {
    let f_vec = vdupq_n_s16(super::consts::F);
    montgomery_mul(a, f_vec)
}

/// Convert from Montgomery form to normal form
///
/// Multiplies by 1 in Montgomery domain, which is equivalent to
/// multiplying by R^-1 mod q.
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn from_montgomery(a: int16x8_t) -> int16x8_t {
    let one = vdupq_n_s16(1);
    montgomery_mul(a, one)
}

/// Reduce all 256 coefficients in a polynomial
///
/// Applies Barrett reduction to bring all coefficients to approximately [-q, q].
///
/// # Safety
/// Requires NEON support
#[inline]
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn reduce_poly(coeffs: &mut [i16; 256]) {
    let q_vec = vdupq_n_s16(Q);
    let v_vec = vdupq_n_s16(BARRETT_V);

    // Process 8 coefficients at a time (32 iterations for 256 coefficients)
    for i in 0..32 {
        let offset = i * 8;
        let a = vld1q_s16(coeffs[offset..].as_ptr());
        let r = barrett_reduce_preloaded(a, q_vec, v_vec);
        vst1q_s16(coeffs[offset..].as_mut_ptr(), r);
    }
}

#[cfg(test)]
mod tests {
    // Tests would go here, but require ARM target to run
}
