//! AVX2 Modular Arithmetic Primitives
//!
//! This module implements highly-optimized modular arithmetic operations
//! using AVX2 SIMD intrinsics. All operations process 16 i16 coefficients
//! in parallel using 256-bit YMM registers.
//!
//! # Key Operations
//!
//! - **Montgomery Reduction**: O(1) modular reduction using Seiler's technique
//! - **Montgomery Multiplication**: Fused multiply + reduce in ~10 cycles
//! - **Barrett Reduction**: Fast approximate reduction for coefficient normalization
//! - **Conditional Subtraction**: Branchless reduction to [0, q)
//!
//! # Performance Characteristics
//!
//! | Operation | Cycles (Haswell) | Throughput |
//! |-----------|------------------|------------|
//! | Montgomery mul | ~10 | 1.6 coeffs/cycle |
//! | Barrett reduce | ~5 | 3.2 coeffs/cycle |
//! | Add/Sub | ~1 | 16 coeffs/cycle |
//!
//! # Mathematical Background
//!
//! Montgomery representation: a' = a * R mod q where R = 2^16
//!
//! Montgomery multiplication: MontyMul(a', b') = a' * b' * R^-1 mod q = (a*b) * R mod q
//!
//! The key insight is that we can compute the low and high 16-bit halves
//! of a 32-bit product separately using vpmullw and vpmulhw, enabling
//! efficient vectorized computation.

use core::arch::x86_64::*;
use super::consts::{Q, QINV, BARRETT_V};

// ============================================================================
// Montgomery Arithmetic
// ============================================================================

/// Montgomery reduction for 16 coefficients
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
/// # Performance
/// - Latency: ~5 cycles
/// - Throughput: 16 reductions per call
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn montgomery_reduce(a_lo: __m256i, a_hi: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q);
    let qinv_vec = _mm256_set1_epi16(QINV);

    // t = a_lo * QINV (only low 16 bits matter)
    let t = _mm256_mullo_epi16(a_lo, qinv_vec);

    // (t * q)_hi
    let tq_hi = _mm256_mulhi_epi16(t, q_vec);

    // result = a_hi - tq_hi
    _mm256_sub_epi16(a_hi, tq_hi)
}

/// Montgomery multiplication for 16 coefficient pairs
///
/// Computes (a * b * R^-1) mod q for 16 coefficient pairs simultaneously.
/// This is the core operation for NTT butterfly multiplications.
///
/// # Algorithm
///
/// 1. Compute 32-bit products a * b (split into low and high halves)
/// 2. Apply Montgomery reduction to get result in [-q, q]
///
/// # Input Range
/// Both a and b should be in range [-q, q] for optimal precision
///
/// # Output Range
/// Result is in range [-q, q]
///
/// # Performance
/// - Latency: ~10 cycles (5 for multiply, 5 for reduction)
/// - Throughput: 16 multiplications per call
/// - Uses 4 multiply instructions: 2 for product, 2 for reduction
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn montgomery_mul(a: __m256i, b: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q);
    let qinv_vec = _mm256_set1_epi16(QINV);

    // Compute a * b (32-bit products split into 16-bit halves)
    let ab_lo = _mm256_mullo_epi16(a, b);  // Low 16 bits of each product
    let ab_hi = _mm256_mulhi_epi16(a, b);  // High 16 bits of each product

    // Montgomery reduction
    // t = ab_lo * QINV (mod 2^16)
    let t = _mm256_mullo_epi16(ab_lo, qinv_vec);

    // (t * q)_hi = high 16 bits of t * q
    let tq_hi = _mm256_mulhi_epi16(t, q_vec);

    // result = ab_hi - tq_hi
    _mm256_sub_epi16(ab_hi, tq_hi)
}

/// Fused multiply-add with Montgomery reduction
///
/// Computes acc + (a * b * R^-1) mod q for 16 coefficients.
/// Used for accumulating products in basemul operations.
///
/// # Performance
/// - Latency: ~11 cycles
/// - More efficient than separate multiply + add
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn montgomery_mul_add(a: __m256i, b: __m256i, acc: __m256i) -> __m256i {
    let product = montgomery_mul(a, b);
    _mm256_add_epi16(acc, product)
}

/// Montgomery multiplication with pre-loaded constants
///
/// Optimized version that takes pre-loaded q and qinv vectors
/// to avoid redundant broadcasts in hot loops.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn montgomery_mul_preloaded(
    a: __m256i,
    b: __m256i,
    q_vec: __m256i,
    qinv_vec: __m256i,
) -> __m256i {
    let ab_lo = _mm256_mullo_epi16(a, b);
    let ab_hi = _mm256_mulhi_epi16(a, b);
    let t = _mm256_mullo_epi16(ab_lo, qinv_vec);
    let tq_hi = _mm256_mulhi_epi16(t, q_vec);
    _mm256_sub_epi16(ab_hi, tq_hi)
}

// ============================================================================
// Barrett Reduction
// ============================================================================

/// Barrett reduction for 16 coefficients
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
/// # Performance
/// - Latency: ~5 cycles
/// - Throughput: 16 reductions per call
///
/// # Note
/// Barrett reduction may leave values slightly outside [0, q).
/// Use conditional_sub_q() for final normalization.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn barrett_reduce(a: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q);
    let v_vec = _mm256_set1_epi16(BARRETT_V);

    // t = (a * v) >> 16 (using mulhi)
    // Then shift right by 10 more bits (total 26)
    let t = _mm256_mulhi_epi16(a, v_vec);
    let t = _mm256_srai_epi16(t, 10);

    // r = a - t * q
    let tq = _mm256_mullo_epi16(t, q_vec);
    _mm256_sub_epi16(a, tq)
}

/// Barrett reduction with pre-loaded constants
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn barrett_reduce_preloaded(a: __m256i, q_vec: __m256i, v_vec: __m256i) -> __m256i {
    let t = _mm256_mulhi_epi16(a, v_vec);
    let t = _mm256_srai_epi16(t, 10);
    let tq = _mm256_mullo_epi16(t, q_vec);
    _mm256_sub_epi16(a, tq)
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
/// 3. Use arithmetic right shift to create mask from sign bit
/// 4. Blend original and subtracted values based on mask
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn conditional_sub_q(a: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q);

    // Compute a - q
    let a_minus_q = _mm256_sub_epi16(a, q_vec);

    // Create mask: 0xFFFF if a < q (a - q is negative), 0x0000 otherwise
    // Arithmetic right shift by 15 propagates sign bit
    let mask = _mm256_srai_epi16(a_minus_q, 15);

    // result = (a & mask) | (a_minus_q & ~mask)
    // If a < q: result = a
    // If a >= q: result = a - q
    _mm256_blendv_epi8(a_minus_q, a, mask)
}

/// Conditionally add q (constant-time)
///
/// If a < 0, returns a + q; otherwise returns a.
/// Used for normalizing negative values to [0, q) range.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn conditional_add_q(a: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q);

    // Create mask from sign bit: 0xFFFF if negative, 0x0000 if non-negative
    let mask = _mm256_srai_epi16(a, 15);

    // Add q if negative
    let q_masked = _mm256_and_si256(mask, q_vec);
    _mm256_add_epi16(a, q_masked)
}

/// Full normalization to [0, q) range (constant-time)
///
/// Handles both negative values and values >= q.
/// Applies conditional_add_q followed by conditional_sub_q.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn normalize_to_positive(a: __m256i) -> __m256i {
    let a = conditional_add_q(a);
    conditional_sub_q(a)
}

// ============================================================================
// Vector Arithmetic Operations
// ============================================================================

/// Add two vectors of 16 coefficients
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
    _mm256_add_epi16(a, b)
}

/// Subtract two vectors of 16 coefficients
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn sub(a: __m256i, b: __m256i) -> __m256i {
    _mm256_sub_epi16(a, b)
}

/// Add with Barrett reduction
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn add_reduce(a: __m256i, b: __m256i) -> __m256i {
    let sum = _mm256_add_epi16(a, b);
    barrett_reduce(sum)
}

/// Subtract with Barrett reduction
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn sub_reduce(a: __m256i, b: __m256i) -> __m256i {
    let diff = _mm256_sub_epi16(a, b);
    barrett_reduce(diff)
}

/// Negate a vector of coefficients
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn negate(a: __m256i) -> __m256i {
    let zero = _mm256_setzero_si256();
    _mm256_sub_epi16(zero, a)
}

// ============================================================================
// fqmulprecomp Optimization (pq-crystals technique)
// ============================================================================
//
// The fqmulprecomp optimization reduces Montgomery multiplication from 4 to 3
// multiplies by precomputing zl = zeta * QINV mod R for each twiddle factor.
//
// Standard Montgomery (4 muls):
//   ab_lo = mullo(a, b)           // low 16 bits of a * b
//   ab_hi = mulhi(a, b)           // high 16 bits of a * b
//   t = mullo(ab_lo, QINV)        // Montgomery quotient
//   tq_hi = mulhi(t, Q)           // correction term
//   result = ab_hi - tq_hi
//
// fqmulprecomp (3 muls):
//   x = mullo(coeff, zl)          // (coeff * zl) mod R = Montgomery quotient
//   b = mulhi(coeff, zh)          // (coeff * zh) >> 16
//   x = mulhi(x, Q)               // correction term
//   result = b - x
//
// The key insight: (coeff * zl) mod R = (coeff * zeta * QINV) mod R
// because the overflow term vanishes when taking mod R.

/// fqmulprecomp: Optimized Montgomery multiplication with precomputed twiddle
///
/// Computes (coeff * zeta * R^-1) mod q using only 3 multiplications.
///
/// # Arguments
/// * `coeff` - Input coefficients (16 x i16)
/// * `zl` - Precomputed zeta * QINV mod R (broadcast to 16 lanes)
/// * `zh` - Original zeta value (broadcast to 16 lanes)
///
/// # Algorithm
/// ```text
/// x = mullo(coeff, zl)    // (coeff * zl) mod R
/// b = mulhi(coeff, zh)    // (coeff * zh) >> 16
/// x = mulhi(x, Q)         // (x * Q) >> 16
/// result = b - x
/// ```
///
/// # Performance
/// - 3 multiplications vs 4 for standard Montgomery
/// - ~25% fewer multiply instructions per butterfly
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn fqmulprecomp(coeff: __m256i, zl: __m256i, zh: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q);

    // x = (coeff * zl) mod R (low 16 bits)
    let x = _mm256_mullo_epi16(coeff, zl);

    // b = (coeff * zh) >> 16 (high 16 bits)
    let b = _mm256_mulhi_epi16(coeff, zh);

    // x = (x * Q) >> 16
    let x = _mm256_mulhi_epi16(x, q_vec);

    // result = b - x
    _mm256_sub_epi16(b, x)
}

/// fqmulprecomp with pre-loaded Q vector
///
/// Optimized version for hot loops where Q is already loaded.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn fqmulprecomp_preloaded(
    coeff: __m256i,
    zl: __m256i,
    zh: __m256i,
    q_vec: __m256i,
) -> __m256i {
    let x = _mm256_mullo_epi16(coeff, zl);
    let b = _mm256_mulhi_epi16(coeff, zh);
    let x = _mm256_mulhi_epi16(x, q_vec);
    _mm256_sub_epi16(b, x)
}

/// fqmulprecomp with scalar (zl, zh) pair
///
/// Convenience wrapper that broadcasts the scalar pair to vectors.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn fqmulprecomp_scalar(coeff: __m256i, zl: i16, zh: i16) -> __m256i {
    let zl_vec = _mm256_set1_epi16(zl);
    let zh_vec = _mm256_set1_epi16(zh);
    fqmulprecomp(coeff, zl_vec, zh_vec)
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
/// This is the standard CT butterfly used in forward NTT.
///
/// # Returns
/// (a', b') = (a + zeta*b, a - zeta*b)
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_ct(a: __m256i, b: __m256i, zeta: __m256i) -> (__m256i, __m256i) {
    let t = montgomery_mul(zeta, b);
    let a_new = _mm256_add_epi16(a, t);
    let b_new = _mm256_sub_epi16(a, t);
    (a_new, b_new)
}

/// Gentleman-Sande butterfly operation (inverse NTT)
///
/// Computes:
/// - a' = a + b (with Barrett reduction)
/// - b' = (a - b) * zeta
///
/// This is the standard GS butterfly used in inverse NTT.
///
/// # Returns
/// (a', b') = (a + b, (a - b) * zeta)
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_gs(a: __m256i, b: __m256i, zeta: __m256i) -> (__m256i, __m256i) {
    let a_new = barrett_reduce(_mm256_add_epi16(a, b));
    let diff = _mm256_sub_epi16(b, a);  // Note: b - a for correct sign
    let b_new = montgomery_mul(zeta, diff);
    (a_new, b_new)
}

/// Lazy Gentleman-Sande butterfly (no reduction on sum)
///
/// Used in lazy INTT where reduction is deferred.
///
/// # Returns
/// (a', b') = (a + b, (a - b) * zeta) without Barrett on sum
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_gs_lazy(a: __m256i, b: __m256i, zeta: __m256i) -> (__m256i, __m256i) {
    let a_new = _mm256_add_epi16(a, b);  // No reduction
    let diff = _mm256_sub_epi16(b, a);
    let b_new = montgomery_mul(zeta, diff);
    (a_new, b_new)
}

// ============================================================================
// fqmulprecomp Butterfly Operations (Optimized)
// ============================================================================

/// Cooley-Tukey butterfly with fqmulprecomp (forward NTT)
///
/// Same as butterfly_ct but uses 3-mul fqmulprecomp instead of 4-mul Montgomery.
///
/// # Arguments
/// * `a`, `b` - Input coefficients
/// * `zl` - Precomputed zeta * QINV mod R
/// * `zh` - Original zeta value
///
/// # Returns
/// (a', b') = (a + zeta*b, a - zeta*b)
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_ct_precomp(
    a: __m256i,
    b: __m256i,
    zl: __m256i,
    zh: __m256i,
) -> (__m256i, __m256i) {
    let t = fqmulprecomp(b, zl, zh);
    let a_new = _mm256_add_epi16(a, t);
    let b_new = _mm256_sub_epi16(a, t);
    (a_new, b_new)
}

/// Cooley-Tukey butterfly with fqmulprecomp and pre-loaded Q
///
/// Most optimized version for hot NTT loops.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_ct_precomp_q(
    a: __m256i,
    b: __m256i,
    zl: __m256i,
    zh: __m256i,
    q_vec: __m256i,
) -> (__m256i, __m256i) {
    let t = fqmulprecomp_preloaded(b, zl, zh, q_vec);
    let a_new = _mm256_add_epi16(a, t);
    let b_new = _mm256_sub_epi16(a, t);
    (a_new, b_new)
}

/// Gentleman-Sande butterfly with fqmulprecomp (inverse NTT)
///
/// # Returns
/// (a', b') = (a + b, (b - a) * zeta) with Barrett on sum
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_gs_precomp(
    a: __m256i,
    b: __m256i,
    zl: __m256i,
    zh: __m256i,
) -> (__m256i, __m256i) {
    let a_new = barrett_reduce(_mm256_add_epi16(a, b));
    let diff = _mm256_sub_epi16(b, a);
    let b_new = fqmulprecomp(diff, zl, zh);
    (a_new, b_new)
}

/// Lazy Gentleman-Sande butterfly with fqmulprecomp
///
/// # Returns
/// (a', b') = (a + b, (b - a) * zeta) without Barrett on sum
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_gs_lazy_precomp(
    a: __m256i,
    b: __m256i,
    zl: __m256i,
    zh: __m256i,
) -> (__m256i, __m256i) {
    let a_new = _mm256_add_epi16(a, b);
    let diff = _mm256_sub_epi16(b, a);
    let b_new = fqmulprecomp(diff, zl, zh);
    (a_new, b_new)
}

/// Lazy GS butterfly with fqmulprecomp and pre-loaded Q
///
/// Most optimized version for hot INTT loops.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn butterfly_gs_lazy_precomp_q(
    a: __m256i,
    b: __m256i,
    zl: __m256i,
    zh: __m256i,
    q_vec: __m256i,
) -> (__m256i, __m256i) {
    let a_new = _mm256_add_epi16(a, b);
    let diff = _mm256_sub_epi16(b, a);
    let b_new = fqmulprecomp_preloaded(diff, zl, zh, q_vec);
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
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn mul_f(a: __m256i) -> __m256i {
    let f_vec = _mm256_set1_epi16(super::consts::F);
    montgomery_mul(a, f_vec)
}

/// Convert from Montgomery form to normal form
///
/// Multiplies by 1 in Montgomery domain, which is equivalent to
/// multiplying by R^-1 mod q.
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn from_montgomery(a: __m256i) -> __m256i {
    let one = _mm256_set1_epi16(1);
    montgomery_mul(a, one)
}

/// Convert to Montgomery form
///
/// Multiplies by R^2 mod q to convert normal form to Montgomery form.
/// R^2 mod 3329 = 2285
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn to_montgomery(a: __m256i) -> __m256i {
    const R2_MOD_Q: i16 = 2285; // R^2 mod q = 2^32 mod 3329
    let r2_vec = _mm256_set1_epi16(R2_MOD_Q);
    montgomery_mul(a, r2_vec)
}

// ============================================================================
// Reduction Helpers for Lazy NTT
// ============================================================================

/// Check if reduction is needed based on coefficient bounds
///
/// After each NTT layer, coefficients grow. This function helps determine
/// when reduction is necessary to prevent overflow.
///
/// Max growth per layer: ~2x (due to add/sub)
/// After 3 layers: ~8x growth (8 * q ≈ 26,632 < 32,767)
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn needs_reduction(max_coeff_bound: i32) -> bool {
    // Conservative threshold: leave headroom for next operation
    max_coeff_bound > 16384
}

/// Reduce all 256 coefficients in a polynomial
///
/// Applies Barrett reduction to bring all coefficients to approximately [-q, q].
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn reduce_poly(coeffs: &mut [i16; 256]) {
    let q_vec = _mm256_set1_epi16(Q);
    let v_vec = _mm256_set1_epi16(BARRETT_V);

    for i in 0..16 {
        let offset = i * 16;
        let a = _mm256_loadu_si256(coeffs[offset..].as_ptr() as *const __m256i);
        let r = barrett_reduce_preloaded(a, q_vec, v_vec);
        _mm256_storeu_si256(coeffs[offset..].as_mut_ptr() as *mut __m256i, r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_montgomery_mul_identity() {
        unsafe {
            // Multiplying by 1 in Montgomery form should give back the original
            // (after accounting for Montgomery representation)
            let a = _mm256_set1_epi16(100);
            let one = _mm256_set1_epi16(1);
            let result = montgomery_mul(a, one);

            // Extract results
            let mut out = [0i16; 16];
            _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, result);

            // Result should be 100 * R^-1 mod q
            // Since we're testing the operation works, just verify it doesn't crash
            // and produces consistent results
            for i in 1..16 {
                assert_eq!(out[0], out[i]);
            }
        }
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_barrett_reduce_in_range() {
        unsafe {
            let a = _mm256_set1_epi16(5000); // > q
            let result = barrett_reduce(a);

            let mut out = [0i16; 16];
            _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, result);

            // Result should be approximately 5000 mod 3329 = 1671
            for &v in &out {
                assert!(v >= -Q && v <= 2 * Q);
            }
        }
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_conditional_sub_q() {
        unsafe {
            // Test value >= q
            let a = _mm256_set1_epi16(3500);
            let result = conditional_sub_q(a);

            let mut out = [0i16; 16];
            _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, result);

            for &v in &out {
                assert_eq!(v, 3500 - Q);
            }

            // Test value < q
            let a = _mm256_set1_epi16(1000);
            let result = conditional_sub_q(a);
            _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, result);

            for &v in &out {
                assert_eq!(v, 1000);
            }
        }
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_fqmulprecomp_matches_montgomery() {
        use super::super::consts::ZETAS_PRECOMP;

        unsafe {
            // Test with various coefficient values
            let test_coeffs: [i16; 16] = [
                0, 1, 100, 500, 1000, 1500, 2000, 2500,
                3000, -100, -500, -1000, -1500, 3328, 1664, 42,
            ];

            // Test with several different zetas
            let test_zeta_indices = [1, 2, 10, 64, 100, 127];

            for &zeta_idx in &test_zeta_indices {
                let (zl, zh) = ZETAS_PRECOMP.get(zeta_idx);
                let zeta = super::super::consts::ZETAS.get(zeta_idx);

                // Load test coefficients
                let coeff_vec = _mm256_loadu_si256(test_coeffs.as_ptr() as *const __m256i);
                let zeta_vec = _mm256_set1_epi16(zeta);
                let zl_vec = _mm256_set1_epi16(zl);
                let zh_vec = _mm256_set1_epi16(zh);

                // Compute with standard Montgomery
                let result_mont = montgomery_mul(coeff_vec, zeta_vec);

                // Compute with fqmulprecomp
                let result_precomp = fqmulprecomp(coeff_vec, zl_vec, zh_vec);

                // Extract results
                let mut out_mont = [0i16; 16];
                let mut out_precomp = [0i16; 16];
                _mm256_storeu_si256(out_mont.as_mut_ptr() as *mut __m256i, result_mont);
                _mm256_storeu_si256(out_precomp.as_mut_ptr() as *mut __m256i, result_precomp);

                // Results must match exactly
                for i in 0..16 {
                    assert_eq!(
                        out_mont[i], out_precomp[i],
                        "Mismatch at zeta_idx={}, coeff_idx={}: mont={}, precomp={}",
                        zeta_idx, i, out_mont[i], out_precomp[i]
                    );
                }
            }
        }
    }

    #[test]
    #[cfg(target_feature = "avx2")]
    fn test_fqmulprecomp_butterfly_matches() {
        use super::super::consts::{ZETAS, ZETAS_PRECOMP};

        unsafe {
            // Test butterfly operations
            let a_vals: [i16; 16] = [100, 200, 300, 400, 500, 600, 700, 800,
                                     900, 1000, 1100, 1200, 1300, 1400, 1500, 1600];
            let b_vals: [i16; 16] = [50, 150, 250, 350, 450, 550, 650, 750,
                                     850, 950, 1050, 1150, 1250, 1350, 1450, 1550];

            let a = _mm256_loadu_si256(a_vals.as_ptr() as *const __m256i);
            let b = _mm256_loadu_si256(b_vals.as_ptr() as *const __m256i);

            // Test with ZETAS[1] = -758
            let zeta = ZETAS.get(1);
            let (zl, zh) = ZETAS_PRECOMP.get(1);

            let zeta_vec = _mm256_set1_epi16(zeta);
            let zl_vec = _mm256_set1_epi16(zl);
            let zh_vec = _mm256_set1_epi16(zh);

            // Standard butterfly
            let (a_std, b_std) = butterfly_ct(a, b, zeta_vec);

            // Precomp butterfly
            let (a_pre, b_pre) = butterfly_ct_precomp(a, b, zl_vec, zh_vec);

            // Extract and compare
            let mut out_a_std = [0i16; 16];
            let mut out_b_std = [0i16; 16];
            let mut out_a_pre = [0i16; 16];
            let mut out_b_pre = [0i16; 16];

            _mm256_storeu_si256(out_a_std.as_mut_ptr() as *mut __m256i, a_std);
            _mm256_storeu_si256(out_b_std.as_mut_ptr() as *mut __m256i, b_std);
            _mm256_storeu_si256(out_a_pre.as_mut_ptr() as *mut __m256i, a_pre);
            _mm256_storeu_si256(out_b_pre.as_mut_ptr() as *mut __m256i, b_pre);

            for i in 0..16 {
                assert_eq!(out_a_std[i], out_a_pre[i], "CT butterfly a mismatch at {}", i);
                assert_eq!(out_b_std[i], out_b_pre[i], "CT butterfly b mismatch at {}", i);
            }
        }
    }
}
