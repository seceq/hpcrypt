//! High-Performance AVX2 Polynomial Arithmetic
//!
//! This module provides optimized polynomial operations for ML-DSA using AVX2
//! SIMD instructions. All operations process 8 coefficients in parallel.
//!
//! # Operations
//!
//! - **Addition/Subtraction**: With optional lazy reduction
//! - **Scalar Multiplication**: Multiply all coefficients by a scalar
//! - **Pointwise Multiplication**: Element-wise multiplication in NTT domain
//! - **Reduction**: Various reduction strategies (Barrett, conditional)
//! - **Norm Computation**: Infinity norm for rejection sampling
//!
//! # Lazy Reduction
//!
//! Many operations support "lazy" variants that skip reduction, allowing
//! multiple operations to be chained before a single reduction. This reduces
//! the total number of expensive reduction operations.

use core::arch::x86_64::*;
use super::consts::{Q, QINV, N};
use super::reduce::{reduce32_avx2, caddq_avx2, barrett_reduce_avx2, fqmul, fqmul_shoup, fqmul_double};

// ============================================================================
// Polynomial Addition
// ============================================================================

/// Add two polynomials with reduction
///
/// Computes c[i] = (a[i] + b[i]) mod Q for all i
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let sum = _mm256_add_epi32(va, vb);
        let reduced = reduce32_avx2(sum);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

/// Optimized addition with hoisted constants and unrolled loop
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_fast(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    let q_vec = _mm256_set1_epi32(Q);
    let zero = _mm256_setzero_si256();
    let q_minus_1 = _mm256_set1_epi32(Q - 1);

    // Process 4 vectors (32 elements) per iteration for better ILP
    for i in (0..N).step_by(32) {
        // Load 4 pairs
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb0 = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let vb1 = _mm256_loadu_si256(b.as_ptr().add(i + 8) as *const __m256i);
        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let vb2 = _mm256_loadu_si256(b.as_ptr().add(i + 16) as *const __m256i);
        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);
        let vb3 = _mm256_loadu_si256(b.as_ptr().add(i + 24) as *const __m256i);

        // Add all 4 pairs (can execute in parallel)
        let sum0 = _mm256_add_epi32(va0, vb0);
        let sum1 = _mm256_add_epi32(va1, vb1);
        let sum2 = _mm256_add_epi32(va2, vb2);
        let sum3 = _mm256_add_epi32(va3, vb3);

        // Inline reduction for all 4: if r < 0 add Q, if r >= Q subtract Q
        // For sum of values in [0, Q), result is in [0, 2Q), so only need >= Q check
        let mask0 = _mm256_cmpgt_epi32(sum0, q_minus_1);
        let mask1 = _mm256_cmpgt_epi32(sum1, q_minus_1);
        let mask2 = _mm256_cmpgt_epi32(sum2, q_minus_1);
        let mask3 = _mm256_cmpgt_epi32(sum3, q_minus_1);

        let r0 = _mm256_sub_epi32(sum0, _mm256_and_si256(mask0, q_vec));
        let r1 = _mm256_sub_epi32(sum1, _mm256_and_si256(mask1, q_vec));
        let r2 = _mm256_sub_epi32(sum2, _mm256_and_si256(mask2, q_vec));
        let r3 = _mm256_sub_epi32(sum3, _mm256_and_si256(mask3, q_vec));

        // Store all 4
        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, r0);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 8) as *mut __m256i, r1);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 16) as *mut __m256i, r2);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 24) as *mut __m256i, r3);
    }
}

/// Add two polynomials in-place: a += b
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_inplace(a: &mut [i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let sum = _mm256_add_epi32(va, vb);
        let reduced = reduce32_avx2(sum);

        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

/// Lazy addition without reduction
///
/// Computes c[i] = a[i] + b[i] without modular reduction.
/// Use when chaining multiple operations before final reduction.
///
/// # Warning
/// Results may overflow if too many lazy operations are chained.
/// Safe for up to ~256 additions before reduction is needed.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_lazy(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let sum = _mm256_add_epi32(va, vb);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, sum);
    }
}

// ============================================================================
// Polynomial Subtraction
// ============================================================================

/// Subtract two polynomials with reduction
///
/// Computes c[i] = (a[i] - b[i]) mod Q for all i
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let diff = _mm256_sub_epi32(va, vb);
        let reduced = caddq_avx2(diff); // Add Q if negative

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

/// Optimized subtraction with hoisted constants and unrolled loop
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_fast(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    let q_vec = _mm256_set1_epi32(Q);
    let zero = _mm256_setzero_si256();

    // Process 4 vectors (32 elements) per iteration for better ILP
    for i in (0..N).step_by(32) {
        // Load 4 pairs
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb0 = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let vb1 = _mm256_loadu_si256(b.as_ptr().add(i + 8) as *const __m256i);
        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let vb2 = _mm256_loadu_si256(b.as_ptr().add(i + 16) as *const __m256i);
        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);
        let vb3 = _mm256_loadu_si256(b.as_ptr().add(i + 24) as *const __m256i);

        // Subtract all 4 pairs (can execute in parallel)
        let diff0 = _mm256_sub_epi32(va0, vb0);
        let diff1 = _mm256_sub_epi32(va1, vb1);
        let diff2 = _mm256_sub_epi32(va2, vb2);
        let diff3 = _mm256_sub_epi32(va3, vb3);

        // Inline caddq: if diff < 0, add Q
        // For diff of values in [0, Q), result is in (-Q, Q), so only need < 0 check
        let mask0 = _mm256_cmpgt_epi32(zero, diff0);
        let mask1 = _mm256_cmpgt_epi32(zero, diff1);
        let mask2 = _mm256_cmpgt_epi32(zero, diff2);
        let mask3 = _mm256_cmpgt_epi32(zero, diff3);

        let r0 = _mm256_add_epi32(diff0, _mm256_and_si256(mask0, q_vec));
        let r1 = _mm256_add_epi32(diff1, _mm256_and_si256(mask1, q_vec));
        let r2 = _mm256_add_epi32(diff2, _mm256_and_si256(mask2, q_vec));
        let r3 = _mm256_add_epi32(diff3, _mm256_and_si256(mask3, q_vec));

        // Store all 4
        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, r0);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 8) as *mut __m256i, r1);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 16) as *mut __m256i, r2);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 24) as *mut __m256i, r3);
    }
}

/// Subtract two polynomials in-place: a -= b
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_inplace(a: &mut [i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let diff = _mm256_sub_epi32(va, vb);
        let reduced = caddq_avx2(diff);

        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

/// Lazy subtraction without reduction
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_lazy(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let diff = _mm256_sub_epi32(va, vb);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, diff);
    }
}

// ============================================================================
// Lazy Reduction Chain Operations
// ============================================================================

/// Maximum number of lazy additions before overflow risk
/// For Q ≈ 2^23, we can safely do ~256 additions before risking i32 overflow
pub const MAX_LAZY_ADDITIONS: usize = 128;

/// Lazy add-accumulate: c += a without reduction
///
/// Use for accumulating multiple polynomials before final reduction.
/// Track the number of lazy additions and call poly_reduce when approaching
/// MAX_LAZY_ADDITIONS to prevent overflow.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_acc_lazy(c: &mut [i32; N], a: &[i32; N]) {
    for i in (0..N).step_by(32) {
        let vc0 = _mm256_loadu_si256(c.as_ptr().add(i) as *const __m256i);
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vc1 = _mm256_loadu_si256(c.as_ptr().add(i + 8) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let vc2 = _mm256_loadu_si256(c.as_ptr().add(i + 16) as *const __m256i);
        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let vc3 = _mm256_loadu_si256(c.as_ptr().add(i + 24) as *const __m256i);
        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);

        let sum0 = _mm256_add_epi32(vc0, va0);
        let sum1 = _mm256_add_epi32(vc1, va1);
        let sum2 = _mm256_add_epi32(vc2, va2);
        let sum3 = _mm256_add_epi32(vc3, va3);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, sum0);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 8) as *mut __m256i, sum1);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 16) as *mut __m256i, sum2);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 24) as *mut __m256i, sum3);
    }
}

/// Lazy sub-accumulate: c -= a without reduction
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_acc_lazy(c: &mut [i32; N], a: &[i32; N]) {
    for i in (0..N).step_by(32) {
        let vc0 = _mm256_loadu_si256(c.as_ptr().add(i) as *const __m256i);
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vc1 = _mm256_loadu_si256(c.as_ptr().add(i + 8) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let vc2 = _mm256_loadu_si256(c.as_ptr().add(i + 16) as *const __m256i);
        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let vc3 = _mm256_loadu_si256(c.as_ptr().add(i + 24) as *const __m256i);
        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);

        let diff0 = _mm256_sub_epi32(vc0, va0);
        let diff1 = _mm256_sub_epi32(vc1, va1);
        let diff2 = _mm256_sub_epi32(vc2, va2);
        let diff3 = _mm256_sub_epi32(vc3, va3);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, diff0);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 8) as *mut __m256i, diff1);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 16) as *mut __m256i, diff2);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 24) as *mut __m256i, diff3);
    }
}

/// Batch lazy sum: compute c = a0 + a1 + a2 + a3 with single final reduction
///
/// More efficient than 3 separate poly_add calls because we avoid
/// intermediate reductions.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sum4(
    a0: &[i32; N],
    a1: &[i32; N],
    a2: &[i32; N],
    a3: &[i32; N],
    c: &mut [i32; N],
) {
    let q_vec = _mm256_set1_epi32(Q);
    let zero = _mm256_setzero_si256();

    for i in (0..N).step_by(8) {
        let v0 = _mm256_loadu_si256(a0.as_ptr().add(i) as *const __m256i);
        let v1 = _mm256_loadu_si256(a1.as_ptr().add(i) as *const __m256i);
        let v2 = _mm256_loadu_si256(a2.as_ptr().add(i) as *const __m256i);
        let v3 = _mm256_loadu_si256(a3.as_ptr().add(i) as *const __m256i);

        // Sum all 4 polynomials (lazy)
        let sum01 = _mm256_add_epi32(v0, v1);
        let sum23 = _mm256_add_epi32(v2, v3);
        let sum_all = _mm256_add_epi32(sum01, sum23);

        // Single reduction at the end
        // For sum of 4 values in [0, Q), result is in [0, 4Q)
        // Barrett reduction handles this range
        let reduced = barrett_reduce_avx2(sum_all);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

/// Compute c = a + b - d with single reduction
///
/// Common pattern in ML-DSA verification.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_sub(
    a: &[i32; N],
    b: &[i32; N],
    d: &[i32; N],
    c: &mut [i32; N],
) {
    let q_vec = _mm256_set1_epi32(Q);
    let zero = _mm256_setzero_si256();
    let q_minus_1 = _mm256_set1_epi32(Q - 1);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let vd = _mm256_loadu_si256(d.as_ptr().add(i) as *const __m256i);

        // (a + b) - d
        let sum = _mm256_add_epi32(va, vb);
        let diff = _mm256_sub_epi32(sum, vd);

        // Result is in (-Q, 2Q), need conditional adjustment
        // First handle negative: add Q if negative
        let mask_neg = _mm256_cmpgt_epi32(zero, diff);
        let r1 = _mm256_add_epi32(diff, _mm256_and_si256(mask_neg, q_vec));

        // Then handle >= Q: subtract Q if >= Q
        let mask_large = _mm256_cmpgt_epi32(r1, q_minus_1);
        let result = _mm256_sub_epi32(r1, _mm256_and_si256(mask_large, q_vec));

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, result);
    }
}

/// Matrix-vector multiply with lazy accumulation
///
/// Computes result[i] = sum_j(matrix[i][j] * vec[j]) with minimal reductions.
/// All pointwise multiplications are accumulated lazily, then reduced once.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_mat_vec_mul_lazy<const K: usize, const L: usize>(
    matrix: &[[[i32; N]; L]; K],
    vec: &[[i32; N]; L],
    result: &mut [[i32; N]; K],
) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    for i in 0..K {
        // Initialize result[i] to zero
        poly_zero(&mut result[i]);

        // Accumulate all L products
        for j in 0..L {
            // Pointwise multiply and accumulate (lazy)
            for k in (0..N).step_by(8) {
                let vm = _mm256_loadu_si256(matrix[i][j].as_ptr().add(k) as *const __m256i);
                let vv = _mm256_loadu_si256(vec[j].as_ptr().add(k) as *const __m256i);
                let vr = _mm256_loadu_si256(result[i].as_ptr().add(k) as *const __m256i);

                // Montgomery multiply
                let prod = fqmul(vm, vv, qinv, q);

                // Lazy accumulate
                let sum = _mm256_add_epi32(vr, prod);

                _mm256_storeu_si256(result[i].as_mut_ptr().add(k) as *mut __m256i, sum);
            }
        }

        // Single reduction at end of each row
        poly_reduce_fast(&mut result[i]);
    }
}

// ============================================================================
// Negation
// ============================================================================

/// Negate polynomial: c[i] = -a[i] mod Q
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_negate(a: &[i32; N], c: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        // -a mod Q = Q - a (for a in [0, Q))
        let neg = _mm256_sub_epi32(q, va);

        // Handle a = 0 case: result should be 0, not Q
        let zero = _mm256_setzero_si256();
        let is_zero = _mm256_cmpeq_epi32(va, zero);
        let result = _mm256_andnot_si256(is_zero, neg); // 0 if a was 0, else Q-a

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, result);
    }
}

// ============================================================================
// Scalar Operations
// ============================================================================

/// Multiply polynomial by scalar
///
/// Computes c[i] = (a[i] * s) mod Q for all i using Montgomery multiplication
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_scalar_mul(a: &[i32; N], s: i32, c: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);
    let s_vec = _mm256_set1_epi32(s);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        let prod = fqmul(va, s_vec, qinv, q);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, prod);
    }
}

/// Multiply polynomial by scalar with Shoup optimization
///
/// Use when multiplying by the same scalar repeatedly.
///
/// # Arguments
/// * `s_shoup` - Precomputed Shoup constant: (s * QINV) mod 2^32
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_scalar_mul_shoup(a: &[i32; N], s: i32, s_shoup: i32, c: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);
    let s_vec = _mm256_set1_epi32(s);
    let s_shoup_vec = _mm256_set1_epi32(s_shoup);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        let prod = fqmul_shoup(va, s_vec, s_shoup_vec, q);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, prod);
    }
}

/// Left shift polynomial coefficients by D=13 bits: c[i] = a[i] << 13
///
/// Used for Power2Round reconstruction: t = t1 * 2^D + t0.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_shiftl_d(a: &[i32; N], c: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        // Shift left by D=13 bits (compile-time constant)
        let shifted = _mm256_slli_epi32::<13>(va);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, shifted);
    }
}

/// Left shift polynomial coefficients by specified amount
///
/// For runtime-determined shift amounts, uses multiplication.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_shiftl(a: &[i32; N], d: i32, c: &mut [i32; N]) {
    let multiplier = _mm256_set1_epi32(1 << d);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        let shifted = _mm256_mullo_epi32(va, multiplier);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, shifted);
    }
}

// ============================================================================
// Pointwise Multiplication
// ============================================================================

/// Pointwise multiplication (Montgomery)
///
/// Computes c[i] = (a[i] * b[i] * R^{-1}) mod Q
/// Use for NTT domain multiplication.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_pointwise_montgomery(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

        let prod = fqmul(va, vb, qinv, q);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, prod);
    }
}

/// Optimized pointwise multiplication with unrolled loop
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_pointwise_montgomery_fast(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    // Process 4 vectors (32 elements) per iteration for better ILP
    for i in (0..N).step_by(32) {
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb0 = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let vb1 = _mm256_loadu_si256(b.as_ptr().add(i + 8) as *const __m256i);
        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let vb2 = _mm256_loadu_si256(b.as_ptr().add(i + 16) as *const __m256i);
        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);
        let vb3 = _mm256_loadu_si256(b.as_ptr().add(i + 24) as *const __m256i);

        let prod0 = fqmul(va0, vb0, qinv, q);
        let prod1 = fqmul(va1, vb1, qinv, q);
        let prod2 = fqmul(va2, vb2, qinv, q);
        let prod3 = fqmul(va3, vb3, qinv, q);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, prod0);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 8) as *mut __m256i, prod1);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 16) as *mut __m256i, prod2);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 24) as *mut __m256i, prod3);
    }
}

/// Pointwise multiplication with accumulation
///
/// Computes c[i] += (a[i] * b[i] * R^{-1}) mod Q
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_pointwise_acc_montgomery(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let vc = _mm256_loadu_si256(c.as_ptr().add(i) as *const __m256i);

        let prod = fqmul(va, vb, qinv, q);
        let sum = _mm256_add_epi32(vc, prod);

        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, sum);
    }
}

// ============================================================================
// Reduction Operations
// ============================================================================

/// Full polynomial reduction to [0, Q)
///
/// Applies Barrett reduction followed by conditional adjustment.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_reduce(a: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        let reduced = barrett_reduce_avx2(va);

        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

/// Optimized polynomial reduction with hoisted constants
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_reduce_fast(a: &mut [i32; N]) {
    let q_vec = _mm256_set1_epi32(Q);
    let v_vec = _mm256_set1_epi32(8); // Barrett constant
    let zero = _mm256_setzero_si256();
    let q_minus_1 = _mm256_set1_epi32(Q - 1);

    // Process 2 vectors (16 elements) per iteration to reduce register pressure
    for i in (0..N).step_by(16) {
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);

        // Barrett reduction: q = (r * V) >> 26, result = r - q * Q
        let rv0 = _mm256_mullo_epi32(va0, v_vec);
        let rv1 = _mm256_mullo_epi32(va1, v_vec);

        let q0 = _mm256_srai_epi32(rv0, 26);
        let q1 = _mm256_srai_epi32(rv1, 26);

        let qmul0 = _mm256_mullo_epi32(q0, q_vec);
        let qmul1 = _mm256_mullo_epi32(q1, q_vec);

        let mut r0 = _mm256_sub_epi32(va0, qmul0);
        let mut r1 = _mm256_sub_epi32(va1, qmul1);

        // Conditional correction: add Q if negative
        let mask_neg0 = _mm256_cmpgt_epi32(zero, r0);
        let mask_neg1 = _mm256_cmpgt_epi32(zero, r1);

        r0 = _mm256_add_epi32(r0, _mm256_and_si256(mask_neg0, q_vec));
        r1 = _mm256_add_epi32(r1, _mm256_and_si256(mask_neg1, q_vec));

        // Conditional correction: subtract Q if >= Q
        let mask_large0 = _mm256_cmpgt_epi32(r0, q_minus_1);
        let mask_large1 = _mm256_cmpgt_epi32(r1, q_minus_1);

        r0 = _mm256_sub_epi32(r0, _mm256_and_si256(mask_large0, q_vec));
        r1 = _mm256_sub_epi32(r1, _mm256_and_si256(mask_large1, q_vec));

        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, r0);
        _mm256_storeu_si256(a.as_mut_ptr().add(i + 8) as *mut __m256i, r1);
    }
}

/// Conditional add Q if negative
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_caddq(a: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        let reduced = caddq_avx2(va);

        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

/// Simple conditional reduction
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_reduce32(a: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        let reduced = reduce32_avx2(va);

        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }
}

// ============================================================================
// Norm Operations
// ============================================================================

/// Compute infinity norm with early exit threshold (for coefficients in [0, Q))
///
/// For coefficients in [0, Q), first center to [-Q/2, Q/2) then compute max|a[i]|.
/// This version includes an early exit when any coefficient exceeds the threshold,
/// making it significantly faster for typical use cases in signing.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn infinity_norm_avx2_threshold(coeffs: &[i32; N], threshold: i32) -> i32 {
    const Q_DIV_2: i32 = Q / 2;
    let q_div_2_vec = _mm256_set1_epi32(Q_DIV_2);
    let q_vec = _mm256_set1_epi32(Q);
    let threshold_vec = _mm256_set1_epi32(threshold);

    let mut max_vec = _mm256_setzero_si256();

    // Process 8 coefficients at a time
    for i in (0..N).step_by(8) {
        // Load 8 coefficients
        let coeff_vec = _mm256_loadu_si256(coeffs.as_ptr().add(i) as *const __m256i);

        // Center: if coeff > Q/2, coeff -= Q
        let mask = _mm256_cmpgt_epi32(coeff_vec, q_div_2_vec);
        let adjusted = _mm256_sub_epi32(coeff_vec, q_vec);
        let centered = _mm256_blendv_epi8(coeff_vec, adjusted, mask);

        // Absolute value
        let negated = _mm256_sub_epi32(_mm256_setzero_si256(), centered);
        let abs_vals = _mm256_max_epi32(centered, negated);

        // Early exit check: if any value > threshold
        let exceeds_mask = _mm256_cmpgt_epi32(abs_vals, threshold_vec);
        let exceeds = _mm256_movemask_epi8(exceeds_mask);
        if exceeds != 0 {
            // At least one value exceeds threshold - early exit
            // Extract the actual max for accuracy
            let max_so_far = _mm256_max_epi32(max_vec, abs_vals);
            let high = _mm256_extracti128_si256(max_so_far, 1);
            let low = _mm256_castsi256_si128(max_so_far);
            let max_128 = _mm_max_epi32(low, high);
            let shuf = _mm_shuffle_epi32(max_128, 0b00_01_10_11);
            let max_128 = _mm_max_epi32(max_128, shuf);
            let shuf = _mm_shuffle_epi32(max_128, 0b00_00_00_01);
            let max_128 = _mm_max_epi32(max_128, shuf);
            return _mm_extract_epi32(max_128, 0);
        }

        // Track maximum
        max_vec = _mm256_max_epi32(max_vec, abs_vals);
    }

    // Horizontal maximum reduction
    let high = _mm256_extracti128_si256(max_vec, 1);
    let low = _mm256_castsi256_si128(max_vec);
    let max_128 = _mm_max_epi32(low, high);
    let shuf = _mm_shuffle_epi32(max_128, 0b00_01_10_11);
    let max_128 = _mm_max_epi32(max_128, shuf);
    let shuf = _mm_shuffle_epi32(max_128, 0b00_00_00_01);
    let max_128 = _mm_max_epi32(max_128, shuf);

    _mm_extract_epi32(max_128, 0)
}

/// Check if infinity norm exceeds threshold
///
/// Returns true if any |a[i]| > threshold.
/// More efficient than computing full norm when only checking bounds.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_chknorm(a: &[i32; N], threshold: i32) -> bool {
    let thresh_vec = _mm256_set1_epi32(threshold);
    let neg_thresh_vec = _mm256_set1_epi32(-threshold);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        // Check if v > threshold OR v < -threshold
        let too_large = _mm256_cmpgt_epi32(va, thresh_vec);
        let too_small = _mm256_cmpgt_epi32(neg_thresh_vec, va);
        let fail = _mm256_or_si256(too_large, too_small);

        // Early exit if any coefficient exceeds threshold
        if _mm256_movemask_epi8(fail) != 0 {
            return true;
        }
    }

    false
}

/// Optimized norm check that processes multiple vectors before checking
///
/// This trades early termination for better throughput on typical (passing) cases.
/// For polynomials that usually pass the check, this is faster than checking
/// each vector individually.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_chknorm_fast(a: &[i32; N], threshold: i32) -> bool {
    let thresh_vec = _mm256_set1_epi32(threshold);
    let neg_thresh_vec = _mm256_set1_epi32(-threshold);
    let zero = _mm256_setzero_si256();

    // Accumulate failures across 4 vectors before checking
    // This reduces branch misprediction penalties
    for i in (0..N).step_by(32) {
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);

        // Check v > threshold for all 4 vectors
        let too_large0 = _mm256_cmpgt_epi32(va0, thresh_vec);
        let too_large1 = _mm256_cmpgt_epi32(va1, thresh_vec);
        let too_large2 = _mm256_cmpgt_epi32(va2, thresh_vec);
        let too_large3 = _mm256_cmpgt_epi32(va3, thresh_vec);

        // Check v < -threshold for all 4 vectors
        let too_small0 = _mm256_cmpgt_epi32(neg_thresh_vec, va0);
        let too_small1 = _mm256_cmpgt_epi32(neg_thresh_vec, va1);
        let too_small2 = _mm256_cmpgt_epi32(neg_thresh_vec, va2);
        let too_small3 = _mm256_cmpgt_epi32(neg_thresh_vec, va3);

        // Combine all failures
        let fail0 = _mm256_or_si256(too_large0, too_small0);
        let fail1 = _mm256_or_si256(too_large1, too_small1);
        let fail2 = _mm256_or_si256(too_large2, too_small2);
        let fail3 = _mm256_or_si256(too_large3, too_small3);

        let fail01 = _mm256_or_si256(fail0, fail1);
        let fail23 = _mm256_or_si256(fail2, fail3);
        let fail_all = _mm256_or_si256(fail01, fail23);

        // Single branch for all 32 elements
        if _mm256_movemask_epi8(fail_all) != 0 {
            return true;
        }
    }

    false
}

/// Check norm with threshold (centered representation)
///
/// For coefficients in [0, Q), first center to [-Q/2, Q/2) then check norm.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_chknorm_centered(a: &[i32; N], threshold: i32) -> bool {
    let q_vec = _mm256_set1_epi32(Q);
    let q_half = _mm256_set1_epi32((Q - 1) / 2);
    let thresh_vec = _mm256_set1_epi32(threshold);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);

        // Center: if v > Q/2, v -= Q
        let mask = _mm256_cmpgt_epi32(va, q_half);
        let centered = _mm256_sub_epi32(va, _mm256_and_si256(mask, q_vec));

        // Compute absolute value
        let zero = _mm256_setzero_si256();
        let neg = _mm256_sub_epi32(zero, centered);
        let abs_val = _mm256_max_epi32(centered, neg);

        // Check against threshold
        let fail = _mm256_cmpgt_epi32(abs_val, thresh_vec);
        if _mm256_movemask_epi8(fail) != 0 {
            return true;
        }
    }

    false
}

// ============================================================================
// Utility Operations
// ============================================================================

/// Copy polynomial
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_copy(src: &[i32; N], dst: &mut [i32; N]) {
    for i in (0..N).step_by(8) {
        let v = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, v);
    }
}

/// Set polynomial to zero
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_zero(a: &mut [i32; N]) {
    let zero = _mm256_setzero_si256();
    for i in (0..N).step_by(8) {
        _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, zero);
    }
}

/// Check if polynomial is zero
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_is_zero(a: &[i32; N]) -> bool {
    let zero = _mm256_setzero_si256();

    for i in (0..N).step_by(8) {
        let v = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let cmp = _mm256_cmpeq_epi32(v, zero);

        // If any element is non-zero, cmp won't be all 1s
        if _mm256_movemask_epi8(cmp) != -1i32 as i32 {
            return false;
        }
    }

    true
}

// ============================================================================
// Vector Operations (for polynomial vectors)
// ============================================================================

/// Add polynomial vectors: c = a + b
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn polyvec_add<const K: usize>(
    a: &[[i32; N]; K],
    b: &[[i32; N]; K],
    c: &mut [[i32; N]; K],
) {
    for i in 0..K {
        poly_add(&a[i], &b[i], &mut c[i]);
    }
}

/// Subtract polynomial vectors: c = a - b
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn polyvec_sub<const K: usize>(
    a: &[[i32; N]; K],
    b: &[[i32; N]; K],
    c: &mut [[i32; N]; K],
) {
    for i in 0..K {
        poly_sub(&a[i], &b[i], &mut c[i]);
    }
}

/// Check norm of polynomial vector
///
/// Returns true if any polynomial in vector has infinity norm > threshold.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn polyvec_chknorm<const K: usize>(v: &[[i32; N]; K], threshold: i32) -> bool {
    for i in 0..K {
        if poly_chknorm(&v[i], threshold) {
            return true;
        }
    }
    false
}

/// Optimized batch norm check for polynomial vectors
///
/// Processes multiple polynomials simultaneously, accumulating failure flags.
/// More efficient than individual checks when most vectors pass.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn polyvec_chknorm_batch<const K: usize>(v: &[[i32; N]; K], threshold: i32) -> bool {
    let thresh_vec = _mm256_set1_epi32(threshold);
    let neg_thresh_vec = _mm256_set1_epi32(-threshold);

    // Accumulate failure flags across all polynomials
    let mut fail_acc = _mm256_setzero_si256();

    // Process all polynomials, accumulating failures
    for poly_idx in 0..K {
        let poly = &v[poly_idx];

        // Process 32 elements at a time (4 vectors)
        for i in (0..N).step_by(32) {
            let va0 = _mm256_loadu_si256(poly.as_ptr().add(i) as *const __m256i);
            let va1 = _mm256_loadu_si256(poly.as_ptr().add(i + 8) as *const __m256i);
            let va2 = _mm256_loadu_si256(poly.as_ptr().add(i + 16) as *const __m256i);
            let va3 = _mm256_loadu_si256(poly.as_ptr().add(i + 24) as *const __m256i);

            // Check v > threshold
            let too_large0 = _mm256_cmpgt_epi32(va0, thresh_vec);
            let too_large1 = _mm256_cmpgt_epi32(va1, thresh_vec);
            let too_large2 = _mm256_cmpgt_epi32(va2, thresh_vec);
            let too_large3 = _mm256_cmpgt_epi32(va3, thresh_vec);

            // Check v < -threshold
            let too_small0 = _mm256_cmpgt_epi32(neg_thresh_vec, va0);
            let too_small1 = _mm256_cmpgt_epi32(neg_thresh_vec, va1);
            let too_small2 = _mm256_cmpgt_epi32(neg_thresh_vec, va2);
            let too_small3 = _mm256_cmpgt_epi32(neg_thresh_vec, va3);

            // Combine failures
            let fail0 = _mm256_or_si256(too_large0, too_small0);
            let fail1 = _mm256_or_si256(too_large1, too_small1);
            let fail2 = _mm256_or_si256(too_large2, too_small2);
            let fail3 = _mm256_or_si256(too_large3, too_small3);

            // Accumulate
            let fail01 = _mm256_or_si256(fail0, fail1);
            let fail23 = _mm256_or_si256(fail2, fail3);
            let fail_all = _mm256_or_si256(fail01, fail23);
            fail_acc = _mm256_or_si256(fail_acc, fail_all);
        }
    }

    // Check if any failure occurred
    _mm256_movemask_epi8(fail_acc) != 0
}

/// Batch pointwise multiply-accumulate for matrix-vector products
///
/// Efficiently computes c += a * b for polynomial pairs.
/// Uses fused operations for better throughput.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_pointwise_acc_montgomery_fast(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    // Process 32 elements per iteration for better ILP
    for i in (0..N).step_by(32) {
        // Load all inputs
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb0 = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let vc0 = _mm256_loadu_si256(c.as_ptr().add(i) as *const __m256i);

        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let vb1 = _mm256_loadu_si256(b.as_ptr().add(i + 8) as *const __m256i);
        let vc1 = _mm256_loadu_si256(c.as_ptr().add(i + 8) as *const __m256i);

        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let vb2 = _mm256_loadu_si256(b.as_ptr().add(i + 16) as *const __m256i);
        let vc2 = _mm256_loadu_si256(c.as_ptr().add(i + 16) as *const __m256i);

        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);
        let vb3 = _mm256_loadu_si256(b.as_ptr().add(i + 24) as *const __m256i);
        let vc3 = _mm256_loadu_si256(c.as_ptr().add(i + 24) as *const __m256i);

        // Multiply and accumulate using fqmul_double for better ILP
        let (prod0, prod1) = fqmul_double(va0, vb0, va1, vb1, qinv, q);
        let (prod2, prod3) = fqmul_double(va2, vb2, va3, vb3, qinv, q);

        let sum0 = _mm256_add_epi32(vc0, prod0);
        let sum1 = _mm256_add_epi32(vc1, prod1);
        let sum2 = _mm256_add_epi32(vc2, prod2);
        let sum3 = _mm256_add_epi32(vc3, prod3);

        // Store results
        _mm256_storeu_si256(c.as_mut_ptr().add(i) as *mut __m256i, sum0);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 8) as *mut __m256i, sum1);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 16) as *mut __m256i, sum2);
        _mm256_storeu_si256(c.as_mut_ptr().add(i + 24) as *mut __m256i, sum3);
    }
}

/// Optimized matrix-vector multiply in NTT domain
///
/// Computes result = matrix * vec where matrix is K×L and vec is L.
/// Uses batch operations and lazy accumulation for maximum throughput.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn polyvec_matrix_pointwise_montgomery<const K: usize, const L: usize>(
    matrix: &[[[i32; N]; L]; K],
    vec: &[[i32; N]; L],
    result: &mut [[i32; N]; K],
) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    for i in 0..K {
        // Initialize result[i] with first product
        poly_pointwise_montgomery(&matrix[i][0], &vec[0], &mut result[i]);

        // Accumulate remaining products
        for j in 1..L {
            poly_pointwise_acc_montgomery_fast(&matrix[i][j], &vec[j], &mut result[i]);
        }

        // Final reduction
        poly_reduce_fast(&mut result[i]);
    }
}

// ============================================================================
// Fused Operations for Hot Paths
// ============================================================================

/// Fused sub-add operation: result = a - b + c
///
/// Common pattern in signing: w - c·s2 + c·t0
/// Fusing avoids intermediate stores and allows better ILP.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_add_lazy(
    a: &[i32; N],
    b: &[i32; N],
    c: &[i32; N],
    result: &mut [i32; N],
) {
    // Process 32 elements per iteration
    for i in (0..N).step_by(32) {
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb0 = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        let vc0 = _mm256_loadu_si256(c.as_ptr().add(i) as *const __m256i);

        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let vb1 = _mm256_loadu_si256(b.as_ptr().add(i + 8) as *const __m256i);
        let vc1 = _mm256_loadu_si256(c.as_ptr().add(i + 8) as *const __m256i);

        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let vb2 = _mm256_loadu_si256(b.as_ptr().add(i + 16) as *const __m256i);
        let vc2 = _mm256_loadu_si256(c.as_ptr().add(i + 16) as *const __m256i);

        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);
        let vb3 = _mm256_loadu_si256(b.as_ptr().add(i + 24) as *const __m256i);
        let vc3 = _mm256_loadu_si256(c.as_ptr().add(i + 24) as *const __m256i);

        // a - b + c (lazy, no reduction)
        let sub0 = _mm256_sub_epi32(va0, vb0);
        let sub1 = _mm256_sub_epi32(va1, vb1);
        let sub2 = _mm256_sub_epi32(va2, vb2);
        let sub3 = _mm256_sub_epi32(va3, vb3);

        let r0 = _mm256_add_epi32(sub0, vc0);
        let r1 = _mm256_add_epi32(sub1, vc1);
        let r2 = _mm256_add_epi32(sub2, vc2);
        let r3 = _mm256_add_epi32(sub3, vc3);

        _mm256_storeu_si256(result.as_mut_ptr().add(i) as *mut __m256i, r0);
        _mm256_storeu_si256(result.as_mut_ptr().add(i + 8) as *mut __m256i, r1);
        _mm256_storeu_si256(result.as_mut_ptr().add(i + 16) as *mut __m256i, r2);
        _mm256_storeu_si256(result.as_mut_ptr().add(i + 24) as *mut __m256i, r3);
    }
}

/// Fast polynomial negation: result[i] = Q - a[i] if a[i] != 0, else 0
///
/// Processes 32 elements per iteration for better throughput.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_negate_fast(a: &[i32; N], result: &mut [i32; N]) {
    let q_vec = _mm256_set1_epi32(Q);
    let zero = _mm256_setzero_si256();

    // Process 32 elements per iteration
    for i in (0..N).step_by(32) {
        let va0 = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let va1 = _mm256_loadu_si256(a.as_ptr().add(i + 8) as *const __m256i);
        let va2 = _mm256_loadu_si256(a.as_ptr().add(i + 16) as *const __m256i);
        let va3 = _mm256_loadu_si256(a.as_ptr().add(i + 24) as *const __m256i);

        // Q - a
        let neg0 = _mm256_sub_epi32(q_vec, va0);
        let neg1 = _mm256_sub_epi32(q_vec, va1);
        let neg2 = _mm256_sub_epi32(q_vec, va2);
        let neg3 = _mm256_sub_epi32(q_vec, va3);

        // If a == 0, result should be 0 (not Q)
        let is_zero0 = _mm256_cmpeq_epi32(va0, zero);
        let is_zero1 = _mm256_cmpeq_epi32(va1, zero);
        let is_zero2 = _mm256_cmpeq_epi32(va2, zero);
        let is_zero3 = _mm256_cmpeq_epi32(va3, zero);

        // Select 0 where input was 0, else Q-a
        let r0 = _mm256_andnot_si256(is_zero0, neg0);
        let r1 = _mm256_andnot_si256(is_zero1, neg1);
        let r2 = _mm256_andnot_si256(is_zero2, neg2);
        let r3 = _mm256_andnot_si256(is_zero3, neg3);

        _mm256_storeu_si256(result.as_mut_ptr().add(i) as *mut __m256i, r0);
        _mm256_storeu_si256(result.as_mut_ptr().add(i + 8) as *mut __m256i, r1);
        _mm256_storeu_si256(result.as_mut_ptr().add(i + 16) as *mut __m256i, r2);
        _mm256_storeu_si256(result.as_mut_ptr().add(i + 24) as *mut __m256i, r3);
    }
}

/// Fast hint counting using AVX2 with efficient horizontal sum
///
/// Counts non-zero coefficients in a hint polynomial.
/// Uses SIMD comparisons and popcount for speed.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_hint_count_fast(h: &[i32; N]) -> usize {
    let zero = _mm256_setzero_si256();
    let mut count: usize = 0;

    // Process 32 elements per iteration
    for i in (0..N).step_by(32) {
        let vh0 = _mm256_loadu_si256(h.as_ptr().add(i) as *const __m256i);
        let vh1 = _mm256_loadu_si256(h.as_ptr().add(i + 8) as *const __m256i);
        let vh2 = _mm256_loadu_si256(h.as_ptr().add(i + 16) as *const __m256i);
        let vh3 = _mm256_loadu_si256(h.as_ptr().add(i + 24) as *const __m256i);

        // Compare with zero - result is all 1s for non-zero elements
        // Using cmpgt catches positive values, but hints are 0 or 1
        // For safety, compare != 0 by checking (val != 0) via (val > 0) | (val < 0)
        let gt0 = _mm256_cmpgt_epi32(vh0, zero);
        let gt1 = _mm256_cmpgt_epi32(vh1, zero);
        let gt2 = _mm256_cmpgt_epi32(vh2, zero);
        let gt3 = _mm256_cmpgt_epi32(vh3, zero);

        // Get masks (each i32 that is non-zero produces 4 bytes of 0xFF)
        let mask0 = _mm256_movemask_epi8(gt0) as u32;
        let mask1 = _mm256_movemask_epi8(gt1) as u32;
        let mask2 = _mm256_movemask_epi8(gt2) as u32;
        let mask3 = _mm256_movemask_epi8(gt3) as u32;

        // Each non-zero i32 contributes 4 bits (0xF) to the mask
        // popcount / 4 gives the count of non-zero elements
        count += (mask0.count_ones() / 4) as usize;
        count += (mask1.count_ones() / 4) as usize;
        count += (mask2.count_ones() / 4) as usize;
        count += (mask3.count_ones() / 4) as usize;
    }

    count
}

/// Batch hint counting for polynomial vectors
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn polyvec_hint_count<const K: usize>(h: &[[i32; N]; K]) -> usize {
    let mut total = 0;
    for i in 0..K {
        total += poly_hint_count_fast(&h[i]);
    }
    total
}

// ============================================================================
// Sparse Polynomial Multiplication Support
// ============================================================================

/// AVX2-accelerated rotation and accumulation for sparse multiplication
///
/// Computes: result += multiplier * (x^pos · p) mod (x^n + 1)
///
/// This is the inner loop of sparse polynomial multiplication, called τ times
/// per multiply (49-60 times for ML-DSA). Vectorizing this provides significant
/// speedup over scalar implementation.
///
/// # Algorithm
/// - Coefficients [0..N-pos) in p go to positions [pos..N) in result (add)
/// - Coefficients [N-pos..N) in p wrap to [0..pos) with negation (x^n = -1)
/// - multiplier is ±1 based on the challenge coefficient sign
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn rotate_and_accumulate_avx2(
    result: &mut [i32; N],
    p: &[i32; N],
    pos: usize,
    multiplier: i32,
) {
    debug_assert!(pos < N);

    let mult_vec = _mm256_set1_epi32(multiplier);
    let neg_mult_vec = _mm256_set1_epi32(-multiplier);

    // Region 1: p[0..N-pos) -> result[pos..N) with sign = multiplier
    // These coefficients don't wrap, so no negation from x^n = -1
    let region1_len = N - pos;
    let region1_full_vecs = region1_len / 8;
    let region1_remainder = region1_len % 8;

    // Process full vectors in region 1
    for i in 0..region1_full_vecs {
        let src_idx = i * 8;
        let dst_idx = pos + i * 8;

        let vp = _mm256_loadu_si256(p.as_ptr().add(src_idx) as *const __m256i);
        let vr = _mm256_loadu_si256(result.as_ptr().add(dst_idx) as *const __m256i);

        // result[dst] += multiplier * p[src]
        let prod = _mm256_mullo_epi32(vp, mult_vec);
        let sum = _mm256_add_epi32(vr, prod);

        _mm256_storeu_si256(result.as_mut_ptr().add(dst_idx) as *mut __m256i, sum);
    }

    // Handle remainder of region 1 (scalar)
    for i in 0..region1_remainder {
        let src_idx = region1_full_vecs * 8 + i;
        let dst_idx = pos + region1_full_vecs * 8 + i;
        result[dst_idx] += multiplier * p[src_idx];
    }

    // Region 2: p[N-pos..N) -> result[0..pos) with sign = -multiplier
    // These coefficients wrap around, getting negated due to x^n = -1
    // So we subtract instead of add: result -= multiplier * p = result + (-multiplier) * p
    let region2_len = pos;
    let region2_full_vecs = region2_len / 8;
    let region2_remainder = region2_len % 8;

    // Process full vectors in region 2
    for i in 0..region2_full_vecs {
        let src_idx = (N - pos) + i * 8;
        let dst_idx = i * 8;

        let vp = _mm256_loadu_si256(p.as_ptr().add(src_idx) as *const __m256i);
        let vr = _mm256_loadu_si256(result.as_ptr().add(dst_idx) as *const __m256i);

        // result[dst] -= multiplier * p[src] = result[dst] + (-multiplier) * p[src]
        let prod = _mm256_mullo_epi32(vp, neg_mult_vec);
        let sum = _mm256_add_epi32(vr, prod);

        _mm256_storeu_si256(result.as_mut_ptr().add(dst_idx) as *mut __m256i, sum);
    }

    // Handle remainder of region 2 (scalar)
    for i in 0..region2_remainder {
        let src_idx = (N - pos) + region2_full_vecs * 8 + i;
        let dst_idx = region2_full_vecs * 8 + i;
        result[dst_idx] -= multiplier * p[src_idx];
    }
}

/// Full sparse polynomial multiplication using AVX2
///
/// Computes c * p where c has only τ non-zero coefficients (all ±1).
/// Uses vectorized rotation-accumulation for ~2-3x speedup over scalar.
///
/// # Arguments
/// - `positions`: Array of positions of non-zero coefficients in c
/// - `signs`: Array of signs (0 = positive/+1, 1 = negative/-1)
/// - `count`: Number of non-zero coefficients (τ)
/// - `p`: Dense polynomial to multiply
/// - `result`: Output polynomial (must be zeroed)
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn sparse_poly_multiply_avx2(
    positions: &[u8],
    signs: &[u8],
    count: usize,
    p: &[i32; N],
    result: &mut [i32; N],
) {
    // Zero the result first
    poly_zero(result);

    // Process each non-zero coefficient
    for idx in 0..count {
        let pos = positions[idx] as usize;
        let sign = signs[idx];

        // sign = 0 means +1, sign = 1 means -1
        let multiplier = 1 - 2 * (sign as i32);

        rotate_and_accumulate_avx2(result, p, pos, multiplier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_poly_add() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let a = [1i32; N];
            let b = [2i32; N];
            let mut c = [0i32; N];

            poly_add(&a, &b, &mut c);

            for &v in &c {
                assert_eq!(v, 3);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_poly_sub() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let a = [5i32; N];
            let b = [2i32; N];
            let mut c = [0i32; N];

            poly_sub(&a, &b, &mut c);

            for &v in &c {
                assert_eq!(v, 3);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_infinity_norm_avx2_threshold() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut a = [0i32; N];
            a[0] = 100;
            a[50] = Q - 200;  // Centered: -200
            a[100] = 150;

            let norm = infinity_norm_avx2_threshold(&a, i32::MAX);
            assert_eq!(norm, 200);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_poly_chknorm() {
        if !hpcrypt_core::cpufeatures::has_avx2() {
            return;
        }

        unsafe {
            let mut a = [50i32; N];

            // All values within threshold
            assert!(!poly_chknorm(&a, 100));

            // One value exceeds threshold
            a[100] = 150;
            assert!(poly_chknorm(&a, 100));
        }
    }
}
