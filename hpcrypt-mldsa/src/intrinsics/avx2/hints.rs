//! High-Performance AVX2 Hint Operations
//!
//! This module provides optimized hint operations for ML-DSA signature
//! verification using AVX2 SIMD instructions.
//!
//! # Operations
//!
//! - **MakeHint**: Create hint indicating whether adding z changes high bits
//! - **UseHint**: Apply hint to recover correct high bits
//!
//! # Background
//!
//! In ML-DSA, hints are used to handle the ambiguity in HighBits during
//! verification. When the signer computes w - c*s2, the result may differ
//! from the verifier's computation of A*z - c*t1*2^d in the low bits,
//! causing different HighBits. The hint h indicates where this occurs.

use core::arch::x86_64::*;
use super::consts::{Q, N};

#[cfg(test)]
use super::consts::ALPHA_65;
use super::rounding::{decompose, highbits_fast};

// ============================================================================
// MakeHint
// ============================================================================

/// Create hint polynomial
///
/// For each coefficient i:
///   h[i] = 1 if HighBits(r + z) ≠ HighBits(r), else 0
///
/// This indicates where adding z changes the high bits.
///
/// # Returns
/// The number of hints set (non-zero coefficients).
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn make_hint(
    z: &[i32; N],
    r: &[i32; N],
    h: &mut [i32; N],
    alpha: i32,
) -> usize {
    let q = Q;
    let m = (q - 1) / alpha;
    let mut count = 0;

    // Compute HighBits(r)
    let mut r1 = [0i32; N];
    highbits_fast(r, &mut r1, alpha);

    // Compute HighBits(r + z)
    let mut r_plus_z = [0i32; N];
    for i in 0..N {
        // Add and reduce modulo Q
        let mut sum = r[i] + z[i];
        if sum >= q {
            sum -= q;
        }
        if sum < 0 {
            sum += q;
        }
        r_plus_z[i] = sum;
    }

    let mut v1 = [0i32; N];
    highbits_fast(&r_plus_z, &mut v1, alpha);

    // Compare and create hints
    let zero = _mm256_setzero_si256();
    let one = _mm256_set1_epi32(1);

    for i in (0..N).step_by(8) {
        let vr1 = _mm256_loadu_si256(r1.as_ptr().add(i) as *const __m256i);
        let vv1 = _mm256_loadu_si256(v1.as_ptr().add(i) as *const __m256i);

        // h[i] = (r1[i] != v1[i]) ? 1 : 0
        let cmp_eq = _mm256_cmpeq_epi32(vr1, vv1);
        let hint = _mm256_andnot_si256(cmp_eq, one);

        _mm256_storeu_si256(h.as_mut_ptr().add(i) as *mut __m256i, hint);

        // Count non-zero hints
        let mask = _mm256_movemask_epi8(_mm256_cmpgt_epi32(hint, zero));
        count += (mask.count_ones() / 4) as usize;
    }

    count
}

/// Create hint with bound checking
///
/// Returns None if the number of hints exceeds omega.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn make_hint_bounded(
    z: &[i32; N],
    r: &[i32; N],
    h: &mut [i32; N],
    alpha: i32,
    omega: usize,
) -> Option<usize> {
    let count = make_hint(z, r, h, alpha);
    if count > omega {
        None
    } else {
        Some(count)
    }
}

/// Optimized make_hint with fully vectorized addition
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn make_hint_fast(
    z: &[i32; N],
    r: &[i32; N],
    h: &mut [i32; N],
    alpha: i32,
) -> usize {
    let q_vec = _mm256_set1_epi32(Q);
    let zero = _mm256_setzero_si256();
    let one = _mm256_set1_epi32(1);

    // Compute HighBits(r)
    let mut r1 = [0i32; N];
    highbits_fast(r, &mut r1, alpha);

    // Compute r + z mod Q using SIMD
    let mut r_plus_z = [0i32; N];
    for i in (0..N).step_by(8) {
        let vr = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);
        let vz = _mm256_loadu_si256(z.as_ptr().add(i) as *const __m256i);

        // Add
        let sum = _mm256_add_epi32(vr, vz);

        // Reduce: if sum >= Q, subtract Q; if sum < 0, add Q
        let ge_q = _mm256_cmpgt_epi32(sum, _mm256_sub_epi32(q_vec, one));
        let lt_zero = _mm256_cmpgt_epi32(zero, sum);

        let mut reduced = _mm256_sub_epi32(sum, _mm256_and_si256(ge_q, q_vec));
        reduced = _mm256_add_epi32(reduced, _mm256_and_si256(lt_zero, q_vec));

        _mm256_storeu_si256(r_plus_z.as_mut_ptr().add(i) as *mut __m256i, reduced);
    }

    // Compute HighBits(r + z)
    let mut v1 = [0i32; N];
    highbits_fast(&r_plus_z, &mut v1, alpha);

    // Compare and create hints - process 2 vectors per iteration
    let mut count = 0;

    for i in (0..N).step_by(16) {
        let vr1_0 = _mm256_loadu_si256(r1.as_ptr().add(i) as *const __m256i);
        let vv1_0 = _mm256_loadu_si256(v1.as_ptr().add(i) as *const __m256i);
        let vr1_1 = _mm256_loadu_si256(r1.as_ptr().add(i + 8) as *const __m256i);
        let vv1_1 = _mm256_loadu_si256(v1.as_ptr().add(i + 8) as *const __m256i);

        // h[i] = (r1[i] != v1[i]) ? 1 : 0
        let cmp_eq_0 = _mm256_cmpeq_epi32(vr1_0, vv1_0);
        let cmp_eq_1 = _mm256_cmpeq_epi32(vr1_1, vv1_1);
        let hint_0 = _mm256_andnot_si256(cmp_eq_0, one);
        let hint_1 = _mm256_andnot_si256(cmp_eq_1, one);

        _mm256_storeu_si256(h.as_mut_ptr().add(i) as *mut __m256i, hint_0);
        _mm256_storeu_si256(h.as_mut_ptr().add(i + 8) as *mut __m256i, hint_1);

        // Count non-zero hints
        let mask_0 = _mm256_movemask_epi8(_mm256_cmpgt_epi32(hint_0, zero));
        let mask_1 = _mm256_movemask_epi8(_mm256_cmpgt_epi32(hint_1, zero));
        count += (mask_0.count_ones() / 4) as usize;
        count += (mask_1.count_ones() / 4) as usize;
    }

    count
}

// ============================================================================
// UseHint
// ============================================================================

/// Apply hint to recover correct high bits
///
/// Given r and hint h, computes the corrected high bits:
///
/// ```text
/// (r1, r0) = Decompose(r, α)
/// if h == 0:
///     return r1
/// if h == 1:
///     if r0 > 0: return (r1 + 1) mod m
///     else:      return (r1 - 1) mod m
/// ```
///
/// where m = (Q-1)/α
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn use_hint(
    h: &[i32; N],
    r: &[i32; N],
    out: &mut [i32; N],
    alpha: i32,
) {
    let m = (Q - 1) / alpha;

    // Decompose r into (r1, r0)
    let mut r1 = [0i32; N];
    let mut r0 = [0i32; N];
    decompose(r, &mut r1, &mut r0, alpha);

    let m_vec = _mm256_set1_epi32(m);
    let m_minus_1 = _mm256_set1_epi32(m - 1);
    let zero = _mm256_setzero_si256();
    let one = _mm256_set1_epi32(1);

    for i in (0..N).step_by(8) {
        let vh = _mm256_loadu_si256(h.as_ptr().add(i) as *const __m256i);
        let vr1 = _mm256_loadu_si256(r1.as_ptr().add(i) as *const __m256i);
        let vr0 = _mm256_loadu_si256(r0.as_ptr().add(i) as *const __m256i);

        // Compute masks
        let hint_nonzero = _mm256_cmpgt_epi32(vh, zero);  // h != 0
        let r0_positive = _mm256_cmpgt_epi32(vr0, zero);  // r0 > 0

        // Case 1: h != 0 and r0 > 0 -> (r1 + 1) mod m
        let r1_plus_1 = _mm256_add_epi32(vr1, one);
        // Handle wraparound: if r1 + 1 == m, result is 0
        let wrap_to_zero = _mm256_cmpeq_epi32(r1_plus_1, m_vec);
        let r1_plus_mod = _mm256_andnot_si256(wrap_to_zero, r1_plus_1);

        // Case 2: h != 0 and r0 <= 0 -> (r1 - 1) mod m
        let r1_minus_1 = _mm256_sub_epi32(vr1, one);
        // Handle wraparound: if r1 == 0, result is m - 1
        let r1_is_zero = _mm256_cmpeq_epi32(vr1, zero);
        let r1_minus_mod = _mm256_blendv_epi8(r1_minus_1, m_minus_1, r1_is_zero);

        // Select based on conditions
        // Start with r1 (h == 0 case)
        let mut result = vr1;

        // Apply h != 0 and r0 > 0 case
        let case1_mask = _mm256_and_si256(hint_nonzero, r0_positive);
        result = _mm256_blendv_epi8(result, r1_plus_mod, case1_mask);

        // Apply h != 0 and r0 <= 0 case
        let case2_mask = _mm256_andnot_si256(r0_positive, hint_nonzero);
        result = _mm256_blendv_epi8(result, r1_minus_mod, case2_mask);

        _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, result);
    }
}

/// Optimized UseHint with unrolled loop
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn use_hint_fast(
    h: &[i32; N],
    r: &[i32; N],
    out: &mut [i32; N],
    alpha: i32,
) {
    let m = (Q - 1) / alpha;

    // Decompose r into (r1, r0)
    let mut r1 = [0i32; N];
    let mut r0 = [0i32; N];
    decompose(r, &mut r1, &mut r0, alpha);

    let m_vec = _mm256_set1_epi32(m);
    let m_minus_1 = _mm256_set1_epi32(m - 1);
    let zero = _mm256_setzero_si256();
    let one = _mm256_set1_epi32(1);

    // Process 2 vectors (16 elements) per iteration
    for i in (0..N).step_by(16) {
        // Load first vector
        let vh0 = _mm256_loadu_si256(h.as_ptr().add(i) as *const __m256i);
        let vr1_0 = _mm256_loadu_si256(r1.as_ptr().add(i) as *const __m256i);
        let vr0_0 = _mm256_loadu_si256(r0.as_ptr().add(i) as *const __m256i);

        // Load second vector
        let vh1 = _mm256_loadu_si256(h.as_ptr().add(i + 8) as *const __m256i);
        let vr1_1 = _mm256_loadu_si256(r1.as_ptr().add(i + 8) as *const __m256i);
        let vr0_1 = _mm256_loadu_si256(r0.as_ptr().add(i + 8) as *const __m256i);

        // Compute masks for first vector
        let hint_nonzero0 = _mm256_cmpgt_epi32(vh0, zero);
        let r0_positive0 = _mm256_cmpgt_epi32(vr0_0, zero);

        // Compute masks for second vector
        let hint_nonzero1 = _mm256_cmpgt_epi32(vh1, zero);
        let r0_positive1 = _mm256_cmpgt_epi32(vr0_1, zero);

        // Case 1: (r1 + 1) mod m for first vector
        let r1_plus_1_0 = _mm256_add_epi32(vr1_0, one);
        let wrap_to_zero0 = _mm256_cmpeq_epi32(r1_plus_1_0, m_vec);
        let r1_plus_mod0 = _mm256_andnot_si256(wrap_to_zero0, r1_plus_1_0);

        // Case 1: (r1 + 1) mod m for second vector
        let r1_plus_1_1 = _mm256_add_epi32(vr1_1, one);
        let wrap_to_zero1 = _mm256_cmpeq_epi32(r1_plus_1_1, m_vec);
        let r1_plus_mod1 = _mm256_andnot_si256(wrap_to_zero1, r1_plus_1_1);

        // Case 2: (r1 - 1) mod m for first vector
        let r1_minus_1_0 = _mm256_sub_epi32(vr1_0, one);
        let r1_is_zero0 = _mm256_cmpeq_epi32(vr1_0, zero);
        let r1_minus_mod0 = _mm256_blendv_epi8(r1_minus_1_0, m_minus_1, r1_is_zero0);

        // Case 2: (r1 - 1) mod m for second vector
        let r1_minus_1_1 = _mm256_sub_epi32(vr1_1, one);
        let r1_is_zero1 = _mm256_cmpeq_epi32(vr1_1, zero);
        let r1_minus_mod1 = _mm256_blendv_epi8(r1_minus_1_1, m_minus_1, r1_is_zero1);

        // Select results for first vector
        let mut result0 = vr1_0;
        let case1_mask0 = _mm256_and_si256(hint_nonzero0, r0_positive0);
        result0 = _mm256_blendv_epi8(result0, r1_plus_mod0, case1_mask0);
        let case2_mask0 = _mm256_andnot_si256(r0_positive0, hint_nonzero0);
        result0 = _mm256_blendv_epi8(result0, r1_minus_mod0, case2_mask0);

        // Select results for second vector
        let mut result1 = vr1_1;
        let case1_mask1 = _mm256_and_si256(hint_nonzero1, r0_positive1);
        result1 = _mm256_blendv_epi8(result1, r1_plus_mod1, case1_mask1);
        let case2_mask1 = _mm256_andnot_si256(r0_positive1, hint_nonzero1);
        result1 = _mm256_blendv_epi8(result1, r1_minus_mod1, case2_mask1);

        _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, result0);
        _mm256_storeu_si256(out.as_mut_ptr().add(i + 8) as *mut __m256i, result1);
    }
}

// ============================================================================
// Hint Utility Functions
// ============================================================================

/// Count number of hints in polynomial
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn count_hints(h: &[i32; N]) -> usize {
    let zero = _mm256_setzero_si256();
    let mut count = 0;

    for i in (0..N).step_by(8) {
        let vh = _mm256_loadu_si256(h.as_ptr().add(i) as *const __m256i);
        let nonzero = _mm256_cmpgt_epi32(vh, zero);
        let mask = _mm256_movemask_epi8(nonzero) as u32;
        count += (mask.count_ones() / 4) as usize;
    }

    count
}

/// Check if hint count is within bounds
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn check_hint_count(h: &[i32; N], omega: usize) -> bool {
    count_hints(h) <= omega
}

/// Batch hint creation for multiple polynomials
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn make_hint_batch<const K: usize>(
    z: &[[i32; N]; K],
    r: &[[i32; N]; K],
    h: &mut [[i32; N]; K],
    alpha: i32,
) -> usize {
    let mut total_count = 0;

    for i in 0..K {
        total_count += make_hint_fast(&z[i], &r[i], &mut h[i], alpha);
    }

    total_count
}

/// Batch hint application for multiple polynomials
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn use_hint_batch<const K: usize>(
    h: &[[i32; N]; K],
    r: &[[i32; N]; K],
    out: &mut [[i32; N]; K],
    alpha: i32,
) {
    for i in 0..K {
        use_hint_fast(&h[i], &r[i], &mut out[i], alpha);
    }
}

/// Verify hint polynomial format
///
/// Returns true if all coefficients are 0 or 1.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn verify_hint_format(h: &[i32; N]) -> bool {
    let zero = _mm256_setzero_si256();
    let one = _mm256_set1_epi32(1);

    for i in (0..N).step_by(8) {
        let vh = _mm256_loadu_si256(h.as_ptr().add(i) as *const __m256i);

        // Check if all elements are 0 or 1
        // Valid iff (v == 0) OR (v == 1)
        let is_zero = _mm256_cmpeq_epi32(vh, zero);
        let is_one = _mm256_cmpeq_epi32(vh, one);
        let is_valid = _mm256_or_si256(is_zero, is_one);

        // All bytes should be 0xFF for valid
        if _mm256_movemask_epi8(is_valid) != -1i32 as i32 {
            return false;
        }
    }

    true
}

/// Pack hints into compact format
///
/// Encodes hint positions using the FIPS 204 hint encoding.
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn pack_hints<const K: usize>(
    h: &[[i32; N]; K],
    packed: &mut [u8],
    omega: usize,
) -> Option<usize> {
    // FIPS 204 hint encoding:
    // For each polynomial, store positions of non-zero hints
    // followed by count

    let mut pos = 0;
    let mut total_hints = 0;

    for k in 0..K {
        let poly_start = pos;

        // Find non-zero positions in this polynomial
        for j in 0..N {
            if h[k][j] != 0 {
                if total_hints >= omega {
                    return None; // Too many hints
                }
                packed[pos] = j as u8;
                pos += 1;
                total_hints += 1;
            }
        }

        // Store count marker at end of each polynomial's hints
        // Actually in FIPS 204, we store cumulative counts after all hints
    }

    // Store cumulative hint counts for each polynomial
    let mut cumulative = 0;
    for k in 0..K {
        let hints_in_poly = count_hints(&h[k]);
        cumulative += hints_in_poly;
        packed[omega + k] = cumulative as u8;
    }

    Some(total_hints)
}

/// Unpack hints from compact format
///
/// # Safety
/// Requires AVX2 CPU support.
#[target_feature(enable = "avx2")]
pub unsafe fn unpack_hints<const K: usize>(
    packed: &[u8],
    h: &mut [[i32; N]; K],
    omega: usize,
) -> bool {
    // Initialize all hints to zero
    for k in 0..K {
        let zero = _mm256_setzero_si256();
        for i in (0..N).step_by(8) {
            _mm256_storeu_si256(h[k].as_mut_ptr().add(i) as *mut __m256i, zero);
        }
    }

    // Read cumulative counts
    let mut prev_count = 0;
    let mut pos = 0;

    for k in 0..K {
        let cumulative = packed[omega + k] as usize;

        if cumulative < prev_count || cumulative > omega {
            return false; // Invalid format
        }

        // Set hints for this polynomial
        for _ in prev_count..cumulative {
            if pos >= omega {
                return false;
            }

            let hint_pos = packed[pos] as usize;
            if hint_pos >= N {
                return false; // Invalid position
            }

            h[k][hint_pos] = 1;
            pos += 1;
        }

        prev_count = cumulative;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_make_hint() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        unsafe {
            let r = [100i32; N];
            let z = [0i32; N]; // Adding zero shouldn't change high bits
            let mut h = [0i32; N];

            let count = make_hint(&z, &r, &mut h, ALPHA_65);

            // Adding zero should produce no hints
            assert_eq!(count, 0);
            for &hint in &h {
                assert_eq!(hint, 0);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_use_hint_no_hint() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        unsafe {
            let h = [0i32; N]; // No hints
            let r = [100i32; N];
            let mut out = [0i32; N];

            use_hint(&h, &r, &mut out, ALPHA_65);

            // With no hints, output should equal HighBits(r)
            let mut expected = [0i32; N];
            highbits_fast(&r, &mut expected, ALPHA_65);

            for i in 0..N {
                assert_eq!(out[i], expected[i]);
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_count_hints() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        unsafe {
            let mut h = [0i32; N];
            h[0] = 1;
            h[50] = 1;
            h[100] = 1;

            let count = count_hints(&h);
            assert_eq!(count, 3);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_verify_hint_format() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        unsafe {
            // Valid hints (all 0 or 1)
            let mut h = [0i32; N];
            h[10] = 1;
            h[20] = 1;
            assert!(verify_hint_format(&h));

            // Invalid hint (value > 1)
            h[30] = 2;
            assert!(!verify_hint_format(&h));
        }
    }
}
