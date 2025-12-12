//! ARM NEON Hint Operations for ML-DSA
//!
//! Provides vectorized MakeHint and UseHint operations.
//!
//! # Optimization Strategy
//!
//! Uses magic multiplication for division by ALPHA (same as rounding.rs).
//! Conditional logic uses NEON comparison and select instructions.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::consts::{Q, N, VECS_PER_POLY, ALPHA_44, ALPHA_65};

// Magic multiplication constants (same as rounding.rs)
const MAGIC_44: u32 = 22550;
const MAGIC_65: u32 = 8200;

/// Vectorized division by alpha using magic multiplication
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn div_by_alpha_vec(r: int32x4_t, half_alpha: int32x4_t, magic: u32) -> int32x4_t {
    let r_biased = vaddq_s32(r, half_alpha);
    let r_u32 = vreinterpretq_u32_s32(r_biased);
    let magic_vec = vdupq_n_u32(magic);

    let r_lo = vget_low_u32(r_u32);
    let r_hi = vget_high_u32(r_u32);
    let magic_lo = vget_low_u32(magic_vec);
    let magic_hi = vget_high_u32(magic_vec);

    let prod_lo = vmull_u32(r_lo, magic_lo);
    let prod_hi = vmull_u32(r_hi, magic_hi);

    let quot_lo = vshrn_n_u64(prod_lo, 32);
    let quot_hi = vshrn_n_u64(prod_hi, 32);
    let quot = vcombine_u32(quot_lo, quot_hi);

    vreinterpretq_s32_u32(quot)
}

/// Compute HighBits inline for a single vector
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn highbits_vec(
    vr: int32x4_t,
    alpha_vec: int32x4_t,
    half_alpha: int32x4_t,
    neg_half_alpha: int32x4_t,
    m_vec: int32x4_t,
    one: int32x4_t,
    magic: u32,
) -> int32x4_t {
    // r1 = (r + alpha/2) / alpha
    let vr1 = div_by_alpha_vec(vr, half_alpha, magic);

    // r0 = r - r1 * alpha
    let vr0 = vmlsq_s32(vr, vr1, alpha_vec);

    // if r0 > alpha/2, r1++
    let cond_high = vcgtq_s32(vr0, half_alpha);
    let vr1_adj_high = vaddq_s32(vr1, vandq_s32(vreinterpretq_s32_u32(cond_high), one));

    // Recompute r0
    let vr0_adj = vmlsq_s32(vr, vr1_adj_high, alpha_vec);

    // if r0 <= -alpha/2, r1--
    let cond_low = vcleq_s32(vr0_adj, neg_half_alpha);
    let vr1_adj = vsubq_s32(vr1_adj_high, vandq_s32(vreinterpretq_s32_u32(cond_low), one));

    // if r1 == m, r1 = 0
    let cond_wrap = vceqq_s32(vr1_adj, m_vec);
    vbicq_s32(vr1_adj, vreinterpretq_s32_u32(cond_wrap))
}

// ============================================================================
// MakeHint
// ============================================================================

/// Compute hint polynomial: h[i] = 1 if HighBits(z[i] + r[i]) != HighBits(r[i])
///
/// Returns the hint polynomial (0 or 1 coefficients).
///
/// Fully vectorized using magic multiplication for division.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn make_hint_fast(
    z: &[i32; N],
    r: &[i32; N],
    h: &mut [i32; N],
    alpha: i32,
) {
    let alpha_vec = vdupq_n_s32(alpha);
    let half_alpha_val = alpha / 2;
    let half_alpha = vdupq_n_s32(half_alpha_val);
    let neg_half_alpha = vdupq_n_s32(-half_alpha_val);
    let one = vdupq_n_s32(1);

    let m = (Q - 1) / alpha;
    let m_vec = vdupq_n_s32(m);

    let magic = if alpha == ALPHA_44 { MAGIC_44 } else { MAGIC_65 };

    for i in 0..VECS_PER_POLY {
        let vz = vld1q_s32(z.as_ptr().add(i * 4));
        let vr = vld1q_s32(r.as_ptr().add(i * 4));

        // Compute HighBits(r)
        let hb_r = highbits_vec(vr, alpha_vec, half_alpha, neg_half_alpha, m_vec, one, magic);

        // Compute z + r and HighBits(z + r)
        let sum = vaddq_s32(vz, vr);
        let hb_sum = highbits_vec(sum, alpha_vec, half_alpha, neg_half_alpha, m_vec, one, magic);

        // Hint is 1 if highbits differ: h = (hb_r != hb_sum) ? 1 : 0
        let diff = vceqq_s32(hb_r, hb_sum);
        // diff is all 1s if equal, all 0s if not equal
        // We want 1 if not equal, so invert and mask with 1
        let not_equal = vmvnq_u32(diff);
        let hint = vandq_s32(vreinterpretq_s32_u32(not_equal), one);

        vst1q_s32(h.as_mut_ptr().add(i * 4), hint);
    }
}

// ============================================================================
// UseHint
// ============================================================================

/// Compute LowBits inline for a single vector (for use_hint)
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn lowbits_vec(
    vr: int32x4_t,
    alpha_vec: int32x4_t,
    half_alpha: int32x4_t,
    neg_half_alpha: int32x4_t,
    magic: u32,
) -> int32x4_t {
    let vr1 = div_by_alpha_vec(vr, half_alpha, magic);
    let vr0 = vmlsq_s32(vr, vr1, alpha_vec);

    let cond_high = vcgtq_s32(vr0, half_alpha);
    let vr0_adj_high = vsubq_s32(vr0, vandq_s32(vreinterpretq_s32_u32(cond_high), alpha_vec));

    let cond_low = vcleq_s32(vr0_adj_high, neg_half_alpha);
    vaddq_s32(vr0_adj_high, vandq_s32(vreinterpretq_s32_u32(cond_low), alpha_vec))
}

/// Apply hints to recover w1': w1'[i] = UseHint(h[i], w[i])
///
/// If h[i] = 0: w1'[i] = HighBits(w[i])
/// If h[i] = 1: Adjust HighBits based on sign of LowBits
///
/// Fully vectorized using magic multiplication for division.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn use_hint_fast(
    h: &[i32; N],
    w: &[i32; N],
    w1_prime: &mut [i32; N],
    alpha: i32,
) {
    let alpha_vec = vdupq_n_s32(alpha);
    let half_alpha_val = alpha / 2;
    let half_alpha = vdupq_n_s32(half_alpha_val);
    let neg_half_alpha = vdupq_n_s32(-half_alpha_val);
    let one = vdupq_n_s32(1);
    let zero = vdupq_n_s32(0);

    let m = (Q - 1) / alpha;
    let m_vec = vdupq_n_s32(m);
    let m_minus_1 = vdupq_n_s32(m - 1);

    let magic = if alpha == ALPHA_44 { MAGIC_44 } else { MAGIC_65 };

    for i in 0..VECS_PER_POLY {
        let vh = vld1q_s32(h.as_ptr().add(i * 4));
        let vw = vld1q_s32(w.as_ptr().add(i * 4));

        // Compute HighBits(w) = w1
        let vw1 = highbits_vec(vw, alpha_vec, half_alpha, neg_half_alpha, m_vec, one, magic);

        // Compute LowBits(w) = w0 (for determining adjustment direction)
        let vw0 = lowbits_vec(vw, alpha_vec, half_alpha, neg_half_alpha, magic);

        // If hint != 0, we need to adjust w1
        let hint_active = vcgtq_s32(vh, zero); // hint != 0

        // If w0 > 0, increment w1; else decrement
        let w0_positive = vcgtq_s32(vw0, zero);

        // w1 + 1, wrapping: if w1 + 1 >= m, result = 0
        let w1_inc = vaddq_s32(vw1, one);
        let inc_wrap = vcgeq_s32(w1_inc, m_vec);
        let w1_inc_wrapped = vbicq_s32(w1_inc, vreinterpretq_s32_u32(inc_wrap));

        // w1 - 1, wrapping: if w1 == 0, result = m - 1
        let w1_dec = vsubq_s32(vw1, one);
        let dec_wrap = vceqq_s32(vw1, zero);
        let w1_dec_wrapped = vbslq_s32(dec_wrap, m_minus_1, w1_dec);

        // Select between increment and decrement based on w0 sign
        let w1_adjusted = vbslq_s32(w0_positive, w1_inc_wrapped, w1_dec_wrapped);

        // Select between original w1 and adjusted based on hint
        let w1_final = vbslq_s32(hint_active, w1_adjusted, vw1);

        vst1q_s32(w1_prime.as_mut_ptr().add(i * 4), w1_final);
    }
}

// ============================================================================
// Hint Counting
// ============================================================================

/// Count number of hints (non-zero values) in hint polynomial
///
/// Uses efficient horizontal sum with vaddvq_s32.
///
/// # Safety
/// Requires NEON CPU support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn count_hints(h: &[i32; N]) -> usize {
    let zero = vdupq_n_s32(0);
    let one = vdupq_n_s32(1);
    let mut count_vec = vdupq_n_s32(0);

    // Process 4 vectors at a time for better ILP
    let mut i = 0;
    while i + 4 <= VECS_PER_POLY {
        let vh0 = vld1q_s32(h.as_ptr().add(i * 4));
        let vh1 = vld1q_s32(h.as_ptr().add((i + 1) * 4));
        let vh2 = vld1q_s32(h.as_ptr().add((i + 2) * 4));
        let vh3 = vld1q_s32(h.as_ptr().add((i + 3) * 4));

        let nz0 = vandq_s32(vreinterpretq_s32_u32(vmvnq_u32(vceqq_s32(vh0, zero))), one);
        let nz1 = vandq_s32(vreinterpretq_s32_u32(vmvnq_u32(vceqq_s32(vh1, zero))), one);
        let nz2 = vandq_s32(vreinterpretq_s32_u32(vmvnq_u32(vceqq_s32(vh2, zero))), one);
        let nz3 = vandq_s32(vreinterpretq_s32_u32(vmvnq_u32(vceqq_s32(vh3, zero))), one);

        // Tree reduction for better ILP
        let sum01 = vaddq_s32(nz0, nz1);
        let sum23 = vaddq_s32(nz2, nz3);
        count_vec = vaddq_s32(count_vec, vaddq_s32(sum01, sum23));

        i += 4;
    }

    // Handle remaining vectors
    while i < VECS_PER_POLY {
        let vh = vld1q_s32(h.as_ptr().add(i * 4));
        let is_nonzero = vmvnq_u32(vceqq_s32(vh, zero));
        let add_mask = vandq_s32(vreinterpretq_s32_u32(is_nonzero), one);
        count_vec = vaddq_s32(count_vec, add_mask);
        i += 1;
    }

    // Efficient horizontal sum
    vaddvq_s32(count_vec) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_count_hints() {
        let mut h = [0i32; N];
        h[0] = 1;
        h[10] = 1;
        h[100] = 1;
        h[200] = 1;

        unsafe {
            let count = count_hints(&h);
            assert_eq!(count, 4);
        }
    }
}
