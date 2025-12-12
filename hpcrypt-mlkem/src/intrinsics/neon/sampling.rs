//! ARM NEON Sampling Operations
//!
//! This module implements CBD-2 sampling for ML-KEM using ARM NEON SIMD.
//!
//! # Performance (Measured on Ampere eMAG @ cfarm185)
//!
//! | Operation | Portable | NEON | Result |
//! |-----------|----------|------|--------|
//! | CBD-2 | 629 ns | 345 ns | 1.82x faster |
//!
//! Note: CBD-3 is NOT included as it's 15% slower than portable.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::consts::N;

/// Sample polynomial from CBD with η=2 using NEON
///
/// Each coefficient is computed as (a₀ + a₁) - (b₀ + b₁) where aᵢ, bᵢ are bits.
/// Coefficients are in range [-2, 2].
///
/// # Input
/// - `bytes`: 128 bytes of randomness (64 * η = 64 * 2)
///
/// # Output
/// - `coeffs`: 256 coefficients in range [-2, 2]
///
/// # Safety
/// Requires NEON support
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn cbd2(bytes: &[u8; 128], coeffs: &mut [i16; N]) {
    let mask_55 = vdupq_n_u8(0x55);
    let mask_03 = vdupq_n_u8(0x03);

    for chunk in 0..8 {
        let byte_offset = chunk * 16;
        let coeff_offset = chunk * 32;

        // Load 16 bytes
        let f = vld1q_u8(bytes[byte_offset..].as_ptr());

        // SWAR: accumulate pairs of bits
        let f_masked = vandq_u8(f, mask_55);
        let f_shifted = vshrq_n_u8(f, 1);
        let f_shifted_masked = vandq_u8(f_shifted, mask_55);
        let d = vaddq_u8(f_masked, f_shifted_masked);

        // Extract a-sums (bits 0-1, 4-5) and b-sums (bits 2-3, 6-7)
        let a_lo = vandq_u8(d, mask_03);
        let b_lo = vandq_u8(vshrq_n_u8(d, 2), mask_03);
        let a_hi = vandq_u8(vshrq_n_u8(d, 4), mask_03);
        let b_hi = vandq_u8(vshrq_n_u8(d, 6), mask_03);

        // Compute a - b for both sets (as signed)
        let coeff_lo = vsubq_s8(
            vreinterpretq_s8_u8(a_lo),
            vreinterpretq_s8_u8(b_lo)
        );
        let coeff_hi = vsubq_s8(
            vreinterpretq_s8_u8(a_hi),
            vreinterpretq_s8_u8(b_hi)
        );

        // Interleave: [lo0, hi0, lo1, hi1, ...]
        let interleaved = vzipq_s8(coeff_lo, coeff_hi);

        // Sign-extend from i8 to i16
        let lo_8 = vget_low_s8(interleaved.0);
        let hi_8 = vget_high_s8(interleaved.0);
        let ext_0 = vmovl_s8(lo_8);
        let ext_1 = vmovl_s8(hi_8);

        let lo_8_1 = vget_low_s8(interleaved.1);
        let hi_8_1 = vget_high_s8(interleaved.1);
        let ext_2 = vmovl_s8(lo_8_1);
        let ext_3 = vmovl_s8(hi_8_1);

        // Store 32 coefficients
        vst1q_s16(coeffs[coeff_offset..].as_mut_ptr(), ext_0);
        vst1q_s16(coeffs[coeff_offset + 8..].as_mut_ptr(), ext_1);
        vst1q_s16(coeffs[coeff_offset + 16..].as_mut_ptr(), ext_2);
        vst1q_s16(coeffs[coeff_offset + 24..].as_mut_ptr(), ext_3);
    }
}
