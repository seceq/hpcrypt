//! ARM NEON Compression Operations
//!
//! This module implements compress_d10 for ML-KEM using ARM NEON SIMD.
//!
//! # Performance (Measured on Ampere eMAG @ cfarm185)
//!
//! | Operation | Portable | NEON | Result |
//! |-----------|----------|------|--------|
//! | compress_d10 | 24.5 ns | 22.7 ns | 8% faster |
//!
//! Note: decompress_d10 and other d values are NOT included as they offer
//! no benefit over portable code.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::consts::{N, Q};

/// Magic divisor for constant-time division by q = 3329
const COMPRESS_MAGIC: u64 = 10_321_340;

/// Half of q for rounding: 3329 / 2 = 1664
const Q_HALF: u32 = 1664;

/// Compress 8 coefficients with d=10 using NEON with UMULL optimization
///
/// Maps each coefficient from [-q, 2q) to [0, 1024).
///
/// Uses NEON widening multiply (vmull_u32) to eliminate scalar 64-bit loop.
///
/// # Safety
/// Requires NEON support
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn compress_d10(coeffs: &[i16; 8]) -> [u16; 8] {
    let q_vec = vdupq_n_s16(Q);

    // Load 8 coefficients
    let x_vec = vld1q_s16(coeffs.as_ptr());

    // Branchless normalization: convert [-q, 2q) to [0, q)
    // Step 1: Add q to handle negatives -> [0, 3q)
    let pos = vaddq_s16(x_vec, q_vec);

    // Step 2: Subtract q, check if result is negative
    let high = vsubq_s16(pos, q_vec);
    let mask = vshrq_n_s16(high, 15);
    let normalized = vbslq_s16(
        vreinterpretq_u16_s16(mask),
        pos,
        high
    );

    // Step 3: Handle case where result is still >= q
    let high2 = vsubq_s16(normalized, q_vec);
    let mask2 = vshrq_n_s16(high2, 15);
    let normalized_final = vbslq_s16(
        vreinterpretq_u16_s16(mask2),
        normalized,
        high2
    );

    // Convert to u16 for widening
    let norm_u16 = vreinterpretq_u16_s16(normalized_final);

    // Widen to u32: process low 4 and high 4 coefficients
    let norm_lo_u32 = vmovl_u16(vget_low_u16(norm_u16));
    let norm_hi_u32 = vmovl_u16(vget_high_u16(norm_u16));

    // Compute (x << 10) + Q_HALF
    let shift_vec = vdupq_n_u32(10);
    let qhalf_vec = vdupq_n_u32(Q_HALF);

    let shifted_lo = vaddq_u32(vshlq_u32(norm_lo_u32, vreinterpretq_s32_u32(shift_vec)), qhalf_vec);
    let shifted_hi = vaddq_u32(vshlq_u32(norm_hi_u32, vreinterpretq_s32_u32(shift_vec)), qhalf_vec);

    // Magic constant for division
    let magic = vdup_n_u32(COMPRESS_MAGIC as u32);

    // Widening multiply: 32x32 -> 64 bit
    let prod_0_1 = vmull_u32(vget_low_u32(shifted_lo), magic);
    let prod_2_3 = vmull_u32(vget_high_u32(shifted_lo), magic);
    let prod_4_5 = vmull_u32(vget_low_u32(shifted_hi), magic);
    let prod_6_7 = vmull_u32(vget_high_u32(shifted_hi), magic);

    // Shift right by 35
    let shifted_0_1 = vshrq_n_u64(prod_0_1, 35);
    let shifted_2_3 = vshrq_n_u64(prod_2_3, 35);
    let shifted_4_5 = vshrq_n_u64(prod_4_5, 35);
    let shifted_6_7 = vshrq_n_u64(prod_6_7, 35);

    // Narrow from u64 to u32
    let result_0_1 = vmovn_u64(shifted_0_1);
    let result_2_3 = vmovn_u64(shifted_2_3);
    let result_4_5 = vmovn_u64(shifted_4_5);
    let result_6_7 = vmovn_u64(shifted_6_7);

    // Combine back to vectors
    let result_lo = vcombine_u32(result_0_1, result_2_3);
    let result_hi = vcombine_u32(result_4_5, result_6_7);

    // Mask to 10 bits (0x3FF)
    let mask_10 = vdupq_n_u32(0x3FF);
    let masked_lo = vandq_u32(result_lo, mask_10);
    let masked_hi = vandq_u32(result_hi, mask_10);

    // Narrow back to u16
    let result_u16_lo = vmovn_u32(masked_lo);
    let result_u16_hi = vmovn_u32(masked_hi);
    let result_vec = vcombine_u16(result_u16_lo, result_u16_hi);

    // Store result
    let mut result = [0u16; 8];
    vst1q_u16(result.as_mut_ptr(), result_vec);
    result
}
