//! ARM NEON Number Theoretic Transform (NTT)
//!
//! This module implements NEON NTT optimizations for ML-KEM.
//!
//! # Performance (Measured on Neoverse-N1 @ cfarm424)
//!
//! | Implementation | Forward NTT | Inverse NTT |
//! |----------------|-------------|-------------|
//! | Portable | 702 ns | 973 ns |
//! | NEON | 662 ns | 816 ns |
//! | Speedup | 1.06x | 1.19x |

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::consts::{N, Q, QINV, F, ZETAS_PRECOMP, BARRETT_V};
use super::arith::{fqmulprecomp_preloaded, barrett_reduce_preloaded};

/// Forward NTT using NEON with fqmulprecomp
///
/// Transforms polynomial from coefficient domain to NTT domain.
///
/// # Safety
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn ntt_inplace(poly: &mut [i16; N]) {
    let q_vec = vdupq_n_s16(Q);
    let mut k = 1usize;

    // Layer 1: len=128
    {
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);
        k += 1;

        for i in 0..16 {
            let offset = i * 8;
            let a = vld1q_s16(poly[offset..].as_ptr());
            let b = vld1q_s16(poly[offset + 128..].as_ptr());

            let t = fqmulprecomp_preloaded(b, zl_vec, zh_vec, q_vec);
            let a_new = vaddq_s16(a, t);
            let b_new = vsubq_s16(a, t);

            vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
            vst1q_s16(poly[offset + 128..].as_mut_ptr(), b_new);
        }
    }

    // Layer 2: len=64
    {
        for half in 0..2 {
            let (zl, zh) = ZETAS_PRECOMP.get(k);
            let zl_vec = vdupq_n_s16(zl);
            let zh_vec = vdupq_n_s16(zh);
            k += 1;
            let base = half * 128;

            for i in 0..8 {
                let offset = base + i * 8;
                let a = vld1q_s16(poly[offset..].as_ptr());
                let b = vld1q_s16(poly[offset + 64..].as_ptr());

                let t = fqmulprecomp_preloaded(b, zl_vec, zh_vec, q_vec);
                let a_new = vaddq_s16(a, t);
                let b_new = vsubq_s16(a, t);

                vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
                vst1q_s16(poly[offset + 64..].as_mut_ptr(), b_new);
            }
        }
    }

    // Layer 3: len=32
    {
        for quarter in 0..4 {
            let (zl, zh) = ZETAS_PRECOMP.get(k);
            let zl_vec = vdupq_n_s16(zl);
            let zh_vec = vdupq_n_s16(zh);
            k += 1;
            let base = quarter * 64;

            for i in 0..4 {
                let offset = base + i * 8;
                let a = vld1q_s16(poly[offset..].as_ptr());
                let b = vld1q_s16(poly[offset + 32..].as_ptr());

                let t = fqmulprecomp_preloaded(b, zl_vec, zh_vec, q_vec);
                let a_new = vaddq_s16(a, t);
                let b_new = vsubq_s16(a, t);

                vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
                vst1q_s16(poly[offset + 32..].as_mut_ptr(), b_new);
            }
        }
    }

    // Layer 4: len=16
    {
        for eighth in 0..8 {
            let (zl, zh) = ZETAS_PRECOMP.get(k);
            let zl_vec = vdupq_n_s16(zl);
            let zh_vec = vdupq_n_s16(zh);
            k += 1;
            let base = eighth * 32;

            for i in 0..2 {
                let offset = base + i * 8;
                let a = vld1q_s16(poly[offset..].as_ptr());
                let b = vld1q_s16(poly[offset + 16..].as_ptr());

                let t = fqmulprecomp_preloaded(b, zl_vec, zh_vec, q_vec);
                let a_new = vaddq_s16(a, t);
                let b_new = vsubq_s16(a, t);

                vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
                vst1q_s16(poly[offset + 16..].as_mut_ptr(), b_new);
            }
        }
    }

    // Layer 5: len=8
    for section in 0..16 {
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);
        k += 1;

        let base = section * 16;
        let a = vld1q_s16(poly[base..].as_ptr());
        let b = vld1q_s16(poly[base + 8..].as_ptr());

        let t = fqmulprecomp_preloaded(b, zl_vec, zh_vec, q_vec);
        let a_new = vaddq_s16(a, t);
        let b_new = vsubq_s16(a, t);

        vst1q_s16(poly[base..].as_mut_ptr(), a_new);
        vst1q_s16(poly[base + 8..].as_mut_ptr(), b_new);
    }

    // Layer 6: len=4
    for pair in 0..16 {
        let section0 = pair * 2;
        let section1 = pair * 2 + 1;

        let (zl0, zh0) = ZETAS_PRECOMP.get(k);
        let (zl1, zh1) = ZETAS_PRECOMP.get(k + 1);
        k += 2;

        let base0 = section0 * 8;
        let base1 = section1 * 8;

        let v0 = vld1q_s16(poly[base0..].as_ptr());
        let v1 = vld1q_s16(poly[base1..].as_ptr());

        let a0 = vget_low_s16(v0);
        let b0 = vget_high_s16(v0);
        let a1 = vget_low_s16(v1);
        let b1 = vget_high_s16(v1);

        let a_vec = vcombine_s16(a0, a1);
        let b_vec = vcombine_s16(b0, b1);

        let zl0_half = vdup_n_s16(zl0);
        let zl1_half = vdup_n_s16(zl1);
        let zh0_half = vdup_n_s16(zh0);
        let zh1_half = vdup_n_s16(zh1);
        let zl_vec = vcombine_s16(zl0_half, zl1_half);
        let zh_vec = vcombine_s16(zh0_half, zh1_half);

        let t = fqmulprecomp_preloaded(b_vec, zl_vec, zh_vec, q_vec);
        let a_new = vaddq_s16(a_vec, t);
        let b_new = vsubq_s16(a_vec, t);

        let a_new_0 = vget_low_s16(a_new);
        let b_new_0 = vget_low_s16(b_new);
        let a_new_1 = vget_high_s16(a_new);
        let b_new_1 = vget_high_s16(b_new);

        let result0 = vcombine_s16(a_new_0, b_new_0);
        let result1 = vcombine_s16(a_new_1, b_new_1);

        vst1q_s16(poly[base0..].as_mut_ptr(), result0);
        vst1q_s16(poly[base1..].as_mut_ptr(), result1);
    }

    // Layer 7: len=2 (scalar)
    for section in 0..64 {
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        k += 1;

        let base = section * 4;
        let a0 = poly[base];
        let a1 = poly[base + 1];
        let b0 = poly[base + 2];
        let b1 = poly[base + 3];

        let t0 = {
            let x = (b0 as i32).wrapping_mul(zl as i32) as i16;
            let b = (((b0 as i32) * (zh as i32)) >> 16) as i16;
            let xq = (((x as i32) * (Q as i32)) >> 16) as i16;
            b.wrapping_sub(xq)
        };
        let t1 = {
            let x = (b1 as i32).wrapping_mul(zl as i32) as i16;
            let b = (((b1 as i32) * (zh as i32)) >> 16) as i16;
            let xq = (((x as i32) * (Q as i32)) >> 16) as i16;
            b.wrapping_sub(xq)
        };

        poly[base] = a0.wrapping_add(t0);
        poly[base + 1] = a1.wrapping_add(t1);
        poly[base + 2] = a0.wrapping_sub(t0);
        poly[base + 3] = a1.wrapping_sub(t1);
    }
}

/// Inverse NTT using NEON with fqmulprecomp
///
/// Transforms polynomial from NTT domain back to coefficient domain.
///
/// # Safety
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn intt_inplace(poly: &mut [i16; N]) {
    let q_vec = vdupq_n_s16(Q);
    let v_vec = vdupq_n_s16(BARRETT_V);

    let mut k = 127usize;

    // Layer 7: len=2 (scalar)
    for section in (0..64).rev() {
        k -= 1;
        let (zl, zh) = ZETAS_PRECOMP.get(k);

        let base = section * 4;
        let a0 = poly[base];
        let a1 = poly[base + 1];
        let b0 = poly[base + 2];
        let b1 = poly[base + 3];

        let a0_new = a0.wrapping_add(b0);
        let a1_new = a1.wrapping_add(b1);

        let diff0 = a0.wrapping_sub(b0);
        let diff1 = a1.wrapping_sub(b1);

        let b0_new = {
            let x = (diff0 as i32).wrapping_mul(zl as i32) as i16;
            let b = (((diff0 as i32) * (zh as i32)) >> 16) as i16;
            let xq = (((x as i32) * (Q as i32)) >> 16) as i16;
            b.wrapping_sub(xq)
        };
        let b1_new = {
            let x = (diff1 as i32).wrapping_mul(zl as i32) as i16;
            let b = (((diff1 as i32) * (zh as i32)) >> 16) as i16;
            let xq = (((x as i32) * (Q as i32)) >> 16) as i16;
            b.wrapping_sub(xq)
        };

        poly[base] = a0_new;
        poly[base + 1] = a1_new;
        poly[base + 2] = b0_new;
        poly[base + 3] = b1_new;
    }

    // Layer 6: len=4
    k = 64;
    for section in (0..32).rev() {
        k -= 1;
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);

        let base = section * 8;
        let v = vld1q_s16(poly[base..].as_ptr());

        let lo = vget_low_s16(v);
        let hi = vget_high_s16(v);

        let a_vec = vcombine_s16(lo, lo);
        let b_vec = vcombine_s16(hi, hi);

        let a_new_full = vaddq_s16(a_vec, b_vec);
        let diff = vsubq_s16(a_vec, b_vec);
        let b_new_full = fqmulprecomp_preloaded(diff, zl_vec, zh_vec, q_vec);

        let a_new = vget_low_s16(a_new_full);
        let b_new = vget_low_s16(b_new_full);
        let result = vcombine_s16(a_new, b_new);

        vst1q_s16(poly[base..].as_mut_ptr(), result);
    }

    // Layer 5: len=8
    k = 32;
    for section in (0..16).rev() {
        k -= 1;
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);

        let base = section * 16;
        let a = vld1q_s16(poly[base..].as_ptr());
        let b = vld1q_s16(poly[base + 8..].as_ptr());

        let a_new = barrett_reduce_preloaded(vaddq_s16(a, b), q_vec, v_vec);
        let diff = vsubq_s16(a, b);
        let b_new = fqmulprecomp_preloaded(diff, zl_vec, zh_vec, q_vec);

        vst1q_s16(poly[base..].as_mut_ptr(), a_new);
        vst1q_s16(poly[base + 8..].as_mut_ptr(), b_new);
    }

    k = 16;

    // Layer 4: len=16
    for eighth in (0..8).rev() {
        k -= 1;
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);
        let base = eighth * 32;

        for i in 0..2 {
            let offset = base + i * 8;
            let a = vld1q_s16(poly[offset..].as_ptr());
            let b = vld1q_s16(poly[offset + 16..].as_ptr());

            let a_new = barrett_reduce_preloaded(vaddq_s16(a, b), q_vec, v_vec);
            let diff = vsubq_s16(a, b);
            let b_new = fqmulprecomp_preloaded(diff, zl_vec, zh_vec, q_vec);

            vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
            vst1q_s16(poly[offset + 16..].as_mut_ptr(), b_new);
        }
    }

    k = 8;

    // Layer 3: len=32
    for quarter in (0..4).rev() {
        k -= 1;
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);
        let base = quarter * 64;

        for i in 0..4 {
            let offset = base + i * 8;
            let a = vld1q_s16(poly[offset..].as_ptr());
            let b = vld1q_s16(poly[offset + 32..].as_ptr());

            let a_new = barrett_reduce_preloaded(vaddq_s16(a, b), q_vec, v_vec);
            let diff = vsubq_s16(a, b);
            let b_new = fqmulprecomp_preloaded(diff, zl_vec, zh_vec, q_vec);

            vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
            vst1q_s16(poly[offset + 32..].as_mut_ptr(), b_new);
        }
    }

    k = 4;

    // Layer 2: len=64
    for half in (0..2).rev() {
        k -= 1;
        let (zl, zh) = ZETAS_PRECOMP.get(k);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);
        let base = half * 128;

        for i in 0..8 {
            let offset = base + i * 8;
            let a = vld1q_s16(poly[offset..].as_ptr());
            let b = vld1q_s16(poly[offset + 64..].as_ptr());

            let a_new = barrett_reduce_preloaded(vaddq_s16(a, b), q_vec, v_vec);
            let diff = vsubq_s16(a, b);
            let b_new = fqmulprecomp_preloaded(diff, zl_vec, zh_vec, q_vec);

            vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
            vst1q_s16(poly[offset + 64..].as_mut_ptr(), b_new);
        }
    }

    // Layer 1: len=128 with F scaling
    {
        let (zl, zh) = ZETAS_PRECOMP.get(1);
        let zl_vec = vdupq_n_s16(zl);
        let zh_vec = vdupq_n_s16(zh);

        let f_zl = ((F as i32).wrapping_mul(QINV as i32) & 0xFFFF) as i16;
        let f_zl_vec = vdupq_n_s16(f_zl);
        let f_zh_vec = vdupq_n_s16(F);

        for i in 0..16 {
            let offset = i * 8;
            let a = vld1q_s16(poly[offset..].as_ptr());
            let b = vld1q_s16(poly[offset + 128..].as_ptr());

            let sum = vaddq_s16(a, b);
            let diff = vsubq_s16(a, b);
            let b_new_raw = fqmulprecomp_preloaded(diff, zl_vec, zh_vec, q_vec);

            let a_new = fqmulprecomp_preloaded(sum, f_zl_vec, f_zh_vec, q_vec);
            let b_new = fqmulprecomp_preloaded(b_new_raw, f_zl_vec, f_zh_vec, q_vec);

            vst1q_s16(poly[offset..].as_mut_ptr(), a_new);
            vst1q_s16(poly[offset + 128..].as_mut_ptr(), b_new);
        }
    }
}
