//! NTT with Software Prefetching
//!
//! Enhanced NTT implementation with software prefetching hints to reduce cache misses
//! and improve memory access latency.
//!
//! # Performance Target
//!
//! Expected: 3-8% improvement over standard NTT by:
//! - Prefetching butterfly operands ahead of access
//! - Reducing L1 cache misses in inner loops
//! - Complementing hardware prefetchers for better prediction

extern crate alloc;
use alloc::vec::Vec;

use crate::params::{N, Q};
use crate::poly::Poly;
use crate::ntt::{ZETAS, montgomery_reduce};
use crate::prefetch::prefetch_poly_coeffs;

/// Reduce coefficient to range (-Q/2, Q/2]
#[inline(always)]
fn reduce32(a: i32) -> i32 {
    let mut t = a;
    t = (t + (1 << 22)) >> 23;
    t = a - t * Q;
    t
}

/// Rolling macro for NTT butterfly with prefetching
///
/// Combines butterfly operation with prefetch hints for next iteration.
/// Prefetches 2-4 cache lines ahead to hide memory latency.
macro_rules! ntt_butterfly_prefetch {
    ($coeffs:expr, $start:expr, $zeta:expr, $prefetch_start:expr, $len:expr) => {{
        // Prefetch operands for next iteration (2 cache lines ahead)
        if $prefetch_start < N {
            unsafe {
                let ptr = $coeffs.as_ptr().add($prefetch_start);
                crate::prefetch::prefetch_read(ptr);
            }
        }
        if $prefetch_start + $len < N {
            unsafe {
                let ptr = $coeffs.as_ptr().add($prefetch_start + $len);
                crate::prefetch::prefetch_read(ptr);
            }
        }

        // Standard butterfly operation
        let t = montgomery_reduce(($zeta as i64) * ($coeffs[$start + $len] as i64));
        $coeffs[$start + $len] = $coeffs[$start] - t;
        $coeffs[$start] = $coeffs[$start] + t;
    }};
}

/// Forward NTT with prefetching
///
/// Adds software prefetch hints to the standard NTT algorithm.
/// Prefetches butterfly operands 16-32 coefficients ahead to hide memory latency.
///
/// # Performance
/// - Expected: 3-8% faster than standard NTT
/// - Reduced L1/L2 cache misses
/// - Better utilization of memory bandwidth
///
/// # Arguments
/// * `poly` - Polynomial to transform (will be modified in-place)
#[inline]
pub fn ntt_with_prefetch(poly: &Poly) -> Poly {
    let mut a = poly.clone();
    let mut k: usize = 0;

    // =========================================================================
    // Standard loops for len = 128, 64, 32, 16, 8 with prefetching
    // =========================================================================

    let mut len: usize = 128;
    while len >= 8 {
        let mut start: usize = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];

            let mut j = start;
            while j < start + len {
                // Prefetch 32 elements ahead (2 cache lines)
                let prefetch_j = j + 32;
                if prefetch_j < start + len {
                    prefetch_poly_coeffs(&a, prefetch_j);
                    prefetch_poly_coeffs(&a, prefetch_j + len);
                }

                // Butterfly operation
                let t = montgomery_reduce((zeta as i64) * (a.coeffs[j + len] as i64));
                a.coeffs[j + len] = a.coeffs[j] - t;
                a.coeffs[j] = a.coeffs[j] + t;
                j += 1;
            }

            start = j + len;
        }
        len >>= 1;
    }

    // =========================================================================
    // Merged layers (len = 4, 2, 1) with rolling macro prefetching
    // =========================================================================

    // len = 4: 32 blocks of 8 coefficients
    for block in 0..32 {
        k += 1;
        let zeta = ZETAS[k];
        let start = block * 8;

        // Prefetch next block (8 coefficients ahead)
        let prefetch_start = (block + 1) * 8;
        if prefetch_start < N {
            prefetch_poly_coeffs(&a, prefetch_start);
        }

        // 4-way unrolled butterfly
        let t0 = montgomery_reduce((zeta as i64) * (a.coeffs[start + 4] as i64));
        a.coeffs[start + 4] = a.coeffs[start] - t0;
        a.coeffs[start] = a.coeffs[start] + t0;

        let t1 = montgomery_reduce((zeta as i64) * (a.coeffs[start + 5] as i64));
        a.coeffs[start + 5] = a.coeffs[start + 1] - t1;
        a.coeffs[start + 1] = a.coeffs[start + 1] + t1;

        let t2 = montgomery_reduce((zeta as i64) * (a.coeffs[start + 6] as i64));
        a.coeffs[start + 6] = a.coeffs[start + 2] - t2;
        a.coeffs[start + 2] = a.coeffs[start + 2] + t2;

        let t3 = montgomery_reduce((zeta as i64) * (a.coeffs[start + 7] as i64));
        a.coeffs[start + 7] = a.coeffs[start + 3] - t3;
        a.coeffs[start + 3] = a.coeffs[start + 3] + t3;
    }

    // len = 2: 64 blocks of 4 coefficients
    for block in 0..64 {
        k += 1;
        let zeta = ZETAS[k];
        let start = block * 4;

        // Prefetch next block
        let prefetch_start = (block + 2) * 4;
        if prefetch_start < N {
            prefetch_poly_coeffs(&a, prefetch_start);
        }

        let t0 = montgomery_reduce((zeta as i64) * (a.coeffs[start + 2] as i64));
        a.coeffs[start + 2] = a.coeffs[start] - t0;
        a.coeffs[start] = a.coeffs[start] + t0;

        let t1 = montgomery_reduce((zeta as i64) * (a.coeffs[start + 3] as i64));
        a.coeffs[start + 3] = a.coeffs[start + 1] - t1;
        a.coeffs[start + 1] = a.coeffs[start + 1] + t1;
    }

    // len = 1: 128 blocks of 2 coefficients
    for block in 0..128 {
        k += 1;
        let zeta = ZETAS[k];
        let start = block * 2;

        // Prefetch 2 blocks ahead
        let prefetch_start = (block + 4) * 2;
        if prefetch_start < N {
            prefetch_poly_coeffs(&a, prefetch_start);
        }

        let t = montgomery_reduce((zeta as i64) * (a.coeffs[start + 1] as i64));
        a.coeffs[start + 1] = a.coeffs[start] - t;
        a.coeffs[start] = a.coeffs[start] + t;
    }

    a
}

/// Inverse NTT with prefetching
///
/// Adds software prefetch hints to inverse NTT for symmetric performance benefits.
#[inline]
pub fn inv_ntt_with_prefetch(poly: &Poly) -> Poly {
    let mut a = poly.clone();
    let mut k: usize = 256;

    // len = 1: 128 blocks
    for block in 0..128 {
        k -= 1;
        let zeta = -ZETAS[k];
        let start = block * 2;

        // Prefetch ahead
        let prefetch_start = (block + 4) * 2;
        if prefetch_start < N {
            prefetch_poly_coeffs(&a, prefetch_start);
        }

        let t = a.coeffs[start];
        a.coeffs[start] = t + a.coeffs[start + 1];
        a.coeffs[start + 1] = t - a.coeffs[start + 1];
        a.coeffs[start + 1] = montgomery_reduce((zeta as i64) * (a.coeffs[start + 1] as i64));
    }

    // len = 2: 64 blocks
    for block in 0..64 {
        k -= 1;
        let zeta = -ZETAS[k];
        let start = block * 4;

        // Prefetch ahead
        let prefetch_start = (block + 2) * 4;
        if prefetch_start < N {
            prefetch_poly_coeffs(&a, prefetch_start);
        }

        let t0 = a.coeffs[start];
        a.coeffs[start] = t0 + a.coeffs[start + 2];
        a.coeffs[start + 2] = t0 - a.coeffs[start + 2];
        a.coeffs[start + 2] = montgomery_reduce((zeta as i64) * (a.coeffs[start + 2] as i64));

        let t1 = a.coeffs[start + 1];
        a.coeffs[start + 1] = t1 + a.coeffs[start + 3];
        a.coeffs[start + 3] = t1 - a.coeffs[start + 3];
        a.coeffs[start + 3] = montgomery_reduce((zeta as i64) * (a.coeffs[start + 3] as i64));
    }

    // len = 4: 32 blocks
    for block in 0..32 {
        k -= 1;
        let zeta = -ZETAS[k];
        let start = block * 8;

        // Prefetch ahead
        let prefetch_start = (block + 1) * 8;
        if prefetch_start < N {
            prefetch_poly_coeffs(&a, prefetch_start);
        }

        let t0 = a.coeffs[start];
        a.coeffs[start] = t0 + a.coeffs[start + 4];
        a.coeffs[start + 4] = t0 - a.coeffs[start + 4];
        a.coeffs[start + 4] = montgomery_reduce((zeta as i64) * (a.coeffs[start + 4] as i64));

        let t1 = a.coeffs[start + 1];
        a.coeffs[start + 1] = t1 + a.coeffs[start + 5];
        a.coeffs[start + 5] = t1 - a.coeffs[start + 5];
        a.coeffs[start + 5] = montgomery_reduce((zeta as i64) * (a.coeffs[start + 5] as i64));

        let t2 = a.coeffs[start + 2];
        a.coeffs[start + 2] = t2 + a.coeffs[start + 6];
        a.coeffs[start + 6] = t2 - a.coeffs[start + 6];
        a.coeffs[start + 6] = montgomery_reduce((zeta as i64) * (a.coeffs[start + 6] as i64));

        let t3 = a.coeffs[start + 3];
        a.coeffs[start + 3] = t3 + a.coeffs[start + 7];
        a.coeffs[start + 7] = t3 - a.coeffs[start + 7];
        a.coeffs[start + 7] = montgomery_reduce((zeta as i64) * (a.coeffs[start + 7] as i64));
    }

    // Larger layers (len >= 8)
    let mut len: usize = 8;
    while len < N {
        let mut start: usize = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];

            let mut j = start;
            while j < start + len {
                // Prefetch ahead
                let prefetch_j = j + 32;
                if prefetch_j < start + len {
                    prefetch_poly_coeffs(&a, prefetch_j);
                    prefetch_poly_coeffs(&a, prefetch_j + len);
                }

                let t = a.coeffs[j];
                a.coeffs[j] = t + a.coeffs[j + len];
                a.coeffs[j + len] = t - a.coeffs[j + len];
                a.coeffs[j + len] = montgomery_reduce((zeta as i64) * (a.coeffs[j + len] as i64));
                j += 1;
            }

            start = j + len;
        }
        len <<= 1;
    }

    // Final normalization
    for i in 0..N {
        a.coeffs[i] = reduce32(a.coeffs[i]);
    }

    a
}

/// Polynomial multiplication with prefetching-optimized NTT
#[inline]
pub fn poly_mul_ntt_prefetch(a: &Poly, b: &Poly) -> Poly {
    use crate::ntt::ntt_multiply;

    let a_ntt = ntt_with_prefetch(a);
    let b_ntt = ntt_with_prefetch(b);
    let c_ntt = ntt_multiply(&a_ntt, &b_ntt);
    inv_ntt_with_prefetch(&c_ntt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::{ntt, inv_ntt};

    #[test]
    fn test_ntt_prefetch_correctness() {
        // Create test polynomial
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i as i32 * 123 + 456) % Q;
        }

        // Compare prefetch version with standard
        let result_standard = ntt(&poly);
        let result_prefetch = ntt_with_prefetch(&poly);

        for i in 0..N {
            assert_eq!(
                result_standard.coeffs[i], result_prefetch.coeffs[i],
                "Mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_inv_ntt_prefetch_correctness() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i as i32 * 789) % Q;
        }

        let result_standard = inv_ntt(&poly);
        let result_prefetch = inv_ntt_with_prefetch(&poly);

        for i in 0..N {
            assert_eq!(
                result_standard.coeffs[i], result_prefetch.coeffs[i],
                "Mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_poly_mul_prefetch_correctness() {
        let mut a = Poly::new();
        let mut b = Poly::new();

        for i in 0..N {
            a.coeffs[i] = (i as i32 * 11 + 7) % Q;
            b.coeffs[i] = (i as i32 * 13 + 5) % Q;
        }

        let result_standard = crate::ntt::poly_mul_ntt(&a, &b);
        let result_prefetch = poly_mul_ntt_prefetch(&a, &b);

        for i in 0..N {
            assert_eq!(
                result_standard.coeffs[i], result_prefetch.coeffs[i],
                "Mismatch at index {}",
                i
            );
        }
    }
}
