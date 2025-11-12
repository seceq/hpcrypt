//! Memory Prefetching Utilities for ML-DSA
//!
//! Provides software prefetching hints to improve cache locality and reduce memory latency
//! in hot paths like NTT operations and matrix multiplication.
//!
//! # Performance Impact
//!
//! Expected: 3-8% improvement in key generation, signing, and verification
//! - Reduces cache misses in sequential polynomial operations
//! - Helps with strided access patterns in matrix multiplication
//! - Complements hardware prefetchers for irregular access patterns
//!
//! # Safety
//!
//! Prefetching is a hint to the CPU and has no functional impact on correctness.
//! Invalid prefetch addresses are safely ignored by the hardware.

extern crate alloc;
use alloc::vec::Vec;

use crate::params::N;
use crate::poly::Poly;

/// Prefetch temporal locality hint
///
///#[cfg(all(target_arch = "x86_64", target_feature = "sse"))]
#[inline(always)]
pub fn prefetch_read<T>(ptr: *const T) {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse"))]
    unsafe {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
        _mm_prefetch(ptr as *const i8, _MM_HINT_T0);
    }

    // No-op on other architectures
    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse")))]
    {
        let _ = ptr; // Suppress unused variable warning
    }
}

/// Prefetch for write (exclusive cache line ownership)
#[inline(always)]
pub fn prefetch_write<T>(ptr: *const T) {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse"))]
    unsafe {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
        // Note: x86 doesn't distinguish read/write prefetch in the instruction,
        // but we keep the interface separate for potential future use
        _mm_prefetch(ptr as *const i8, _MM_HINT_T0);
    }

    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse")))]
    {
        let _ = ptr;
    }
}

/// Prefetch polynomial coefficients ahead of access
///
/// Prefetches a cache line containing polynomial coefficients.
/// Each cache line (64 bytes) holds 16 coefficients (4 bytes each).
///
/// # Arguments
/// * `poly` - Polynomial to prefetch
/// * `start_idx` - Starting coefficient index
#[inline(always)]
pub fn prefetch_poly_coeffs(poly: &Poly, start_idx: usize) {
    if start_idx < N {
        // Prefetch cache line containing coefficients[start_idx..]
        unsafe {
            let ptr = poly.coeffs.as_ptr().add(start_idx);
            prefetch_read(ptr);
        }
    }
}

/// Rolling macro for prefetching polynomial arrays
///
/// Prefetches multiple polynomial coefficient arrays ahead of access.
/// Useful for matrix operations where we access multiple polynomials sequentially.
///
/// # Example
/// ```ignore
/// prefetch_poly_array!(matrix_a, i, j + 4);  // Prefetch 4 iterations ahead
/// ```
#[macro_export]
macro_rules! prefetch_poly_array {
    ($array:expr, $row:expr, $col:expr) => {
        if $row < $array.len() && $col < $array[$row].len() {
            $crate::prefetch::prefetch_poly_coeffs(&$array[$row][$col], 0);
        }
    };
}

/// Rolling macro for prefetching vector elements
#[macro_export]
macro_rules! prefetch_vector {
    ($vec:expr, $idx:expr) => {
        if $idx < $vec.len() {
            $crate::prefetch::prefetch_poly_coeffs(&$vec[$idx], 0);
        }
    };
}

/// Prefetch strategy for NTT butterfly operations
///
/// NTT accesses coefficients in a specific pattern based on the butterfly structure.
/// We prefetch ahead by one cache line (16 coefficients) to hide memory latency.
///
/// # Arguments
/// * `poly` - Polynomial being transformed
/// * `current_j` - Current butterfly index
/// * `len` - Current NTT layer length
/// * `prefetch_distance` - Number of butterflies to prefetch ahead (default: 16)
#[inline(always)]
pub fn prefetch_ntt_butterfly(poly: &Poly, current_j: usize, len: usize, prefetch_distance: usize) {
    let next_j = current_j + prefetch_distance;

    // Prefetch both butterfly operands
    if next_j < N {
        prefetch_poly_coeffs(poly, next_j);
    }

    if next_j + len < N {
        prefetch_poly_coeffs(poly, next_j + len);
    }
}

/// Prefetch strategy for matrix-vector multiplication
///
/// Matrix multiplication has the pattern: result[i] = sum(A[i][j] * v[j])
/// We prefetch the next row of A and next element of v ahead of time.
///
/// # Arguments
/// * `matrix_a` - Matrix being accessed
/// * `v_ntt` - Vector being multiplied
/// * `current_i` - Current row index
/// * `current_j` - Current column index
/// * `prefetch_ahead` - Number of iterations to prefetch ahead (default: 2)
#[inline(always)]
pub fn prefetch_matrix_mul(
    matrix_a: &[Vec<Poly>],
    v_ntt: &[Poly],
    current_i: usize,
    current_j: usize,
    prefetch_ahead: usize,
) {
    // Prefetch next matrix element in current row
    let next_j = current_j + prefetch_ahead;
    if current_i < matrix_a.len() && next_j < matrix_a[current_i].len() {
        prefetch_poly_coeffs(&matrix_a[current_i][next_j], 0);
    }

    // Prefetch corresponding vector element
    if next_j < v_ntt.len() {
        prefetch_poly_coeffs(&v_ntt[next_j], 0);
    }

    // Prefetch first element of next row (for outer loop)
    let next_i = current_i + 1;
    if next_i < matrix_a.len() && !matrix_a[next_i].is_empty() {
        prefetch_poly_coeffs(&matrix_a[next_i][0], 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefetch_safety() {
        // Prefetching should never crash, even with invalid pointers
        let poly = Poly::new();

        // Valid prefetches
        prefetch_poly_coeffs(&poly, 0);
        prefetch_poly_coeffs(&poly, 128);
        prefetch_poly_coeffs(&poly, 255);

        // Out of bounds prefetch (should be safely ignored)
        prefetch_poly_coeffs(&poly, 256);
        prefetch_poly_coeffs(&poly, 1000);
    }

    #[test]
    fn test_prefetch_ntt() {
        let poly = Poly::new();

        // Test prefetching at various NTT layer lengths
        for len in [1, 2, 4, 8, 16, 32, 64, 128] {
            for j in (0..256).step_by(len) {
                prefetch_ntt_butterfly(&poly, j, len, 16);
            }
        }
    }
}
