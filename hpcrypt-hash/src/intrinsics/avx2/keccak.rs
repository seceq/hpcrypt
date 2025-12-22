//! AVX2-optimized Keccak-f[1600] permutation.
//!
//! # Implementation Strategy
//!
//! Single-state operations use scalar code with fully unrolled loops, which
//! benchmarks faster than AVX2 vectorization due to load/store overhead.
//!
//! The 4-way parallel implementation processes four independent Keccak states
//! simultaneously, achieving 3-4x throughput for batch operations.
//!
//! # Safety
//!
//! All functions require AVX2 support and are marked with `#[target_feature]`.
//! Use the safe wrapper functions for automatic runtime detection.

#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
use core::arch::x86_64::*;

#[cfg(target_arch = "x86")]
#[allow(unused_imports)]
use core::arch::x86::*;

/// Keccak round constants.
#[repr(C, align(32))]
struct RoundConstants {
    values: [u64; 24],
}

static ROUND_CONSTANTS: RoundConstants = RoundConstants {
    values: [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ],
};

// =============================================================================
// Macros for unrolled Keccak steps
// =============================================================================

/// Apply Theta D values to a row of 5 lanes.
macro_rules! theta_d_row {
    ($a:ident, $base:expr, $d0:ident, $d1:ident, $d2:ident, $d3:ident, $d4:ident) => {
        $a[$base] ^= $d0;
        $a[$base + 1] ^= $d1;
        $a[$base + 2] ^= $d2;
        $a[$base + 3] ^= $d3;
        $a[$base + 4] ^= $d4;
    };
}

/// Apply Chi to a row of 5 lanes.
macro_rules! chi_row {
    ($a:ident, $b:ident, $base:expr) => {
        $a[$base] = $b[$base] ^ ((!$b[$base + 1]) & $b[$base + 2]);
        $a[$base + 1] = $b[$base + 1] ^ ((!$b[$base + 2]) & $b[$base + 3]);
        $a[$base + 2] = $b[$base + 2] ^ ((!$b[$base + 3]) & $b[$base + 4]);
        $a[$base + 3] = $b[$base + 3] ^ ((!$b[$base + 4]) & $b[$base]);
        $a[$base + 4] = $b[$base + 4] ^ ((!$b[$base]) & $b[$base + 1]);
    };
}

/// Rho-Pi: b[dst] = a[src].rotate_left(rot)
macro_rules! rho_pi {
    ($b:ident, $a:ident, $dst:expr, $src:expr, $rot:expr) => {
        $b[$dst] = $a[$src].rotate_left($rot);
    };
}

/// Keccak-f[1600] permutation (24 rounds).
///
/// Uses scalar code with unrolled loops for optimal single-state performance.
///
/// # Safety
///
/// Requires AVX2 support.
#[target_feature(enable = "avx2")]
pub unsafe fn keccak_f1600_avx2(state: &mut [u64; 25]) {
    keccak_f1600_scalar_optimized(state);
}

#[inline(always)]
fn keccak_f1600_scalar_optimized(state: &mut [u64; 25]) {
    let mut a = *state;
    let mut b = [0u64; 25];

    for round in 0..24 {
        // Theta: column parity
        let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);

        theta_d_row!(a, 0, d0, d1, d2, d3, d4);
        theta_d_row!(a, 5, d0, d1, d2, d3, d4);
        theta_d_row!(a, 10, d0, d1, d2, d3, d4);
        theta_d_row!(a, 15, d0, d1, d2, d3, d4);
        theta_d_row!(a, 20, d0, d1, d2, d3, d4);

        // Rho-Pi
        b[0] = a[0];
        rho_pi!(b, a, 10, 1, 1);
        rho_pi!(b, a, 7, 10, 3);
        rho_pi!(b, a, 11, 7, 6);
        rho_pi!(b, a, 17, 11, 10);
        rho_pi!(b, a, 18, 17, 15);
        rho_pi!(b, a, 3, 18, 21);
        rho_pi!(b, a, 5, 3, 28);
        rho_pi!(b, a, 16, 5, 36);
        rho_pi!(b, a, 8, 16, 45);
        rho_pi!(b, a, 21, 8, 55);
        rho_pi!(b, a, 24, 21, 2);
        rho_pi!(b, a, 4, 24, 14);
        rho_pi!(b, a, 15, 4, 27);
        rho_pi!(b, a, 23, 15, 41);
        rho_pi!(b, a, 19, 23, 56);
        rho_pi!(b, a, 13, 19, 8);
        rho_pi!(b, a, 12, 13, 25);
        rho_pi!(b, a, 2, 12, 43);
        rho_pi!(b, a, 20, 2, 62);
        rho_pi!(b, a, 14, 20, 18);
        rho_pi!(b, a, 22, 14, 39);
        rho_pi!(b, a, 9, 22, 61);
        rho_pi!(b, a, 6, 9, 20);
        rho_pi!(b, a, 1, 6, 44);

        // Chi
        chi_row!(a, b, 0);
        chi_row!(a, b, 5);
        chi_row!(a, b, 10);
        chi_row!(a, b, 15);
        chi_row!(a, b, 20);

        // Iota
        a[0] ^= ROUND_CONSTANTS.values[round];
    }

    *state = a;
}

/// Keccak-p[1600, 12] permutation (12 rounds for TurboSHAKE).
///
/// # Safety
///
/// Requires AVX2 support.
#[target_feature(enable = "avx2")]
pub unsafe fn keccak_p12_avx2(state: &mut [u64; 25]) {
    keccak_p12_scalar_optimized(state);
}

#[inline(always)]
fn keccak_p12_scalar_optimized(state: &mut [u64; 25]) {
    let mut a = *state;
    let mut b = [0u64; 25];

    for round in 12..24 {
        let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);

        theta_d_row!(a, 0, d0, d1, d2, d3, d4);
        theta_d_row!(a, 5, d0, d1, d2, d3, d4);
        theta_d_row!(a, 10, d0, d1, d2, d3, d4);
        theta_d_row!(a, 15, d0, d1, d2, d3, d4);
        theta_d_row!(a, 20, d0, d1, d2, d3, d4);

        b[0] = a[0];
        rho_pi!(b, a, 10, 1, 1);
        rho_pi!(b, a, 7, 10, 3);
        rho_pi!(b, a, 11, 7, 6);
        rho_pi!(b, a, 17, 11, 10);
        rho_pi!(b, a, 18, 17, 15);
        rho_pi!(b, a, 3, 18, 21);
        rho_pi!(b, a, 5, 3, 28);
        rho_pi!(b, a, 16, 5, 36);
        rho_pi!(b, a, 8, 16, 45);
        rho_pi!(b, a, 21, 8, 55);
        rho_pi!(b, a, 24, 21, 2);
        rho_pi!(b, a, 4, 24, 14);
        rho_pi!(b, a, 15, 4, 27);
        rho_pi!(b, a, 23, 15, 41);
        rho_pi!(b, a, 19, 23, 56);
        rho_pi!(b, a, 13, 19, 8);
        rho_pi!(b, a, 12, 13, 25);
        rho_pi!(b, a, 2, 12, 43);
        rho_pi!(b, a, 20, 2, 62);
        rho_pi!(b, a, 14, 20, 18);
        rho_pi!(b, a, 22, 14, 39);
        rho_pi!(b, a, 9, 22, 61);
        rho_pi!(b, a, 6, 9, 20);
        rho_pi!(b, a, 1, 6, 44);

        chi_row!(a, b, 0);
        chi_row!(a, b, 5);
        chi_row!(a, b, 10);
        chi_row!(a, b, 15);
        chi_row!(a, b, 20);

        a[0] ^= ROUND_CONSTANTS.values[round];
    }

    *state = a;
}

// =============================================================================
// 4-Way Parallel Implementation
// =============================================================================

/// 4-way parallel Keccak state for AVX2.
///
/// Each lane holds the same index from 4 independent states, enabling true
/// SIMD parallel processing.
#[repr(C, align(32))]
pub struct KeccakState4 {
    pub lanes: [__m256i; 25],
}

impl KeccakState4 {
    /// Creates a zeroed state.
    #[inline]
    pub fn new() -> Self {
        Self {
            lanes: [unsafe { _mm256_setzero_si256() }; 25],
        }
    }

    /// Loads 4 states into parallel structure.
    ///
    /// # Safety
    ///
    /// Requires AVX2 support.
    #[target_feature(enable = "avx2")]
    #[inline]
    pub unsafe fn load_states(states: &[[u64; 25]; 4]) -> Self {
        let mut result = Self::new();
        for i in 0..25 {
            result.lanes[i] = _mm256_set_epi64x(
                states[3][i] as i64,
                states[2][i] as i64,
                states[1][i] as i64,
                states[0][i] as i64,
            );
        }
        result
    }

    /// Stores parallel states back to individual arrays.
    ///
    /// # Safety
    ///
    /// Requires AVX2 support.
    #[target_feature(enable = "avx2")]
    #[inline]
    pub unsafe fn store_states(&self, states: &mut [[u64; 25]; 4]) {
        for i in 0..25 {
            states[0][i] = _mm256_extract_epi64(self.lanes[i], 0) as u64;
            states[1][i] = _mm256_extract_epi64(self.lanes[i], 1) as u64;
            states[2][i] = _mm256_extract_epi64(self.lanes[i], 2) as u64;
            states[3][i] = _mm256_extract_epi64(self.lanes[i], 3) as u64;
        }
    }
}

impl Default for KeccakState4 {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// 4-Way Parallel Macros
// =============================================================================

/// Rotate left for 4 parallel u64 values.
macro_rules! rotate_left_4 {
    ($x:expr, $n:expr) => {{
        let left = _mm256_slli_epi64($x, $n);
        let right = _mm256_srli_epi64($x, 64 - $n);
        _mm256_or_si256(left, right)
    }};
}

/// Apply Theta D to a row (4-way parallel).
macro_rules! theta_d_row_x4 {
    ($a:ident, $base:expr, $d0:ident, $d1:ident, $d2:ident, $d3:ident, $d4:ident) => {
        $a[$base] = _mm256_xor_si256($a[$base], $d0);
        $a[$base + 1] = _mm256_xor_si256($a[$base + 1], $d1);
        $a[$base + 2] = _mm256_xor_si256($a[$base + 2], $d2);
        $a[$base + 3] = _mm256_xor_si256($a[$base + 3], $d3);
        $a[$base + 4] = _mm256_xor_si256($a[$base + 4], $d4);
    };
}

/// Rho-Pi (4-way parallel).
macro_rules! rho_pi_x4 {
    ($b:ident, $a:ident, $dst:expr, $src:expr, $rot:expr) => {
        $b[$dst] = rotate_left_4!($a[$src], $rot);
    };
}

/// Apply Chi to a row (4-way parallel).
macro_rules! chi_row_x4 {
    ($a:ident, $b:ident, $base:expr) => {
        $a[$base] = _mm256_xor_si256($b[$base], _mm256_andnot_si256($b[$base + 1], $b[$base + 2]));
        $a[$base + 1] = _mm256_xor_si256($b[$base + 1], _mm256_andnot_si256($b[$base + 2], $b[$base + 3]));
        $a[$base + 2] = _mm256_xor_si256($b[$base + 2], _mm256_andnot_si256($b[$base + 3], $b[$base + 4]));
        $a[$base + 3] = _mm256_xor_si256($b[$base + 3], _mm256_andnot_si256($b[$base + 4], $b[$base]));
        $a[$base + 4] = _mm256_xor_si256($b[$base + 4], _mm256_andnot_si256($b[$base], $b[$base + 1]));
    };
}

/// 4-way parallel Keccak-f[1600].
///
/// Processes 4 independent states simultaneously for 3-4x throughput.
///
/// # Safety
///
/// Requires AVX2 support.
#[target_feature(enable = "avx2")]
pub unsafe fn keccak_f1600_x4(state: &mut KeccakState4) {
    let mut a = state.lanes;
    let mut b = [_mm256_setzero_si256(); 25];

    for round in 0..24 {
        // Theta
        let c0 = _mm256_xor_si256(
            _mm256_xor_si256(a[0], a[5]),
            _mm256_xor_si256(_mm256_xor_si256(a[10], a[15]), a[20]),
        );
        let c1 = _mm256_xor_si256(
            _mm256_xor_si256(a[1], a[6]),
            _mm256_xor_si256(_mm256_xor_si256(a[11], a[16]), a[21]),
        );
        let c2 = _mm256_xor_si256(
            _mm256_xor_si256(a[2], a[7]),
            _mm256_xor_si256(_mm256_xor_si256(a[12], a[17]), a[22]),
        );
        let c3 = _mm256_xor_si256(
            _mm256_xor_si256(a[3], a[8]),
            _mm256_xor_si256(_mm256_xor_si256(a[13], a[18]), a[23]),
        );
        let c4 = _mm256_xor_si256(
            _mm256_xor_si256(a[4], a[9]),
            _mm256_xor_si256(_mm256_xor_si256(a[14], a[19]), a[24]),
        );

        let d0 = _mm256_xor_si256(c4, rotate_left_4!(c1, 1));
        let d1 = _mm256_xor_si256(c0, rotate_left_4!(c2, 1));
        let d2 = _mm256_xor_si256(c1, rotate_left_4!(c3, 1));
        let d3 = _mm256_xor_si256(c2, rotate_left_4!(c4, 1));
        let d4 = _mm256_xor_si256(c3, rotate_left_4!(c0, 1));

        theta_d_row_x4!(a, 0, d0, d1, d2, d3, d4);
        theta_d_row_x4!(a, 5, d0, d1, d2, d3, d4);
        theta_d_row_x4!(a, 10, d0, d1, d2, d3, d4);
        theta_d_row_x4!(a, 15, d0, d1, d2, d3, d4);
        theta_d_row_x4!(a, 20, d0, d1, d2, d3, d4);

        // Rho-Pi
        b[0] = a[0];
        rho_pi_x4!(b, a, 10, 1, 1);
        rho_pi_x4!(b, a, 7, 10, 3);
        rho_pi_x4!(b, a, 11, 7, 6);
        rho_pi_x4!(b, a, 17, 11, 10);
        rho_pi_x4!(b, a, 18, 17, 15);
        rho_pi_x4!(b, a, 3, 18, 21);
        rho_pi_x4!(b, a, 5, 3, 28);
        rho_pi_x4!(b, a, 16, 5, 36);
        rho_pi_x4!(b, a, 8, 16, 45);
        rho_pi_x4!(b, a, 21, 8, 55);
        rho_pi_x4!(b, a, 24, 21, 2);
        rho_pi_x4!(b, a, 4, 24, 14);
        rho_pi_x4!(b, a, 15, 4, 27);
        rho_pi_x4!(b, a, 23, 15, 41);
        rho_pi_x4!(b, a, 19, 23, 56);
        rho_pi_x4!(b, a, 13, 19, 8);
        rho_pi_x4!(b, a, 12, 13, 25);
        rho_pi_x4!(b, a, 2, 12, 43);
        rho_pi_x4!(b, a, 20, 2, 62);
        rho_pi_x4!(b, a, 14, 20, 18);
        rho_pi_x4!(b, a, 22, 14, 39);
        rho_pi_x4!(b, a, 9, 22, 61);
        rho_pi_x4!(b, a, 6, 9, 20);
        rho_pi_x4!(b, a, 1, 6, 44);

        // Chi
        chi_row_x4!(a, b, 0);
        chi_row_x4!(a, b, 5);
        chi_row_x4!(a, b, 10);
        chi_row_x4!(a, b, 15);
        chi_row_x4!(a, b, 20);

        // Iota
        let rc = _mm256_set1_epi64x(ROUND_CONSTANTS.values[round] as i64);
        a[0] = _mm256_xor_si256(a[0], rc);
    }

    state.lanes = a;
}

/// Convenience wrapper for 4-way parallel processing.
///
/// # Safety
///
/// Requires AVX2 support.
#[target_feature(enable = "avx2")]
pub unsafe fn keccak_f1600_x4_states(states: &mut [[u64; 25]; 4]) {
    let mut state4 = KeccakState4::load_states(states);
    keccak_f1600_x4(&mut state4);
    state4.store_states(states);
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::is_x86_feature_detected;

    fn keccak_f1600_reference(state: &mut [u64; 25]) {
        const RC: [u64; 24] = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ];
        const RHO: [u32; 24] = [
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
        ];

        let mut a = *state;
        let mut b = [0u64; 25];
        let mut c = [0u64; 5];
        let mut d = [0u64; 5];

        for round in 0..24 {
            for x in 0..5 {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for x in 0..5 {
                for y in 0..5 {
                    a[x + 5 * y] ^= d[x];
                }
            }

            b[0] = a[0];
            let mut x = 1usize;
            let mut y = 0usize;
            for i in 0..24 {
                let new_y = (2 * x + 3 * y) % 5;
                b[y + 5 * new_y] = a[x + 5 * y].rotate_left(RHO[i]);
                let temp = y;
                y = new_y;
                x = temp;
            }

            for yy in 0..5 {
                for xx in 0..5 {
                    let idx = xx + 5 * yy;
                    a[idx] = b[idx] ^ ((!b[(xx + 1) % 5 + 5 * yy]) & b[(xx + 2) % 5 + 5 * yy]);
                }
            }

            a[0] ^= RC[round];
        }

        *state = a;
    }

    #[test]
    fn test_avx2_matches_reference() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let test_cases: [[u64; 25]; 4] = [
            [0u64; 25],
            [0xFFFFFFFFFFFFFFFFu64; 25],
            core::array::from_fn(|i| i as u64),
            core::array::from_fn(|i| 0x123456789ABCDEF0u64.wrapping_add(i as u64)),
        ];

        for initial in test_cases.iter() {
            let mut state_avx2 = *initial;
            let mut state_ref = *initial;

            unsafe { keccak_f1600_avx2(&mut state_avx2); }
            keccak_f1600_reference(&mut state_ref);

            assert_eq!(state_avx2, state_ref);
        }
    }

    #[test]
    fn test_x4_matches_reference() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let mut states: [[u64; 25]; 4] = [
            core::array::from_fn(|i| i as u64),
            core::array::from_fn(|i| (i as u64).wrapping_mul(0x123456789ABCDEF0)),
            core::array::from_fn(|i| (i as u64) ^ 0xFFFFFFFFFFFFFFFF),
            core::array::from_fn(|i| (i as u64).wrapping_add(0x1000000000000000)),
        ];

        let mut expected = states.clone();
        for state in expected.iter_mut() {
            keccak_f1600_reference(state);
        }

        unsafe { keccak_f1600_x4_states(&mut states); }

        for i in 0..4 {
            assert_eq!(states[i], expected[i]);
        }
    }
}
