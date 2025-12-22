//! NEON-optimized Keccak-f[1600] permutation.
//!
//! # Implementation Strategy
//!
//! Single-state operations use scalar code with fully unrolled loops, which
//! benchmarks faster than NEON vectorization due to load/store overhead.
//!
//! The 4-way parallel implementation processes four independent Keccak states
//! using pairs of `uint64x2_t` registers, achieving approximately 2x throughput.
//!
//! # Safety
//!
//! All functions require NEON support (mandatory on AArch64) and are marked
//! with `#[target_feature]`. Use the safe wrapper functions for convenience.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

/// Keccak round constants.
#[repr(C, align(16))]
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

// =============================================================================
// 4-Way Parallel Macros
// =============================================================================

/// Rotate left for 2 parallel u64 values in uint64x2_t.
#[cfg(target_arch = "aarch64")]
macro_rules! rotate_left_x2 {
    ($x:expr, $n:expr) => {{
        let left = vshlq_n_u64($x, $n);
        let right = vshrq_n_u64($x, 64 - $n);
        vorrq_u64(left, right)
    }};
}

/// XOR two uint64x2_t values.
#[cfg(target_arch = "aarch64")]
macro_rules! xor_x2 {
    ($a:expr, $b:expr) => {
        veorq_u64($a, $b)
    };
}

/// AND-NOT: (~a) & b for uint64x2_t.
#[cfg(target_arch = "aarch64")]
macro_rules! andnot_x2 {
    ($a:expr, $b:expr) => {
        vbicq_u64($b, $a)
    };
}

/// Apply Theta D to a lane (4-way parallel).
#[cfg(target_arch = "aarch64")]
macro_rules! theta_d_row_x4 {
    ($a_lo:ident, $a_hi:ident, $base:expr, $d_lo:ident, $d_hi:ident, $idx:expr) => {
        $a_lo[$base + $idx] = xor_x2!($a_lo[$base + $idx], $d_lo[$idx]);
        $a_hi[$base + $idx] = xor_x2!($a_hi[$base + $idx], $d_hi[$idx]);
    };
}

/// Rho-Pi (4-way parallel).
#[cfg(target_arch = "aarch64")]
macro_rules! rho_pi_x4 {
    ($b_lo:ident, $b_hi:ident, $a_lo:ident, $a_hi:ident, $dst:expr, $src:expr, $rot:expr) => {
        $b_lo[$dst] = rotate_left_x2!($a_lo[$src], $rot);
        $b_hi[$dst] = rotate_left_x2!($a_hi[$src], $rot);
    };
}

/// Apply Chi to a row (4-way parallel).
#[cfg(target_arch = "aarch64")]
macro_rules! chi_row_x4 {
    ($a_lo:ident, $a_hi:ident, $b_lo:ident, $b_hi:ident, $base:expr) => {
        $a_lo[$base] = xor_x2!($b_lo[$base], andnot_x2!($b_lo[$base + 1], $b_lo[$base + 2]));
        $a_hi[$base] = xor_x2!($b_hi[$base], andnot_x2!($b_hi[$base + 1], $b_hi[$base + 2]));
        $a_lo[$base + 1] = xor_x2!($b_lo[$base + 1], andnot_x2!($b_lo[$base + 2], $b_lo[$base + 3]));
        $a_hi[$base + 1] = xor_x2!($b_hi[$base + 1], andnot_x2!($b_hi[$base + 2], $b_hi[$base + 3]));
        $a_lo[$base + 2] = xor_x2!($b_lo[$base + 2], andnot_x2!($b_lo[$base + 3], $b_lo[$base + 4]));
        $a_hi[$base + 2] = xor_x2!($b_hi[$base + 2], andnot_x2!($b_hi[$base + 3], $b_hi[$base + 4]));
        $a_lo[$base + 3] = xor_x2!($b_lo[$base + 3], andnot_x2!($b_lo[$base + 4], $b_lo[$base]));
        $a_hi[$base + 3] = xor_x2!($b_hi[$base + 3], andnot_x2!($b_hi[$base + 4], $b_hi[$base]));
        $a_lo[$base + 4] = xor_x2!($b_lo[$base + 4], andnot_x2!($b_lo[$base], $b_lo[$base + 1]));
        $a_hi[$base + 4] = xor_x2!($b_hi[$base + 4], andnot_x2!($b_hi[$base], $b_hi[$base + 1]));
    };
}

// =============================================================================
// Single-State Implementation
// =============================================================================

/// Keccak-f[1600] permutation (24 rounds).
///
/// Uses scalar code with unrolled loops for optimal single-state performance.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn keccak_f1600_neon(state: &mut [u64; 25]) {
    keccak_f1600_scalar_optimized(state);
}

#[inline(always)]
fn keccak_f1600_scalar_optimized(state: &mut [u64; 25]) {
    let mut a = *state;
    let mut b = [0u64; 25];

    for round in 0..24 {
        // Theta
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
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn keccak_p12_neon(state: &mut [u64; 25]) {
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

/// 4-way parallel Keccak state for NEON.
///
/// Uses pairs of uint64x2_t registers:
/// - `lo[i]` holds lanes from states 0 and 1
/// - `hi[i]` holds lanes from states 2 and 3
#[cfg(target_arch = "aarch64")]
#[repr(C, align(16))]
pub struct KeccakState4Neon {
    pub lo: [uint64x2_t; 25],
    pub hi: [uint64x2_t; 25],
}

#[cfg(target_arch = "aarch64")]
impl KeccakState4Neon {
    /// Creates a zeroed state.
    #[inline]
    pub fn new() -> Self {
        unsafe {
            Self {
                lo: [vdupq_n_u64(0); 25],
                hi: [vdupq_n_u64(0); 25],
            }
        }
    }

    /// Loads 4 states into parallel structure.
    ///
    /// # Safety
    ///
    /// Requires NEON support.
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn load_states(states: &[[u64; 25]; 4]) -> Self {
        let mut result = Self::new();
        for i in 0..25 {
            result.lo[i] = vld1q_u64([states[0][i], states[1][i]].as_ptr());
            result.hi[i] = vld1q_u64([states[2][i], states[3][i]].as_ptr());
        }
        result
    }

    /// Stores parallel states back to individual arrays.
    ///
    /// # Safety
    ///
    /// Requires NEON support.
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn store_states(&self, states: &mut [[u64; 25]; 4]) {
        for i in 0..25 {
            states[0][i] = vgetq_lane_u64(self.lo[i], 0);
            states[1][i] = vgetq_lane_u64(self.lo[i], 1);
            states[2][i] = vgetq_lane_u64(self.hi[i], 0);
            states[3][i] = vgetq_lane_u64(self.hi[i], 1);
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl Default for KeccakState4Neon {
    fn default() -> Self {
        Self::new()
    }
}

/// 4-way parallel Keccak-f[1600].
///
/// Processes 4 independent states simultaneously for approximately 2x throughput.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn keccak_f1600_x4_neon(state: &mut KeccakState4Neon) {
    let mut a_lo = state.lo;
    let mut a_hi = state.hi;
    let mut b_lo = [vdupq_n_u64(0); 25];
    let mut b_hi = [vdupq_n_u64(0); 25];

    for round in 0..24 {
        // Theta
        let c0_lo = xor_x2!(xor_x2!(a_lo[0], a_lo[5]), xor_x2!(xor_x2!(a_lo[10], a_lo[15]), a_lo[20]));
        let c0_hi = xor_x2!(xor_x2!(a_hi[0], a_hi[5]), xor_x2!(xor_x2!(a_hi[10], a_hi[15]), a_hi[20]));
        let c1_lo = xor_x2!(xor_x2!(a_lo[1], a_lo[6]), xor_x2!(xor_x2!(a_lo[11], a_lo[16]), a_lo[21]));
        let c1_hi = xor_x2!(xor_x2!(a_hi[1], a_hi[6]), xor_x2!(xor_x2!(a_hi[11], a_hi[16]), a_hi[21]));
        let c2_lo = xor_x2!(xor_x2!(a_lo[2], a_lo[7]), xor_x2!(xor_x2!(a_lo[12], a_lo[17]), a_lo[22]));
        let c2_hi = xor_x2!(xor_x2!(a_hi[2], a_hi[7]), xor_x2!(xor_x2!(a_hi[12], a_hi[17]), a_hi[22]));
        let c3_lo = xor_x2!(xor_x2!(a_lo[3], a_lo[8]), xor_x2!(xor_x2!(a_lo[13], a_lo[18]), a_lo[23]));
        let c3_hi = xor_x2!(xor_x2!(a_hi[3], a_hi[8]), xor_x2!(xor_x2!(a_hi[13], a_hi[18]), a_hi[23]));
        let c4_lo = xor_x2!(xor_x2!(a_lo[4], a_lo[9]), xor_x2!(xor_x2!(a_lo[14], a_lo[19]), a_lo[24]));
        let c4_hi = xor_x2!(xor_x2!(a_hi[4], a_hi[9]), xor_x2!(xor_x2!(a_hi[14], a_hi[19]), a_hi[24]));

        let d_lo = [
            xor_x2!(c4_lo, rotate_left_x2!(c1_lo, 1)),
            xor_x2!(c0_lo, rotate_left_x2!(c2_lo, 1)),
            xor_x2!(c1_lo, rotate_left_x2!(c3_lo, 1)),
            xor_x2!(c2_lo, rotate_left_x2!(c4_lo, 1)),
            xor_x2!(c3_lo, rotate_left_x2!(c0_lo, 1)),
        ];
        let d_hi = [
            xor_x2!(c4_hi, rotate_left_x2!(c1_hi, 1)),
            xor_x2!(c0_hi, rotate_left_x2!(c2_hi, 1)),
            xor_x2!(c1_hi, rotate_left_x2!(c3_hi, 1)),
            xor_x2!(c2_hi, rotate_left_x2!(c4_hi, 1)),
            xor_x2!(c3_hi, rotate_left_x2!(c0_hi, 1)),
        ];

        for row in 0..5 {
            let base = row * 5;
            theta_d_row_x4!(a_lo, a_hi, base, d_lo, d_hi, 0);
            theta_d_row_x4!(a_lo, a_hi, base, d_lo, d_hi, 1);
            theta_d_row_x4!(a_lo, a_hi, base, d_lo, d_hi, 2);
            theta_d_row_x4!(a_lo, a_hi, base, d_lo, d_hi, 3);
            theta_d_row_x4!(a_lo, a_hi, base, d_lo, d_hi, 4);
        }

        // Rho-Pi
        b_lo[0] = a_lo[0];
        b_hi[0] = a_hi[0];
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 10, 1, 1);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 7, 10, 3);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 11, 7, 6);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 17, 11, 10);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 18, 17, 15);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 3, 18, 21);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 5, 3, 28);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 16, 5, 36);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 8, 16, 45);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 21, 8, 55);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 24, 21, 2);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 4, 24, 14);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 15, 4, 27);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 23, 15, 41);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 19, 23, 56);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 13, 19, 8);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 12, 13, 25);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 2, 12, 43);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 20, 2, 62);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 14, 20, 18);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 22, 14, 39);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 9, 22, 61);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 6, 9, 20);
        rho_pi_x4!(b_lo, b_hi, a_lo, a_hi, 1, 6, 44);

        // Chi
        chi_row_x4!(a_lo, a_hi, b_lo, b_hi, 0);
        chi_row_x4!(a_lo, a_hi, b_lo, b_hi, 5);
        chi_row_x4!(a_lo, a_hi, b_lo, b_hi, 10);
        chi_row_x4!(a_lo, a_hi, b_lo, b_hi, 15);
        chi_row_x4!(a_lo, a_hi, b_lo, b_hi, 20);

        // Iota
        let rc = vdupq_n_u64(ROUND_CONSTANTS.values[round]);
        a_lo[0] = xor_x2!(a_lo[0], rc);
        a_hi[0] = xor_x2!(a_hi[0], rc);
    }

    state.lo = a_lo;
    state.hi = a_hi;
}

/// Convenience wrapper for 4-way parallel processing.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn keccak_f1600_x4_states_neon(states: &mut [[u64; 25]; 4]) {
    let mut state4 = KeccakState4Neon::load_states(states);
    keccak_f1600_x4_neon(&mut state4);
    state4.store_states(states);
}

#[cfg(all(test, target_arch = "aarch64", feature = "std"))]
mod tests {
    use super::*;

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
    fn test_neon_matches_reference() {
        let test_cases: [[u64; 25]; 4] = [
            [0u64; 25],
            [0xFFFFFFFFFFFFFFFFu64; 25],
            core::array::from_fn(|i| i as u64),
            core::array::from_fn(|i| 0x123456789ABCDEF0u64.wrapping_add(i as u64)),
        ];

        for initial in test_cases.iter() {
            let mut state_neon = *initial;
            let mut state_ref = *initial;

            unsafe { keccak_f1600_neon(&mut state_neon); }
            keccak_f1600_reference(&mut state_ref);

            assert_eq!(state_neon, state_ref);
        }
    }

    #[test]
    fn test_x4_matches_reference() {
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

        unsafe { keccak_f1600_x4_states_neon(&mut states); }

        for i in 0..4 {
            assert_eq!(states[i], expected[i]);
        }
    }
}
