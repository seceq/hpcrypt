//! Keccak-f Step-Level Unrolling Optimization
//!
//! Optimizations:
//! 1. Theta step unrolling - unroll 5-element loops
//! 2. Chi step unrolling - unroll 5 rows × 5 lanes
//! 3. Rho-Pi step unrolling - unroll 24 permutations
//!
//! Expected improvement: 5-10% on Keccak-f permutation
//!
//! Strategy: Keep the 24-round loop but unroll inner step loops to reduce loop overhead
//! while maintaining manageable code size (unlike full round unrolling which failed).

#![forbid(unsafe_code)]

/// Round constants for Keccak-f[1600]
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for Keccak-f[1600]
const ROTATION_OFFSETS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Pi lane permutation indices
const PI_LANE: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

// ===== Optimization Macros Copied from sha3.rs =====

/// Macro for unrolled Theta step
///
/// Unrolls the Theta column parity computation and D array calculation
macro_rules! theta_unrolled {
    ($state:expr, $c:ident, $d:ident) => {
        {
            // Compute column parities (unrolled)
            $c[0] = $state[0] ^ $state[5] ^ $state[10] ^ $state[15] ^ $state[20];
            $c[1] = $state[1] ^ $state[6] ^ $state[11] ^ $state[16] ^ $state[21];
            $c[2] = $state[2] ^ $state[7] ^ $state[12] ^ $state[17] ^ $state[22];
            $c[3] = $state[3] ^ $state[8] ^ $state[13] ^ $state[18] ^ $state[23];
            $c[4] = $state[4] ^ $state[9] ^ $state[14] ^ $state[19] ^ $state[24];

            // Compute D values (unrolled)
            $d[0] = $c[4] ^ $c[1].rotate_left(1);
            $d[1] = $c[0] ^ $c[2].rotate_left(1);
            $d[2] = $c[1] ^ $c[3].rotate_left(1);
            $d[3] = $c[2] ^ $c[4].rotate_left(1);
            $d[4] = $c[3] ^ $c[0].rotate_left(1);

            // Apply D to all lanes (fully unrolled)
            $state[0] ^= $d[0];
            $state[1] ^= $d[1];
            $state[2] ^= $d[2];
            $state[3] ^= $d[3];
            $state[4] ^= $d[4];
            $state[5] ^= $d[0];
            $state[6] ^= $d[1];
            $state[7] ^= $d[2];
            $state[8] ^= $d[3];
            $state[9] ^= $d[4];
            $state[10] ^= $d[0];
            $state[11] ^= $d[1];
            $state[12] ^= $d[2];
            $state[13] ^= $d[3];
            $state[14] ^= $d[4];
            $state[15] ^= $d[0];
            $state[16] ^= $d[1];
            $state[17] ^= $d[2];
            $state[18] ^= $d[3];
            $state[19] ^= $d[4];
            $state[20] ^= $d[0];
            $state[21] ^= $d[1];
            $state[22] ^= $d[2];
            $state[23] ^= $d[3];
            $state[24] ^= $d[4];
        }
    };
}

/// Macro for unrolled Chi step
///
/// Unrolls the 5 rows of Chi step completely
macro_rules! chi_unrolled {
    ($state:expr, $b:expr) => {
        {
            // Row 0 (unrolled)
            let t0 = $b[0];
            let t1 = $b[1];
            let t2 = $b[2];
            let t3 = $b[3];
            let t4 = $b[4];
            $state[0] = t0 ^ ((!t1) & t2);
            $state[1] = t1 ^ ((!t2) & t3);
            $state[2] = t2 ^ ((!t3) & t4);
            $state[3] = t3 ^ ((!t4) & t0);
            $state[4] = t4 ^ ((!t0) & t1);

            // Row 1 (unrolled)
            let t0 = $b[5];
            let t1 = $b[6];
            let t2 = $b[7];
            let t3 = $b[8];
            let t4 = $b[9];
            $state[5] = t0 ^ ((!t1) & t2);
            $state[6] = t1 ^ ((!t2) & t3);
            $state[7] = t2 ^ ((!t3) & t4);
            $state[8] = t3 ^ ((!t4) & t0);
            $state[9] = t4 ^ ((!t0) & t1);

            // Row 2 (unrolled)
            let t0 = $b[10];
            let t1 = $b[11];
            let t2 = $b[12];
            let t3 = $b[13];
            let t4 = $b[14];
            $state[10] = t0 ^ ((!t1) & t2);
            $state[11] = t1 ^ ((!t2) & t3);
            $state[12] = t2 ^ ((!t3) & t4);
            $state[13] = t3 ^ ((!t4) & t0);
            $state[14] = t4 ^ ((!t0) & t1);

            // Row 3 (unrolled)
            let t0 = $b[15];
            let t1 = $b[16];
            let t2 = $b[17];
            let t3 = $b[18];
            let t4 = $b[19];
            $state[15] = t0 ^ ((!t1) & t2);
            $state[16] = t1 ^ ((!t2) & t3);
            $state[17] = t2 ^ ((!t3) & t4);
            $state[18] = t3 ^ ((!t4) & t0);
            $state[19] = t4 ^ ((!t0) & t1);

            // Row 4 (unrolled)
            let t0 = $b[20];
            let t1 = $b[21];
            let t2 = $b[22];
            let t3 = $b[23];
            let t4 = $b[24];
            $state[20] = t0 ^ ((!t1) & t2);
            $state[21] = t1 ^ ((!t2) & t3);
            $state[22] = t2 ^ ((!t3) & t4);
            $state[23] = t3 ^ ((!t4) & t0);
            $state[24] = t4 ^ ((!t0) & t1);
        }
    };
}

/// Macro for unrolled Rho-Pi step
///
/// Unrolls the Rho-Pi permutation completely with hardcoded rotation offsets
macro_rules! rho_pi_unrolled {
    ($state:expr, $b:expr) => {
        {
            // Rho-Pi unrolled with explicit rotation offsets
            $b[0] = $state[0];  // No rotation for position 0
            $b[10] = $state[1].rotate_left(1);
            $b[7] = $state[10].rotate_left(3);
            $b[11] = $state[7].rotate_left(6);
            $b[17] = $state[11].rotate_left(10);
            $b[18] = $state[17].rotate_left(15);
            $b[3] = $state[18].rotate_left(21);
            $b[5] = $state[3].rotate_left(28);
            $b[16] = $state[5].rotate_left(36);
            $b[8] = $state[16].rotate_left(45);
            $b[21] = $state[8].rotate_left(55);
            $b[24] = $state[21].rotate_left(2);
            $b[4] = $state[24].rotate_left(14);
            $b[15] = $state[4].rotate_left(27);
            $b[23] = $state[15].rotate_left(41);
            $b[19] = $state[23].rotate_left(56);
            $b[13] = $state[19].rotate_left(8);
            $b[12] = $state[13].rotate_left(25);
            $b[2] = $state[12].rotate_left(43);
            $b[20] = $state[2].rotate_left(62);
            $b[14] = $state[20].rotate_left(18);
            $b[22] = $state[14].rotate_left(39);
            $b[9] = $state[22].rotate_left(61);
            $b[6] = $state[9].rotate_left(20);
            $b[1] = $state[6].rotate_left(44);
        }
    };
}

// ===== End of Optimization Macros =====

/// Baseline Keccak-f permutation (looped version for comparison)
///
/// This is the current implementation from kmac.rs
#[inline(never)]
pub fn keccak_f_baseline(state: &mut [u64; 25]) {
    #[allow(clippy::needless_range_loop)]
    for round in 0..24 {
        // θ (theta) step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ (rho) and π (pi) steps
        let mut current = state[1];
        for i in 0..24 {
            let (x, y) = (PI_LANE[i] % 5, PI_LANE[i] / 5);
            let temp = state[x + 5 * y];
            state[x + 5 * y] = current.rotate_left(ROTATION_OFFSETS[i]);
            current = temp;
        }

        // χ (chi) step
        for y in 0..5 {
            let mut t = [0u64; 5];
            for x in 0..5 {
                t[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // ι (iota) step
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Optimized Keccak-f permutation with step-level unrolling
///
/// Keeps the 24-round loop but unrolls inner loops within theta, rho-pi, and chi steps.
/// This provides performance benefits while keeping code size manageable.
#[inline]
pub fn keccak_f_step_unrolled(state: &mut [u64; 25]) {
    for round in 0..24 {
        // Theta step (unrolled via macro)
        let mut c = [0u64; 5];
        let mut d = [0u64; 5];
        theta_unrolled!(state, c, d);

        // Rho and Pi steps combined (unrolled via macro)
        let mut b = [0u64; 25];
        rho_pi_unrolled!(state, b);

        // Chi step (unrolled via macro)
        chi_unrolled!(state, b);

        // Iota step
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test_state() -> [u64; 25] {
        let mut state = [0u64; 25];
        for i in 0..25 {
            state[i] = i as u64 * 0x0123456789ABCDEF;
        }
        state
    }

    #[test]
    fn test_step_unrolled_matches_baseline() {
        let mut state1 = init_test_state();
        let mut state2 = state1;

        keccak_f_baseline(&mut state1);
        keccak_f_step_unrolled(&mut state2);

        assert_eq!(state1, state2, "Step-unrolled should match baseline");
    }

    #[test]
    fn test_zero_state() {
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        keccak_f_baseline(&mut state1);
        keccak_f_step_unrolled(&mut state2);

        assert_eq!(state1, state2, "Zero state should match");
    }

    #[test]
    fn test_all_ones_state() {
        let mut state1 = [0xFFFFFFFFFFFFFFFFu64; 25];
        let mut state2 = state1;

        keccak_f_baseline(&mut state1);
        keccak_f_step_unrolled(&mut state2);

        assert_eq!(state1, state2, "All-ones state should match");
    }

    #[test]
    fn test_multiple_rounds() {
        let mut state1 = init_test_state();
        let mut state2 = state1;

        // Apply permutation 10 times
        for _ in 0..10 {
            keccak_f_baseline(&mut state1);
            keccak_f_step_unrolled(&mut state2);
            assert_eq!(state1, state2, "States should match after each permutation");
        }
    }
}
