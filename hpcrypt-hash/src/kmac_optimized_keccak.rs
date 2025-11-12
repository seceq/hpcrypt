//! Keccak-f Permutation Optimization
//!
//! Optimizations:
//! 1. Full round unrolling (10-20% gain) - Unroll all 24 rounds
//!
//! Expected improvement: 10-20% on Keccak-f permutation
//!
//! Trade-off: Larger binary size for better performance

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

/// Rolling macro for unrolled Keccak-f round
/// Generates clean, readable code for each round
macro_rules! keccak_round {
    ($state:expr, $round:expr) => {{
        // θ (theta) step - unrolled
        let c0 = $state[0] ^ $state[5] ^ $state[10] ^ $state[15] ^ $state[20];
        let c1 = $state[1] ^ $state[6] ^ $state[11] ^ $state[16] ^ $state[21];
        let c2 = $state[2] ^ $state[7] ^ $state[12] ^ $state[17] ^ $state[22];
        let c3 = $state[3] ^ $state[8] ^ $state[13] ^ $state[18] ^ $state[23];
        let c4 = $state[4] ^ $state[9] ^ $state[14] ^ $state[19] ^ $state[24];

        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);

        $state[0] ^= d0;
        $state[1] ^= d1;
        $state[2] ^= d2;
        $state[3] ^= d3;
        $state[4] ^= d4;
        $state[5] ^= d0;
        $state[6] ^= d1;
        $state[7] ^= d2;
        $state[8] ^= d3;
        $state[9] ^= d4;
        $state[10] ^= d0;
        $state[11] ^= d1;
        $state[12] ^= d2;
        $state[13] ^= d3;
        $state[14] ^= d4;
        $state[15] ^= d0;
        $state[16] ^= d1;
        $state[17] ^= d2;
        $state[18] ^= d3;
        $state[19] ^= d4;
        $state[20] ^= d0;
        $state[21] ^= d1;
        $state[22] ^= d2;
        $state[23] ^= d3;
        $state[24] ^= d4;

        // ρ (rho) and π (pi) steps - unrolled
        let mut current = $state[1];

        let temp = $state[PI_LANE[0]];
        $state[PI_LANE[0]] = current.rotate_left(ROTATION_OFFSETS[0]);
        current = temp;

        let temp = $state[PI_LANE[1]];
        $state[PI_LANE[1]] = current.rotate_left(ROTATION_OFFSETS[1]);
        current = temp;

        let temp = $state[PI_LANE[2]];
        $state[PI_LANE[2]] = current.rotate_left(ROTATION_OFFSETS[2]);
        current = temp;

        let temp = $state[PI_LANE[3]];
        $state[PI_LANE[3]] = current.rotate_left(ROTATION_OFFSETS[3]);
        current = temp;

        let temp = $state[PI_LANE[4]];
        $state[PI_LANE[4]] = current.rotate_left(ROTATION_OFFSETS[4]);
        current = temp;

        let temp = $state[PI_LANE[5]];
        $state[PI_LANE[5]] = current.rotate_left(ROTATION_OFFSETS[5]);
        current = temp;

        let temp = $state[PI_LANE[6]];
        $state[PI_LANE[6]] = current.rotate_left(ROTATION_OFFSETS[6]);
        current = temp;

        let temp = $state[PI_LANE[7]];
        $state[PI_LANE[7]] = current.rotate_left(ROTATION_OFFSETS[7]);
        current = temp;

        let temp = $state[PI_LANE[8]];
        $state[PI_LANE[8]] = current.rotate_left(ROTATION_OFFSETS[8]);
        current = temp;

        let temp = $state[PI_LANE[9]];
        $state[PI_LANE[9]] = current.rotate_left(ROTATION_OFFSETS[9]);
        current = temp;

        let temp = $state[PI_LANE[10]];
        $state[PI_LANE[10]] = current.rotate_left(ROTATION_OFFSETS[10]);
        current = temp;

        let temp = $state[PI_LANE[11]];
        $state[PI_LANE[11]] = current.rotate_left(ROTATION_OFFSETS[11]);
        current = temp;

        let temp = $state[PI_LANE[12]];
        $state[PI_LANE[12]] = current.rotate_left(ROTATION_OFFSETS[12]);
        current = temp;

        let temp = $state[PI_LANE[13]];
        $state[PI_LANE[13]] = current.rotate_left(ROTATION_OFFSETS[13]);
        current = temp;

        let temp = $state[PI_LANE[14]];
        $state[PI_LANE[14]] = current.rotate_left(ROTATION_OFFSETS[14]);
        current = temp;

        let temp = $state[PI_LANE[15]];
        $state[PI_LANE[15]] = current.rotate_left(ROTATION_OFFSETS[15]);
        current = temp;

        let temp = $state[PI_LANE[16]];
        $state[PI_LANE[16]] = current.rotate_left(ROTATION_OFFSETS[16]);
        current = temp;

        let temp = $state[PI_LANE[17]];
        $state[PI_LANE[17]] = current.rotate_left(ROTATION_OFFSETS[17]);
        current = temp;

        let temp = $state[PI_LANE[18]];
        $state[PI_LANE[18]] = current.rotate_left(ROTATION_OFFSETS[18]);
        current = temp;

        let temp = $state[PI_LANE[19]];
        $state[PI_LANE[19]] = current.rotate_left(ROTATION_OFFSETS[19]);
        current = temp;

        let temp = $state[PI_LANE[20]];
        $state[PI_LANE[20]] = current.rotate_left(ROTATION_OFFSETS[20]);
        current = temp;

        let temp = $state[PI_LANE[21]];
        $state[PI_LANE[21]] = current.rotate_left(ROTATION_OFFSETS[21]);
        current = temp;

        let temp = $state[PI_LANE[22]];
        $state[PI_LANE[22]] = current.rotate_left(ROTATION_OFFSETS[22]);
        current = temp;

        // Final lane - no need to preserve 'current' after this
        $state[PI_LANE[23]] = current.rotate_left(ROTATION_OFFSETS[23]);

        // χ (chi) step - unrolled by row
        let t0 = $state[0];
        let t1 = $state[1];
        let t2 = $state[2];
        let t3 = $state[3];
        let t4 = $state[4];
        $state[0] = t0 ^ ((!t1) & t2);
        $state[1] = t1 ^ ((!t2) & t3);
        $state[2] = t2 ^ ((!t3) & t4);
        $state[3] = t3 ^ ((!t4) & t0);
        $state[4] = t4 ^ ((!t0) & t1);

        let t0 = $state[5];
        let t1 = $state[6];
        let t2 = $state[7];
        let t3 = $state[8];
        let t4 = $state[9];
        $state[5] = t0 ^ ((!t1) & t2);
        $state[6] = t1 ^ ((!t2) & t3);
        $state[7] = t2 ^ ((!t3) & t4);
        $state[8] = t3 ^ ((!t4) & t0);
        $state[9] = t4 ^ ((!t0) & t1);

        let t0 = $state[10];
        let t1 = $state[11];
        let t2 = $state[12];
        let t3 = $state[13];
        let t4 = $state[14];
        $state[10] = t0 ^ ((!t1) & t2);
        $state[11] = t1 ^ ((!t2) & t3);
        $state[12] = t2 ^ ((!t3) & t4);
        $state[13] = t3 ^ ((!t4) & t0);
        $state[14] = t4 ^ ((!t0) & t1);

        let t0 = $state[15];
        let t1 = $state[16];
        let t2 = $state[17];
        let t3 = $state[18];
        let t4 = $state[19];
        $state[15] = t0 ^ ((!t1) & t2);
        $state[16] = t1 ^ ((!t2) & t3);
        $state[17] = t2 ^ ((!t3) & t4);
        $state[18] = t3 ^ ((!t4) & t0);
        $state[19] = t4 ^ ((!t0) & t1);

        let t0 = $state[20];
        let t1 = $state[21];
        let t2 = $state[22];
        let t3 = $state[23];
        let t4 = $state[24];
        $state[20] = t0 ^ ((!t1) & t2);
        $state[21] = t1 ^ ((!t2) & t3);
        $state[22] = t2 ^ ((!t3) & t4);
        $state[23] = t3 ^ ((!t4) & t0);
        $state[24] = t4 ^ ((!t0) & t1);

        // ι (iota) step
        $state[0] ^= ROUND_CONSTANTS[$round];
    }};
}

/// Baseline Keccak-f permutation (looped version for comparison)
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
        #[allow(unused_assignments)]
        for i in 0..24 {
            let (x, y) = (PI_LANE[i] % 5, PI_LANE[i] / 5);
            let temp = state[x + 5 * y];
            state[x + 5 * y] = current.rotate_left(ROTATION_OFFSETS[i]);
            current = temp; // Last assignment (i=23) is not read, but loop structure requires it
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

/// Optimized Keccak-f permutation with full round unrolling
#[inline]
pub fn keccak_f_unrolled(state: &mut [u64; 25]) {
    keccak_round!(state, 0);
    keccak_round!(state, 1);
    keccak_round!(state, 2);
    keccak_round!(state, 3);
    keccak_round!(state, 4);
    keccak_round!(state, 5);
    keccak_round!(state, 6);
    keccak_round!(state, 7);
    keccak_round!(state, 8);
    keccak_round!(state, 9);
    keccak_round!(state, 10);
    keccak_round!(state, 11);
    keccak_round!(state, 12);
    keccak_round!(state, 13);
    keccak_round!(state, 14);
    keccak_round!(state, 15);
    keccak_round!(state, 16);
    keccak_round!(state, 17);
    keccak_round!(state, 18);
    keccak_round!(state, 19);
    keccak_round!(state, 20);
    keccak_round!(state, 21);
    keccak_round!(state, 22);
    keccak_round!(state, 23);
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
    fn test_unrolled_matches_baseline() {
        let mut state1 = init_test_state();
        let mut state2 = state1;

        keccak_f_baseline(&mut state1);
        keccak_f_unrolled(&mut state2);

        assert_eq!(state1, state2, "Unrolled should match baseline");
    }

    #[test]
    fn test_zero_state() {
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        keccak_f_baseline(&mut state1);
        keccak_f_unrolled(&mut state2);

        assert_eq!(state1, state2, "Zero state should match");
    }

    #[test]
    fn test_all_ones_state() {
        let mut state1 = [0xFFFFFFFFFFFFFFFFu64; 25];
        let mut state2 = state1;

        keccak_f_baseline(&mut state1);
        keccak_f_unrolled(&mut state2);

        assert_eq!(state1, state2, "All-ones state should match");
    }
}
