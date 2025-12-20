//! Ascon permutation primitives
//!
//! This module provides the core Ascon permutation and related functions
//! shared between Ascon AEAD (hpcrypt-aead) and Ascon Hash (hpcrypt-hash).
//!
//! The Ascon permutation is a 320-bit cryptographic permutation used as the
//! building block for both authenticated encryption and hashing modes.
//!
//! # References
//!
//! - Ascon specification: <https://ascon.iaik.tugraz.at/>
//! - NIST SP 800-232: Ascon-Based Lightweight Cryptography Standards
//! - Dobraunig, Eichlseder, Mendel, Schläffer: "Ascon v1.2"

/// Ascon state: 5 x 64-bit words = 320 bits
pub type AsconState = [u64; 5];

/// Round constants for Ascon permutation
pub const ROUND_CONSTANTS: [u64; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

/// Ascon permutation with configurable number of rounds
///
/// The Ascon permutation consists of:
/// 1. Addition of round constant
/// 2. Substitution layer (S-box)
/// 3. Linear diffusion layer
///
/// # Parameters
///
/// - `state`: The 320-bit state (5 × 64-bit words)
/// - `rounds`: Number of rounds to perform (typically 6, 8, or 12)
///
/// # Security
///
/// - 12 rounds: Full security (initialization, finalization)
/// - 8 rounds: Reduced rounds for Ascon-128a intermediate steps
/// - 6 rounds: Reduced rounds for Ascon-128 intermediate steps
#[inline]
pub fn ascon_permutation(state: &mut AsconState, rounds: usize) {
    debug_assert!(rounds <= 12, "Ascon supports maximum 12 rounds");
    let start_round = 12 - rounds;

    #[allow(clippy::needless_range_loop)]
    for i in start_round..12 {
        // Add round constant to state[2]
        state[2] ^= ROUND_CONSTANTS[i];

        // Substitution layer
        ascon_sbox(state);

        // Linear diffusion layer
        ascon_linear(state);
    }
}

/// Ascon S-box (substitution layer)
///
/// Implements the Ascon S-box as specified in the Ascon specification:
/// 1. Pre-mixing (affine layer before chi)
/// 2. Chi layer (Keccak-style non-linear transformation)
/// 3. Post-mixing (affine layer after chi)
///
/// The S-box provides non-linearity to the permutation.
#[inline(always)]
fn ascon_sbox(state: &mut AsconState) {
    // Pre-mixing (affine layer before chi)
    state[0] ^= state[4];
    state[4] ^= state[3];
    state[2] ^= state[1];

    // Save values for chi layer
    let x0 = state[0];
    let x1 = state[1];
    let x2 = state[2];
    let x3 = state[3];
    let x4 = state[4];

    // Chi layer (Keccak-style non-linear transformation)
    // This is the only non-linear component of the permutation
    state[0] = x0 ^ (!x1 & x2);
    state[1] = x1 ^ (!x2 & x3);
    state[2] = x2 ^ (!x3 & x4);
    state[3] = x3 ^ (!x4 & x0);
    state[4] = x4 ^ (!x0 & x1);

    // Post-mixing (affine layer after chi)
    state[1] ^= state[0];
    state[0] ^= state[4];
    state[3] ^= state[2];
    state[2] = !state[2];
}

/// Ascon linear diffusion layer
///
/// Provides diffusion across the state using rotation and XOR operations.
/// Each 64-bit word is combined with two rotated versions of itself.
///
/// The rotation amounts are carefully chosen to provide optimal diffusion
/// while maintaining efficiency on various platforms.
#[inline(always)]
fn ascon_linear(state: &mut AsconState) {
    let x0 = state[0];
    let x1 = state[1];
    let x2 = state[2];
    let x3 = state[3];
    let x4 = state[4];

    // Each word is XORed with two rotated versions of itself
    // Rotation amounts: [19,28], [61,39], [1,6], [10,17], [7,41]
    state[0] = x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28);
    state[1] = x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39);
    state[2] = x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6);
    state[3] = x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17);
    state[4] = x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascon_permutation_12_rounds() {
        // Test vector from Ascon specification
        let mut state: AsconState = [0, 0, 0, 0, 0];
        ascon_permutation(&mut state, 12);

        // After 12 rounds of permutation on zero state, we should get a specific result
        // This is a basic sanity check
        assert_ne!(state, [0, 0, 0, 0, 0], "State should change after permutation");
    }

    #[test]
    fn test_ascon_permutation_deterministic() {
        // Test that the permutation is deterministic
        let mut state1: AsconState = [1, 2, 3, 4, 5];
        let mut state2: AsconState = [1, 2, 3, 4, 5];

        ascon_permutation(&mut state1, 12);
        ascon_permutation(&mut state2, 12);

        assert_eq!(state1, state2, "Permutation should be deterministic");
    }

    #[test]
    fn test_ascon_permutation_different_rounds() {
        // Test that different numbers of rounds produce different results
        let mut state6: AsconState = [1, 2, 3, 4, 5];
        let mut state8: AsconState = [1, 2, 3, 4, 5];
        let mut state12: AsconState = [1, 2, 3, 4, 5];

        ascon_permutation(&mut state6, 6);
        ascon_permutation(&mut state8, 8);
        ascon_permutation(&mut state12, 12);

        // All should be different
        assert_ne!(state6, state8);
        assert_ne!(state8, state12);
        assert_ne!(state6, state12);
    }
}
