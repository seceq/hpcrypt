//! Fixslicing AES Implementation
//!
//! This module implements the fixslicing technique for AES, which provides:
//! - **Constant-time execution** (immune to cache-timing attacks)
//! - **Parallel processing** of 4 AES blocks simultaneously
//! - **52% reduction** in linear layer operations compared to standard bitslicing
//!
//! # References
//!
//! - Adomnicai & Peyrin (2020): "Fixslicing AES-like Ciphers" (IACR TCHES 2021)
//!   <https://eprint.iacr.org/2020/1123>
//! - Boyar & Peralta (2010): "A depth-16 circuit for the AES S-box"

#![allow(dead_code)] // Remove this as we implement

use alloc::vec::Vec;

mod bitslice;
mod consts;
mod keysched;
mod mixcolumns;
mod sbox;

#[cfg(test)]
mod tests;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixsliced AES state representing 4 blocks in parallel
///
/// Each of the 8 u64 values represents one bit from 64 positions across 4 blocks.
/// Total: 8 × 64 bits = 512 bits = 4 × 128-bit AES blocks
pub(crate) type State = [u64; 8];

/// AES block size in bytes (128 bits)
pub const BLOCK_SIZE: usize = 16;

/// AES-128 key size in bytes
pub const AES128_KEY_SIZE: usize = 16;
/// AES-192 key size in bytes
pub const AES192_KEY_SIZE: usize = 24;
/// AES-256 key size in bytes
pub const AES256_KEY_SIZE: usize = 32;

/// Number of rounds for each AES variant
const NR_128: usize = 10;
const NR_192: usize = 12;
const NR_256: usize = 14;

/// Fixsliced AES cipher instance
///
/// Processes 4 AES blocks in parallel using bitslicing technique.
/// Provides constant-time execution (immune to cache-timing attacks).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AesFixslice {
    /// Fixsliced round keys with embedded ShiftRows
    /// Size: (NR + 1) round keys × 8 u64 per key
    round_keys: Vec<State>,
    /// Number of rounds (10, 12, or 14)
    nr: usize,
}

impl AesFixslice {
    /// Create a new AES-128 instance with fixslicing
    pub fn new_128(key: &[u8; 16]) -> Self {
        let round_keys = keysched::expand_key_128(key);
        Self {
            round_keys,
            nr: NR_128,
        }
    }

    /// Create a new AES-192 instance with fixslicing
    pub fn new_192(key: &[u8; 24]) -> Self {
        let round_keys = keysched::expand_key_192(key);
        Self {
            round_keys,
            nr: NR_192,
        }
    }

    /// Create a new AES-256 instance with fixslicing
    pub fn new_256(key: &[u8; 32]) -> Self {
        let round_keys = keysched::expand_key_256(key);
        Self {
            round_keys,
            nr: NR_256,
        }
    }

    /// Encrypt 4 blocks in parallel (primary API)
    ///
    /// This is the most efficient way to use fixslicing, as it processes
    /// 4 blocks simultaneously using bitwise operations.
    ///
    /// # Arguments
    ///
    /// * `blocks` - Array of 4 blocks to encrypt in-place
    ///
    /// # Security
    ///
    /// This function is constant-time: execution time does not depend on
    /// the input data.
    pub fn encrypt_blocks_4(&self, blocks: &mut [[u8; 16]; 4]) {
        // Step 1: Convert 4 blocks to bitsliced representation
        let mut state = bitslice::bitslice_4blocks(blocks);

        // Step 2: Initial round key addition
        bitslice::xor_round_key(&mut state, &self.round_keys[0]);

        // Step 3: Main rounds
        for round in 1..self.nr {
            sbox::sub_bytes(&mut state);
            // Note: sub_bytes_nots is NOT called here - the compensation is in the round keys
            bitslice::shift_rows_1(&mut state); // Standard ShiftRows
            mixcolumns::mix_columns(&mut state);
            bitslice::xor_round_key(&mut state, &self.round_keys[round]);
        }

        // Step 4: Final round (no MixColumns)
        sbox::sub_bytes(&mut state);
        // Note: sub_bytes_nots is NOT called here - the compensation is in the round keys
        bitslice::shift_rows_1(&mut state); // Standard ShiftRows
        bitslice::xor_round_key(&mut state, &self.round_keys[self.nr]);

        // Step 5: Convert back to block representation
        *blocks = bitslice::unbitslice_4blocks(&state);
    }

    /// Decrypt 4 blocks in parallel
    ///
    /// # Arguments
    ///
    /// * `blocks` - Array of 4 blocks to decrypt in-place
    ///
    /// # Security
    ///
    /// This function is constant-time: execution time does not depend on
    /// the input data.
    pub fn decrypt_blocks_4(&self, blocks: &mut [[u8; 16]; 4]) {
        // Step 1: Convert 4 blocks to bitsliced representation
        let mut state = bitslice::bitslice_4blocks(blocks);

        // Step 2: Initial round key addition (reverse order)
        bitslice::xor_round_key(&mut state, &self.round_keys[self.nr]);

        // Step 3: Inverse final round (no InvMixColumns)
        bitslice::inv_shift_rows_1(&mut state); // Inverse ShiftRows
        sbox::inv_sub_bytes(&mut state);
        // Note: sub_bytes_nots is NOT called - the compensation is in the round keys

        // Step 4: Main rounds (reverse order)
        for round in (1..self.nr).rev() {
            bitslice::xor_round_key(&mut state, &self.round_keys[round]);
            mixcolumns::inv_mix_columns(&mut state);
            bitslice::inv_shift_rows_1(&mut state); // Inverse ShiftRows
            sbox::inv_sub_bytes(&mut state);
            // Note: sub_bytes_nots is NOT called - the compensation is in the round keys
        }

        // Step 5: Final round key
        bitslice::xor_round_key(&mut state, &self.round_keys[0]);

        // Step 6: Convert back to block representation
        *blocks = bitslice::unbitslice_4blocks(&state);
    }

    /// Encrypt a single block (convenience wrapper)
    ///
    /// Note: This is less efficient than `encrypt_blocks_4` as it processes
    /// only one block but still performs full bitslicing conversion.
    /// For best performance, use `encrypt_blocks_4` when possible.
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut blocks = [*block; 4];
        self.encrypt_blocks_4(&mut blocks);
        blocks[0]
    }

    /// Decrypt a single block (convenience wrapper)
    ///
    /// Note: This is less efficient than `decrypt_blocks_4` as it processes
    /// only one block but still performs full bitslicing conversion.
    /// For best performance, use `decrypt_blocks_4` when possible.
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut blocks = [*block; 4];
        self.decrypt_blocks_4(&mut blocks);
        blocks[0]
    }
}
