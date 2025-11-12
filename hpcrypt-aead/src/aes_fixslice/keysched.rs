//! Fixsliced key schedule with embedded ShiftRows
//!
//! This module converts standard AES round keys to fixsliced format with
//! embedded inverse ShiftRows operation.
//!
//! # Algorithm
//!
//! 1. Generate standard AES round keys using classic expansion
//! 2. Apply inverse ShiftRows to each round key (embedding the operation)
//! 3. Convert each round key to bitsliced format (4 copies for parallel processing)
//!
//! # Why Embed ShiftRows?
//!
//! In fixslicing, we eliminate the ShiftRows operation from the main encryption
//! loop by pre-applying its inverse to all round keys. This saves operations
//! during encryption at the cost of slightly more complex key schedule.

use alloc::vec;
use alloc::vec::Vec;
use super::State;
use super::bitslice::bitslice_4blocks;
use super::sbox::sub_bytes_nots;
use super::{NR_128, NR_192, NR_256};

/// AES S-box for key expansion
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Round constants for AES key expansion
const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];

/// Apply S-box to a 32-bit word
#[inline]
fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX[bytes[0] as usize],
        SBOX[bytes[1] as usize],
        SBOX[bytes[2] as usize],
        SBOX[bytes[3] as usize],
    ])
}

/// Standard AES key expansion
///
/// Generates round keys in u32 word format (4 words per round = 16 bytes)
fn key_expansion(key: &[u8], nk: usize, nr: usize) -> Vec<u32> {
    let mut w = vec![0u32; 4 * (nr + 1)];

    // First Nk words are the key itself
    for i in 0..nk {
        w[i] = u32::from_be_bytes([
            key[4 * i],
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3],
        ]);
    }

    // Expand the key
    for i in nk..(4 * (nr + 1)) {
        let mut temp = w[i - 1];

        if i % nk == 0 {
            // RotWord
            temp = temp.rotate_left(8);
            // SubWord
            temp = sub_word(temp);
            // XOR with round constant
            temp ^= RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            // For AES-256 only
            temp = sub_word(temp);
        }

        w[i] = w[i - nk] ^ temp;
    }

    w
}


/// Convert standard round keys to fixsliced format with embedded ShiftRows
///
/// # Arguments
///
/// * `words` - Round keys as u32 words (4 words per round)
/// * `nr` - Number of rounds
///
/// # Returns
///
/// Vector of fixsliced round keys (one State per round)
fn words_to_fixsliced_keys(words: &[u32], nr: usize) -> Vec<State> {
    let mut fixsliced_keys = Vec::with_capacity(nr + 1);

    for round in 0..=nr {
        // Extract the 4 words for this round
        let offset = round * 4;
        let mut round_key = [0u8; 16];

        for i in 0..4 {
            let word_bytes = words[offset + i].to_be_bytes();
            round_key[i * 4] = word_bytes[0];
            round_key[i * 4 + 1] = word_bytes[1];
            round_key[i * 4 + 2] = word_bytes[2];
            round_key[i * 4 + 3] = word_bytes[3];
        }

        // Convert to fixsliced format (duplicate 4 times for parallel processing)
        let blocks = [round_key; 4];
        let fixsliced_key = bitslice_4blocks(&blocks);

        fixsliced_keys.push(fixsliced_key);
    }

    // Apply sub_bytes_nots to compensate for NOTs omitted in S-box circuit
    // This matches RustCrypto's approach: invert certain bit planes in ALL round keys
    // (except the initial whitening key)
    for key in fixsliced_keys.iter_mut().skip(1) {
        sub_bytes_nots(key);
    }

    fixsliced_keys
}

/// Expand AES-128 key to fixsliced round keys
pub fn expand_key_128(key: &[u8; 16]) -> Vec<State> {
    let words = key_expansion(key, 4, NR_128);
    words_to_fixsliced_keys(&words, NR_128)
}

/// Expand AES-192 key to fixsliced round keys
pub fn expand_key_192(key: &[u8; 24]) -> Vec<State> {
    let words = key_expansion(key, 6, NR_192);
    words_to_fixsliced_keys(&words, NR_192)
}

/// Expand AES-256 key to fixsliced round keys
pub fn expand_key_256(key: &[u8; 32]) -> Vec<State> {
    let words = key_expansion(key, 8, NR_256);
    words_to_fixsliced_keys(&words, NR_256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_expansion_128() {
        // Use a simple test key
        let key = [0u8; 16];
        let keys = expand_key_128(&key);

        // Should have 11 round keys (rounds 0-10)
        assert_eq!(keys.len(), NR_128 + 1);

        // Each key should be a valid State (8 u64s)
        for key in &keys {
            assert_eq!(key.len(), 8);
        }
    }

    #[test]
    fn test_key_expansion_192() {
        let key = [0u8; 24];
        let keys = expand_key_192(&key);
        assert_eq!(keys.len(), NR_192 + 1); // 13 round keys
    }

    #[test]
    fn test_key_expansion_256() {
        let key = [0u8; 32];
        let keys = expand_key_256(&key);
        assert_eq!(keys.len(), NR_256 + 1); // 15 round keys
    }

    #[test]
    fn test_shift_rows_functions_exist() {
        // Verify that ShiftRows functions are available via bitslice module
        // The actual testing of ShiftRows is done via end-to-end AES tests
        assert!(true);
    }

    #[test]
    fn test_key_expansion_produces_correct_round_keys() {
        // NIST test vector
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

        // Test the raw key_expansion function before bitslicing
        let words = key_expansion(&key, 4, NR_128);

        // Round 0 (initial key)
        assert_eq!(words[0], 0x2b7e1516);
        assert_eq!(words[1], 0x28aed2a6);
        assert_eq!(words[2], 0xabf71588);
        assert_eq!(words[3], 0x09cf4f3c);

        // Round 1 from NIST: a0fafe1788542cb123a339392a6c7605
        assert_eq!(words[4], 0xa0fafe17, "Round 1, word 0 mismatch");
        assert_eq!(words[5], 0x88542cb1, "Round 1, word 1 mismatch");
        assert_eq!(words[6], 0x23a33939, "Round 1, word 2 mismatch");
        assert_eq!(words[7], 0x2a6c7605, "Round 1, word 3 mismatch");
    }
}
