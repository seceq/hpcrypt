//! Optimized AES (Advanced Encryption Standard) block cipher
//!
//! This module contains Phase 1 optimizations:
//! - Optimization 1.2: Aggressive function inlining (#[inline(always)])
//! - Optimization 1.3: Loop unrolling with rolling macros
//!
//! Pure Rust implementation of AES-128, AES-192, and AES-256
//! Based on FIPS 197

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES block size in bytes (128 bits)
pub const BLOCK_SIZE: usize = 16;

/// AES-128 key size in bytes
pub const AES128_KEY_SIZE: usize = 16;
/// AES-192 key size in bytes
pub const AES192_KEY_SIZE: usize = 24;
/// AES-256 key size in bytes
pub const AES256_KEY_SIZE: usize = 32;

/// AES S-box (Substitution box)
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

/// AES inverse S-box (for decryption)
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Round constants for key expansion
const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];

// ============================================================================
// Optimization 1.3: Rolling Macros for Loop Unrolling
// ============================================================================

/// Rolling macro for AES encryption rounds
/// Makes unrolled code readable and maintainable
macro_rules! aes_encrypt_round {
    ($self:ident, $state:ident, $round:expr) => {
        $self.sub_bytes(&mut $state);
        $self.shift_rows(&mut $state);
        $self.mix_columns(&mut $state);
        $self.add_round_key(&mut $state, $round);
    };
}

/// Rolling macro for final encryption round (no MixColumns)
macro_rules! aes_encrypt_final_round {
    ($self:ident, $state:ident, $round:expr) => {
        $self.sub_bytes(&mut $state);
        $self.shift_rows(&mut $state);
        $self.add_round_key(&mut $state, $round);
    };
}

/// Rolling macro for AES decryption rounds
macro_rules! aes_decrypt_round {
    ($self:ident, $state:ident, $round:expr) => {
        $self.inv_shift_rows(&mut $state);
        $self.inv_sub_bytes(&mut $state);
        $self.add_round_key(&mut $state, $round);
        $self.inv_mix_columns(&mut $state);
    };
}

/// Rolling macro for final decryption round (no InvMixColumns)
macro_rules! aes_decrypt_final_round {
    ($self:ident, $state:ident, $round:expr) => {
        $self.inv_shift_rows(&mut $state);
        $self.inv_sub_bytes(&mut $state);
        $self.add_round_key(&mut $state, $round);
    };
}

// ============================================================================
// AES Cipher Implementation
// ============================================================================

/// AES cipher context (optimized)
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AesOptimized {
    /// Expanded round keys
    round_keys: Vec<u32>,
    /// Number of rounds (10, 12, or 14)
    nr: usize,
}

impl AesOptimized {
    /// Create a new AES-128 cipher
    pub fn new_128(key: &[u8; 16]) -> Self {
        Self::new(key, 10)
    }

    /// Create a new AES-192 cipher
    pub fn new_192(key: &[u8; 24]) -> Self {
        Self::new(key, 12)
    }

    /// Create a new AES-256 cipher
    pub fn new_256(key: &[u8; 32]) -> Self {
        Self::new(key, 14)
    }

    /// Create AES cipher with key expansion
    fn new(key: &[u8], nr: usize) -> Self {
        let nk = key.len() / 4; // Number of 32-bit words in key
        let round_keys = Self::key_expansion(key, nk, nr);
        Self { round_keys, nr }
    }

    /// AES key expansion
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
                temp = Self::sub_word(temp);
                // XOR with round constant
                temp ^= RCON[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                // For AES-256 only
                temp = Self::sub_word(temp);
            }

            w[i] = w[i - nk] ^ temp;
        }

        w
    }

    /// Apply S-box to a 32-bit word
    #[inline(always)]  // Optimization 1.2
    fn sub_word(word: u32) -> u32 {
        let bytes = word.to_be_bytes();
        u32::from_be_bytes([
            SBOX[bytes[0] as usize],
            SBOX[bytes[1] as usize],
            SBOX[bytes[2] as usize],
            SBOX[bytes[3] as usize],
        ])
    }

    /// Encrypt a single block (16 bytes) with unrolled loops
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = [
            [block[0], block[4], block[8], block[12]],
            [block[1], block[5], block[9], block[13]],
            [block[2], block[6], block[10], block[14]],
            [block[3], block[7], block[11], block[15]],
        ];

        // Initial round key addition
        self.add_round_key(&mut state, 0);

        // Optimization 1.3: Unrolled rounds with macros
        match self.nr {
            10 => {
                // AES-128: 10 rounds
                aes_encrypt_round!(self, state, 1);
                aes_encrypt_round!(self, state, 2);
                aes_encrypt_round!(self, state, 3);
                aes_encrypt_round!(self, state, 4);
                aes_encrypt_round!(self, state, 5);
                aes_encrypt_round!(self, state, 6);
                aes_encrypt_round!(self, state, 7);
                aes_encrypt_round!(self, state, 8);
                aes_encrypt_round!(self, state, 9);
                aes_encrypt_final_round!(self, state, 10);
            }
            12 => {
                // AES-192: 12 rounds
                aes_encrypt_round!(self, state, 1);
                aes_encrypt_round!(self, state, 2);
                aes_encrypt_round!(self, state, 3);
                aes_encrypt_round!(self, state, 4);
                aes_encrypt_round!(self, state, 5);
                aes_encrypt_round!(self, state, 6);
                aes_encrypt_round!(self, state, 7);
                aes_encrypt_round!(self, state, 8);
                aes_encrypt_round!(self, state, 9);
                aes_encrypt_round!(self, state, 10);
                aes_encrypt_round!(self, state, 11);
                aes_encrypt_final_round!(self, state, 12);
            }
            14 => {
                // AES-256: 14 rounds
                aes_encrypt_round!(self, state, 1);
                aes_encrypt_round!(self, state, 2);
                aes_encrypt_round!(self, state, 3);
                aes_encrypt_round!(self, state, 4);
                aes_encrypt_round!(self, state, 5);
                aes_encrypt_round!(self, state, 6);
                aes_encrypt_round!(self, state, 7);
                aes_encrypt_round!(self, state, 8);
                aes_encrypt_round!(self, state, 9);
                aes_encrypt_round!(self, state, 10);
                aes_encrypt_round!(self, state, 11);
                aes_encrypt_round!(self, state, 12);
                aes_encrypt_round!(self, state, 13);
                aes_encrypt_final_round!(self, state, 14);
            }
            _ => unreachable!("Invalid number of rounds"),
        }

        // Convert state back to bytes
        [
            state[0][0], state[1][0], state[2][0], state[3][0],
            state[0][1], state[1][1], state[2][1], state[3][1],
            state[0][2], state[1][2], state[2][2], state[3][2],
            state[0][3], state[1][3], state[2][3], state[3][3],
        ]
    }

    /// Decrypt a single block (16 bytes) with unrolled loops
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = [
            [block[0], block[4], block[8], block[12]],
            [block[1], block[5], block[9], block[13]],
            [block[2], block[6], block[10], block[14]],
            [block[3], block[7], block[11], block[15]],
        ];

        // Initial round key addition
        self.add_round_key(&mut state, self.nr);

        // Optimization 1.3: Unrolled rounds with macros
        match self.nr {
            10 => {
                // AES-128: rounds 9-0
                aes_decrypt_round!(self, state, 9);
                aes_decrypt_round!(self, state, 8);
                aes_decrypt_round!(self, state, 7);
                aes_decrypt_round!(self, state, 6);
                aes_decrypt_round!(self, state, 5);
                aes_decrypt_round!(self, state, 4);
                aes_decrypt_round!(self, state, 3);
                aes_decrypt_round!(self, state, 2);
                aes_decrypt_round!(self, state, 1);
                aes_decrypt_final_round!(self, state, 0);
            }
            12 => {
                // AES-192: rounds 11-0
                aes_decrypt_round!(self, state, 11);
                aes_decrypt_round!(self, state, 10);
                aes_decrypt_round!(self, state, 9);
                aes_decrypt_round!(self, state, 8);
                aes_decrypt_round!(self, state, 7);
                aes_decrypt_round!(self, state, 6);
                aes_decrypt_round!(self, state, 5);
                aes_decrypt_round!(self, state, 4);
                aes_decrypt_round!(self, state, 3);
                aes_decrypt_round!(self, state, 2);
                aes_decrypt_round!(self, state, 1);
                aes_decrypt_final_round!(self, state, 0);
            }
            14 => {
                // AES-256: rounds 13-0
                aes_decrypt_round!(self, state, 13);
                aes_decrypt_round!(self, state, 12);
                aes_decrypt_round!(self, state, 11);
                aes_decrypt_round!(self, state, 10);
                aes_decrypt_round!(self, state, 9);
                aes_decrypt_round!(self, state, 8);
                aes_decrypt_round!(self, state, 7);
                aes_decrypt_round!(self, state, 6);
                aes_decrypt_round!(self, state, 5);
                aes_decrypt_round!(self, state, 4);
                aes_decrypt_round!(self, state, 3);
                aes_decrypt_round!(self, state, 2);
                aes_decrypt_round!(self, state, 1);
                aes_decrypt_final_round!(self, state, 0);
            }
            _ => unreachable!("Invalid number of rounds"),
        }

        // Convert state back to bytes
        [
            state[0][0], state[1][0], state[2][0], state[3][0],
            state[0][1], state[1][1], state[2][1], state[3][1],
            state[0][2], state[1][2], state[2][2], state[3][2],
            state[0][3], state[1][3], state[2][3], state[3][3],
        ]
    }

    // ========================================================================
    // Round Functions with Optimization 1.2: #[inline(always)]
    // ========================================================================

    /// SubBytes transformation
    #[inline(always)]  // Optimization 1.2
    fn sub_bytes(&self, state: &mut [[u8; 4]; 4]) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = SBOX[state[i][j] as usize];
            }
        }
    }

    /// Inverse SubBytes transformation
    #[inline(always)]  // Optimization 1.2
    fn inv_sub_bytes(&self, state: &mut [[u8; 4]; 4]) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = INV_SBOX[state[i][j] as usize];
            }
        }
    }

    /// ShiftRows transformation
    #[inline(always)]  // Optimization 1.2
    fn shift_rows(&self, state: &mut [[u8; 4]; 4]) {
        // Row 0: no shift
        // Row 1: shift left by 1
        state[1].rotate_left(1);
        // Row 2: shift left by 2
        state[2].rotate_left(2);
        // Row 3: shift left by 3
        state[3].rotate_left(3);
    }

    /// Inverse ShiftRows transformation
    #[inline(always)]  // Optimization 1.2
    fn inv_shift_rows(&self, state: &mut [[u8; 4]; 4]) {
        // Row 0: no shift
        // Row 1: shift right by 1
        state[1].rotate_right(1);
        // Row 2: shift right by 2
        state[2].rotate_right(2);
        // Row 3: shift right by 3
        state[3].rotate_right(3);
    }

    /// MixColumns transformation
    /// Note: Optimization 1.1 (GF multiplication) would be applied here
    #[inline(always)]  // Optimization 1.2
    fn mix_columns(&self, state: &mut [[u8; 4]; 4]) {
        for col in 0..4 {
            let s0 = state[0][col];
            let s1 = state[1][col];
            let s2 = state[2][col];
            let s3 = state[3][col];

            // Compute gf_mul2 values once (will be Optimization 1.1 later)
            let s0_2 = (s0 << 1) ^ (((s0 >> 7) & 1) * 0x1b);
            let s1_2 = (s1 << 1) ^ (((s1 >> 7) & 1) * 0x1b);
            let s2_2 = (s2 << 1) ^ (((s2 >> 7) & 1) * 0x1b);
            let s3_2 = (s3 << 1) ^ (((s3 >> 7) & 1) * 0x1b);

            // gf_mul3(x) = gf_mul2(x) ^ x
            state[0][col] = s0_2 ^ (s1_2 ^ s1) ^ s2 ^ s3;
            state[1][col] = s0 ^ s1_2 ^ (s2_2 ^ s2) ^ s3;
            state[2][col] = s0 ^ s1 ^ s2_2 ^ (s3_2 ^ s3);
            state[3][col] = (s0_2 ^ s0) ^ s1 ^ s2 ^ s3_2;
        }
    }

    /// Inverse MixColumns transformation
    #[inline(always)]  // Optimization 1.2
    fn inv_mix_columns(&self, state: &mut [[u8; 4]; 4]) {
        for col in 0..4 {
            let s0 = state[0][col];
            let s1 = state[1][col];
            let s2 = state[2][col];
            let s3 = state[3][col];

            // Precompute all GF multiplications
            let s0_2 = (s0 << 1) ^ (((s0 >> 7) & 1) * 0x1b);
            let s1_2 = (s1 << 1) ^ (((s1 >> 7) & 1) * 0x1b);
            let s2_2 = (s2 << 1) ^ (((s2 >> 7) & 1) * 0x1b);
            let s3_2 = (s3 << 1) ^ (((s3 >> 7) & 1) * 0x1b);

            let s0_4 = (s0_2 << 1) ^ (((s0_2 >> 7) & 1) * 0x1b);
            let s1_4 = (s1_2 << 1) ^ (((s1_2 >> 7) & 1) * 0x1b);
            let s2_4 = (s2_2 << 1) ^ (((s2_2 >> 7) & 1) * 0x1b);
            let s3_4 = (s3_2 << 1) ^ (((s3_2 >> 7) & 1) * 0x1b);

            let s0_8 = (s0_4 << 1) ^ (((s0_4 >> 7) & 1) * 0x1b);
            let s1_8 = (s1_4 << 1) ^ (((s1_4 >> 7) & 1) * 0x1b);
            let s2_8 = (s2_4 << 1) ^ (((s2_4 >> 7) & 1) * 0x1b);
            let s3_8 = (s3_4 << 1) ^ (((s3_4 >> 7) & 1) * 0x1b);

            // gf_mul9(x) = gf_mul8(x) ^ x
            // gf_mul11(x) = gf_mul8(x) ^ gf_mul2(x) ^ x
            // gf_mul13(x) = gf_mul8(x) ^ gf_mul4(x) ^ x
            // gf_mul14(x) = gf_mul8(x) ^ gf_mul4(x) ^ gf_mul2(x)

            state[0][col] = (s0_8 ^ s0_4 ^ s0_2) ^ (s1_8 ^ s1_2 ^ s1) ^ (s2_8 ^ s2_4 ^ s2) ^ (s3_8 ^ s3);
            state[1][col] = (s0_8 ^ s0) ^ (s1_8 ^ s1_4 ^ s1_2) ^ (s2_8 ^ s2_2 ^ s2) ^ (s3_8 ^ s3_4 ^ s3);
            state[2][col] = (s0_8 ^ s0_4 ^ s0) ^ (s1_8 ^ s1) ^ (s2_8 ^ s2_4 ^ s2_2) ^ (s3_8 ^ s3_2 ^ s3);
            state[3][col] = (s0_8 ^ s0_2 ^ s0) ^ (s1_8 ^ s1_4 ^ s1) ^ (s2_8 ^ s2) ^ (s3_8 ^ s3_4 ^ s3_2);
        }
    }

    /// AddRoundKey transformation
    #[inline(always)]  // Optimization 1.2
    fn add_round_key(&self, state: &mut [[u8; 4]; 4], round: usize) {
        for col in 0..4 {
            let key_word = self.round_keys[round * 4 + col];
            let key_bytes = key_word.to_be_bytes();
            for row in 0..4 {
                state[row][col] ^= key_bytes[row];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_encrypt_nist() {
        // NIST FIPS 197 Appendix B test vector
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = hex_literal::hex!("3243f6a8885a308d313198a2e0370734");
        let expected = hex_literal::hex!("3925841d02dc09fbdc118597196a0b32");

        let cipher = AesOptimized::new_128(&key);
        let ciphertext = cipher.encrypt_block(&plaintext);

        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_aes128_decrypt_nist() {
        // NIST FIPS 197 Appendix B test vector
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let ciphertext = hex_literal::hex!("3925841d02dc09fbdc118597196a0b32");
        let expected = hex_literal::hex!("3243f6a8885a308d313198a2e0370734");

        let cipher = AesOptimized::new_128(&key);
        let plaintext = cipher.decrypt_block(&ciphertext);

        assert_eq!(plaintext, expected);
    }

    #[test]
    fn test_aes128_roundtrip() {
        let key = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex_literal::hex!("00112233445566778899aabbccddeeff");

        let cipher = AesOptimized::new_128(&key);
        let ciphertext = cipher.encrypt_block(&plaintext);
        let decrypted = cipher.decrypt_block(&ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes192_encrypt() {
        // NIST test vector for AES-192
        let key = hex_literal::hex!("000102030405060708090a0b0c0d0e0f1011121314151617");
        let plaintext = hex_literal::hex!("00112233445566778899aabbccddeeff");
        let expected = hex_literal::hex!("dda97ca4864cdfe06eaf70a0ec0d7191");

        let cipher = AesOptimized::new_192(&key);
        let ciphertext = cipher.encrypt_block(&plaintext);

        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_aes256_encrypt() {
        // NIST test vector for AES-256
        let key = hex_literal::hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        let plaintext = hex_literal::hex!("00112233445566778899aabbccddeeff");
        let expected = hex_literal::hex!("8ea2b7ca516745bfeafc49904b496089");

        let cipher = AesOptimized::new_256(&key);
        let ciphertext = cipher.encrypt_block(&plaintext);

        assert_eq!(ciphertext, expected);
    }
}
