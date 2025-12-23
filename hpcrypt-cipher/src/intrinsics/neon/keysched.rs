//! ARM NEON AES key expansion.
//!
//! ARM's AES instructions work differently from x86 AES-NI:
//! - vaeseq_u8(state, key) performs: SubBytes(ShiftRows(state XOR key))
//! - vaesmcq_u8(state) performs: MixColumns(state)
//! - vaesdq_u8(state, key) performs: InvSubBytes(InvShiftRows(state XOR key))
//! - vaesimcq_u8(state) performs: InvMixColumns(state)
//!
//! The key schedule generates standard AES round keys. For encryption,
//! keys are used as-is. For decryption, the middle keys need InvMixColumns
//! applied (Equivalent Inverse Cipher transformation).

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use zeroize::{Zeroize, ZeroizeOnDrop};

const NR_128: usize = 10;
const NR_192: usize = 12;
const NR_256: usize = 14;

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

/// AES-128 cipher using ARM NEON.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(C, align(16))]
pub struct AesNeon128 {
    #[zeroize(skip)]
    enc_keys: [uint8x16_t; 11],
    #[zeroize(skip)]
    dec_keys: [uint8x16_t; 11],
}

/// AES-192 cipher using ARM NEON.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(C, align(16))]
pub struct AesNeon192 {
    #[zeroize(skip)]
    enc_keys: [uint8x16_t; 13],
    #[zeroize(skip)]
    dec_keys: [uint8x16_t; 13],
}

/// AES-256 cipher using ARM NEON.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(C, align(16))]
pub struct AesNeon256 {
    #[zeroize(skip)]
    enc_keys: [uint8x16_t; 15],
    #[zeroize(skip)]
    dec_keys: [uint8x16_t; 15],
}

impl AesNeon128 {
    /// Creates a new AES-128 cipher.
    ///
    /// # Safety
    ///
    /// Caller must ensure ARM Cryptographic Extensions are available.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    pub unsafe fn new(key: &[u8; 16]) -> Self {
        let enc_keys = expand_key_128(key);
        let dec_keys = prepare_dec_keys_128(&enc_keys);
        Self { enc_keys, dec_keys }
    }

    /// Returns the number of rounds.
    #[inline]
    pub const fn rounds(&self) -> usize {
        NR_128
    }

    #[inline]
    pub(crate) fn enc_keys(&self) -> &[uint8x16_t; 11] {
        &self.enc_keys
    }

    #[inline]
    pub(crate) fn dec_keys(&self) -> &[uint8x16_t; 11] {
        &self.dec_keys
    }
}

impl AesNeon192 {
    /// Creates a new AES-192 cipher.
    ///
    /// # Safety
    ///
    /// Caller must ensure ARM Cryptographic Extensions are available.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    pub unsafe fn new(key: &[u8; 24]) -> Self {
        let enc_keys = expand_key_192(key);
        let dec_keys = prepare_dec_keys_192(&enc_keys);
        Self { enc_keys, dec_keys }
    }

    /// Returns the number of rounds.
    #[inline]
    pub const fn rounds(&self) -> usize {
        NR_192
    }

    #[inline]
    pub(crate) fn enc_keys(&self) -> &[uint8x16_t; 13] {
        &self.enc_keys
    }

    #[inline]
    pub(crate) fn dec_keys(&self) -> &[uint8x16_t; 13] {
        &self.dec_keys
    }
}

impl AesNeon256 {
    /// Creates a new AES-256 cipher.
    ///
    /// # Safety
    ///
    /// Caller must ensure ARM Cryptographic Extensions are available.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    pub unsafe fn new(key: &[u8; 32]) -> Self {
        let enc_keys = expand_key_256(key);
        let dec_keys = prepare_dec_keys_256(&enc_keys);
        Self { enc_keys, dec_keys }
    }

    /// Returns the number of rounds.
    #[inline]
    pub const fn rounds(&self) -> usize {
        NR_256
    }

    #[inline]
    pub(crate) fn enc_keys(&self) -> &[uint8x16_t; 15] {
        &self.enc_keys
    }

    #[inline]
    pub(crate) fn dec_keys(&self) -> &[uint8x16_t; 15] {
        &self.dec_keys
    }
}

/// Expand AES-128 key using textbook algorithm
#[target_feature(enable = "neon")]
unsafe fn expand_key_128(key: &[u8; 16]) -> [uint8x16_t; 11] {
    let mut w = [0u32; 44];

    // First 4 words are the key itself
    for i in 0..4 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    // Expand the key
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = temp.rotate_left(8);
            temp = sub_word(temp);
            temp ^= RCON[i / 4 - 1];
        }
        w[i] = w[i - 4] ^ temp;
    }

    // Pack words into NEON vectors
    let mut rk = [vdupq_n_u8(0); 11];
    for i in 0..11 {
        let offset = i * 4;
        let mut bytes = [0u8; 16];
        for j in 0..4 {
            let word_bytes = w[offset + j].to_be_bytes();
            bytes[j * 4] = word_bytes[0];
            bytes[j * 4 + 1] = word_bytes[1];
            bytes[j * 4 + 2] = word_bytes[2];
            bytes[j * 4 + 3] = word_bytes[3];
        }
        rk[i] = vld1q_u8(bytes.as_ptr());
    }

    rk
}

/// Expand AES-192 key using textbook algorithm
#[target_feature(enable = "neon")]
unsafe fn expand_key_192(key: &[u8; 24]) -> [uint8x16_t; 13] {
    let mut w = [0u32; 52];

    // First 6 words are the key itself
    for i in 0..6 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    // Expand the key
    for i in 6..52 {
        let mut temp = w[i - 1];
        if i % 6 == 0 {
            temp = temp.rotate_left(8);
            temp = sub_word(temp);
            temp ^= RCON[i / 6 - 1];
        }
        w[i] = w[i - 6] ^ temp;
    }

    // Pack words into NEON vectors
    let mut rk = [vdupq_n_u8(0); 13];
    for i in 0..13 {
        let offset = i * 4;
        let mut bytes = [0u8; 16];
        for j in 0..4 {
            let word_bytes = w[offset + j].to_be_bytes();
            bytes[j * 4] = word_bytes[0];
            bytes[j * 4 + 1] = word_bytes[1];
            bytes[j * 4 + 2] = word_bytes[2];
            bytes[j * 4 + 3] = word_bytes[3];
        }
        rk[i] = vld1q_u8(bytes.as_ptr());
    }

    rk
}

/// Expand AES-256 key using textbook algorithm
#[target_feature(enable = "neon")]
unsafe fn expand_key_256(key: &[u8; 32]) -> [uint8x16_t; 15] {
    let mut w = [0u32; 60];

    // First 8 words are the key itself
    for i in 0..8 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    // Expand the key
    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = temp.rotate_left(8);
            temp = sub_word(temp);
            temp ^= RCON[i / 8 - 1];
        } else if i % 8 == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }

    // Pack words into NEON vectors
    let mut rk = [vdupq_n_u8(0); 15];
    for i in 0..15 {
        let offset = i * 4;
        let mut bytes = [0u8; 16];
        for j in 0..4 {
            let word_bytes = w[offset + j].to_be_bytes();
            bytes[j * 4] = word_bytes[0];
            bytes[j * 4 + 1] = word_bytes[1];
            bytes[j * 4 + 2] = word_bytes[2];
            bytes[j * 4 + 3] = word_bytes[3];
        }
        rk[i] = vld1q_u8(bytes.as_ptr());
    }

    rk
}

/// Prepare decryption keys for AES-128 (Equivalent Inverse Cipher)
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
unsafe fn prepare_dec_keys_128(enc_keys: &[uint8x16_t; 11]) -> [uint8x16_t; 11] {
    let mut dec_keys = [vdupq_n_u8(0); 11];
    // First decryption key is last encryption key
    dec_keys[0] = enc_keys[10];
    // Middle keys need InvMixColumns
    for i in 1..10 {
        dec_keys[i] = vaesimcq_u8(enc_keys[10 - i]);
    }
    // Last decryption key is first encryption key
    dec_keys[10] = enc_keys[0];
    dec_keys
}

/// Prepare decryption keys for AES-192 (Equivalent Inverse Cipher)
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
unsafe fn prepare_dec_keys_192(enc_keys: &[uint8x16_t; 13]) -> [uint8x16_t; 13] {
    let mut dec_keys = [vdupq_n_u8(0); 13];
    dec_keys[0] = enc_keys[12];
    for i in 1..12 {
        dec_keys[i] = vaesimcq_u8(enc_keys[12 - i]);
    }
    dec_keys[12] = enc_keys[0];
    dec_keys
}

/// Prepare decryption keys for AES-256 (Equivalent Inverse Cipher)
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
unsafe fn prepare_dec_keys_256(enc_keys: &[uint8x16_t; 15]) -> [uint8x16_t; 15] {
    let mut dec_keys = [vdupq_n_u8(0); 15];
    dec_keys[0] = enc_keys[14];
    for i in 1..14 {
        dec_keys[i] = vaesimcq_u8(enc_keys[14 - i]);
    }
    dec_keys[14] = enc_keys[0];
    dec_keys
}

impl core::fmt::Debug for AesNeon128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesNeon128")
            .field("rounds", &NR_128)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for AesNeon192 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesNeon192")
            .field("rounds", &NR_192)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for AesNeon256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesNeon256")
            .field("rounds", &NR_256)
            .finish_non_exhaustive()
    }
}
