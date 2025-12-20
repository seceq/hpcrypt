//! Ascon AEAD implementation
//!
//! Ascon is a family of lightweight authenticated encryption algorithms
//! designed for resource-constrained environments. It was selected as the
//! winner of the NIST Lightweight Cryptography competition in 2023.
//!
//! This implementation provides:
//! - **Ascon-128** - Standard variant (128-bit security, 64-bit rate)
//! - **Ascon-128a** - High-speed variant (128-bit security, 128-bit rate)
//!
//! # Security Properties
//!
//! - 128-bit security level
//! - Nonce-based AEAD (nonces must never be reused with the same key)
//! - Resistant to side-channel attacks
//! - Small memory footprint (~600 bytes)
//! - Constant-time implementation
//!
//! # Standards
//!
//! - NIST Lightweight Cryptography Winner (2023)
//! - Specified in: <https://ascon.iaik.tugraz.at/>
//!
//! # References
//!
//! - Dobraunig, Eichlseder, Mendel, Schläffer: "Ascon v1.2"
//! - NIST LWC Standardization: <https://csrc.nist.gov/projects/lightweight-cryptography>

extern crate alloc;

use alloc::vec::Vec;
use hpcrypt_core::ascon::{ascon_permutation, AsconState};
use zeroize::Zeroize;

/// Ascon-128 AEAD cipher
///
/// Standard variant with 64-bit rate (slower but more conservative).
///
/// - Key size: 16 bytes (128 bits)
/// - Nonce size: 16 bytes (128 bits)
/// - Tag size: 16 bytes (128 bits)
/// - Rate: 64 bits (8 bytes)
/// - Rounds: 12 (initialization), 6 (absorbing), 12 (finalization)
///
/// # Example
///
/// ```
/// use hpcrypt_aead::ascon::Ascon128;
///
/// let key = [0u8; 16];
/// let nonce = [0u8; 16];
/// let plaintext = b"Hello, Ascon!";
/// let aad = b"associated data";
///
/// let ciphertext = Ascon128::encrypt(&key, &nonce, plaintext, aad);
/// let decrypted = Ascon128::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
///
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
#[derive(Debug)]
pub struct Ascon128;

/// Ascon-128a AEAD cipher
///
/// High-speed variant with 128-bit rate (faster, suitable for most applications).
///
/// - Key size: 16 bytes (128 bits)
/// - Nonce size: 16 bytes (128 bits)
/// - Tag size: 16 bytes (128 bits)
/// - Rate: 128 bits (16 bytes)
/// - Rounds: 12 (initialization), 8 (absorbing), 12 (finalization)
///
/// # Example
///
/// ```
/// use hpcrypt_aead::ascon::Ascon128a;
///
/// let key = [0u8; 16];
/// let nonce = [0u8; 16];
/// let plaintext = b"Hello, Ascon!";
/// let aad = b"associated data";
///
/// let ciphertext = Ascon128a::encrypt(&key, &nonce, plaintext, aad);
/// let decrypted = Ascon128a::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
///
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
#[derive(Debug)]
pub struct Ascon128a;

// Ascon permutation constants (original Ascon v1.2 - big-endian)
const ASCON_128_IV: u64 = 0x80400c0600000000;
const ASCON_128A_IV: u64 = 0x80800c0800000000;

// NIST SP 800-232 constants (little-endian)
// IV = (VARIANT) | (PA_ROUNDS << 16) | (PB_ROUNDS << 20) | (TAG_SIZE*8 << 24) | (RATE << 40)
// AEAD128: VARIANT=1, PA=12, PB=8, TAG=16*8=128, RATE=16 -> 0x00001000808c0001
// Note: NIST AEAD128 is the former Ascon-128a (rate=128 bits), not Ascon-128 (rate=64 bits)
const ASCON_NIST_AEAD128_IV: u64 = 0x00001000808c0001;

impl Ascon128 {
    /// Number of initialization/finalization rounds
    const ROUNDS_A: usize = 12;

    /// Number of intermediate rounds
    const ROUNDS_B: usize = 6;

    /// Rate in bytes (64 bits = 8 bytes)
    const RATE: usize = 8;

    /// Encrypt plaintext with Ascon-128
    ///
    /// Returns ciphertext || tag (16-byte tag appended)
    pub fn encrypt(
        key: &[u8; 16],
        nonce: &[u8; 16],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        ascon_encrypt(
            key,
            nonce,
            plaintext,
            associated_data,
            ASCON_128_IV,
            Self::RATE,
            Self::ROUNDS_A,
            Self::ROUNDS_B,
        )
    }

    /// Decrypt ciphertext with Ascon-128
    ///
    /// Expects ciphertext || tag (16-byte tag appended)
    ///
    /// Returns Some(plaintext) if authentication succeeds, None otherwise
    pub fn decrypt(
        key: &[u8; 16],
        nonce: &[u8; 16],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return None;
        }

        ascon_decrypt(
            key,
            nonce,
            ciphertext_with_tag,
            associated_data,
            ASCON_128_IV,
            Self::RATE,
            Self::ROUNDS_A,
            Self::ROUNDS_B,
        )
    }
}

impl Ascon128a {
    /// Number of initialization/finalization rounds
    const ROUNDS_A: usize = 12;

    /// Number of intermediate rounds
    const ROUNDS_B: usize = 8;

    /// Rate in bytes (128 bits = 16 bytes)
    const RATE: usize = 16;

    /// Encrypt plaintext with Ascon-128a
    ///
    /// Returns ciphertext || tag (16-byte tag appended)
    pub fn encrypt(
        key: &[u8; 16],
        nonce: &[u8; 16],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        ascon_encrypt(
            key,
            nonce,
            plaintext,
            associated_data,
            ASCON_128A_IV,
            Self::RATE,
            Self::ROUNDS_A,
            Self::ROUNDS_B,
        )
    }

    /// Decrypt ciphertext with Ascon-128a
    ///
    /// Expects ciphertext || tag (16-byte tag appended)
    ///
    /// Returns Some(plaintext) if authentication succeeds, None otherwise
    pub fn decrypt(
        key: &[u8; 16],
        nonce: &[u8; 16],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return None;
        }

        ascon_decrypt(
            key,
            nonce,
            ciphertext_with_tag,
            associated_data,
            ASCON_128A_IV,
            Self::RATE,
            Self::ROUNDS_A,
            Self::ROUNDS_B,
        )
    }
}

/// Ascon encryption
#[allow(clippy::too_many_arguments)]
fn ascon_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    plaintext: &[u8],
    associated_data: &[u8],
    iv: u64,
    rate: usize,
    rounds_a: usize,
    rounds_b: usize,
) -> Vec<u8> {
    let mut state = ascon_initialize(key, nonce, iv, rounds_a);

    ascon_absorb(&mut state, associated_data, rate, rounds_b);

    state[4] ^= 1;

    let ciphertext = ascon_encrypt_blocks(&mut state, plaintext, rate, rounds_b);

    let tag = ascon_finalize(&mut state, key, rate, rounds_a);

    state.zeroize();

    let mut result = Vec::with_capacity(ciphertext.len() + 16);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);

    result
}

/// Ascon decryption
#[allow(clippy::too_many_arguments)]
fn ascon_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ciphertext: &[u8],
    associated_data: &[u8],
    iv: u64,
    rate: usize,
    rounds_a: usize,
    rounds_b: usize,
) -> Option<Vec<u8>> {
    let ct_len = ciphertext.len() - 16;
    let ct = &ciphertext[..ct_len];
    let received_tag = &ciphertext[ct_len..];

    let mut state = ascon_initialize(key, nonce, iv, rounds_a);

    ascon_absorb(&mut state, associated_data, rate, rounds_b);

    state[4] ^= 1;

    let plaintext = ascon_decrypt_blocks(&mut state, ct, rate, rounds_b);

    let mut computed_tag = ascon_finalize(&mut state, key, rate, rounds_a);

    state.zeroize();

    let result = if constant_time_eq(&computed_tag, received_tag) {
        Some(plaintext)
    } else {
        None
    };

    computed_tag.zeroize();

    result
}

/// Initialize Ascon state
fn ascon_initialize(key: &[u8; 16], nonce: &[u8; 16], iv: u64, rounds: usize) -> AsconState {
    let mut k0 = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let mut k1 = u64::from_be_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);
    let n0 = u64::from_be_bytes([
        nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
    ]);
    let n1 = u64::from_be_bytes([
        nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15],
    ]);

    let mut state = [iv, k0, k1, n0, n1];

    ascon_permutation(&mut state, rounds);

    state[3] ^= k0;
    state[4] ^= k1;

    k0.zeroize();
    k1.zeroize();

    state
}

/// Absorb associated data
fn ascon_absorb(state: &mut AsconState, data: &[u8], rate: usize, rounds: usize) {
    if data.is_empty() {
        return;
    }

    let mut pos = 0;

    while pos + rate <= data.len() {
        // XOR full block
        if rate == 8 {
            let block = u64::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            state[0] ^= block;
        } else {
            // rate == 16
            let block0 = u64::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            let block1 = u64::from_be_bytes([
                data[pos + 8],
                data[pos + 9],
                data[pos + 10],
                data[pos + 11],
                data[pos + 12],
                data[pos + 13],
                data[pos + 14],
                data[pos + 15],
            ]);
            state[0] ^= block0;
            state[1] ^= block1;
        }

        ascon_permutation(state, rounds);
        pos += rate;
    }

    // Handle partial block
    if pos < data.len() {
        let remaining = data.len() - pos;
        let mut padded = [0u8; 16];
        padded[..remaining].copy_from_slice(&data[pos..]);
        padded[remaining] = 0x80; // Padding

        if rate == 8 {
            let block = u64::from_be_bytes([
                padded[0], padded[1], padded[2], padded[3], padded[4], padded[5], padded[6],
                padded[7],
            ]);
            state[0] ^= block;
        } else {
            let block0 = u64::from_be_bytes([
                padded[0], padded[1], padded[2], padded[3], padded[4], padded[5], padded[6],
                padded[7],
            ]);
            let block1 = u64::from_be_bytes([
                padded[8], padded[9], padded[10], padded[11], padded[12], padded[13], padded[14],
                padded[15],
            ]);
            state[0] ^= block0;
            state[1] ^= block1;
        }

        ascon_permutation(state, rounds);
    } else {
        // Empty block or exact multiple - add padding
        state[0] ^= 0x8000000000000000u64;
        ascon_permutation(state, rounds);
    }
}

/// Encrypt plaintext blocks
fn ascon_encrypt_blocks(
    state: &mut AsconState,
    plaintext: &[u8],
    rate: usize,
    rounds: usize,
) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut pos = 0;

    while pos + rate <= plaintext.len() {
        if rate == 8 {
            let block = u64::from_be_bytes([
                plaintext[pos],
                plaintext[pos + 1],
                plaintext[pos + 2],
                plaintext[pos + 3],
                plaintext[pos + 4],
                plaintext[pos + 5],
                plaintext[pos + 6],
                plaintext[pos + 7],
            ]);
            state[0] ^= block;
            ciphertext.extend_from_slice(&state[0].to_be_bytes());
        } else {
            // rate == 16
            let block0 = u64::from_be_bytes([
                plaintext[pos],
                plaintext[pos + 1],
                plaintext[pos + 2],
                plaintext[pos + 3],
                plaintext[pos + 4],
                plaintext[pos + 5],
                plaintext[pos + 6],
                plaintext[pos + 7],
            ]);
            let block1 = u64::from_be_bytes([
                plaintext[pos + 8],
                plaintext[pos + 9],
                plaintext[pos + 10],
                plaintext[pos + 11],
                plaintext[pos + 12],
                plaintext[pos + 13],
                plaintext[pos + 14],
                plaintext[pos + 15],
            ]);
            state[0] ^= block0;
            state[1] ^= block1;
            ciphertext.extend_from_slice(&state[0].to_be_bytes());
            ciphertext.extend_from_slice(&state[1].to_be_bytes());
        }

        ascon_permutation(state, rounds);
        pos += rate;
    }

    // Handle partial block
    if pos < plaintext.len() {
        let remaining = plaintext.len() - pos;

        if rate == 8 {
            let mut padded = [0u8; 8];
            padded[..remaining].copy_from_slice(&plaintext[pos..]);
            let block = u64::from_be_bytes(padded);
            state[0] ^= block;
            let ct_bytes = state[0].to_be_bytes();
            ciphertext.extend_from_slice(&ct_bytes[..remaining]);

            // Apply padding to state
            padded.fill(0);
            padded[..remaining].copy_from_slice(&plaintext[pos..]);
            padded[remaining] = 0x80;
            let padding_block = u64::from_be_bytes(padded);
            state[0] ^= padding_block ^ block;
        } else {
            // rate == 16
            if remaining < 8 {
                // Partial block in first word only (0-7 bytes)
                let mut padded = [0u8; 8];
                padded[..remaining].copy_from_slice(&plaintext[pos..]);
                let block = u64::from_be_bytes(padded);
                state[0] ^= block;
                let ct_bytes = state[0].to_be_bytes();
                ciphertext.extend_from_slice(&ct_bytes[..remaining]);

                padded.fill(0);
                padded[..remaining].copy_from_slice(&plaintext[pos..]);
                padded[remaining] = 0x80;
                let padding_block = u64::from_be_bytes(padded);
                state[0] ^= padding_block ^ block;
            } else {
                // Partial block spans both words (8-15 bytes)
                // First 8 bytes go to state[0]
                let mut padded0 = [0u8; 8];
                padded0.copy_from_slice(&plaintext[pos..pos + 8]);
                let block0 = u64::from_be_bytes(padded0);
                state[0] ^= block0;
                ciphertext.extend_from_slice(&state[0].to_be_bytes());

                // Remaining bytes (0-7) go to state[1]
                let rem2 = remaining - 8;
                let mut padded1 = [0u8; 8];
                if rem2 > 0 {
                    padded1[..rem2].copy_from_slice(&plaintext[pos + 8..]);
                }
                let block1 = u64::from_be_bytes(padded1);
                state[1] ^= block1;
                let ct_bytes = state[1].to_be_bytes();
                ciphertext.extend_from_slice(&ct_bytes[..rem2]);

                // Apply padding
                padded1.fill(0);
                if rem2 > 0 {
                    padded1[..rem2].copy_from_slice(&plaintext[pos + 8..]);
                }
                padded1[rem2] = 0x80;
                let padding_block = u64::from_be_bytes(padded1);
                state[1] ^= padding_block ^ block1;
            }
        }
    } else {
        // Always apply padding, even for empty plaintext
        state[0] ^= 0x8000000000000000u64;
    }

    ciphertext
}

/// Decrypt ciphertext blocks
fn ascon_decrypt_blocks(
    state: &mut AsconState,
    ciphertext: &[u8],
    rate: usize,
    rounds: usize,
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut pos = 0;

    while pos + rate <= ciphertext.len() {
        if rate == 8 {
            let c = u64::from_be_bytes([
                ciphertext[pos],
                ciphertext[pos + 1],
                ciphertext[pos + 2],
                ciphertext[pos + 3],
                ciphertext[pos + 4],
                ciphertext[pos + 5],
                ciphertext[pos + 6],
                ciphertext[pos + 7],
            ]);
            let p = state[0] ^ c;
            plaintext.extend_from_slice(&p.to_be_bytes());
            state[0] = c;
        } else {
            // rate == 16
            let c0 = u64::from_be_bytes([
                ciphertext[pos],
                ciphertext[pos + 1],
                ciphertext[pos + 2],
                ciphertext[pos + 3],
                ciphertext[pos + 4],
                ciphertext[pos + 5],
                ciphertext[pos + 6],
                ciphertext[pos + 7],
            ]);
            let c1 = u64::from_be_bytes([
                ciphertext[pos + 8],
                ciphertext[pos + 9],
                ciphertext[pos + 10],
                ciphertext[pos + 11],
                ciphertext[pos + 12],
                ciphertext[pos + 13],
                ciphertext[pos + 14],
                ciphertext[pos + 15],
            ]);
            let p0 = state[0] ^ c0;
            let p1 = state[1] ^ c1;
            plaintext.extend_from_slice(&p0.to_be_bytes());
            plaintext.extend_from_slice(&p1.to_be_bytes());
            state[0] = c0;
            state[1] = c1;
        }

        ascon_permutation(state, rounds);
        pos += rate;
    }

    // Handle partial block
    if pos < ciphertext.len() {
        let remaining = ciphertext.len() - pos;

        if rate == 8 {
            let mut padded = [0u8; 8];
            padded[..remaining].copy_from_slice(&ciphertext[pos..]);
            let c = u64::from_be_bytes(padded);
            let p = state[0] ^ c;
            let p_bytes = p.to_be_bytes();
            plaintext.extend_from_slice(&p_bytes[..remaining]);

            let mut state_bytes = state[0].to_be_bytes();
            state_bytes[..remaining].copy_from_slice(&ciphertext[pos..]);
            state_bytes[remaining] ^= 0x80;
            state[0] = u64::from_be_bytes(state_bytes);
        } else {
            // rate == 16
            if remaining < 8 {
                // Partial block in first word only (0-7 bytes)
                let mut padded = [0u8; 8];
                padded[..remaining].copy_from_slice(&ciphertext[pos..]);
                let c = u64::from_be_bytes(padded);
                let p = state[0] ^ c;
                let p_bytes = p.to_be_bytes();
                plaintext.extend_from_slice(&p_bytes[..remaining]);

                let mut state_bytes = state[0].to_be_bytes();
                state_bytes[..remaining].copy_from_slice(&ciphertext[pos..]);
                state_bytes[remaining] ^= 0x80;
                state[0] = u64::from_be_bytes(state_bytes);
            } else {
                // Partial block spans both words (8-15 bytes)
                // First 8 bytes from state[0]
                let c0 = u64::from_be_bytes([
                    ciphertext[pos],
                    ciphertext[pos + 1],
                    ciphertext[pos + 2],
                    ciphertext[pos + 3],
                    ciphertext[pos + 4],
                    ciphertext[pos + 5],
                    ciphertext[pos + 6],
                    ciphertext[pos + 7],
                ]);
                let p0 = state[0] ^ c0;
                plaintext.extend_from_slice(&p0.to_be_bytes());
                state[0] = c0;

                // Remaining bytes (0-7) from state[1]
                let rem2 = remaining - 8;
                let mut padded = [0u8; 8];
                if rem2 > 0 {
                    padded[..rem2].copy_from_slice(&ciphertext[pos + 8..]);
                }
                let c1 = u64::from_be_bytes(padded);
                let p1 = state[1] ^ c1;
                let p1_bytes = p1.to_be_bytes();
                plaintext.extend_from_slice(&p1_bytes[..rem2]);

                let mut state_bytes = state[1].to_be_bytes();
                if rem2 > 0 {
                    state_bytes[..rem2].copy_from_slice(&ciphertext[pos + 8..]);
                }
                state_bytes[rem2] ^= 0x80;
                state[1] = u64::from_be_bytes(state_bytes);
            }
        }
    } else {
        // Always apply padding, even for empty ciphertext
        state[0] ^= 0x8000000000000000u64;
    }

    plaintext
}

/// Finalize and produce tag
///
/// For Ascon-128 (rate=8), key is XORed to state[1,2] before permutation.
/// For Ascon-128a (rate=16), key is XORed to state[2,3] before permutation.
/// Tag is always extracted from state[3,4] XORed with key.
fn ascon_finalize(state: &mut AsconState, key: &[u8; 16], rate: usize, rounds: usize) -> [u8; 16] {
    let mut k0 = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let mut k1 = u64::from_be_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    // XOR key at position rate/64 (1 for Ascon-128, 2 for Ascon-128a)
    let key_idx = rate / 8;
    state[key_idx] ^= k0;
    state[key_idx + 1] ^= k1;

    ascon_permutation(state, rounds);

    // Tag is always state[3,4] XORed with key
    state[3] ^= k0;
    state[4] ^= k1;

    k0.zeroize();
    k1.zeroize();

    let mut tag = [0u8; 16];
    tag[0..8].copy_from_slice(&state[3].to_be_bytes());
    tag[8..16].copy_from_slice(&state[4].to_be_bytes());

    tag
}

/// Ascon permutation
// Ascon permutation functions are now provided by hpcrypt-core::ascon
// This eliminates code duplication between hpcrypt-aead and hpcrypt-hash

/// Constant-time equality comparison for AEAD tag verification
///
/// Compares two byte slices in constant time to prevent timing attacks.
/// Optimized for 16-byte Ascon tags with fallback for other lengths.
///
/// # Security Properties
///
/// - Execution time independent of where differences occur
/// - Execution time independent of number of differences
/// - No early exit on mismatch
/// - Handles length mismatches without timing leaks
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use core::hint::black_box;

    let len_diff = a.len() ^ b.len();

    if a.len() == 16 && b.len() == 16 {
        let a0 = u64::from_ne_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
        let a1 = u64::from_ne_bytes([a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]]);
        let b0 = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let b1 = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);

        let diff = (a0 ^ b0) | (a1 ^ b1);

        let is_zero = black_box((diff | diff.wrapping_neg()) >> 63);

        is_zero == 0
    } else {
        let len = a.len().min(b.len());
        let mut diff = len_diff as u8;

        for i in 0..len {
            diff |= a[i] ^ b[i];
        }

        let is_zero = black_box((diff | diff.wrapping_neg()) >> 7);
        is_zero == 0
    }
}

// ============================================================================
// NIST SP 800-232 Variants (Little-Endian)
// ============================================================================

/// Ascon-128 AEAD cipher (NIST SP 800-232)
///
/// NIST standardized variant using little-endian byte order as specified
/// in NIST SP 800-232.
///
/// - Key size: 16 bytes (128 bits)
/// - Nonce size: 16 bytes (128 bits)
/// - Tag size: 16 bytes (128 bits)
/// - Rate: 64 bits (8 bytes)
/// - Rounds: 12 (initialization), 6 (absorbing), 12 (finalization)
///
/// # Difference from Ascon128
///
/// This implementation uses little-endian byte order as specified in NIST SP 800-232,
/// while `Ascon128` uses big-endian as in the original Ascon v1.2 specification.
#[derive(Debug)]
pub struct Ascon128Nist;

impl Ascon128Nist {
    /// Number of initialization/finalization rounds
    const ROUNDS_A: usize = 12;

    /// Number of intermediate rounds (NIST AEAD128 uses 8, same as former Ascon-128a)
    const ROUNDS_B: usize = 8;

    /// Rate in bytes (128 bits = 16 bytes, same as former Ascon-128a)
    const RATE: usize = 16;

    /// Encrypt plaintext with Ascon-128 (NIST SP 800-232)
    ///
    /// Returns ciphertext || tag (16-byte tag appended)
    pub fn encrypt(
        key: &[u8; 16],
        nonce: &[u8; 16],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        ascon_encrypt_nist(
            key,
            nonce,
            plaintext,
            associated_data,
            ASCON_NIST_AEAD128_IV,
            Self::RATE,
            Self::ROUNDS_A,
            Self::ROUNDS_B,
        )
    }

    /// Decrypt ciphertext with Ascon-128 (NIST SP 800-232)
    ///
    /// Expects ciphertext || tag (16-byte tag appended)
    ///
    /// Returns Some(plaintext) if authentication succeeds, None otherwise
    pub fn decrypt(
        key: &[u8; 16],
        nonce: &[u8; 16],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return None;
        }

        ascon_decrypt_nist(
            key,
            nonce,
            ciphertext_with_tag,
            associated_data,
            ASCON_NIST_AEAD128_IV,
            Self::RATE,
            Self::ROUNDS_A,
            Self::ROUNDS_B,
        )
    }

    /// Encrypt plaintext with nonce masking (NIST SP 800-232)
    ///
    /// Uses a second key to mask the nonce for enhanced robustness.
    /// The masked nonce is computed as: nonce_masked = nonce XOR second_key
    ///
    /// # Parameters
    /// - `key`: Primary 16-byte key (K1)
    /// - `second_key`: Secondary 16-byte key (K2) for nonce masking
    /// - `nonce`: 16-byte nonce
    /// - `plaintext`: Data to encrypt
    /// - `associated_data`: Additional authenticated data
    ///
    /// Returns ciphertext || tag (16-byte tag appended)
    pub fn encrypt_with_nonce_masking(
        key: &[u8; 16],
        second_key: &[u8; 16],
        nonce: &[u8; 16],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        // Compute masked nonce: N_masked = N XOR K2
        let mut masked_nonce = [0u8; 16];
        for i in 0..16 {
            masked_nonce[i] = nonce[i] ^ second_key[i];
        }

        // Use standard encryption with masked nonce
        Self::encrypt(key, &masked_nonce, plaintext, associated_data)
    }

    /// Decrypt ciphertext with nonce masking (NIST SP 800-232)
    ///
    /// Uses a second key to mask the nonce for enhanced robustness.
    /// The masked nonce is computed as: nonce_masked = nonce XOR second_key
    ///
    /// # Parameters
    /// - `key`: Primary 16-byte key (K1)
    /// - `second_key`: Secondary 16-byte key (K2) for nonce masking
    /// - `nonce`: 16-byte nonce
    /// - `ciphertext_with_tag`: Ciphertext || tag to decrypt
    /// - `associated_data`: Additional authenticated data
    ///
    /// Returns Some(plaintext) if authentication succeeds, None otherwise
    pub fn decrypt_with_nonce_masking(
        key: &[u8; 16],
        second_key: &[u8; 16],
        nonce: &[u8; 16],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        // Compute masked nonce: N_masked = N XOR K2
        let mut masked_nonce = [0u8; 16];
        for i in 0..16 {
            masked_nonce[i] = nonce[i] ^ second_key[i];
        }

        // Use standard decryption with masked nonce
        Self::decrypt(key, &masked_nonce, ciphertext_with_tag, associated_data)
    }
}

/// NIST SP 800-232 encryption (little-endian)
#[allow(clippy::too_many_arguments)]
fn ascon_encrypt_nist(
    key: &[u8; 16],
    nonce: &[u8; 16],
    plaintext: &[u8],
    associated_data: &[u8],
    iv: u64,
    rate: usize,
    rounds_a: usize,
    rounds_b: usize,
) -> Vec<u8> {
    let mut state = ascon_initialize_nist(key, nonce, iv, rounds_a);

    ascon_absorb_nist(&mut state, associated_data, rate, rounds_b);

    // Domain separator: XOR 1<<63 into state[4] (NIST SP 800-232)
    state[4] ^= 1u64 << 63;

    let ciphertext = ascon_encrypt_blocks_nist(&mut state, plaintext, rate, rounds_b);

    let tag = ascon_finalize_nist(&mut state, key, rate, rounds_a);

    state.zeroize();

    let mut result = Vec::with_capacity(ciphertext.len() + 16);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);

    result
}

/// NIST SP 800-232 decryption (little-endian)
#[allow(clippy::too_many_arguments)]
fn ascon_decrypt_nist(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ciphertext: &[u8],
    associated_data: &[u8],
    iv: u64,
    rate: usize,
    rounds_a: usize,
    rounds_b: usize,
) -> Option<Vec<u8>> {
    let ct_len = ciphertext.len() - 16;
    let ct = &ciphertext[..ct_len];
    let received_tag = &ciphertext[ct_len..];

    let mut state = ascon_initialize_nist(key, nonce, iv, rounds_a);

    ascon_absorb_nist(&mut state, associated_data, rate, rounds_b);

    // Domain separator: XOR 1<<63 into state[4] (NIST SP 800-232)
    state[4] ^= 1u64 << 63;

    let plaintext = ascon_decrypt_blocks_nist(&mut state, ct, rate, rounds_b);

    let mut computed_tag = ascon_finalize_nist(&mut state, key, rate, rounds_a);

    state.zeroize();

    let result = if constant_time_eq(&computed_tag, received_tag) {
        Some(plaintext)
    } else {
        None
    };

    computed_tag.zeroize();

    result
}

/// Initialize Ascon state (NIST SP 800-232 little-endian)
fn ascon_initialize_nist(key: &[u8; 16], nonce: &[u8; 16], iv: u64, rounds: usize) -> AsconState {
    let mut k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let mut k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);
    let n0 = u64::from_le_bytes([
        nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
    ]);
    let n1 = u64::from_le_bytes([
        nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15],
    ]);

    let mut state: AsconState = [iv, k0, k1, n0, n1];

    ascon_permutation(&mut state, rounds);

    state[3] ^= k0;
    state[4] ^= k1;

    k0.zeroize();
    k1.zeroize();

    state
}

/// Absorb associated data (NIST SP 800-232 little-endian)
fn ascon_absorb_nist(state: &mut AsconState, data: &[u8], rate: usize, rounds: usize) {
    if data.is_empty() {
        return;
    }

    let chunks = data.chunks(rate);
    let num_chunks = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        if chunk.len() == rate {
            if rate == 8 {
                let block = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                state[0] ^= block;
            } else {
                let block0 = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                let block1 = u64::from_le_bytes([
                    chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14],
                    chunk[15],
                ]);
                state[0] ^= block0;
                state[1] ^= block1;
            }
        } else {
            // Partial block with padding (NIST SP 800-232 uses 0x01)
            let mut padded = [0u8; 16];
            padded[..chunk.len()].copy_from_slice(chunk);
            padded[chunk.len()] = 0x01;

            if rate == 8 {
                let block = u64::from_le_bytes([
                    padded[0], padded[1], padded[2], padded[3], padded[4], padded[5], padded[6],
                    padded[7],
                ]);
                state[0] ^= block;
            } else {
                let block0 = u64::from_le_bytes([
                    padded[0], padded[1], padded[2], padded[3], padded[4], padded[5], padded[6],
                    padded[7],
                ]);
                let block1 = u64::from_le_bytes([
                    padded[8], padded[9], padded[10], padded[11], padded[12], padded[13],
                    padded[14], padded[15],
                ]);
                state[0] ^= block0;
                state[1] ^= block1;
            }
        }

        if i < num_chunks - 1 {
            ascon_permutation(state, rounds);
        }
    }

    // Pad if data was aligned (NIST SP 800-232 uses 0x01)
    if data.len() % rate == 0 {
        ascon_permutation(state, rounds);
        // XOR padding: 0x01 || 0...
        if rate == 8 {
            state[0] ^= 0x01;
        } else {
            state[0] ^= 0x01;
        }
    }

    ascon_permutation(state, rounds);
}

/// Encrypt blocks (NIST SP 800-232 little-endian)
fn ascon_encrypt_blocks_nist(
    state: &mut AsconState,
    plaintext: &[u8],
    rate: usize,
    rounds: usize,
) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    let chunks = plaintext.chunks(rate);

    for chunk in chunks {
        if chunk.len() == rate {
            if rate == 8 {
                let block = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                state[0] ^= block;
                ciphertext.extend_from_slice(&state[0].to_le_bytes());
            } else {
                let block0 = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                let block1 = u64::from_le_bytes([
                    chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14],
                    chunk[15],
                ]);
                state[0] ^= block0;
                state[1] ^= block1;
                ciphertext.extend_from_slice(&state[0].to_le_bytes());
                ciphertext.extend_from_slice(&state[1].to_le_bytes());
            }

            // Always permute after processing a full block
            ascon_permutation(state, rounds);
        } else {
            // Partial block (NIST SP 800-232 uses 0x01 padding)
            let remaining = chunk.len();
            let mut padded = [0u8; 16];
            padded[..remaining].copy_from_slice(chunk);
            padded[remaining] = 0x01;

            if rate == 8 {
                let block = u64::from_le_bytes(padded[..8].try_into().unwrap());
                state[0] ^= block;
                let ct_bytes = state[0].to_le_bytes();
                ciphertext.extend_from_slice(&ct_bytes[..remaining]);
            } else if remaining < 8 {
                let block = u64::from_le_bytes(padded[..8].try_into().unwrap());
                state[0] ^= block;
                let ct_bytes = state[0].to_le_bytes();
                ciphertext.extend_from_slice(&ct_bytes[..remaining]);
            } else {
                let block0 = u64::from_le_bytes(padded[..8].try_into().unwrap());
                state[0] ^= block0;
                ciphertext.extend_from_slice(&state[0].to_le_bytes());

                let block1 = u64::from_le_bytes(padded[8..16].try_into().unwrap());
                state[1] ^= block1;
                let ct_bytes = state[1].to_le_bytes();
                ciphertext.extend_from_slice(&ct_bytes[..remaining - 8]);
            }
        }
    }

    // Apply padding (NIST SP 800-232 uses 0x01)
    // - If plaintext is empty or an exact multiple of rate, apply padding
    if plaintext.is_empty() || plaintext.len() % rate == 0 {
        state[0] ^= 0x01;
    }

    ciphertext
}

/// Decrypt blocks (NIST SP 800-232 little-endian)
fn ascon_decrypt_blocks_nist(
    state: &mut AsconState,
    ciphertext: &[u8],
    rate: usize,
    rounds: usize,
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    let chunks = ciphertext.chunks(rate);

    for chunk in chunks {
        if chunk.len() == rate {
            if rate == 8 {
                let c = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                let p = state[0] ^ c;
                state[0] = c;
                plaintext.extend_from_slice(&p.to_le_bytes());
            } else {
                let c0 = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                let c1 = u64::from_le_bytes([
                    chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14],
                    chunk[15],
                ]);
                let p0 = state[0] ^ c0;
                let p1 = state[1] ^ c1;
                state[0] = c0;
                state[1] = c1;
                plaintext.extend_from_slice(&p0.to_le_bytes());
                plaintext.extend_from_slice(&p1.to_le_bytes());
            }

            // Always permute after processing a full block
            ascon_permutation(state, rounds);
        } else {
            // Partial block (NIST SP 800-232 uses 0x01 padding)
            let remaining = chunk.len();
            let mut padded = [0u8; 16];
            padded[..remaining].copy_from_slice(chunk);

            if rate == 8 {
                let c = u64::from_le_bytes(padded[..8].try_into().unwrap());
                let p = state[0] ^ c;
                let p_bytes = p.to_le_bytes();
                plaintext.extend_from_slice(&p_bytes[..remaining]);
                // Update state with ciphertext
                let mut state_bytes = state[0].to_le_bytes();
                state_bytes[..remaining].copy_from_slice(&chunk[..remaining]);
                state_bytes[remaining] ^= 0x01;
                state[0] = u64::from_le_bytes(state_bytes);
            } else if remaining < 8 {
                let c = u64::from_le_bytes(padded[..8].try_into().unwrap());
                let p = state[0] ^ c;
                let p_bytes = p.to_le_bytes();
                plaintext.extend_from_slice(&p_bytes[..remaining]);
                let mut state_bytes = state[0].to_le_bytes();
                state_bytes[..remaining].copy_from_slice(&chunk[..remaining]);
                state_bytes[remaining] ^= 0x01;
                state[0] = u64::from_le_bytes(state_bytes);
            } else {
                let c0 = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                let p0 = state[0] ^ c0;
                state[0] = c0;
                plaintext.extend_from_slice(&p0.to_le_bytes());

                let c1 = u64::from_le_bytes(padded[8..16].try_into().unwrap());
                let p1 = state[1] ^ c1;
                let p1_bytes = p1.to_le_bytes();
                plaintext.extend_from_slice(&p1_bytes[..remaining - 8]);
                // Update state[1] with ciphertext and padding
                let mut state_bytes = state[1].to_le_bytes();
                for (j, &b) in chunk[8..].iter().enumerate() {
                    state_bytes[j] = b;
                }
                state_bytes[remaining - 8] ^= 0x01;
                state[1] = u64::from_le_bytes(state_bytes);
            }
        }
    }

    // Apply padding (NIST SP 800-232 uses 0x01)
    // - If ciphertext is empty or an exact multiple of rate, apply padding
    if ciphertext.is_empty() || ciphertext.len() % rate == 0 {
        state[0] ^= 0x01;
    }

    plaintext
}

/// Finalize and produce tag (NIST SP 800-232 little-endian)
fn ascon_finalize_nist(
    state: &mut AsconState,
    key: &[u8; 16],
    rate: usize,
    rounds: usize,
) -> [u8; 16] {
    let mut k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let mut k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    // XOR key at position rate/64 (1 for Ascon-128, 2 for Ascon-128a)
    let key_idx = rate / 8;
    state[key_idx] ^= k0;
    state[key_idx + 1] ^= k1;

    ascon_permutation(state, rounds);

    state[3] ^= k0;
    state[4] ^= k1;

    k0.zeroize();
    k1.zeroize();

    let mut tag = [0u8; 16];
    tag[0..8].copy_from_slice(&state[3].to_le_bytes());
    tag[8..16].copy_from_slice(&state[4].to_le_bytes());

    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascon128_empty() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"";
        let aad = b"";

        let ciphertext = Ascon128::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Ascon128::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(ciphertext.len(), 16);
    }

    #[test]
    fn test_ascon128_basic() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Hello, Ascon!";
        let aad = b"";

        let ciphertext = Ascon128::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = Ascon128::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ascon128_with_aad() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Secret message";
        let aad = b"associated data";

        let ciphertext = Ascon128::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Ascon128::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ascon128_wrong_tag() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Secret message";
        let aad = b"";

        let mut ciphertext = Ascon128::encrypt(&key, &nonce, plaintext, aad);

        let len = ciphertext.len();
        ciphertext[len - 1] ^= 1;

        let result = Ascon128::decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_none());
    }

    #[test]
    fn test_ascon128_wrong_aad() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Secret message";
        let aad1 = b"aad1";
        let aad2 = b"aad2";

        let ciphertext = Ascon128::encrypt(&key, &nonce, plaintext, aad1);
        let result = Ascon128::decrypt(&key, &nonce, &ciphertext, aad2);

        assert!(result.is_none());
    }

    #[test]
    fn test_ascon128a_empty() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"";
        let aad = b"";

        let ciphertext = Ascon128a::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Ascon128a::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(ciphertext.len(), 16);
    }

    #[test]
    fn test_ascon128a_basic() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Hello, Ascon-128a!";
        let aad = b"";

        let ciphertext = Ascon128a::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = Ascon128a::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ascon128a_with_aad() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Secret message";
        let aad = b"associated data";

        let ciphertext = Ascon128a::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Ascon128a::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ascon128a_long_message() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"This is a longer message to test Ascon-128a with multiple blocks of data that exceeds the rate";
        let aad = b"";

        let ciphertext = Ascon128a::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Ascon128a::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ascon128a_wrong_tag() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Secret";
        let aad = b"";

        let mut ciphertext = Ascon128a::encrypt(&key, &nonce, plaintext, aad);
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 1;

        let result = Ascon128a::decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_none());
    }

    #[test]
    fn test_ascon128_different_keys() {
        let key1 = [1u8; 16];
        let key2 = [2u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"test";

        let ct1 = Ascon128::encrypt(&key1, &nonce, plaintext, b"");
        let ct2 = Ascon128::encrypt(&key2, &nonce, plaintext, b"");

        assert_ne!(ct1, ct2);
        assert!(Ascon128::decrypt(&key2, &nonce, &ct1, b"").is_none());
    }

    #[test]
    fn test_ascon128a_block_boundaries() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];

        let pt16 = [0xAAu8; 16];
        let ct16 = Ascon128a::encrypt(&key, &nonce, &pt16, b"");
        let dec16 = Ascon128a::decrypt(&key, &nonce, &ct16, b"").unwrap();
        assert_eq!(&pt16[..], &dec16[..]);

        let pt32 = [0xBBu8; 32];
        let ct32 = Ascon128a::encrypt(&key, &nonce, &pt32, b"");
        let dec32 = Ascon128a::decrypt(&key, &nonce, &ct32, b"").unwrap();
        assert_eq!(&pt32[..], &dec32[..]);

        let pt17 = [0xCCu8; 17];
        let ct17 = Ascon128a::encrypt(&key, &nonce, &pt17, b"");
        let dec17 = Ascon128a::decrypt(&key, &nonce, &ct17, b"").unwrap();
        assert_eq!(&pt17[..], &dec17[..]);
    }
}
