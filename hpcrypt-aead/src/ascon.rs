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

// Ascon permutation constants
const ASCON_128_IV: u64 = 0x80400c0600000000;
const ASCON_128A_IV: u64 = 0x80800c0800000000;

// Round constants for Ascon permutation
const ROUND_CONSTANTS: [u64; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

/// Ascon state: 5 x 64-bit words = 320 bits
type AsconState = [u64; 5];

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

    let tag = ascon_finalize(&mut state, key, rounds_a);

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

    let mut computed_tag = ascon_finalize(&mut state, key, rounds_a);

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
            if remaining <= 8 {
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
                let mut padded0 = [0u8; 8];
                padded0.copy_from_slice(&plaintext[pos..pos + 8]);
                let block0 = u64::from_be_bytes(padded0);
                state[0] ^= block0;
                ciphertext.extend_from_slice(&state[0].to_be_bytes());

                let rem2 = remaining - 8;
                let mut padded1 = [0u8; 8];
                padded1[..rem2].copy_from_slice(&plaintext[pos + 8..]);
                let block1 = u64::from_be_bytes(padded1);
                state[1] ^= block1;
                let ct_bytes = state[1].to_be_bytes();
                ciphertext.extend_from_slice(&ct_bytes[..rem2]);

                padded1.fill(0);
                padded1[..rem2].copy_from_slice(&plaintext[pos + 8..]);
                padded1[rem2] = 0x80;
                let padding_block = u64::from_be_bytes(padded1);
                state[1] ^= padding_block ^ block1;
            }
        }
    } else if !plaintext.is_empty() {
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
            if remaining <= 8 {
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

                let rem2 = remaining - 8;
                let mut padded = [0u8; 8];
                padded[..rem2].copy_from_slice(&ciphertext[pos + 8..]);
                let c1 = u64::from_be_bytes(padded);
                let p1 = state[1] ^ c1;
                let p1_bytes = p1.to_be_bytes();
                plaintext.extend_from_slice(&p1_bytes[..rem2]);

                let mut state_bytes = state[1].to_be_bytes();
                state_bytes[..rem2].copy_from_slice(&ciphertext[pos + 8..]);
                state_bytes[rem2] ^= 0x80;
                state[1] = u64::from_be_bytes(state_bytes);
            }
        }
    } else if !ciphertext.is_empty() {
        state[0] ^= 0x8000000000000000u64;
    }

    plaintext
}

/// Finalize and produce tag
fn ascon_finalize(state: &mut AsconState, key: &[u8; 16], rounds: usize) -> [u8; 16] {
    let mut k0 = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let mut k1 = u64::from_be_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    state[1] ^= k0;
    state[2] ^= k1;

    ascon_permutation(state, rounds);

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
fn ascon_permutation(state: &mut AsconState, rounds: usize) {
    let start_round = 12 - rounds;

    #[allow(clippy::needless_range_loop)]
    for i in start_round..12 {
        state[2] ^= ROUND_CONSTANTS[i];

        ascon_sbox(state);

        ascon_linear(state);
    }
}

/// Ascon S-box (substitution layer)
#[inline(always)]
fn ascon_sbox(state: &mut AsconState) {
    let x0 = state[0];
    let x1 = state[1];
    let x2 = state[2];
    let x3 = state[3];
    let x4 = state[4];

    state[0] = x0 ^ (!x1 & x2);
    state[1] = x1 ^ (!x2 & x3);
    state[2] = x2 ^ (!x3 & x4);
    state[3] = x3 ^ (!x4 & x0);
    state[4] = x4 ^ (!x0 & x1);

    state[1] ^= x0;
    state[0] ^= x4;
    state[3] ^= x2;
    state[2] = !state[2];
}

/// Ascon linear diffusion layer
#[inline(always)]
fn ascon_linear(state: &mut AsconState) {
    let x0 = state[0];
    let x1 = state[1];
    let x2 = state[2];
    let x3 = state[3];
    let x4 = state[4];

    state[0] = x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28);
    state[1] = x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39);
    state[2] = x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6);
    state[3] = x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17);
    state[4] = x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41);
}

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
