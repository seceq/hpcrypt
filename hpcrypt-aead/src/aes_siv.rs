//! AES-SIV - Synthetic IV Authenticated Encryption
//!
//! SIV (Synthetic Initialization Vector) is a nonce-misuse resistant AEAD mode.
//! It provides deterministic authenticated encryption when the nonce is reused,
//! making it ideal for scenarios where nonce management is difficult.
//!
//! # Features
//!
//! - **Nonce-misuse resistant**: Reusing a nonce leaks only equality of plaintexts
//! - **Deterministic**: Same plaintext+nonce produces same ciphertext (when nonce reused)
//! - **Key-wrapping**: Can be used for key wrapping (RFC 5297)
//! - **SIV-then-CTR**: Authenticate-then-encrypt construction
//!
//! # Security
//!
//! SIV provides the strongest security guarantees among AEAD modes:
//! - Nonce reuse only leaks message equality
//! - Still provides authenticity even with nonce reuse
//! - Requires two passes over the data
//!
//! # References
//!
//! - [RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption](https://tools.ietf.org/html/rfc5297)
//! - [Deterministic Authenticated-Encryption](http://web.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf)

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::aes::{Aes, BLOCK_SIZE};
use hpcrypt_core::error::AeadError;

const TAG_SIZE: usize = 16;

/// AES-128-SIV (uses 256-bit key: 128-bit for MAC + 128-bit for CTR)
#[derive(Debug)]
pub struct Aes128Siv;

impl Aes128Siv {
    /// Encrypt and authenticate data
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit key (128-bit MAC key || 128-bit CTR key)
    /// * `nonce` - Nonce (can be reused without catastrophic failure)
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Associated authenticated data
    ///
    /// # Returns
    ///
    /// IV || Ciphertext (IV is the synthetic IV/tag)
    #[cfg(feature = "alloc")]
    pub fn encrypt(key: &[u8; 32], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let k1: [u8; 16] = key[..16].try_into().unwrap();
        let k2: [u8; 16] = key[16..].try_into().unwrap();

        siv_encrypt(&k1, &k2, nonce, plaintext, aad)
    }

    /// Decrypt and verify authenticated data
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit key (must match encryption key)
    /// * `nonce` - Nonce used for encryption
    /// * `iv_and_ciphertext` - IV (16 bytes) || ciphertext
    /// * `aad` - Associated authenticated data
    ///
    /// # Returns
    ///
    /// Decrypted plaintext if authentication succeeds
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8],
        iv_and_ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let k1: [u8; 16] = key[..16].try_into().unwrap();
        let k2: [u8; 16] = key[16..].try_into().unwrap();

        siv_decrypt(&k1, &k2, nonce, iv_and_ciphertext, aad)
    }
}

/// AES-256-SIV (uses 512-bit key: 256-bit for MAC + 256-bit for CTR)
#[derive(Debug)]
pub struct Aes256Siv;

impl Aes256Siv {
    /// Encrypt and authenticate data
    #[cfg(feature = "alloc")]
    pub fn encrypt(key: &[u8; 64], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let k1: [u8; 32] = key[..32].try_into().unwrap();
        let k2: [u8; 32] = key[32..].try_into().unwrap();

        siv_encrypt_256(&k1, &k2, nonce, plaintext, aad)
    }

    /// Decrypt and verify authenticated data
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        key: &[u8; 64],
        nonce: &[u8],
        iv_and_ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let k2: [u8; 32] = key[32..].try_into().unwrap();
        let k1: [u8; 32] = key[..32].try_into().unwrap();

        siv_decrypt_256(&k1, &k2, nonce, iv_and_ciphertext, aad)
    }
}

// Core SIV encryption for AES-128
#[cfg(feature = "alloc")]
fn siv_encrypt(
    mac_key: &[u8; 16],
    ctr_key: &[u8; 16],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    // Step 1: Compute synthetic IV using S2V
    let iv = s2v(mac_key, &[aad, nonce, plaintext]);

    // Step 2: Encrypt plaintext using CTR mode with IV
    let cipher = Aes::new_128(ctr_key);
    let ciphertext = ctr_encrypt(&cipher, &iv, plaintext);

    // Step 3: Return IV || ciphertext
    let mut result = Vec::with_capacity(TAG_SIZE + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    result
}

// Core SIV decryption for AES-128
#[cfg(feature = "alloc")]
fn siv_decrypt(
    mac_key: &[u8; 16],
    ctr_key: &[u8; 16],
    nonce: &[u8],
    iv_and_ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if iv_and_ciphertext.len() < TAG_SIZE {
        return Err(AeadError::InvalidCiphertextLength {
            minimum: TAG_SIZE,
            actual: iv_and_ciphertext.len(),
        });
    }

    let iv: [u8; TAG_SIZE] = iv_and_ciphertext[..TAG_SIZE].try_into().unwrap();
    let ciphertext = &iv_and_ciphertext[TAG_SIZE..];

    // Step 1: Decrypt ciphertext using CTR mode
    let cipher = Aes::new_128(ctr_key);
    let plaintext = ctr_encrypt(&cipher, &iv, ciphertext);

    // Step 2: Recompute IV using S2V
    let expected_iv = s2v(mac_key, &[aad, nonce, &plaintext]);

    // Step 3: Verify IV
    if !constant_time_compare(&iv, &expected_iv) {
        return Err(AeadError::AuthenticationFailed);
    }

    Ok(plaintext)
}

// Core SIV encryption for AES-256
#[cfg(feature = "alloc")]
fn siv_encrypt_256(
    mac_key: &[u8; 32],
    ctr_key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let iv = s2v_256(mac_key, &[aad, nonce, plaintext]);
    let cipher = Aes::new_256(ctr_key);
    let ciphertext = ctr_encrypt(&cipher, &iv, plaintext);

    let mut result = Vec::with_capacity(TAG_SIZE + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    result
}

// Core SIV decryption for AES-256
#[cfg(feature = "alloc")]
fn siv_decrypt_256(
    mac_key: &[u8; 32],
    ctr_key: &[u8; 32],
    nonce: &[u8],
    iv_and_ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if iv_and_ciphertext.len() < TAG_SIZE {
        return Err(AeadError::InvalidCiphertextLength {
            minimum: TAG_SIZE,
            actual: iv_and_ciphertext.len(),
        });
    }

    let iv: [u8; TAG_SIZE] = iv_and_ciphertext[..TAG_SIZE].try_into().unwrap();
    let ciphertext = &iv_and_ciphertext[TAG_SIZE..];

    let cipher = Aes::new_256(ctr_key);
    let plaintext = ctr_encrypt(&cipher, &iv, ciphertext);

    let expected_iv = s2v_256(mac_key, &[aad, nonce, &plaintext]);

    if !constant_time_compare(&iv, &expected_iv) {
        return Err(AeadError::AuthenticationFailed);
    }

    Ok(plaintext)
}

/// S2V (String-to-Vector) - Deterministic MAC construction
fn s2v(key: &[u8; 16], strings: &[&[u8]]) -> [u8; BLOCK_SIZE] {
    let cipher = Aes::new_128(key);

    // D = AES(K, <zero>)
    let mut d = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Process all strings except the last
    for &s in &strings[..strings.len().saturating_sub(1)] {
        // D = dbl(D) xor CMAC(K, S_i)
        d = dbl(&d);
        let mac = cmac(&cipher, s);
        xor_block(&mut d, &mac);
    }

    // Handle last string
    if let Some(&last) = strings.last() {
        if last.len() >= BLOCK_SIZE {
            // T = S_n xorend D
            let mut t = last.to_vec();
            let len = t.len();
            for i in 0..BLOCK_SIZE {
                t[len - BLOCK_SIZE + i] ^= d[i];
            }
            cmac(&cipher, &t)
        } else {
            // T = dbl(D) xor pad(S_n)
            d = dbl(&d);
            let mut padded = [0u8; BLOCK_SIZE];
            padded[..last.len()].copy_from_slice(last);
            if last.len() < BLOCK_SIZE {
                padded[last.len()] = 0x80;
            }
            xor_block(&mut d, &padded);
            cmac(&cipher, &d)
        }
    } else {
        // No strings: CMAC(K, <one>)
        let one = [0x01u8; BLOCK_SIZE];
        cmac(&cipher, &one)
    }
}

/// S2V for AES-256
fn s2v_256(key: &[u8; 32], strings: &[&[u8]]) -> [u8; BLOCK_SIZE] {
    let cipher = Aes::new_256(key);

    let mut d = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    for &s in &strings[..strings.len().saturating_sub(1)] {
        d = dbl(&d);
        let mac = cmac(&cipher, s);
        xor_block(&mut d, &mac);
    }

    if let Some(&last) = strings.last() {
        if last.len() >= BLOCK_SIZE {
            let mut t = last.to_vec();
            let len = t.len();
            for i in 0..BLOCK_SIZE {
                t[len - BLOCK_SIZE + i] ^= d[i];
            }
            cmac(&cipher, &t)
        } else {
            d = dbl(&d);
            let mut padded = [0u8; BLOCK_SIZE];
            padded[..last.len()].copy_from_slice(last);
            if last.len() < BLOCK_SIZE {
                padded[last.len()] = 0x80;
            }
            xor_block(&mut d, &padded);
            cmac(&cipher, &d)
        }
    } else {
        let one = [0x01u8; BLOCK_SIZE];
        cmac(&cipher, &one)
    }
}

/// CMAC computation
fn cmac(cipher: &Aes, message: &[u8]) -> [u8; BLOCK_SIZE] {
    // Generate subkeys
    let l = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);
    let k1 = left_shift_one_bit(&l);
    let k2 = left_shift_one_bit(&k1);

    let last_block_complete = message.len() % BLOCK_SIZE == 0 && !message.is_empty();
    let n_blocks = if last_block_complete {
        message.len() / BLOCK_SIZE - 1
    } else {
        message.len() / BLOCK_SIZE
    };

    let mut state = [0u8; BLOCK_SIZE];

    // Process complete blocks
    for i in 0..n_blocks {
        let block = &message[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let block_array: [u8; BLOCK_SIZE] = block.try_into().unwrap();
        xor_block(&mut state, &block_array);
        state = cipher.encrypt_block(&state);
    }

    // Process last block
    let mut last_block = [0u8; BLOCK_SIZE];
    if last_block_complete {
        let start = (message.len() / BLOCK_SIZE - 1) * BLOCK_SIZE;
        last_block.copy_from_slice(&message[start..]);
        xor_block(&mut last_block, &k1);
    } else {
        let remaining = message.len() % BLOCK_SIZE;
        if remaining > 0 {
            let start = (message.len() / BLOCK_SIZE) * BLOCK_SIZE;
            last_block[..remaining].copy_from_slice(&message[start..]);
        }
        last_block[remaining] = 0x80;
        xor_block(&mut last_block, &k2);
    }

    xor_block(&mut state, &last_block);
    cipher.encrypt_block(&state)
}

/// Double operation in GF(2^128)
fn dbl(block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    let mut carry = 0u8;

    // Left shift by 1 bit (big-endian)
    for i in (0..BLOCK_SIZE).rev() {
        result[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }

    // If MSB was 1, XOR with 0x87
    if carry != 0 {
        result[BLOCK_SIZE - 1] ^= 0x87;
    }

    result
}

/// CTR mode encryption
#[cfg(feature = "alloc")]
fn ctr_encrypt(cipher: &Aes, iv: &[u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut counter = *iv;

    // Clear bit 63 and bit 31 as per RFC 5297
    counter[8] &= 0x7F;
    counter[12] &= 0x7F;

    for chunk in data.chunks(BLOCK_SIZE) {
        let keystream = cipher.encrypt_block(&counter);

        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }

        increment_counter(&mut counter);
    }

    result
}

/// Left shift by one bit
fn left_shift_one_bit(input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    let mut carry = 0u8;

    for i in (0..BLOCK_SIZE).rev() {
        output[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }

    if carry != 0 {
        output[BLOCK_SIZE - 1] ^= 0x87;
    }

    output
}

/// XOR two blocks
fn xor_block(a: &mut [u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        a[i] ^= b[i];
    }
}

/// Increment counter (big-endian)
fn increment_counter(counter: &mut [u8; BLOCK_SIZE]) {
    for i in (0..BLOCK_SIZE).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// Constant-time comparison
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_aes128_siv_roundtrip() {
        let key = [0x42; 32]; // 256-bit key for AES-128-SIV
        let nonce = [0x00; 16];
        let plaintext = b"Hello, SIV mode!";
        let aad = b"associated data";

        let iv_and_ciphertext = Aes128Siv::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes128Siv::decrypt(&key, &nonce, &iv_and_ciphertext, aad).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_siv_roundtrip() {
        let key = [0x55; 64]; // 512-bit key for AES-256-SIV
        let nonce = [0x01; 12];
        let plaintext = b"SIV mode test with AES-256";
        let aad = b"AAD";

        let iv_and_ciphertext = Aes256Siv::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes256Siv::decrypt(&key, &nonce, &iv_and_ciphertext, aad).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_siv_deterministic() {
        let key = [0x00; 32];
        let nonce = [0x00; 16];
        let plaintext = b"deterministic";
        let aad = b"aad";

        let ct1 = Aes128Siv::encrypt(&key, &nonce, plaintext, aad);
        let ct2 = Aes128Siv::encrypt(&key, &nonce, plaintext, aad);

        // Same inputs produce same output (deterministic)
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_siv_authentication_failure() {
        let key = [0x00; 32];
        let nonce = [0x00; 16];
        let plaintext = b"Test message";
        let aad = b"aad";

        let mut iv_and_ciphertext = Aes128Siv::encrypt(&key, &nonce, plaintext, aad);

        // Tamper with ciphertext
        if iv_and_ciphertext.len() > TAG_SIZE {
            iv_and_ciphertext[TAG_SIZE] ^= 1;
        }

        let result = Aes128Siv::decrypt(&key, &nonce, &iv_and_ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_siv_empty_message() {
        let key = [0x00; 32];
        let nonce = [0x00; 12];
        let plaintext = b"";
        let aad = b"";

        let iv_and_ciphertext = Aes128Siv::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(iv_and_ciphertext.len(), TAG_SIZE); // Only IV

        let decrypted = Aes128Siv::decrypt(&key, &nonce, &iv_and_ciphertext, aad).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_siv_various_lengths() {
        let key = [0x42; 32];
        let nonce = [0x00; 16];
        let aad = b"test";

        for len in [0, 1, 15, 16, 17, 31, 32, 48, 100] {
            let plaintext = vec![0x55; len];
            let iv_and_ciphertext = Aes128Siv::encrypt(&key, &nonce, &plaintext, aad);
            let decrypted = Aes128Siv::decrypt(&key, &nonce, &iv_and_ciphertext, aad).unwrap();
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }
}
