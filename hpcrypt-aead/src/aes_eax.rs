//! AES-EAX - Authenticated Encryption with Associated Data
//!
//! EAX (Encrypt-then-Authenticate-then-Translate) is an AEAD mode that combines
//! CTR mode encryption with CMAC authentication. It's specified in the ANSI C12.22
//! standard and is particularly elegant due to its use of a single primitive (CMAC).
//!
//! # Features
//!
//! - Single-pass authenticated encryption
//! - Variable-length nonces (recommended: 96-128 bits)
//! - Supports associated data
//! - Patent-free
//! - Provably secure
//!
//! # References
//!
//! - [The EAX Mode of Operation](http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf)
//! - [ANSI C12.22-2008](https://webstore.ansi.org/standards/ansi/ansic12222008)

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use hpcrypt_cipher::{Aes, BLOCK_SIZE};
use hpcrypt_core::error::AeadError;

const TAG_SIZE: usize = 16;

/// AES-128-EAX
#[derive(Debug)]
pub struct Aes128Eax;

impl Aes128Eax {
    /// Encrypt and authenticate data
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit encryption key
    /// * `nonce` - Unique nonce (recommended 96-128 bits)
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Associated authenticated data (not encrypted)
    ///
    /// # Returns
    ///
    /// Ciphertext || Tag (tag appended to ciphertext)
    #[cfg(feature = "alloc")]
    pub fn encrypt(key: &[u8; 16], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes::new_128(key);
        eax_encrypt(&cipher, nonce, plaintext, aad)
    }

    /// Decrypt and verify authenticated data
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit encryption key
    /// * `nonce` - Unique nonce used for encryption
    /// * `ciphertext_and_tag` - Encrypted data with appended authentication tag
    /// * `aad` - Associated authenticated data
    ///
    /// # Returns
    ///
    /// Decrypted plaintext if authentication succeeds
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        key: &[u8; 16],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = Aes::new_128(key);
        eax_decrypt(&cipher, nonce, ciphertext_and_tag, aad)
    }
}

/// AES-256-EAX
#[derive(Debug)]
pub struct Aes256Eax;

impl Aes256Eax {
    /// Encrypt and authenticate data
    #[cfg(feature = "alloc")]
    pub fn encrypt(key: &[u8; 32], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes::new_256(key);
        eax_encrypt(&cipher, nonce, plaintext, aad)
    }

    /// Decrypt and verify authenticated data
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = Aes::new_256(key);
        eax_decrypt(&cipher, nonce, ciphertext_and_tag, aad)
    }
}

// Core EAX encryption
#[cfg(feature = "alloc")]
fn eax_encrypt(cipher: &Aes, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    // Compute OMAC tags
    let n = omac(cipher, 0, nonce);
    let h = omac(cipher, 1, aad);
    let c_prime = ctr_encrypt(cipher, &n, plaintext);
    let c = omac(cipher, 2, &c_prime);

    // Compute authentication tag: N ^ H ^ C
    let mut tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        tag[i] = n[i] ^ h[i] ^ c[i];
    }

    // Return ciphertext || tag
    let mut result = c_prime;
    result.extend_from_slice(&tag);
    result
}

// Core EAX decryption
#[cfg(feature = "alloc")]
fn eax_decrypt(
    cipher: &Aes,
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_and_tag.len() < TAG_SIZE {
        return Err(AeadError::InvalidCiphertextLength {
            minimum: TAG_SIZE,
            actual: ciphertext_and_tag.len(),
        });
    }

    let ciphertext_len = ciphertext_and_tag.len() - TAG_SIZE;
    let ciphertext = &ciphertext_and_tag[..ciphertext_len];
    let received_tag = &ciphertext_and_tag[ciphertext_len..];

    // Compute OMAC tags
    let n = omac(cipher, 0, nonce);
    let h = omac(cipher, 1, aad);
    let c = omac(cipher, 2, ciphertext);

    // Compute expected tag: N ^ H ^ C
    let mut expected_tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        expected_tag[i] = n[i] ^ h[i] ^ c[i];
    }

    // Constant-time comparison
    if !constant_time_compare(&expected_tag, received_tag) {
        return Err(AeadError::AuthenticationFailed);
    }

    // Decrypt
    Ok(ctr_encrypt(cipher, &n, ciphertext))
}

/// OMAC (One-Key MAC) with tag encoding
/// OMAC_K(t, M) = CMAC_K([t]_n || M)
fn omac(cipher: &Aes, t: u8, message: &[u8]) -> [u8; TAG_SIZE] {
    // Generate subkeys for CMAC
    let l = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);
    let k1 = left_shift_one_bit(&l);
    let k2 = left_shift_one_bit(&k1);

    // Prepare tagged message: [t]_n || M
    let tag_block = [t; BLOCK_SIZE];

    // CMAC computation with tag prefix
    let mut state = [0u8; BLOCK_SIZE];

    // Process tag block
    xor_block(&mut state, &tag_block);
    state = cipher.encrypt_block(&state);

    // Process message blocks
    let full_blocks = message.len() / BLOCK_SIZE;

    for i in 0..full_blocks {
        let block = &message[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            state[j] ^= block[j];
        }
        state = cipher.encrypt_block(&state);
    }

    // Handle last block
    let remaining = message.len() - full_blocks * BLOCK_SIZE;
    if remaining > 0 {
        // Incomplete block: pad and XOR with K2
        let mut last_block = [0u8; BLOCK_SIZE];
        last_block[..remaining].copy_from_slice(&message[full_blocks * BLOCK_SIZE..]);
        last_block[remaining] = 0x80; // Padding
        xor_block(&mut last_block, &k2);
        xor_block(&mut state, &last_block);
    } else if full_blocks > 0 || message.is_empty() {
        // Complete last block or empty: XOR with K1
        xor_block(&mut state, &k1);
    }

    cipher.encrypt_block(&state)
}

/// CTR mode encryption/decryption
#[cfg(feature = "alloc")]
fn ctr_encrypt(cipher: &Aes, nonce: &[u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut counter = *nonce;

    for chunk in data.chunks(BLOCK_SIZE) {
        let keystream = cipher.encrypt_block(&counter);

        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }

        // Increment counter (big-endian)
        increment_counter(&mut counter);
    }

    result
}

/// Left shift by one bit (for CMAC subkey generation)
fn left_shift_one_bit(input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    let mut carry = 0u8;

    for i in (0..BLOCK_SIZE).rev() {
        output[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }

    // If MSB was 1, XOR with Rb (0x87)
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
    fn test_aes128_eax_roundtrip() {
        let key = [0x00; 16];
        let nonce = [0x00; 16];
        let plaintext = b"Hello, EAX mode!";
        let aad = b"associated data";

        let ciphertext_and_tag = Aes128Eax::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes128Eax::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_eax_roundtrip() {
        let key = [0x42; 32];
        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let plaintext = b"EAX mode test with AES-256";
        let aad = b"some AAD";

        let ciphertext_and_tag = Aes256Eax::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes256Eax::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_eax_authentication_failure() {
        let key = [0x00; 16];
        let nonce = [0x00; 16];
        let plaintext = b"Test message";
        let aad = b"aad";

        let mut ciphertext_and_tag = Aes128Eax::encrypt(&key, &nonce, plaintext, aad);

        // Tamper with ciphertext
        ciphertext_and_tag[0] ^= 1;

        let result = Aes128Eax::decrypt(&key, &nonce, &ciphertext_and_tag, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_eax_empty_message() {
        let key = [0x00; 16];
        let nonce = [0x00; 12];
        let plaintext = b"";
        let aad = b"";

        let ciphertext_and_tag = Aes128Eax::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ciphertext_and_tag.len(), TAG_SIZE); // Only tag

        let decrypted = Aes128Eax::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_eax_various_lengths() {
        let key = [0x42; 16];
        let nonce = [0x00; 16];
        let aad = b"test";

        for len in [0, 1, 15, 16, 17, 31, 32, 48, 100] {
            let plaintext = vec![0x55; len];
            let ciphertext_and_tag = Aes128Eax::encrypt(&key, &nonce, &plaintext, aad);
            let decrypted = Aes128Eax::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }
}
