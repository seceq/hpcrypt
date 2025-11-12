//! AES-GCM (Galois/Counter Mode) AEAD cipher
//!
//! AES-GCM combines AES in Counter (CTR) mode for encryption with GHASH for authentication.
//! Specified in NIST SP 800-38D.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_core::traits::AeadError;
use subtle::ConstantTimeEq;

use crate::aes::{Aes, AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE};
use crate::ghash::GHash;

/// AES-128-GCM tag size (128 bits)
pub const TAG_SIZE: usize = 16;

/// AES-128-GCM nonce size (96 bits recommended)
pub const NONCE_SIZE: usize = 12;

/// AES-128-GCM AEAD cipher
#[derive(Debug)]
pub struct Aes128Gcm;

impl Aes128Gcm {
    /// Encrypt plaintext and authenticate additional data
    ///
    /// Returns ciphertext || tag
    pub fn encrypt(
        key: &[u8; AES128_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes::new_128(key);
        gcm_encrypt(&cipher, nonce, plaintext, aad)
    }

    /// Decrypt ciphertext and verify authentication tag
    ///
    /// Expects ciphertext || tag
    pub fn decrypt(
        key: &[u8; AES128_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = Aes::new_128(key);
        gcm_decrypt(&cipher, nonce, ciphertext_with_tag, aad)
    }
}

/// AES-192-GCM AEAD cipher
#[derive(Debug)]
pub struct Aes192Gcm;

impl Aes192Gcm {
    /// Encrypt plaintext and authenticate additional data
    pub fn encrypt(
        key: &[u8; AES192_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes::new_192(key);
        gcm_encrypt(&cipher, nonce, plaintext, aad)
    }

    /// Decrypt ciphertext and verify authentication tag
    pub fn decrypt(
        key: &[u8; AES192_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = Aes::new_192(key);
        gcm_decrypt(&cipher, nonce, ciphertext_with_tag, aad)
    }
}

/// AES-256-GCM AEAD cipher
#[derive(Debug)]
pub struct Aes256Gcm;

impl Aes256Gcm {
    /// Encrypt plaintext and authenticate additional data
    pub fn encrypt(
        key: &[u8; AES256_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes::new_256(key);
        gcm_encrypt(&cipher, nonce, plaintext, aad)
    }

    /// Decrypt ciphertext and verify authentication tag
    pub fn decrypt(
        key: &[u8; AES256_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = Aes::new_256(key);
        gcm_decrypt(&cipher, nonce, ciphertext_with_tag, aad)
    }
}

/// Core GCM encryption function
fn gcm_encrypt(cipher: &Aes, nonce: &[u8; NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    // Derive hash key H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Initialize counter block: nonce || 0x00000001
    let mut counter_block = [0u8; BLOCK_SIZE];
    counter_block[..NONCE_SIZE].copy_from_slice(nonce);
    counter_block[BLOCK_SIZE - 1] = 1;

    // Encrypt plaintext using CTR mode
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut counter = u32::from_be_bytes([
        counter_block[12],
        counter_block[13],
        counter_block[14],
        counter_block[15],
    ]);

    for (i, chunk) in plaintext.chunks(BLOCK_SIZE).enumerate() {
        // Increment counter
        if i > 0 {
            counter = counter.wrapping_add(1);
            counter_block[12..].copy_from_slice(&counter.to_be_bytes());
        }

        // Encrypt counter block
        let keystream = cipher.encrypt_block(&counter_block);

        // XOR plaintext with keystream
        for (j, &byte) in chunk.iter().enumerate() {
            ciphertext[i * BLOCK_SIZE + j] = byte ^ keystream[j];
        }
    }

    // Compute GHASH(H, A, C)
    let tag = compute_ghash(&h, aad, &ciphertext);

    // Encrypt tag with counter block 0 (nonce || 0x00000001 from initial)
    let mut counter_block_0 = [0u8; BLOCK_SIZE];
    counter_block_0[..NONCE_SIZE].copy_from_slice(nonce);
    counter_block_0[BLOCK_SIZE - 1] = 1;
    let j0 = cipher.encrypt_block(&counter_block_0);

    let mut final_tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        final_tag[i] = tag[i] ^ j0[i];
    }

    // Return ciphertext || tag
    let mut result = ciphertext;
    result.extend_from_slice(&final_tag);
    result
}

/// Core GCM decryption function
fn gcm_decrypt(
    cipher: &Aes,
    nonce: &[u8; NONCE_SIZE],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(AeadError::InvalidCiphertextLength {
            minimum: TAG_SIZE,
            actual: ciphertext_with_tag.len(),
        });
    }

    let ciphertext_len = ciphertext_with_tag.len() - TAG_SIZE;
    let ciphertext = &ciphertext_with_tag[..ciphertext_len];
    let received_tag = &ciphertext_with_tag[ciphertext_len..];

    // Derive hash key H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Compute GHASH(H, A, C)
    let tag = compute_ghash(&h, aad, ciphertext);

    // Encrypt tag with counter block 0
    let mut counter_block_0 = [0u8; BLOCK_SIZE];
    counter_block_0[..NONCE_SIZE].copy_from_slice(nonce);
    counter_block_0[BLOCK_SIZE - 1] = 1;
    let j0 = cipher.encrypt_block(&counter_block_0);

    let mut computed_tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        computed_tag[i] = tag[i] ^ j0[i];
    }

    // Verify tag in constant time
    if computed_tag.ct_eq(received_tag).into() {
        // Decrypt ciphertext using CTR mode
        let mut plaintext = vec![0u8; ciphertext_len];
        let mut counter_block = counter_block_0;
        let mut counter = u32::from_be_bytes([
            counter_block[12],
            counter_block[13],
            counter_block[14],
            counter_block[15],
        ]);

        for (i, chunk) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
            // Increment counter
            if i > 0 {
                counter = counter.wrapping_add(1);
                counter_block[12..].copy_from_slice(&counter.to_be_bytes());
            }

            // Encrypt counter block
            let keystream = cipher.encrypt_block(&counter_block);

            // XOR ciphertext with keystream
            for (j, &byte) in chunk.iter().enumerate() {
                plaintext[i * BLOCK_SIZE + j] = byte ^ keystream[j];
            }
        }

        Ok(plaintext)
    } else {
        Err(AeadError::AuthenticationFailed)
    }
}

/// Compute GHASH(H, A, C) as specified in GCM
fn compute_ghash(h: &[u8; BLOCK_SIZE], aad: &[u8], ciphertext: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut ghash = GHash::new(h);

    // Process AAD
    for chunk in aad.chunks(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block[..chunk.len()].copy_from_slice(chunk);
        ghash.update(&block);
    }

    // Pad AAD to block boundary if needed
    let aad_padding = (BLOCK_SIZE - (aad.len() % BLOCK_SIZE)) % BLOCK_SIZE;
    if aad_padding > 0 {
        // AAD padding is implicit (zeros)
    }

    // Process ciphertext
    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block[..chunk.len()].copy_from_slice(chunk);
        ghash.update(&block);
    }

    // Compute length block: len(A) || len(C) in bits, each 64-bit big-endian
    let aad_bits = (aad.len() as u64) * 8;
    let ciphertext_bits = (ciphertext.len() as u64) * 8;

    let mut len_block = [0u8; BLOCK_SIZE];
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
    ghash.update(&len_block);

    ghash.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_gcm_empty() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"";
        let aad = b"";

        let ciphertext_with_tag = Aes128Gcm::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ciphertext_with_tag.len(), TAG_SIZE); // Only tag, no ciphertext

        let decrypted = Aes128Gcm::decrypt(&key, &nonce, &ciphertext_with_tag, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_gcm_roundtrip() {
        let key = hex_literal::hex!("00000000000000000000000000000000");
        let nonce = hex_literal::hex!("000000000000000000000000");
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext_with_tag = Aes128Gcm::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes128Gcm::decrypt(&key, &nonce, &ciphertext_with_tag, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aes128_gcm_auth_failure() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plaintext = b"secret message";
        let aad = b"metadata";

        let mut ciphertext_with_tag = Aes128Gcm::encrypt(&key, &nonce, plaintext, aad);

        // Tamper with ciphertext
        ciphertext_with_tag[0] ^= 1;

        let result = Aes128Gcm::decrypt(&key, &nonce, &ciphertext_with_tag, aad);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = [0xABu8; 32];
        let nonce = [0xCDu8; 12];
        let plaintext = b"AES-256-GCM test";
        let aad = b"";

        let ciphertext_with_tag = Aes256Gcm::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext_with_tag, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aes192_gcm_roundtrip() {
        let key = [0x55u8; 24];
        let nonce = [0x66u8; 12];
        let plaintext = b"Testing AES-192-GCM";
        let aad = b"extra info";

        let ciphertext_with_tag = Aes192Gcm::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes192Gcm::decrypt(&key, &nonce, &ciphertext_with_tag, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }
}
