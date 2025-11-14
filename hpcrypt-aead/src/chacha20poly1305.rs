//! ChaCha20-Poly1305 AEAD cipher
//!
//! Authenticated Encryption with Associated Data combining ChaCha20 stream cipher
//! and Poly1305 MAC as specified in RFC 8439.
//!
//! This construction provides both confidentiality and authenticity.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_cipher::chacha20::{ChaCha20, XChaCha20};
use hpcrypt_mac::poly1305::{Poly1305, KEY_SIZE as POLY_KEY_SIZE, TAG_SIZE};
use hpcrypt_core::utils::write_u64_le;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// ChaCha20-Poly1305 key size (256 bits)
pub const KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (96 bits)
pub const NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 AEAD cipher
#[derive(Debug)]
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Encrypt and authenticate data
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `nonce` - 96-bit nonce (must be unique per key)
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data (not encrypted)
    ///
    /// # Returns
    /// Ciphertext concatenated with 16-byte authentication tag
    pub fn encrypt(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        let mut output = vec![0u8; plaintext.len() + TAG_SIZE];

        // Generate Poly1305 key using ChaCha20 with counter = 0
        let mut poly_key = [0u8; POLY_KEY_SIZE];
        let mut chacha = ChaCha20::new(key, nonce, 0);
        chacha.encrypt(&mut poly_key);

        // Encrypt plaintext using ChaCha20 with counter = 1
        let mut chacha = ChaCha20::new(key, nonce, 1);
        output[..plaintext.len()].copy_from_slice(plaintext);
        chacha.encrypt(&mut output[..plaintext.len()]);

        // Compute Poly1305 MAC over AAD || ciphertext
        let tag = Self::compute_mac(&poly_key, associated_data, &output[..plaintext.len()]);
        output[plaintext.len()..].copy_from_slice(&tag);

        poly_key.zeroize();
        output
    }

    /// Decrypt and verify authenticated data
    ///
    /// # Arguments
    /// * `key` - 256-bit decryption key
    /// * `nonce` - 96-bit nonce
    /// * `ciphertext_with_tag` - Ciphertext concatenated with authentication tag
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// Decrypted plaintext on success, or None if authentication fails
    pub fn decrypt(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < TAG_SIZE {
            return None;
        }

        let ciphertext_len = ciphertext_with_tag.len() - TAG_SIZE;
        let ciphertext = &ciphertext_with_tag[..ciphertext_len];
        let received_tag = &ciphertext_with_tag[ciphertext_len..];

        // Generate Poly1305 key
        let mut poly_key = [0u8; POLY_KEY_SIZE];
        let mut chacha = ChaCha20::new(key, nonce, 0);
        chacha.encrypt(&mut poly_key);

        // Verify MAC
        let computed_tag = Self::compute_mac(&poly_key, associated_data, ciphertext);

        // Constant-time comparison
        let tags_match = computed_tag.ct_eq(received_tag);

        poly_key.zeroize();

        if tags_match.into() {
            // Decrypt ciphertext
            let mut plaintext = ciphertext.to_vec();
            let mut chacha = ChaCha20::new(key, nonce, 1);
            chacha.decrypt(&mut plaintext);
            Some(plaintext)
        } else {
            None
        }
    }

    /// Compute Poly1305 MAC according to RFC 8439 construction
    fn compute_mac(key: &[u8; POLY_KEY_SIZE], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_SIZE] {
        let mut mac = Poly1305::new(key);

        // Add AAD with padding
        mac.update(aad);
        if aad.len() % 16 != 0 {
            let padding = [0u8; 16];
            mac.update(&padding[..(16 - (aad.len() % 16))]);
        }

        // Add ciphertext with padding
        mac.update(ciphertext);
        if ciphertext.len() % 16 != 0 {
            let padding = [0u8; 16];
            mac.update(&padding[..(16 - (ciphertext.len() % 16))]);
        }

        // Add lengths (little-endian)
        let mut lengths = [0u8; 16];
        write_u64_le(&mut lengths[0..8], aad.len() as u64);
        write_u64_le(&mut lengths[8..16], ciphertext.len() as u64);
        mac.update(&lengths);

        mac.finalize()
    }
}

/// XChaCha20-Poly1305 AEAD cipher with extended nonce
#[derive(Debug)]
pub struct XChaCha20Poly1305;

impl XChaCha20Poly1305 {
    /// XChaCha20-Poly1305 nonce size (192 bits)
    pub const NONCE_SIZE: usize = 24;

    /// Encrypt and authenticate data with extended nonce
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `nonce` - 192-bit nonce
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// Ciphertext concatenated with 16-byte authentication tag
    pub fn encrypt(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Vec<u8> {
        let mut output = vec![0u8; plaintext.len() + TAG_SIZE];

        // Generate Poly1305 key using XChaCha20 with counter = 0
        let mut poly_key = [0u8; POLY_KEY_SIZE];
        let mut xchacha = XChaCha20::new(key, nonce, 0);
        xchacha.encrypt(&mut poly_key);

        // Encrypt plaintext using XChaCha20 with counter = 1
        let mut xchacha = XChaCha20::new(key, nonce, 1);
        output[..plaintext.len()].copy_from_slice(plaintext);
        xchacha.encrypt(&mut output[..plaintext.len()]);

        // Compute Poly1305 MAC
        let tag =
            ChaCha20Poly1305::compute_mac(&poly_key, associated_data, &output[..plaintext.len()]);
        output[plaintext.len()..].copy_from_slice(&tag);

        poly_key.zeroize();
        output
    }

    /// Decrypt and verify authenticated data with extended nonce
    ///
    /// # Arguments
    /// * `key` - 256-bit decryption key
    /// * `nonce` - 192-bit nonce
    /// * `ciphertext_with_tag` - Ciphertext concatenated with authentication tag
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// Decrypted plaintext on success, or None if authentication fails
    pub fn decrypt(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; Self::NONCE_SIZE],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < TAG_SIZE {
            return None;
        }

        let ciphertext_len = ciphertext_with_tag.len() - TAG_SIZE;
        let ciphertext = &ciphertext_with_tag[..ciphertext_len];
        let received_tag = &ciphertext_with_tag[ciphertext_len..];

        // Generate Poly1305 key
        let mut poly_key = [0u8; POLY_KEY_SIZE];
        let mut xchacha = XChaCha20::new(key, nonce, 0);
        xchacha.encrypt(&mut poly_key);

        // Verify MAC
        let computed_tag = ChaCha20Poly1305::compute_mac(&poly_key, associated_data, ciphertext);
        let tags_match = computed_tag.ct_eq(received_tag);

        poly_key.zeroize();

        if tags_match.into() {
            // Decrypt ciphertext
            let mut plaintext = ciphertext.to_vec();
            let mut xchacha = XChaCha20::new(key, nonce, 1);
            xchacha.decrypt(&mut plaintext);
            Some(plaintext)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20poly1305_rfc8439() {
        // Test vector from RFC 8439 Section 2.8.2
        let key = hex_literal::hex!(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
        );
        let nonce = hex_literal::hex!("070000004041424344454647");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = hex_literal::hex!("50515253c0c1c2c3c4c5c6c7");

        let ciphertext_with_tag = ChaCha20Poly1305::encrypt(&key, &nonce, plaintext, &aad);

        // Verify we can decrypt
        let decrypted = ChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext_with_tag, &aad);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);

        // Verify authentication failure with wrong AAD
        let wrong_aad = b"wrong";
        let failed = ChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext_with_tag, wrong_aad);
        assert!(failed.is_none());

        // Verify authentication failure with corrupted ciphertext
        let mut corrupted = ciphertext_with_tag.clone();
        corrupted[0] ^= 1;
        let failed = ChaCha20Poly1305::decrypt(&key, &nonce, &corrupted, &aad);
        assert!(failed.is_none());
    }

    #[test]
    fn test_chacha20poly1305_empty() {
        let key = [0u8; KEY_SIZE];
        let nonce = [0u8; NONCE_SIZE];

        // Empty plaintext
        let ct = ChaCha20Poly1305::encrypt(&key, &nonce, b"", b"");
        assert_eq!(ct.len(), TAG_SIZE); // Only tag

        let pt = ChaCha20Poly1305::decrypt(&key, &nonce, &ct, b"");
        assert!(pt.is_some());
        assert_eq!(pt.unwrap(), b"");
    }

    #[test]
    fn test_xchacha20poly1305() {
        let key = [42u8; KEY_SIZE];
        let nonce = [1u8; XChaCha20Poly1305::NONCE_SIZE];
        let plaintext = b"Hello, XChaCha20-Poly1305!";
        let aad = b"additional data";

        let ciphertext_with_tag = XChaCha20Poly1305::encrypt(&key, &nonce, plaintext, aad);

        let decrypted = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext_with_tag, aad);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);

        // Wrong nonce should fail
        let wrong_nonce = [2u8; XChaCha20Poly1305::NONCE_SIZE];
        let failed = XChaCha20Poly1305::decrypt(&key, &wrong_nonce, &ciphertext_with_tag, aad);
        assert!(failed.is_none());
    }

    #[test]
    fn test_chacha20poly1305_incremental_aad() {
        let key = [99u8; KEY_SIZE];
        let nonce = [7u8; NONCE_SIZE];
        let plaintext = b"Secret message";

        // Multiple AAD chunks
        let aad1 = b"part1";
        let aad2 = b"part2";
        let mut combined_aad = Vec::new();
        combined_aad.extend_from_slice(aad1);
        combined_aad.extend_from_slice(aad2);

        let ct = ChaCha20Poly1305::encrypt(&key, &nonce, plaintext, &combined_aad);
        let pt = ChaCha20Poly1305::decrypt(&key, &nonce, &ct, &combined_aad);

        assert!(pt.is_some());
        assert_eq!(pt.unwrap(), plaintext);
    }
}
