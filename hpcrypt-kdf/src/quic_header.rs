#![cfg(feature = "quic-header-protection")]
//! QUIC Header Protection
//!
//! This module implements header protection as defined in RFC 9001 Section 5.4.
//!
//! Header protection encrypts packet headers to prevent middleboxes from observing
//! or modifying QUIC headers.
//!
//! # Algorithm
//!
//! The header protection mask is generated as follows:
//!
//! - For AES-based cipher suites: `mask = AES-ECB(hp_key, sample)[0..5]`
//! - For ChaCha20: `mask = ChaCha20(hp_key, sample)[0..5]`
//!
//! Where `sample` is 16 bytes extracted from the packet.

use hpcrypt_aead::aes::Aes;
use hpcrypt_aead::chacha20::ChaCha20;

/// Header Protection trait
pub trait HeaderProtection {
    /// Generate a 5-byte mask from a sample
    ///
    /// # Arguments
    ///
    /// * `sample` - 16-byte sample extracted from the packet
    ///
    /// # Returns
    ///
    /// A 5-byte mask used to protect the header
    fn generate_mask(&self, sample: &[u8]) -> [u8; 5];
}

/// Header Protection using AES-128-ECB
///
/// This is used with AES-128-GCM cipher suites.
///
/// # Example
///
/// ```rust
/// use hpcrypt_quic::{HeaderProtectionAes128, HeaderProtection};
///
/// let hp_key = [0x42; 16];
/// let hp = HeaderProtectionAes128::new(&hp_key);
///
/// let sample = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
/// let mask = hp.generate_mask(&sample);
/// assert_eq!(mask.len(), 5);
/// ```
pub struct HeaderProtectionAes128 {
    cipher: Aes,
}

impl HeaderProtectionAes128 {
    /// Create a new AES-128 header protection instance
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte header protection key
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16, "AES-128 key must be 16 bytes");
        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(key);
        Self {
            cipher: Aes::new_128(&key_array),
        }
    }
}

impl HeaderProtection for HeaderProtectionAes128 {
    fn generate_mask(&self, sample: &[u8]) -> [u8; 5] {
        assert_eq!(sample.len(), 16, "Sample must be 16 bytes");

        // AES-ECB encrypt the sample
        let mut block = [0u8; 16];
        block.copy_from_slice(sample);
        let encrypted = self.cipher.encrypt_block(&block);

        // Return first 5 bytes
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&encrypted[..5]);
        mask
    }
}

/// Header Protection using AES-256-ECB
///
/// This is used with AES-256-GCM cipher suites.
pub struct HeaderProtectionAes256 {
    cipher: Aes,
}

impl HeaderProtectionAes256 {
    /// Create a new AES-256 header protection instance
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte header protection key
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32, "AES-256 key must be 32 bytes");
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Self {
            cipher: Aes::new_256(&key_array),
        }
    }
}

impl HeaderProtection for HeaderProtectionAes256 {
    fn generate_mask(&self, sample: &[u8]) -> [u8; 5] {
        assert_eq!(sample.len(), 16, "Sample must be 16 bytes");

        // AES-ECB encrypt the sample
        let mut block = [0u8; 16];
        block.copy_from_slice(sample);
        let encrypted = self.cipher.encrypt_block(&block);

        // Return first 5 bytes
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&encrypted[..5]);
        mask
    }
}

/// Header Protection using ChaCha20
///
/// This is used with ChaCha20-Poly1305 cipher suite.
///
/// # Example
///
/// ```rust
/// use hpcrypt_quic::{HeaderProtectionChaCha20, HeaderProtection};
///
/// let hp_key = [0x42; 32];
/// let hp = HeaderProtectionChaCha20::new(&hp_key);
///
/// let sample = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
/// let mask = hp.generate_mask(&sample);
/// assert_eq!(mask.len(), 5);
/// ```
pub struct HeaderProtectionChaCha20 {
    key: [u8; 32],
}

impl HeaderProtectionChaCha20 {
    /// Create a new ChaCha20 header protection instance
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte header protection key
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32, "ChaCha20 key must be 32 bytes");
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Self { key: key_array }
    }
}

impl HeaderProtection for HeaderProtectionChaCha20 {
    fn generate_mask(&self, sample: &[u8]) -> [u8; 5] {
        assert_eq!(sample.len(), 16, "Sample must be 16 bytes");

        // ChaCha20 uses sample[0..4] as counter and sample[4..16] as nonce
        let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sample[4..16]);

        // Create ChaCha20 cipher
        let mut cipher = ChaCha20::new(&self.key, &nonce, counter);

        // Generate 5 bytes of keystream
        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);

        mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_aes128_header_protection() {
        // Basic functionality test
        let key = [0x42; 16];
        let hp = HeaderProtectionAes128::new(&key);

        let sample = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mask = hp.generate_mask(&sample);

        assert_eq!(mask.len(), 5);

        // Same sample should produce same mask
        let mask2 = hp.generate_mask(&sample);
        assert_eq!(mask, mask2);
    }

    #[test]
    fn test_aes256_header_protection() {
        let key = [0x42; 32];
        let hp = HeaderProtectionAes256::new(&key);

        let sample = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mask = hp.generate_mask(&sample);

        assert_eq!(mask.len(), 5);
    }

    #[test]
    fn test_chacha20_header_protection() {
        let key = [0x42; 32];
        let hp = HeaderProtectionChaCha20::new(&key);

        let sample = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mask = hp.generate_mask(&sample);

        assert_eq!(mask.len(), 5);

        // Same sample should produce same mask
        let mask2 = hp.generate_mask(&sample);
        assert_eq!(mask, mask2);
    }

    #[test]
    fn test_different_samples_produce_different_masks() {
        let key = [0x42; 16];
        let hp = HeaderProtectionAes128::new(&key);

        let sample1 = [0x01; 16];
        let sample2 = [0x02; 16];

        let mask1 = hp.generate_mask(&sample1);
        let mask2 = hp.generate_mask(&sample2);

        assert_ne!(mask1, mask2);
    }

    #[test]
    fn test_aes128_vs_aes256_different_masks() {
        let key128 = [0x42; 16];
        let key256 = [0x42; 32];

        let hp128 = HeaderProtectionAes128::new(&key128);
        let hp256 = HeaderProtectionAes256::new(&key256);

        let sample = [0x01; 16];

        let mask128 = hp128.generate_mask(&sample);
        let mask256 = hp256.generate_mask(&sample);

        // Different ciphers should produce different masks
        assert_ne!(mask128, mask256);
    }

    #[test]
    fn test_aes_vs_chacha_different_masks() {
        let key = [0x42; 32];

        let hp_aes = HeaderProtectionAes256::new(&key);
        let hp_chacha = HeaderProtectionChaCha20::new(&key);

        let sample = [0x01; 16];

        let mask_aes = hp_aes.generate_mask(&sample);
        let mask_chacha = hp_chacha.generate_mask(&sample);

        // Different algorithms should produce different masks
        assert_ne!(mask_aes, mask_chacha);
    }

    #[test]
    #[should_panic(expected = "AES-128 key must be 16 bytes")]
    fn test_aes128_wrong_key_size() {
        let key = [0u8; 32]; // Wrong size
        HeaderProtectionAes128::new(&key);
    }

    #[test]
    #[should_panic(expected = "AES-256 key must be 32 bytes")]
    fn test_aes256_wrong_key_size() {
        let key = [0u8; 16]; // Wrong size
        HeaderProtectionAes256::new(&key);
    }

    #[test]
    #[should_panic(expected = "ChaCha20 key must be 32 bytes")]
    fn test_chacha20_wrong_key_size() {
        let key = [0u8; 16]; // Wrong size
        HeaderProtectionChaCha20::new(&key);
    }

    #[test]
    #[should_panic(expected = "Sample must be 16 bytes")]
    fn test_aes128_wrong_sample_size() {
        let key = [0u8; 16];
        let hp = HeaderProtectionAes128::new(&key);
        let sample = [0u8; 15]; // Wrong size
        hp.generate_mask(&sample);
    }

    #[test]
    fn test_rfc9001_appendix_a() {
        // Test vector from RFC 9001 Appendix A
        // Client Initial packet header protection

        // Header protection key (derived from client initial secret)
        let hp_key = hex!("9f 50 44 9e 04 a0 e8 10 28 3a 1e 99 33 ad ed d2");

        let hp = HeaderProtectionAes128::new(&hp_key);

        // Sample (16 bytes from encrypted payload)
        let sample = hex!("d1 b1 c9 8d d7 68 9f b8 ec 11 d2 42 b1 23 dc 9b");

        // Generate mask
        let mask = hp.generate_mask(&sample);

        // Expected mask from RFC 9001
        let expected_mask = hex!("43 7b 9a ec 36");

        assert_eq!(mask, expected_mask, "Header protection mask mismatch");
    }

    #[test]
    fn test_protect_unprotect_roundtrip() {
        let key = [0x42; 16];
        let hp = HeaderProtectionAes128::new(&key);

        let sample = [0x01; 16];
        let mask = hp.generate_mask(&sample);

        // Simulate protecting header
        let original_first_byte = 0b11000000u8; // QUIC long header
        let protected_first_byte = original_first_byte ^ mask[0];

        // Unprotect
        let unprotected_first_byte = protected_first_byte ^ mask[0];

        assert_eq!(original_first_byte, unprotected_first_byte);
    }
}
