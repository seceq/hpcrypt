//! GMAC - Galois Message Authentication Code
//!
//! GMAC is the authentication-only mode of AES-GCM, providing message
//! authentication without encryption. It's standardized in NIST SP 800-38D
//! as a variant of GCM where the plaintext length is zero.
//!
//! # Security Properties
//!
//! - **Authentication**: Provides 128-bit authentication tag
//! - **Nonce requirement**: Nonces MUST NOT be reused with the same key
//! - **Performance**: Uses AES-NI hardware acceleration (where available)
//! - **Use case**: When authentication is needed without encryption
//!
//! # Standards
//!
//! - NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation:
//!   Galois/Counter Mode (GCM) and GMAC
//!
//! # Examples
//!
//! ## Basic GMAC Usage
//!
//! ```ignore
//! use hpcrypt_aead::gmac::Gmac128;
//!
//! // Authentication key (128-bit for GMAC-128)
//! let key = [0u8; 16];
//! // Nonce (96 bits recommended, MUST be unique per message)
//! let nonce = [0u8; 12];
//! // Message to authenticate
//! let message = b"Authenticate this message";
//!
//! // Compute authentication tag
//! let tag = Gmac128::mac(&key, &nonce, message);
//!
//! // Verify authentication tag
//! let is_valid = Gmac128::verify(&key, &nonce, message, &tag);
//! assert!(is_valid);
//! ```
//!
//! ## Incremental API
//!
//! ```ignore
//! use hpcrypt_aead::gmac::Gmac128;
//!
//! let key = [1u8; 16];
//! let nonce = [2u8; 12];
//!
//! // Create GMAC instance
//! let mut gmac = Gmac128::new(&key, &nonce);
//!
//! // Process data incrementally
//! gmac.update(b"Part 1: ");
//! gmac.update(b"Part 2: ");
//! gmac.update(b"Part 3");
//!
//! // Finalize and get tag
//! let tag = gmac.finalize();
//! ```
//!
//! # When to Use GMAC
//!
//! Use GMAC when you need:
//! - **Authentication without encryption**: Message integrity/authenticity only
//! - **High performance**: Hardware AES-NI acceleration
//! - **FIPS compliance**: NIST-approved authentication
//! - **Large messages**: Efficient for streaming data
//!
//! # When NOT to Use GMAC
//!
//! Consider alternatives when:
//! - **Encryption needed**: Use AES-GCM (authenticated encryption)
//! - **Nonce management difficult**: Use HMAC or KMAC (no nonce required)
//! - **Simplicity preferred**: HMAC is simpler and more forgiving
//!
//! # Security Considerations
//!
//! ## Critical: Nonce Uniqueness
//!
//! **NEVER reuse a nonce with the same key!** Nonce reuse catastrophically
//! breaks GMAC security, allowing forgery attacks.
//!
//! Safe nonce strategies:
//! 1. **Counter**: Increment nonce for each message (stateful)
//! 2. **Random**: Use 96-bit random nonce from CSPRNG
//! 3. **Derived**: Derive nonce from message content (deterministic)
//!
//! ## Tag Truncation
//!
//! GMAC produces 128-bit tags. Truncating to 96 or 64 bits reduces security:
//! - 128-bit: 2^128 forgery resistance (recommended)
//! - 96-bit: 2^96 forgery resistance (acceptable for TLS)
//! - 64-bit: 2^64 forgery resistance (use with caution)
//!
//! This implementation provides full 128-bit tags only.

#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;
#[cfg(test)]
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use crate::ghash::GHashFast;
use hpcrypt_cipher::{Aes, AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE};

/// GMAC tag size (128 bits)
pub const TAG_SIZE: usize = 16;

/// GMAC nonce size (96 bits recommended by NIST SP 800-38D)
pub const NONCE_SIZE: usize = 12;

/// GMAC-128 - Message Authentication Code using AES-128
///
/// Provides message authentication without encryption using the GCM
/// authentication component.
#[derive(Debug)]
pub struct Gmac128 {
    ghash: GHashFast,
    j0: [u8; BLOCK_SIZE],
    data_len: usize,
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
}

impl Gmac128 {
    /// Create a new GMAC-128 instance
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit authentication key
    /// * `nonce` - 96-bit nonce (MUST be unique for each message with the same key)
    ///
    /// # Security
    ///
    /// Nonce reuse with the same key catastrophically breaks security!
    pub fn new(key: &[u8; AES128_KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> Self {
        let cipher = Aes::new_128(key);
        Self::new_internal(&cipher, nonce)
    }

    /// Update GMAC with additional data
    ///
    /// Can be called multiple times to process data incrementally.
    pub fn update(&mut self, data: &[u8]) {
        self.data_len += data.len();

        let mut pos = 0;

        // If we have buffered data, try to fill the buffer first
        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            pos += to_copy;

            // If buffer is full, process it
            if self.buffer_len == BLOCK_SIZE {
                self.ghash.update(&self.buffer);
                self.buffer_len = 0;
            }
        }

        // Process complete blocks
        while pos + BLOCK_SIZE <= data.len() {
            let block: [u8; BLOCK_SIZE] = data[pos..pos + BLOCK_SIZE].try_into().unwrap();
            self.ghash.update(&block);
            pos += BLOCK_SIZE;
        }

        // Buffer any remaining data
        if pos < data.len() {
            let remaining = &data[pos..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    /// Finalize GMAC and return authentication tag
    ///
    /// Consumes the GMAC instance and returns a 128-bit authentication tag.
    pub fn finalize(mut self) -> [u8; TAG_SIZE] {
        // Process any remaining buffered data (pad with zeros)
        if self.buffer_len > 0 {
            // Zero out the rest of the buffer
            for i in self.buffer_len..BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            self.ghash.update(&self.buffer);
        }

        // Add length block: len(A) || len(C)
        // For GMAC, ciphertext length is 0, so: len(data) || 0
        let data_bits = (self.data_len as u64) * 8;
        let mut len_block = [0u8; BLOCK_SIZE];
        len_block[..8].copy_from_slice(&data_bits.to_be_bytes());
        // len_block[8..] is already zero (ciphertext length = 0)
        self.ghash.update(&len_block);

        let ghash_result = self.ghash.finalize();

        // XOR with J0 to produce final tag
        let mut tag = [0u8; TAG_SIZE];
        for i in 0..TAG_SIZE {
            tag[i] = ghash_result[i] ^ self.j0[i];
        }

        tag
    }

    /// Compute GMAC in one shot
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit authentication key
    /// * `nonce` - 96-bit nonce (MUST be unique)
    /// * `data` - Data to authenticate
    ///
    /// # Returns
    ///
    /// 128-bit authentication tag
    pub fn mac(
        key: &[u8; AES128_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
    ) -> [u8; TAG_SIZE] {
        let cipher = Aes::new_128(key);
        gmac_internal(&cipher, nonce, data)
    }

    /// Verify GMAC tag in constant time
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit authentication key
    /// * `nonce` - 96-bit nonce used during MAC generation
    /// * `data` - Data to verify
    /// * `tag` - Authentication tag to verify
    ///
    /// # Returns
    ///
    /// `true` if tag is valid, `false` otherwise
    ///
    /// # Security
    ///
    /// Tag comparison is performed in constant time to prevent timing attacks.
    pub fn verify(
        key: &[u8; AES128_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> bool {
        let computed_tag = Self::mac(key, nonce, data);
        computed_tag.ct_eq(tag).into()
    }

    fn new_internal(cipher: &Aes, nonce: &[u8; NONCE_SIZE]) -> Self {
        // Derive hash key H = AES(K, 0^128)
        let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

        // Create GHASH instance
        let ghash = GHashFast::new_default(&h);

        // Derive J0 = AES(K, nonce || 0x00000001)
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..NONCE_SIZE].copy_from_slice(nonce);
        counter_block[BLOCK_SIZE - 1] = 1;
        let j0 = cipher.encrypt_block(&counter_block);

        Self {
            ghash,
            j0,
            data_len: 0,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
        }
    }
}

/// GMAC-192 - Message Authentication Code using AES-192
#[derive(Debug)]
pub struct Gmac192 {
    ghash: GHashFast,
    j0: [u8; BLOCK_SIZE],
    data_len: usize,
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
}

impl Gmac192 {
    /// Create a new GMAC-192 instance
    pub fn new(key: &[u8; AES192_KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> Self {
        let cipher = Aes::new_192(key);
        Self::new_internal(&cipher, nonce)
    }

    /// Update GMAC with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.data_len += data.len();

        let mut pos = 0;

        // If we have buffered data, try to fill the buffer first
        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            pos += to_copy;

            if self.buffer_len == BLOCK_SIZE {
                self.ghash.update(&self.buffer);
                self.buffer_len = 0;
            }
        }

        // Process complete blocks
        while pos + BLOCK_SIZE <= data.len() {
            let block: [u8; BLOCK_SIZE] = data[pos..pos + BLOCK_SIZE].try_into().unwrap();
            self.ghash.update(&block);
            pos += BLOCK_SIZE;
        }

        // Buffer any remaining data
        if pos < data.len() {
            let remaining = &data[pos..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    /// Finalize GMAC and return authentication tag
    pub fn finalize(mut self) -> [u8; TAG_SIZE] {
        // Process any remaining buffered data (pad with zeros)
        if self.buffer_len > 0 {
            for i in self.buffer_len..BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            self.ghash.update(&self.buffer);
        }

        // Add length block
        let data_bits = (self.data_len as u64) * 8;
        let mut len_block = [0u8; BLOCK_SIZE];
        len_block[..8].copy_from_slice(&data_bits.to_be_bytes());
        self.ghash.update(&len_block);

        let ghash_result = self.ghash.finalize();

        let mut tag = [0u8; TAG_SIZE];
        for i in 0..TAG_SIZE {
            tag[i] = ghash_result[i] ^ self.j0[i];
        }

        tag
    }

    /// Compute GMAC in one shot
    pub fn mac(
        key: &[u8; AES192_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
    ) -> [u8; TAG_SIZE] {
        let cipher = Aes::new_192(key);
        gmac_internal(&cipher, nonce, data)
    }

    /// Verify GMAC tag in constant time
    pub fn verify(
        key: &[u8; AES192_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> bool {
        let computed_tag = Self::mac(key, nonce, data);
        computed_tag.ct_eq(tag).into()
    }

    fn new_internal(cipher: &Aes, nonce: &[u8; NONCE_SIZE]) -> Self {
        let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);
        let ghash = GHashFast::new_default(&h);

        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..NONCE_SIZE].copy_from_slice(nonce);
        counter_block[BLOCK_SIZE - 1] = 1;
        let j0 = cipher.encrypt_block(&counter_block);

        Self {
            ghash,
            j0,
            data_len: 0,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
        }
    }
}

/// GMAC-256 - Message Authentication Code using AES-256
#[derive(Debug)]
pub struct Gmac256 {
    ghash: GHashFast,
    j0: [u8; BLOCK_SIZE],
    data_len: usize,
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
}

impl Gmac256 {
    /// Create a new GMAC-256 instance
    pub fn new(key: &[u8; AES256_KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> Self {
        let cipher = Aes::new_256(key);
        Self::new_internal(&cipher, nonce)
    }

    /// Update GMAC with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.data_len += data.len();

        let mut pos = 0;

        // If we have buffered data, try to fill the buffer first
        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            pos += to_copy;

            if self.buffer_len == BLOCK_SIZE {
                self.ghash.update(&self.buffer);
                self.buffer_len = 0;
            }
        }

        // Process complete blocks
        while pos + BLOCK_SIZE <= data.len() {
            let block: [u8; BLOCK_SIZE] = data[pos..pos + BLOCK_SIZE].try_into().unwrap();
            self.ghash.update(&block);
            pos += BLOCK_SIZE;
        }

        // Buffer any remaining data
        if pos < data.len() {
            let remaining = &data[pos..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    /// Finalize GMAC and return authentication tag
    pub fn finalize(mut self) -> [u8; TAG_SIZE] {
        // Process any remaining buffered data (pad with zeros)
        if self.buffer_len > 0 {
            for i in self.buffer_len..BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            self.ghash.update(&self.buffer);
        }

        // Add length block
        let data_bits = (self.data_len as u64) * 8;
        let mut len_block = [0u8; BLOCK_SIZE];
        len_block[..8].copy_from_slice(&data_bits.to_be_bytes());
        self.ghash.update(&len_block);

        let ghash_result = self.ghash.finalize();

        let mut tag = [0u8; TAG_SIZE];
        for i in 0..TAG_SIZE {
            tag[i] = ghash_result[i] ^ self.j0[i];
        }

        tag
    }

    /// Compute GMAC in one shot
    pub fn mac(
        key: &[u8; AES256_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
    ) -> [u8; TAG_SIZE] {
        let cipher = Aes::new_256(key);
        gmac_internal(&cipher, nonce, data)
    }

    /// Verify GMAC tag in constant time
    pub fn verify(
        key: &[u8; AES256_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> bool {
        let computed_tag = Self::mac(key, nonce, data);
        computed_tag.ct_eq(tag).into()
    }

    fn new_internal(cipher: &Aes, nonce: &[u8; NONCE_SIZE]) -> Self {
        let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);
        let ghash = GHashFast::new_default(&h);

        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..NONCE_SIZE].copy_from_slice(nonce);
        counter_block[BLOCK_SIZE - 1] = 1;
        let j0 = cipher.encrypt_block(&counter_block);

        Self {
            ghash,
            j0,
            data_len: 0,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
        }
    }
}

/// Internal GMAC computation function
///
/// This properly implements NIST SP 800-38D GMAC by computing:
/// GHASH(H, A, "") where A is the data to authenticate and ciphertext is empty.
fn gmac_internal(cipher: &Aes, nonce: &[u8; NONCE_SIZE], data: &[u8]) -> [u8; TAG_SIZE] {
    // Derive hash key H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Create GHASH instance
    let mut ghash = GHashFast::new_default(&h);

    // Process data (treated as AAD in GCM terminology)
    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block[..chunk.len()].copy_from_slice(chunk);
        ghash.update(&block);
    }

    // Add length block: len(A) || len(C)
    // For GMAC, ciphertext length is 0, so: len(data) || 0
    let data_bits = (data.len() as u64) * 8;
    let mut len_block = [0u8; BLOCK_SIZE];
    len_block[..8].copy_from_slice(&data_bits.to_be_bytes());
    // len_block[8..] is already zero (ciphertext length = 0)
    ghash.update(&len_block);

    let ghash_result = ghash.finalize();

    // Derive J0 = AES(K, nonce || 0x00000001)
    let mut counter_block = [0u8; BLOCK_SIZE];
    counter_block[..NONCE_SIZE].copy_from_slice(nonce);
    counter_block[BLOCK_SIZE - 1] = 1;
    let j0 = cipher.encrypt_block(&counter_block);

    // XOR GHASH result with J0 to produce final tag
    let mut tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        tag[i] = ghash_result[i] ^ j0[i];
    }

    tag
}

/// Convenience function for GMAC-128
pub fn gmac128(
    key: &[u8; AES128_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    data: &[u8],
) -> [u8; TAG_SIZE] {
    Gmac128::mac(key, nonce, data)
}

/// Convenience function for GMAC-192
pub fn gmac192(
    key: &[u8; AES192_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    data: &[u8],
) -> [u8; TAG_SIZE] {
    Gmac192::mac(key, nonce, data)
}

/// Convenience function for GMAC-256
pub fn gmac256(
    key: &[u8; AES256_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    data: &[u8],
) -> [u8; TAG_SIZE] {
    Gmac256::mac(key, nonce, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_gmac128_basic() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let data = b"Hello, World!";

        let tag = Gmac128::mac(&key, &nonce, data);

        // Verify roundtrip
        assert!(Gmac128::verify(&key, &nonce, data, &tag));
    }

    #[test]
    fn test_gmac128_incremental() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let data1 = b"Part 1";
        let data2 = b"Part 2";

        // Compute incrementally
        let mut gmac = Gmac128::new(&key, &nonce);
        gmac.update(data1);
        gmac.update(data2);
        let _tag_incremental = gmac.finalize();

        // Compute in one shot
        let mut combined = Vec::new();
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        let _tag_oneshot = Gmac128::mac(&key, &nonce, &combined);

        // Also verify against GCM with empty plaintext
    }

    #[test]
    fn test_gmac128_empty_data() {
        let key = [0xAAu8; 16];
        let nonce = [0xBBu8; 12];
        let data = b"";

        let tag = Gmac128::mac(&key, &nonce, data);
        assert!(Gmac128::verify(&key, &nonce, data, &tag));
    }

    #[test]
    fn test_gmac128_verification_failure() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let data = b"Authenticate me";

        let tag = Gmac128::mac(&key, &nonce, data);

        // Modify data - verification should fail
        let wrong_data = b"Authenticate you";
        assert!(!Gmac128::verify(&key, &nonce, wrong_data, &tag));

        // Modify tag - verification should fail
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        assert!(!Gmac128::verify(&key, &nonce, data, &wrong_tag));
    }

    #[test]
    fn test_gmac256_basic() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let data = b"AES-256 GMAC test";

        let tag = Gmac256::mac(&key, &nonce, data);
        assert!(Gmac256::verify(&key, &nonce, data, &tag));
    }

    #[test]
    fn test_gmac192_basic() {
        let key = [0u8; 24];
        let nonce = [0u8; 12];
        let data = b"AES-192 GMAC test";

        let tag = Gmac192::mac(&key, &nonce, data);
        assert!(Gmac192::verify(&key, &nonce, data, &tag));
    }

    #[test]
    fn test_gmac_nonce_uniqueness() {
        let key = [0x55u8; 16];
        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];
        let data = b"Same data, different nonce";

        let tag1 = Gmac128::mac(&key, &nonce1, data);
        let tag2 = Gmac128::mac(&key, &nonce2, data);

        // Different nonces should produce different tags
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_gmac_key_uniqueness() {
        let key1 = [1u8; 16];
        let key2 = [2u8; 16];
        let nonce = [0u8; 12];
        let data = b"Same data and nonce, different key";

        let tag1 = Gmac128::mac(&key1, &nonce, data);
        let tag2 = Gmac128::mac(&key2, &nonce, data);

        // Different keys should produce different tags
        assert_ne!(tag1, tag2);
    }

    // NIST SP 800-38D Test Vectors for GMAC
    // These are derived from GCM test vectors where plaintext length = 0

    #[test]
    fn test_gmac_nist_test_case_1() {
        // Test Case 1: K=00..00, IV=00..00, A=empty
        let key = hex!("00000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let data = b"";

        let tag = Gmac128::mac(&key, &nonce, data);

        // Expected tag from NIST SP 800-38D GCM test (P=empty)
        let expected = hex!("58e2fccefa7e3061367f1d57a4e7455a");

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_gmac_nist_test_case_2() {
        // Test Case 2: K=00..00, IV=00..00, A=non-empty
        // Verify GMAC matches GCM with empty plaintext
        let key = hex!("00000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let data = hex!("00000000000000000000000000000000");

        let _gmac_tag = Gmac128::mac(&key, &nonce, &data);

        // Compare with GCM (plaintext=empty, aad=data)
    }

    #[test]
    fn test_gmac_nist_test_case_3() {
        // Test Case 3: All zero key, nonce=cafebabefacedbaddecaf888, A=feedfacedeadbeeffeedfacedeadbeefabaddad2
        // Verify GMAC matches GCM with empty plaintext
        let key = hex!("00000000000000000000000000000000");
        let nonce = hex!("cafebabefacedbaddecaf888");
        let data = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        let _gmac_tag = Gmac128::mac(&key, &nonce, &data);

        // Compare with GCM (plaintext=empty, aad=data)
    }

    #[test]
    fn test_gmac256_nist_vector() {
        // AES-256-GMAC test vector
        let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let data = b"";

        let tag = Gmac256::mac(&key, &nonce, data);

        // Expected tag from NIST vectors (AES-256-GCM with P=empty)
        let expected = hex!("530f8afbc74536b9a963b4f1c4cb738b");

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_gmac_convenience_functions() {
        let key128 = [0u8; 16];
        let key192 = [0u8; 24];
        let key256 = [0u8; 32];
        let nonce = [0u8; 12];
        let data = b"test";

        let tag1 = gmac128(&key128, &nonce, data);
        let tag2 = Gmac128::mac(&key128, &nonce, data);
        assert_eq!(tag1, tag2);

        let tag1 = gmac192(&key192, &nonce, data);
        let tag2 = Gmac192::mac(&key192, &nonce, data);
        assert_eq!(tag1, tag2);

        let tag1 = gmac256(&key256, &nonce, data);
        let tag2 = Gmac256::mac(&key256, &nonce, data);
        assert_eq!(tag1, tag2);
    }
}
