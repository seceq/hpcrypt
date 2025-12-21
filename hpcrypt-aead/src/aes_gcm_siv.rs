//! AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption (RFC 8452)
//!
//! AES-GCM-SIV provides authenticated encryption with associated data (AEAD) that
//! is resistant to nonce misuse. Unlike AES-GCM, repeating a nonce does not
//! catastrophically compromise security - it only reveals whether two plaintexts
//! are identical.
//!
//! ## Security Properties
//!
//! - **Nonce misuse resistance**: Repeating nonces doesn't leak plaintext
//! - **Deterministic with same inputs**: Same key+nonce+plaintext = same ciphertext
//! - **128-bit authentication tag**
//! - **96-bit nonce**
//!
//! ## Performance
//!
//! - Encryption: ~2/3 speed of AES-GCM (requires two passes)
//! - Decryption: Within 5% of AES-GCM speed
//!
//! ## Example
//!
//! ```
//! use hpcrypt_aead::aes_gcm_siv::Aes128GcmSiv;
//!
//! let key = [0u8; 16]; // 128-bit key
//! let nonce = [0u8; 12]; // 96-bit nonce
//! let plaintext = b"secret message";
//! let aad = b"additional data";
//!
//! // Encrypt
//! let ciphertext = Aes128GcmSiv::encrypt(&key, &nonce, plaintext, aad);
//!
//! // Decrypt
//! let decrypted = Aes128GcmSiv::decrypt(&key, &nonce, &ciphertext, aad)
//!     .expect("Decryption failed");
//!
//! assert_eq!(decrypted, plaintext);
//! ```

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;
use hpcrypt_cipher::Aes;
use hpcrypt_mac::Polyval;

/// AES-128-GCM-SIV (128-bit key)
#[derive(Debug)]
pub struct Aes128GcmSiv;

/// AES-256-GCM-SIV (256-bit key)
#[derive(Debug)]
pub struct Aes256GcmSiv;

impl Aes128GcmSiv {
    /// Encrypt plaintext with AES-128-GCM-SIV
    ///
    /// # Parameters
    /// - `key`: 16-byte encryption key
    /// - `nonce`: 12-byte nonce
    /// - `plaintext`: Data to encrypt
    /// - `aad`: Additional authenticated data (not encrypted)
    ///
    /// # Returns
    /// Ciphertext with 16-byte authentication tag appended
    pub fn encrypt(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        // Derive keys from master key and nonce
        let (auth_key, enc_key) = derive_keys_128(key, nonce);

        // Compute authentication tag
        let tag = compute_tag(&auth_key, &enc_key, nonce, aad, plaintext);

        // Encrypt plaintext using counter mode with tag as initial counter
        let ciphertext = ctr_encrypt_128(&enc_key, &tag, plaintext);

        // Return ciphertext || tag
        let mut output = ciphertext;
        output.extend_from_slice(&tag);
        output
    }

    /// Decrypt ciphertext with AES-128-GCM-SIV
    ///
    /// # Parameters
    /// - `key`: 16-byte encryption key
    /// - `nonce`: 12-byte nonce
    /// - `ciphertext`: Data to decrypt (includes 16-byte tag)
    /// - `aad`: Additional authenticated data
    ///
    /// # Returns
    /// Plaintext if authentication succeeds, None otherwise
    pub fn decrypt(
        key: &[u8; 16],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<Vec<u8>> {
        // Must have at least the 16-byte tag
        if ciphertext.len() < 16 {
            return None;
        }

        // Split ciphertext and tag
        let ct_len = ciphertext.len() - 16;
        let ct = &ciphertext[..ct_len];
        let received_tag: [u8; 16] = ciphertext[ct_len..].try_into().unwrap();

        // Derive keys
        let (auth_key, enc_key) = derive_keys_128(key, nonce);

        // Decrypt using counter mode
        let plaintext = ctr_encrypt_128(&enc_key, &received_tag, ct);

        // Recompute tag
        let expected_tag = compute_tag(&auth_key, &enc_key, nonce, aad, &plaintext);

        // Constant-time comparison
        if constant_time_eq(&received_tag, &expected_tag) {
            Some(plaintext)
        } else {
            None
        }
    }
}

impl Aes256GcmSiv {
    /// Encrypt plaintext with AES-256-GCM-SIV
    ///
    /// # Parameters
    /// - `key`: 32-byte encryption key
    /// - `nonce`: 12-byte nonce
    /// - `plaintext`: Data to encrypt
    /// - `aad`: Additional authenticated data (not encrypted)
    ///
    /// # Returns
    /// Ciphertext with 16-byte authentication tag appended
    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        // Derive keys from master key and nonce
        let (auth_key, enc_key) = derive_keys_256(key, nonce);

        // Compute authentication tag
        let tag = compute_tag_256(&auth_key, &enc_key, nonce, aad, plaintext);

        // Encrypt plaintext using counter mode with tag as initial counter
        let ciphertext = ctr_encrypt_256(&enc_key, &tag, plaintext);

        // Return ciphertext || tag
        let mut output = ciphertext;
        output.extend_from_slice(&tag);
        output
    }

    /// Decrypt ciphertext with AES-256-GCM-SIV
    ///
    /// # Parameters
    /// - `key`: 32-byte encryption key
    /// - `nonce`: 12-byte nonce
    /// - `ciphertext`: Data to decrypt (includes 16-byte tag)
    /// - `aad`: Additional authenticated data
    ///
    /// # Returns
    /// Plaintext if authentication succeeds, None otherwise
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<Vec<u8>> {
        // Must have at least the 16-byte tag
        if ciphertext.len() < 16 {
            return None;
        }

        // Split ciphertext and tag
        let ct_len = ciphertext.len() - 16;
        let ct = &ciphertext[..ct_len];
        let received_tag: [u8; 16] = ciphertext[ct_len..].try_into().unwrap();

        // Derive keys
        let (auth_key, enc_key) = derive_keys_256(key, nonce);

        // Decrypt using counter mode
        let plaintext = ctr_encrypt_256(&enc_key, &received_tag, ct);

        // Recompute tag
        let expected_tag = compute_tag_256(&auth_key, &enc_key, nonce, aad, &plaintext);

        // Constant-time comparison
        if constant_time_eq(&received_tag, &expected_tag) {
            Some(plaintext)
        } else {
            None
        }
    }
}

/// Derive authentication and encryption keys for AES-128-GCM-SIV
fn derive_keys_128(key: &[u8; 16], nonce: &[u8; 12]) -> ([u8; 16], [u8; 16]) {
    let aes = Aes::new_128(key);

    // Create counter-nonce blocks
    let mut block0 = [0u8; 16];
    let mut block1 = [0u8; 16];
    let mut block2 = [0u8; 16];
    let mut block3 = [0u8; 16];

    // Counter 0 || nonce
    block0[0..4].copy_from_slice(&0u32.to_le_bytes());
    block0[4..16].copy_from_slice(nonce);

    // Counter 1 || nonce
    block1[0..4].copy_from_slice(&1u32.to_le_bytes());
    block1[4..16].copy_from_slice(nonce);

    // Counter 2 || nonce
    block2[0..4].copy_from_slice(&2u32.to_le_bytes());
    block2[4..16].copy_from_slice(nonce);

    // Counter 3 || nonce
    block3[0..4].copy_from_slice(&3u32.to_le_bytes());
    block3[4..16].copy_from_slice(nonce);

    // Encrypt blocks
    let enc0 = aes.encrypt_block(&block0);
    let enc1 = aes.encrypt_block(&block1);
    let enc2 = aes.encrypt_block(&block2);
    let enc3 = aes.encrypt_block(&block3);

    // Combine for keys
    let mut auth_key = [0u8; 16];
    auth_key[0..8].copy_from_slice(&enc0[0..8]);
    auth_key[8..16].copy_from_slice(&enc1[0..8]);

    let mut enc_key = [0u8; 16];
    enc_key[0..8].copy_from_slice(&enc2[0..8]);
    enc_key[8..16].copy_from_slice(&enc3[0..8]);

    (auth_key, enc_key)
}

/// Compute authentication tag using POLYVAL
fn compute_tag(
    auth_key: &[u8; 16],
    enc_key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; 16] {
    let mut poly = Polyval::new(auth_key);

    // Process AAD (padded to 16-byte blocks)
    poly.update(aad);

    // Pad AAD if needed
    let aad_padding = (16 - (aad.len() % 16)) % 16;
    if aad_padding > 0 {
        poly.update(&vec![0u8; aad_padding]);
    }

    // Process plaintext (padded to 16-byte blocks)
    poly.update(plaintext);

    // Pad plaintext if needed
    let pt_padding = (16 - (plaintext.len() % 16)) % 16;
    if pt_padding > 0 {
        poly.update(&vec![0u8; pt_padding]);
    }

    // Add length block (AAD length || plaintext length in BITS per RFC 8452)
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_le_bytes());
    len_block[8..16].copy_from_slice(&((plaintext.len() as u64) * 8).to_le_bytes());
    poly.update_block(&len_block);

    // Get POLYVAL output
    let mut s = poly.finalize();

    // XOR first 12 bytes with nonce
    for i in 0..12 {
        s[i] ^= nonce[i];
    }

    // Clear MSB of last byte
    s[15] &= 0x7F;

    // Encrypt with AES using encryption key (not auth key!) per RFC 8452
    let aes = Aes::new_128(enc_key);
    aes.encrypt_block(&s)
}

/// Counter mode encryption/decryption for AES-128
fn ctr_encrypt_128(key: &[u8; 16], initial_counter: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let aes = Aes::new_128(key);
    let mut output = Vec::with_capacity(data.len());

    // Set MSB of last byte to 1 for initial counter
    let mut counter = *initial_counter;
    counter[15] |= 0x80;

    let mut offset = 0;
    while offset < data.len() {
        // Encrypt counter
        let keystream = aes.encrypt_block(&counter);

        // XOR with plaintext
        let chunk_len = core::cmp::min(16, data.len() - offset);
        for i in 0..chunk_len {
            output.push(data[offset + i] ^ keystream[i]);
        }

        offset += chunk_len;

        // Increment counter (little-endian)
        increment_counter_le(&mut counter);
    }

    output
}

/// Derive authentication and encryption keys for AES-256-GCM-SIV
///
/// Per RFC 8452, for 256-bit keys we derive:
/// - 16-byte authentication key (from blocks 0-1)
/// - 32-byte encryption key (from blocks 2-5)
fn derive_keys_256(key: &[u8; 32], nonce: &[u8; 12]) -> ([u8; 16], [u8; 32]) {
    let aes = Aes::new_256(key);

    // Create counter-nonce blocks (need 6 blocks for 256-bit)
    let mut blocks = [[0u8; 16]; 6];

    for (i, block) in blocks.iter_mut().enumerate() {
        block[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        block[4..16].copy_from_slice(nonce);
    }

    // Encrypt all blocks
    let enc: Vec<[u8; 16]> = blocks.iter().map(|b| aes.encrypt_block(b)).collect();

    // Combine for keys
    // Auth key: first 8 bytes of enc[0] || first 8 bytes of enc[1]
    let mut auth_key = [0u8; 16];
    auth_key[0..8].copy_from_slice(&enc[0][0..8]);
    auth_key[8..16].copy_from_slice(&enc[1][0..8]);

    // Enc key: first 8 bytes of enc[2-5]
    let mut enc_key = [0u8; 32];
    enc_key[0..8].copy_from_slice(&enc[2][0..8]);
    enc_key[8..16].copy_from_slice(&enc[3][0..8]);
    enc_key[16..24].copy_from_slice(&enc[4][0..8]);
    enc_key[24..32].copy_from_slice(&enc[5][0..8]);

    (auth_key, enc_key)
}

/// Compute authentication tag using POLYVAL for AES-256-GCM-SIV
fn compute_tag_256(
    auth_key: &[u8; 16],
    enc_key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; 16] {
    let mut poly = Polyval::new(auth_key);

    // Process AAD (padded to 16-byte blocks)
    poly.update(aad);

    // Pad AAD if needed
    let aad_padding = (16 - (aad.len() % 16)) % 16;
    if aad_padding > 0 {
        poly.update(&vec![0u8; aad_padding]);
    }

    // Process plaintext (padded to 16-byte blocks)
    poly.update(plaintext);

    // Pad plaintext if needed
    let pt_padding = (16 - (plaintext.len() % 16)) % 16;
    if pt_padding > 0 {
        poly.update(&vec![0u8; pt_padding]);
    }

    // Add length block (AAD length || plaintext length in BITS per RFC 8452)
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_le_bytes());
    len_block[8..16].copy_from_slice(&((plaintext.len() as u64) * 8).to_le_bytes());
    poly.update_block(&len_block);

    // Get POLYVAL output
    let mut s = poly.finalize();

    // XOR first 12 bytes with nonce
    for i in 0..12 {
        s[i] ^= nonce[i];
    }

    // Clear MSB of last byte
    s[15] &= 0x7F;

    // Encrypt with AES-256 to get final tag
    let aes = Aes::new_256(enc_key);
    aes.encrypt_block(&s)
}

/// Counter mode encryption/decryption for AES-256
fn ctr_encrypt_256(key: &[u8; 32], initial_counter: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let aes = Aes::new_256(key);
    let mut output = Vec::with_capacity(data.len());

    // Set MSB of last byte to 1 for initial counter
    let mut counter = *initial_counter;
    counter[15] |= 0x80;

    let mut offset = 0;
    while offset < data.len() {
        // Encrypt counter
        let keystream = aes.encrypt_block(&counter);

        // XOR with plaintext
        let chunk_len = core::cmp::min(16, data.len() - offset);
        for i in 0..chunk_len {
            output.push(data[offset + i] ^ keystream[i]);
        }

        offset += chunk_len;

        // Increment counter (little-endian)
        increment_counter_le(&mut counter);
    }

    output
}

/// Increment counter in little-endian
fn increment_counter_le(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().take(4) {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Constant-time equality check
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_gcm_siv_basic() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        let ciphertext = Aes128GcmSiv::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes128GcmSiv::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_gcm_siv_wrong_tag() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"secret";
        let aad = b"public";

        let mut ciphertext = Aes128GcmSiv::encrypt(&key, &nonce, plaintext, aad);

        // Corrupt the tag
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 1;

        // Should fail to decrypt
        assert!(Aes128GcmSiv::decrypt(&key, &nonce, &ciphertext, aad).is_none());
    }

    #[test]
    fn test_aes128_gcm_siv_empty_plaintext() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plaintext = b"";
        let aad = b"aad";

        let ciphertext = Aes128GcmSiv::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ciphertext.len(), 16); // Just the tag

        let decrypted = Aes128GcmSiv::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_deterministic() {
        let key = [5u8; 16];
        let nonce = [6u8; 12];
        let plaintext = b"test message";
        let aad = b"context";

        let ct1 = Aes128GcmSiv::encrypt(&key, &nonce, plaintext, aad);
        let ct2 = Aes128GcmSiv::encrypt(&key, &nonce, plaintext, aad);

        // Should be deterministic - same inputs produce same output
        assert_eq!(ct1, ct2);
    }

    // AES-256-GCM-SIV tests

    #[test]
    fn test_aes256_gcm_siv_basic() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        let ciphertext = Aes256GcmSiv::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes256GcmSiv::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_siv_wrong_tag() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret";
        let aad = b"public";

        let mut ciphertext = Aes256GcmSiv::encrypt(&key, &nonce, plaintext, aad);

        // Corrupt the tag
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 1;

        // Should fail to decrypt
        assert!(Aes256GcmSiv::decrypt(&key, &nonce, &ciphertext, aad).is_none());
    }

    #[test]
    fn test_aes256_gcm_siv_empty_plaintext() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"";
        let aad = b"aad";

        let ciphertext = Aes256GcmSiv::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ciphertext.len(), 16); // Just the tag

        let decrypted = Aes256GcmSiv::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_siv_deterministic() {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        let plaintext = b"test message";
        let aad = b"context";

        let ct1 = Aes256GcmSiv::encrypt(&key, &nonce, plaintext, aad);
        let ct2 = Aes256GcmSiv::encrypt(&key, &nonce, plaintext, aad);

        // Should be deterministic - same inputs produce same output
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_aes256_gcm_siv_different_from_aes128() {
        // Same nonce and plaintext with zero-extended key should produce different output
        let key128 = [0u8; 16];
        let key256 = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"test";
        let aad = b"";

        let ct128 = Aes128GcmSiv::encrypt(&key128, &nonce, plaintext, aad);
        let ct256 = Aes256GcmSiv::encrypt(&key256, &nonce, plaintext, aad);

        // Different key sizes should produce different ciphertexts
        assert_ne!(ct128, ct256);
    }

    // RFC 8452 Appendix C.1 Test Vector
    #[test]
    fn test_rfc8452_appendix_c1_test1() {
        // First test case from RFC 8452 Appendix C.1
        // Key: 01000000000000000000000000000000
        // Nonce: 030000000000000000000000
        // Plaintext: (empty)
        // AAD: (empty)
        // Expected: dc20e2d83f25705bb49e439eca56de25

        let key: [u8; 16] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nonce: [u8; 12] = [
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"";
        let aad = b"";

        let expected: [u8; 16] = [
            0xdc, 0x20, 0xe2, 0xd8, 0x3f, 0x25, 0x70, 0x5b,
            0xb4, 0x9e, 0x43, 0x9e, 0xca, 0x56, 0xde, 0x25,
        ];

        let result = Aes128GcmSiv::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(result.as_slice(), &expected, "RFC 8452 C.1 test 1 failed");
    }

    // RFC 8452 Appendix C.1 Test with AAD and plaintext
    #[test]
    fn test_rfc8452_appendix_c1_with_aad() {
        // Test case from RFC 8452 Appendix C.1 with AAD and plaintext
        // Key: 01000000000000000000000000000000
        // Nonce: 030000000000000000000000
        // Plaintext: 0200000000000000 (8 bytes)
        // AAD: 01 (1 byte)
        // Expected CT: 1e6daba35669f4273b0a1a2560969cdf790d99759abd1508

        let key: [u8; 16] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nonce: [u8; 12] = [
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let aad: [u8; 1] = [0x01];

        let expected: [u8; 24] = [
            0x1e, 0x6d, 0xab, 0xa3, 0x56, 0x69, 0xf4, 0x27,
            0x3b, 0x0a, 0x1a, 0x25, 0x60, 0x96, 0x9c, 0xdf,
            0x79, 0x0d, 0x99, 0x75, 0x9a, 0xbd, 0x15, 0x08,
        ];

        let result = Aes128GcmSiv::encrypt(&key, &nonce, &plaintext, &aad);
        assert_eq!(result.as_slice(), &expected, "RFC 8452 C.1 test with AAD failed");
    }
}
