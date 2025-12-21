//! AES-GCM (Galois/Counter Mode) AEAD cipher
//!
//! AES-GCM combines AES in Counter (CTR) mode for encryption with GHASH for authentication.
//! Specified in NIST SP 800-38D.
//!
//! This implementation supports:
//! - Variable IV lengths (96-bit recommended, but any length supported per NIST SP 800-38D)
//! - Variable tag lengths (32, 64, 96, 104, 112, 120, 128 bits per NIST SP 800-38D)

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_core::traits::AeadError;
use subtle::ConstantTimeEq;

use hpcrypt_cipher::{Aes, AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE};
use hpcrypt_mac::ghash::GHashFast;

/// AES-GCM default tag size (128 bits)
pub const TAG_SIZE: usize = 16;

/// AES-GCM default nonce size (96 bits recommended)
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

// ============================================================================
// Variable IV/Tag Length API
// ============================================================================

/// Encrypt with variable IV length and custom tag size
///
/// This is the flexible API that supports any IV length per NIST SP 800-38D.
/// For 96-bit IVs, use the standard `encrypt` methods which are more efficient.
///
/// # Arguments
/// * `key` - AES key (16, 24, or 32 bytes)
/// * `iv` - Initialization vector (any length, 96 bits recommended)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data
/// * `tag_len` - Desired tag length in bytes (4, 8, 12, 13, 14, 15, or 16)
///
/// # Returns
/// Ciphertext || tag
pub fn gcm_encrypt_variable(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, AeadError> {
    let cipher = match key.len() {
        AES128_KEY_SIZE => Aes::new_128(key.try_into().unwrap()),
        AES192_KEY_SIZE => Aes::new_192(key.try_into().unwrap()),
        AES256_KEY_SIZE => Aes::new_256(key.try_into().unwrap()),
        _ => return Err(AeadError::InvalidKeyLength {
            expected: &[16, 24, 32],
            actual: key.len(),
        }),
    };

    // Validate tag length per NIST SP 800-38D (must be 32, 64, 96, 104, 112, 120, or 128 bits)
    if !matches!(tag_len, 4 | 8 | 12 | 13 | 14 | 15 | 16) {
        return Err(AeadError::InvalidTagLength {
            expected: &[4, 8, 12, 13, 14, 15, 16],
            actual: tag_len,
        });
    }

    Ok(gcm_encrypt_with_iv(&cipher, iv, plaintext, aad, tag_len))
}

/// Decrypt with variable IV length and custom tag size
///
/// # Arguments
/// * `key` - AES key (16, 24, or 32 bytes)
/// * `iv` - Initialization vector (any length, 96 bits recommended)
/// * `ciphertext_with_tag` - Ciphertext || tag
/// * `aad` - Additional authenticated data
/// * `tag_len` - Tag length in bytes (4, 8, 12, 13, 14, 15, or 16)
///
/// # Returns
/// Plaintext on success, error on authentication failure
pub fn gcm_decrypt_variable(
    key: &[u8],
    iv: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, AeadError> {
    let cipher = match key.len() {
        AES128_KEY_SIZE => Aes::new_128(key.try_into().unwrap()),
        AES192_KEY_SIZE => Aes::new_192(key.try_into().unwrap()),
        AES256_KEY_SIZE => Aes::new_256(key.try_into().unwrap()),
        _ => return Err(AeadError::InvalidKeyLength {
            expected: &[16, 24, 32],
            actual: key.len(),
        }),
    };

    // Validate tag length
    if !matches!(tag_len, 4 | 8 | 12 | 13 | 14 | 15 | 16) {
        return Err(AeadError::InvalidTagLength {
            expected: &[4, 8, 12, 13, 14, 15, 16],
            actual: tag_len,
        });
    }

    gcm_decrypt_with_iv(&cipher, iv, ciphertext_with_tag, aad, tag_len)
}

// ============================================================================
// Core GCM Functions (96-bit IV, 128-bit tag)
// ============================================================================

/// Core GCM encryption function (96-bit IV, 128-bit tag)
fn gcm_encrypt(cipher: &Aes, nonce: &[u8; NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    // Derive hash key H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Initialize counter block: nonce || 0x00000001
    let mut counter_block = [0u8; BLOCK_SIZE];
    counter_block[..NONCE_SIZE].copy_from_slice(nonce);
    counter_block[BLOCK_SIZE - 1] = 1;

    // Encrypt plaintext using CTR mode
    // Note: GCM uses counter J0 (nonce||1) for tag encryption
    // Data encryption starts with J1 (nonce||2)
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut counter = u32::from_be_bytes([
        counter_block[12],
        counter_block[13],
        counter_block[14],
        counter_block[15],
    ]);

    for (i, chunk) in plaintext.chunks(BLOCK_SIZE).enumerate() {
        // Increment counter for each block (starts at 2 for first plaintext block)
        counter = counter.wrapping_add(1);
        counter_block[12..].copy_from_slice(&counter.to_be_bytes());

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
        // Note: GCM uses counter J0 (nonce||1) for tag encryption
        // Data decryption starts with J1 (nonce||2)
        let mut plaintext = vec![0u8; ciphertext_len];
        let mut counter_block = counter_block_0;
        let mut counter = u32::from_be_bytes([
            counter_block[12],
            counter_block[13],
            counter_block[14],
            counter_block[15],
        ]);

        for (i, chunk) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
            // Increment counter for each block (starts at 2 for first ciphertext block)
            counter = counter.wrapping_add(1);
            counter_block[12..].copy_from_slice(&counter.to_be_bytes());

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

// ============================================================================
// Variable IV/Tag Length Core Functions
// ============================================================================

/// Compute J0 (initial counter) for variable-length IV
///
/// Per NIST SP 800-38D:
/// - If len(IV) = 96: J0 = IV || 0^31 || 1
/// - Otherwise: J0 = GHASH(H, {}, IV || 0^s || len(IV))
///   where s = 128 * ceil(len(IV)/128) - len(IV) + 64
fn compute_j0(h: &[u8; BLOCK_SIZE], iv: &[u8]) -> [u8; BLOCK_SIZE] {
    if iv.len() == NONCE_SIZE {
        // 96-bit IV: J0 = IV || 0^31 || 1
        let mut j0 = [0u8; BLOCK_SIZE];
        j0[..NONCE_SIZE].copy_from_slice(iv);
        j0[BLOCK_SIZE - 1] = 1;
        j0
    } else {
        // Variable-length IV: J0 = GHASH(H, {}, IV || 0^s || len(IV))
        let mut ghash = GHashFast::new_default(h);

        // Process IV in 16-byte blocks
        for chunk in iv.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            ghash.update(&block);
        }

        // Add padding to reach next block boundary plus 64 bits
        // s = 128 * ceil(len(IV)/128) - len(IV) + 64 bits
        // We need padding so total is multiple of 128 bits, plus 64-bit zero, plus 64-bit length
        let iv_bits = (iv.len() as u64) * 8;

        // If IV is already block-aligned, we need a full zero block before length
        // Otherwise, the partial block padding is implicit from the loop above
        if iv.len() % BLOCK_SIZE == 0 && !iv.is_empty() {
            // No additional padding needed before length block
        }

        // Final block: 64 bits of zeros || 64-bit len(IV) in bits
        let mut len_block = [0u8; BLOCK_SIZE];
        len_block[8..].copy_from_slice(&iv_bits.to_be_bytes());
        ghash.update(&len_block);

        ghash.finalize()
    }
}

/// GCM encryption with variable-length IV and tag
fn gcm_encrypt_with_iv(
    cipher: &Aes,
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    tag_len: usize,
) -> Vec<u8> {
    // Derive hash key H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Compute J0 based on IV length
    let j0 = compute_j0(&h, iv);

    // Initialize counter from J0
    let mut counter_block = j0;
    let mut counter = u32::from_be_bytes([
        counter_block[12],
        counter_block[13],
        counter_block[14],
        counter_block[15],
    ]);

    // Encrypt plaintext using CTR mode starting at J0 + 1
    let mut ciphertext = vec![0u8; plaintext.len()];

    for (i, chunk) in plaintext.chunks(BLOCK_SIZE).enumerate() {
        // Increment counter for each block
        counter = counter.wrapping_add(1);
        counter_block[12..].copy_from_slice(&counter.to_be_bytes());

        // Encrypt counter block
        let keystream = cipher.encrypt_block(&counter_block);

        // XOR plaintext with keystream
        for (j, &byte) in chunk.iter().enumerate() {
            ciphertext[i * BLOCK_SIZE + j] = byte ^ keystream[j];
        }
    }

    // Compute GHASH(H, A, C)
    let ghash_result = compute_ghash(&h, aad, &ciphertext);

    // Encrypt GHASH result with J0 to get tag
    let encrypted_j0 = cipher.encrypt_block(&j0);

    let mut full_tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        full_tag[i] = ghash_result[i] ^ encrypted_j0[i];
    }

    // Return ciphertext || truncated tag
    let mut result = ciphertext;
    result.extend_from_slice(&full_tag[..tag_len]);
    result
}

/// GCM decryption with variable-length IV and tag
fn gcm_decrypt_with_iv(
    cipher: &Aes,
    iv: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_with_tag.len() < tag_len {
        return Err(AeadError::InvalidCiphertextLength {
            minimum: tag_len,
            actual: ciphertext_with_tag.len(),
        });
    }

    let ciphertext_len = ciphertext_with_tag.len() - tag_len;
    let ciphertext = &ciphertext_with_tag[..ciphertext_len];
    let received_tag = &ciphertext_with_tag[ciphertext_len..];

    // Derive hash key H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Compute J0 based on IV length
    let j0 = compute_j0(&h, iv);

    // Compute GHASH(H, A, C)
    let ghash_result = compute_ghash(&h, aad, ciphertext);

    // Encrypt GHASH result with J0 to get expected tag
    let encrypted_j0 = cipher.encrypt_block(&j0);

    let mut computed_tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        computed_tag[i] = ghash_result[i] ^ encrypted_j0[i];
    }

    // Verify tag (only compare tag_len bytes) in constant time
    if computed_tag[..tag_len].ct_eq(received_tag).into() {
        // Decrypt ciphertext using CTR mode starting at J0 + 1
        let mut plaintext = vec![0u8; ciphertext_len];
        let mut counter_block = j0;
        let mut counter = u32::from_be_bytes([
            counter_block[12],
            counter_block[13],
            counter_block[14],
            counter_block[15],
        ]);

        for (i, chunk) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
            // Increment counter for each block
            counter = counter.wrapping_add(1);
            counter_block[12..].copy_from_slice(&counter.to_be_bytes());

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
    let mut ghash = GHashFast::new_default(h);

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
