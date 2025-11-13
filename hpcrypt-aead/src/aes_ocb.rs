//! AES-OCB3 - Offset Codebook Mode (Version 3)
//!
//! OCB is a high-performance authenticated encryption mode that provides
//! both confidentiality and authenticity in a single pass. OCB3 is the
//! latest version specified in RFC 7253.
//!
//! # Features
//!
//! - **Single-pass**: Processes data only once (unlike EAX or SIV)
//! - **Parallelizable**: Can process blocks in parallel
//! - **Efficient**: Faster than GCM on platforms without AES-NI
//! - **Provably secure**: Based on strong cryptographic foundations
//!
//! # Patent Status
//!
//! OCB is patent-free for open-source software. See RFC 7253 Appendix A
//! for licensing information. Commercial use may require a license.
//!
//! # References
//!
//! - [RFC 7253: The OCB Authenticated-Encryption Algorithm](https://tools.ietf.org/html/rfc7253)
//! - [OCB Home Page](http://web.cs.ucdavis.edu/~rogaway/ocb/)

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::aes::{Aes, BLOCK_SIZE};
use hpcrypt_core::error::AeadError;

const TAG_SIZE: usize = 16;
// Recommended nonce size for OCB is 12 bytes (96 bits)

/// AES-128-OCB3
#[derive(Debug)]
pub struct Aes128Ocb;

impl Aes128Ocb {
    /// Encrypt and authenticate data
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit encryption key
    /// * `nonce` - Unique nonce (recommended: 96 bits / 12 bytes)
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Associated authenticated data
    ///
    /// # Returns
    ///
    /// Ciphertext || Tag (tag appended to ciphertext)
    #[cfg(feature = "alloc")]
    pub fn encrypt(key: &[u8; 16], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes::new_128(key);
        ocb_encrypt(&cipher, nonce, plaintext, aad)
    }

    /// Decrypt and verify authenticated data
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit encryption key
    /// * `nonce` - Nonce used for encryption
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
        ocb_decrypt(&cipher, nonce, ciphertext_and_tag, aad)
    }
}

/// AES-256-OCB3
#[derive(Debug)]
pub struct Aes256Ocb;

impl Aes256Ocb {
    /// Encrypt and authenticate data
    #[cfg(feature = "alloc")]
    pub fn encrypt(key: &[u8; 32], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes::new_256(key);
        ocb_encrypt(&cipher, nonce, plaintext, aad)
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
        ocb_decrypt(&cipher, nonce, ciphertext_and_tag, aad)
    }
}

// Core OCB encryption
#[cfg(feature = "alloc")]
fn ocb_encrypt(cipher: &Aes, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    // Initialize
    let l_star = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);
    let l_dollar = double(&l_star);

    // Process nonce
    let mut nonce_block = [0u8; BLOCK_SIZE];
    let nonce_len = nonce.len().min(BLOCK_SIZE - 1);
    nonce_block[BLOCK_SIZE - nonce_len - 1] = ((TAG_SIZE * 8) % 128) as u8;
    nonce_block[BLOCK_SIZE - nonce_len..].copy_from_slice(&nonce[..nonce_len]);
    nonce_block[0] = (TAG_SIZE * 8 / 128) as u8;

    let bottom = nonce_block[BLOCK_SIZE - 1] & 0x3F;
    nonce_block[BLOCK_SIZE - 1] &= 0xC0;

    let ktop = cipher.encrypt_block(&nonce_block);
    let mut stretch = [0u8; BLOCK_SIZE + 8];
    stretch[..BLOCK_SIZE].copy_from_slice(&ktop);
    for i in 0..8 {
        stretch[BLOCK_SIZE + i] = ktop[i] ^ ktop[i + 1];
    }

    let mut offset = [0u8; BLOCK_SIZE];
    let shift_bytes = (bottom / 8) as usize;
    let shift_bits = (bottom % 8) as usize;

    for i in 0..BLOCK_SIZE {
        let idx = shift_bytes + i;
        if shift_bits == 0 {
            offset[i] = stretch[idx];
        } else {
            offset[i] = (stretch[idx] << shift_bits) | (stretch[idx + 1] >> (8 - shift_bits));
        }
    }

    // Process AAD
    let mut sum = process_aad(cipher, &l_star, aad);

    // Process plaintext
    let mut ciphertext = Vec::with_capacity(plaintext.len() + TAG_SIZE);
    let full_blocks = plaintext.len() / BLOCK_SIZE;

    for i in 0..full_blocks {
        let l_i = get_l(i + 1, &l_star);
        xor_block(&mut offset, &l_i);

        let block = &plaintext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let mut xored = [0u8; BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            xored[j] = block[j] ^ offset[j];
        }

        let encrypted = cipher.encrypt_block(&xored);
        let mut c_block = [0u8; BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            c_block[j] = encrypted[j] ^ offset[j];
            sum[j] ^= block[j];
        }
        ciphertext.extend_from_slice(&c_block);
    }

    // Process final block if partial
    let remaining = plaintext.len() % BLOCK_SIZE;
    if remaining > 0 {
        xor_block(&mut offset, &l_star);
        let pad = cipher.encrypt_block(&offset);

        let final_block = &plaintext[full_blocks * BLOCK_SIZE..];
        for (i, &byte) in final_block.iter().enumerate() {
            ciphertext.push(byte ^ pad[i]);
            sum[i] ^= byte;
        }
        sum[remaining] ^= 0x80;
    }

    // Compute tag
    xor_block(&mut offset, &l_dollar);
    xor_block(&mut sum, &offset);
    let tag = cipher.encrypt_block(&sum);

    ciphertext.extend_from_slice(&tag);
    ciphertext
}

// Core OCB decryption
#[cfg(feature = "alloc")]
fn ocb_decrypt(
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

    // Initialize
    let l_star = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);
    let l_dollar = double(&l_star);

    // Process nonce (same as encryption)
    let mut nonce_block = [0u8; BLOCK_SIZE];
    let nonce_len = nonce.len().min(BLOCK_SIZE - 1);
    nonce_block[BLOCK_SIZE - nonce_len - 1] = ((TAG_SIZE * 8) % 128) as u8;
    nonce_block[BLOCK_SIZE - nonce_len..].copy_from_slice(&nonce[..nonce_len]);
    nonce_block[0] = (TAG_SIZE * 8 / 128) as u8;

    let bottom = nonce_block[BLOCK_SIZE - 1] & 0x3F;
    nonce_block[BLOCK_SIZE - 1] &= 0xC0;

    let ktop = cipher.encrypt_block(&nonce_block);
    let mut stretch = [0u8; BLOCK_SIZE + 8];
    stretch[..BLOCK_SIZE].copy_from_slice(&ktop);
    for i in 0..8 {
        stretch[BLOCK_SIZE + i] = ktop[i] ^ ktop[i + 1];
    }

    let mut offset = [0u8; BLOCK_SIZE];
    let shift_bytes = (bottom / 8) as usize;
    let shift_bits = (bottom % 8) as usize;

    for i in 0..BLOCK_SIZE {
        let idx = shift_bytes + i;
        if shift_bits == 0 {
            offset[i] = stretch[idx];
        } else {
            offset[i] = (stretch[idx] << shift_bits) | (stretch[idx + 1] >> (8 - shift_bits));
        }
    }

    // Process AAD
    let mut sum = process_aad(cipher, &l_star, aad);

    // Process ciphertext
    let mut plaintext = Vec::with_capacity(ciphertext_len);
    let full_blocks = ciphertext_len / BLOCK_SIZE;

    for i in 0..full_blocks {
        let l_i = get_l(i + 1, &l_star);
        xor_block(&mut offset, &l_i);

        let block = &ciphertext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let mut xored = [0u8; BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            xored[j] = block[j] ^ offset[j];
        }

        let decrypted = cipher.decrypt_block(&xored);
        let mut p_block = [0u8; BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            p_block[j] = decrypted[j] ^ offset[j];
            sum[j] ^= p_block[j];
        }
        plaintext.extend_from_slice(&p_block);
    }

    // Process final block if partial
    let remaining = ciphertext_len % BLOCK_SIZE;
    if remaining > 0 {
        xor_block(&mut offset, &l_star);
        let pad = cipher.encrypt_block(&offset);

        let final_block = &ciphertext[full_blocks * BLOCK_SIZE..];
        for (i, &byte) in final_block.iter().enumerate() {
            let p_byte = byte ^ pad[i];
            plaintext.push(p_byte);
            sum[i] ^= p_byte;
        }
        sum[remaining] ^= 0x80;
    }

    // Verify tag
    xor_block(&mut offset, &l_dollar);
    xor_block(&mut sum, &offset);
    let expected_tag = cipher.encrypt_block(&sum);

    if !constant_time_compare(&expected_tag, received_tag) {
        return Err(AeadError::AuthenticationFailed);
    }

    Ok(plaintext)
}

// Process AAD
fn process_aad(cipher: &Aes, l_star: &[u8; BLOCK_SIZE], aad: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut offset = [0u8; BLOCK_SIZE];
    let mut sum = [0u8; BLOCK_SIZE];

    let full_blocks = aad.len() / BLOCK_SIZE;

    for i in 0..full_blocks {
        let l_i = get_l(i + 1, l_star);
        xor_block(&mut offset, &l_i);

        let block = &aad[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let mut xored = [0u8; BLOCK_SIZE];
        for j in 0..BLOCK_SIZE {
            xored[j] = block[j] ^ offset[j];
        }

        let encrypted = cipher.encrypt_block(&xored);
        xor_block(&mut sum, &encrypted);
    }

    // Process final AAD block if partial
    let remaining = aad.len() % BLOCK_SIZE;
    if remaining > 0 {
        xor_block(&mut offset, &l_star);

        let mut final_block = [0u8; BLOCK_SIZE];
        final_block[..remaining].copy_from_slice(&aad[full_blocks * BLOCK_SIZE..]);
        final_block[remaining] = 0x80;

        xor_block(&mut final_block, &offset);
        let encrypted = cipher.encrypt_block(&final_block);
        xor_block(&mut sum, &encrypted);
    }

    sum
}

// Get L_i value for OCB
fn get_l(i: usize, l_star: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let ntz = ntz(i); // Number of trailing zeros
    let mut l = *l_star;
    for _ in 0..ntz {
        l = double(&l);
    }
    l
}

// Number of trailing zero bits
fn ntz(mut n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut count = 0;
    while n & 1 == 0 {
        count += 1;
        n >>= 1;
    }
    count
}

// Double in GF(2^128)
fn double(block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    let mut carry = 0u8;

    // Left shift (little-endian for OCB)
    for i in 0..BLOCK_SIZE {
        result[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }

    // Conditional XOR with 0x87
    if carry != 0 {
        result[0] ^= 0x87;
    }

    result
}

// XOR two blocks
fn xor_block(a: &mut [u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        a[i] ^= b[i];
    }
}

// Constant-time comparison
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
    fn test_aes128_ocb_roundtrip() {
        let key = [0x00; 16];
        let nonce = [0x00; 12];
        let plaintext = b"Hello, OCB mode!";
        let aad = b"associated data";

        let ciphertext_and_tag = Aes128Ocb::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes128Ocb::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_ocb_roundtrip() {
        let key = [0x42; 32];
        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let plaintext = b"OCB mode test with AES-256";
        let aad = b"some AAD";

        let ciphertext_and_tag = Aes256Ocb::encrypt(&key, &nonce, plaintext, aad);
        let decrypted = Aes256Ocb::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_ocb_authentication_failure() {
        let key = [0x00; 16];
        let nonce = [0x00; 12];
        let plaintext = b"Test message";
        let aad = b"aad";

        let mut ciphertext_and_tag = Aes128Ocb::encrypt(&key, &nonce, plaintext, aad);

        // Tamper with ciphertext
        ciphertext_and_tag[0] ^= 1;

        let result = Aes128Ocb::decrypt(&key, &nonce, &ciphertext_and_tag, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_ocb_empty_message() {
        let key = [0x00; 16];
        let nonce = [0x00; 12];
        let plaintext = b"";
        let aad = b"";

        let ciphertext_and_tag = Aes128Ocb::encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ciphertext_and_tag.len(), TAG_SIZE); // Only tag

        let decrypted = Aes128Ocb::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_ocb_various_lengths() {
        let key = [0x42; 16];
        let nonce = [0x00; 12];
        let aad = b"test";

        for len in [0, 1, 15, 16, 17, 31, 32, 48, 100] {
            let plaintext = vec![0x55; len];
            let ciphertext_and_tag = Aes128Ocb::encrypt(&key, &nonce, &plaintext, aad);
            let decrypted = Aes128Ocb::decrypt(&key, &nonce, &ciphertext_and_tag, aad).unwrap();
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }

    #[test]
    fn test_ntz() {
        assert_eq!(ntz(1), 0); // 1 = 0b1
        assert_eq!(ntz(2), 1); // 2 = 0b10
        assert_eq!(ntz(4), 2); // 4 = 0b100
        assert_eq!(ntz(8), 3); // 8 = 0b1000
        assert_eq!(ntz(6), 1); // 6 = 0b110
        assert_eq!(ntz(12), 2); // 12 = 0b1100
    }
}
