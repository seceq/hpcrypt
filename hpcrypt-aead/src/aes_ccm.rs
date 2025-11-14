//! AES-CCM (Counter with CBC-MAC)
//!
//! RFC 3610 compliant implementation of AES-CCM authenticated encryption.
//! CCM combines CTR mode encryption with CBC-MAC for authentication.

extern crate alloc;
use hpcrypt_cipher::{Aes, BLOCK_SIZE};
use alloc::vec;
use alloc::vec::Vec;

/// CCM error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcmError {
    /// Invalid nonce length
    InvalidNonceLength,
    /// Invalid tag length
    InvalidTagLength,
    /// Message too long
    MessageTooLong,
    /// AAD too long
    AadTooLong,
    /// Authentication failed
    AuthenticationFailed,
}

/// AES-128-CCM implementation
#[derive(Debug)]
pub struct Aes128Ccm;

impl Aes128Ccm {
    /// Encrypt and authenticate data with AES-128-CCM
    ///
    /// # Parameters
    /// - `key`: 16-byte encryption key
    /// - `nonce`: Nonce (7-13 bytes). Longer nonces = better security, shorter = longer messages
    /// - `plaintext`: Data to encrypt
    /// - `aad`: Additional authenticated data (not encrypted)
    /// - `tag_len`: Authentication tag length (4, 6, 8, 10, 12, 14, or 16 bytes)
    ///
    /// # Returns
    /// Ciphertext || Tag
    pub fn encrypt(
        key: &[u8; 16],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, CcmError> {
        // Validate parameters
        if nonce.len() < 7 || nonce.len() > 13 {
            return Err(CcmError::InvalidNonceLength);
        }
        if ![4, 6, 8, 10, 12, 14, 16].contains(&tag_len) {
            return Err(CcmError::InvalidTagLength);
        }

        let l = 15 - nonce.len(); // Length field size
        let max_msg_len = if l < 8 {
            (1u64 << (8 * l)) - 1
        } else {
            u64::MAX
        };
        if plaintext.len() as u64 > max_msg_len {
            return Err(CcmError::MessageTooLong);
        }
        // AAD length is limited by the encoding format (not by u64::MAX)
        // Max AAD length is 2^64 - 1, but since usize <= u64, this is always satisfied

        let cipher = Aes::new_128(key);

        // Step 1: Compute CBC-MAC (authentication tag T)
        let tag = compute_cbc_mac(&cipher, nonce, plaintext, aad, tag_len, l)?;

        // Step 2: Encrypt the message using CTR mode
        let ciphertext = ctr_encrypt(&cipher, nonce, plaintext, l);

        // Step 3: Encrypt the tag with S_0
        let s0 = compute_s0(&cipher, nonce, l);
        let mut encrypted_tag = vec![0u8; tag_len];
        for i in 0..tag_len {
            encrypted_tag[i] = tag[i] ^ s0[i];
        }

        // Return ciphertext || encrypted_tag
        let mut result = ciphertext;
        result.extend_from_slice(&encrypted_tag);
        Ok(result)
    }

    /// Decrypt and verify data with AES-128-CCM
    ///
    /// # Parameters
    /// - `key`: 16-byte encryption key
    /// - `nonce`: Nonce (7-13 bytes, must match encryption)
    /// - `ciphertext_and_tag`: Ciphertext followed by authentication tag
    /// - `aad`: Additional authenticated data (must match encryption)
    /// - `tag_len`: Authentication tag length (must match encryption)
    ///
    /// # Returns
    /// Plaintext if authentication succeeds
    pub fn decrypt(
        key: &[u8; 16],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, CcmError> {
        // Validate parameters
        if nonce.len() < 7 || nonce.len() > 13 {
            return Err(CcmError::InvalidNonceLength);
        }
        if ![4, 6, 8, 10, 12, 14, 16].contains(&tag_len) {
            return Err(CcmError::InvalidTagLength);
        }
        if ciphertext_and_tag.len() < tag_len {
            return Err(CcmError::AuthenticationFailed);
        }

        let cipher = Aes::new_128(key);
        let l = 15 - nonce.len();

        // Split ciphertext and tag
        let ciphertext = &ciphertext_and_tag[..ciphertext_and_tag.len() - tag_len];
        let encrypted_tag = &ciphertext_and_tag[ciphertext_and_tag.len() - tag_len..];

        // Step 1: Decrypt the tag with S_0
        let s0 = compute_s0(&cipher, nonce, l);
        let mut tag = vec![0u8; tag_len];
        for i in 0..tag_len {
            tag[i] = encrypted_tag[i] ^ s0[i];
        }

        // Step 2: Decrypt the ciphertext using CTR mode
        let plaintext = ctr_encrypt(&cipher, nonce, ciphertext, l); // CTR is symmetric

        // Step 3: Recompute CBC-MAC and verify
        let expected_tag = compute_cbc_mac(&cipher, nonce, &plaintext, aad, tag_len, l)?;

        // Constant-time comparison
        let mut diff = 0u8;
        for i in 0..tag_len {
            diff |= tag[i] ^ expected_tag[i];
        }

        if diff != 0 {
            return Err(CcmError::AuthenticationFailed);
        }

        Ok(plaintext)
    }
}

/// AES-256-CCM implementation
#[derive(Debug)]
pub struct Aes256Ccm;

impl Aes256Ccm {
    /// Encrypt and authenticate data with AES-256-CCM
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, CcmError> {
        if nonce.len() < 7 || nonce.len() > 13 {
            return Err(CcmError::InvalidNonceLength);
        }
        if ![4, 6, 8, 10, 12, 14, 16].contains(&tag_len) {
            return Err(CcmError::InvalidTagLength);
        }

        let l = 15 - nonce.len();
        let max_msg_len = if l < 8 {
            (1u64 << (8 * l)) - 1
        } else {
            u64::MAX
        };
        if plaintext.len() as u64 > max_msg_len {
            return Err(CcmError::MessageTooLong);
        }
        // AAD length is limited by the encoding format (not by u64::MAX)
        // Max AAD length is 2^64 - 1, but since usize <= u64, this is always satisfied

        let cipher = Aes::new_256(key);

        let tag = compute_cbc_mac(&cipher, nonce, plaintext, aad, tag_len, l)?;
        let ciphertext = ctr_encrypt(&cipher, nonce, plaintext, l);
        let s0 = compute_s0(&cipher, nonce, l);

        let mut encrypted_tag = vec![0u8; tag_len];
        for i in 0..tag_len {
            encrypted_tag[i] = tag[i] ^ s0[i];
        }

        let mut result = ciphertext;
        result.extend_from_slice(&encrypted_tag);
        Ok(result)
    }

    /// Decrypt and verify data with AES-256-CCM
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, CcmError> {
        if nonce.len() < 7 || nonce.len() > 13 {
            return Err(CcmError::InvalidNonceLength);
        }
        if ![4, 6, 8, 10, 12, 14, 16].contains(&tag_len) {
            return Err(CcmError::InvalidTagLength);
        }
        if ciphertext_and_tag.len() < tag_len {
            return Err(CcmError::AuthenticationFailed);
        }

        let cipher = Aes::new_256(key);
        let l = 15 - nonce.len();

        let ciphertext = &ciphertext_and_tag[..ciphertext_and_tag.len() - tag_len];
        let encrypted_tag = &ciphertext_and_tag[ciphertext_and_tag.len() - tag_len..];

        let s0 = compute_s0(&cipher, nonce, l);
        let mut tag = vec![0u8; tag_len];
        for i in 0..tag_len {
            tag[i] = encrypted_tag[i] ^ s0[i];
        }

        let plaintext = ctr_encrypt(&cipher, nonce, ciphertext, l);
        let expected_tag = compute_cbc_mac(&cipher, nonce, &plaintext, aad, tag_len, l)?;

        let mut diff = 0u8;
        for i in 0..tag_len {
            diff |= tag[i] ^ expected_tag[i];
        }

        if diff != 0 {
            return Err(CcmError::AuthenticationFailed);
        }

        Ok(plaintext)
    }
}

/// Compute CBC-MAC authentication tag
fn compute_cbc_mac(
    cipher: &Aes,
    nonce: &[u8],
    message: &[u8],
    aad: &[u8],
    tag_len: usize,
    l: usize,
) -> Result<Vec<u8>, CcmError> {
    // Format B_0 block
    let mut b0 = [0u8; BLOCK_SIZE];

    // Flags byte: Reserved(1) | Adata(1) | M'(3) | L'(3)
    let has_aad = if aad.is_empty() { 0 } else { 1 };
    let m_prime = ((tag_len - 2) / 2) as u8; // (M-2)/2
    let l_prime = (l - 1) as u8; // L-1
    b0[0] = (has_aad << 6) | (m_prime << 3) | l_prime;

    // Nonce
    b0[1..1 + nonce.len()].copy_from_slice(nonce);

    // Message length
    let msg_len = message.len();
    for i in 0..l {
        b0[15 - i] = ((msg_len >> (8 * i)) & 0xFF) as u8;
    }

    // Process B_0
    let mut mac_state = cipher.encrypt_block(&b0);

    // Process AAD if present
    if !aad.is_empty() {
        let mut aad_block = [0u8; BLOCK_SIZE];

        // Encode AAD length
        let mut pos = if aad.len() < 0xFF00 {
            // Short form: 2 bytes
            aad_block[0] = (aad.len() >> 8) as u8;
            aad_block[1] = (aad.len() & 0xFF) as u8;
            2
        } else {
            // Long form: 6 bytes (0xFFFE followed by 4-byte length)
            aad_block[0] = 0xFF;
            aad_block[1] = 0xFE;
            aad_block[2] = (aad.len() >> 24) as u8;
            aad_block[3] = (aad.len() >> 16) as u8;
            aad_block[4] = (aad.len() >> 8) as u8;
            aad_block[5] = (aad.len() & 0xFF) as u8;
            6
        };

        // Process AAD data
        let mut aad_offset = 0;
        while aad_offset < aad.len() {
            let to_copy = core::cmp::min(BLOCK_SIZE - pos, aad.len() - aad_offset);
            aad_block[pos..pos + to_copy].copy_from_slice(&aad[aad_offset..aad_offset + to_copy]);
            pos += to_copy;
            aad_offset += to_copy;

            if pos == BLOCK_SIZE {
                for i in 0..BLOCK_SIZE {
                    mac_state[i] ^= aad_block[i];
                }
                mac_state = cipher.encrypt_block(&mac_state);
                aad_block = [0u8; BLOCK_SIZE];
                pos = 0;
            }
        }

        // Process partial AAD block
        if pos > 0 {
            for i in 0..BLOCK_SIZE {
                mac_state[i] ^= aad_block[i];
            }
            mac_state = cipher.encrypt_block(&mac_state);
        }
    }

    // Process message
    let mut msg_block = [0u8; BLOCK_SIZE];
    let mut msg_offset = 0;

    while msg_offset < message.len() {
        let to_copy = core::cmp::min(BLOCK_SIZE, message.len() - msg_offset);
        msg_block[..to_copy].copy_from_slice(&message[msg_offset..msg_offset + to_copy]);

        // Pad with zeros if partial block
        if to_copy < BLOCK_SIZE {
            msg_block[to_copy..].fill(0);
        }

        for i in 0..BLOCK_SIZE {
            mac_state[i] ^= msg_block[i];
        }
        mac_state = cipher.encrypt_block(&mac_state);

        msg_offset += to_copy;
        msg_block = [0u8; BLOCK_SIZE];
    }

    // Return first tag_len bytes
    Ok(mac_state[..tag_len].to_vec())
}

/// CTR mode encryption/decryption (symmetric operation)
fn ctr_encrypt(cipher: &Aes, nonce: &[u8], data: &[u8], l: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut counter = 1u64; // Counter starts at 1 for message encryption
    let mut offset = 0;

    while offset < data.len() {
        // Format counter block A_i
        let ctr_block = format_counter_block(nonce, counter, l);
        let keystream = cipher.encrypt_block(&ctr_block);

        // XOR with data
        let to_process = core::cmp::min(BLOCK_SIZE, data.len() - offset);
        for i in 0..to_process {
            result.push(data[offset + i] ^ keystream[i]);
        }

        offset += to_process;
        counter += 1;
    }

    result
}

/// Compute S_0 (keystream block for tag encryption)
fn compute_s0(cipher: &Aes, nonce: &[u8], l: usize) -> [u8; BLOCK_SIZE] {
    let ctr_block = format_counter_block(nonce, 0, l);
    cipher.encrypt_block(&ctr_block)
}

/// Format a counter block for CTR mode
fn format_counter_block(nonce: &[u8], counter: u64, l: usize) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];

    // Flags byte: only L' field
    block[0] = (l - 1) as u8;

    // Nonce
    block[1..1 + nonce.len()].copy_from_slice(nonce);

    // Counter value
    for i in 0..l {
        block[15 - i] = ((counter >> (8 * i)) & 0xFF) as u8;
    }

    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_aes128_ccm_basic() {
        let key = hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = hex!("00000003020100A0A1A2A3A4A5");
        let plaintext = hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        let aad = hex!("0001020304050607");
        let tag_len = 8;

        let ciphertext_and_tag =
            Aes128Ccm::encrypt(&key, &nonce, &plaintext, &aad, tag_len).unwrap();

        // Verify we can decrypt
        let decrypted =
            Aes128Ccm::decrypt(&key, &nonce, &ciphertext_and_tag, &aad, tag_len).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_ccm_empty_plaintext() {
        let key = hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = hex!("00000003020100A0A1A2A3A4A5");
        let plaintext = b"";
        let aad = hex!("0001020304050607");
        let tag_len = 8;

        let ciphertext_and_tag =
            Aes128Ccm::encrypt(&key, &nonce, plaintext, &aad, tag_len).unwrap();
        let decrypted =
            Aes128Ccm::decrypt(&key, &nonce, &ciphertext_and_tag, &aad, tag_len).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_ccm_no_aad() {
        let key = hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = hex!("00000003020100A0A1A2A3A4A5");
        let plaintext = hex!("08090A0B0C0D0E0F");
        let aad = b"";
        let tag_len = 8;

        let ciphertext_and_tag =
            Aes128Ccm::encrypt(&key, &nonce, &plaintext, aad, tag_len).unwrap();
        let decrypted =
            Aes128Ccm::decrypt(&key, &nonce, &ciphertext_and_tag, aad, tag_len).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_ccm_wrong_tag() {
        let key = hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = hex!("00000003020100A0A1A2A3A4A5");
        let plaintext = hex!("08090A0B0C0D0E0F");
        let aad = hex!("0001020304050607");
        let tag_len = 8;

        let mut ciphertext_and_tag =
            Aes128Ccm::encrypt(&key, &nonce, &plaintext, &aad, tag_len).unwrap();

        // Corrupt the tag
        let len = ciphertext_and_tag.len();
        ciphertext_and_tag[len - 1] ^= 1;

        let result = Aes128Ccm::decrypt(&key, &nonce, &ciphertext_and_tag, &aad, tag_len);
        assert_eq!(result, Err(CcmError::AuthenticationFailed));
    }

    #[test]
    fn test_aes128_ccm_wrong_aad() {
        let key = hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = hex!("00000003020100A0A1A2A3A4A5");
        let plaintext = hex!("08090A0B0C0D0E0F");
        let aad = hex!("0001020304050607");
        let wrong_aad = hex!("0001020304050608");
        let tag_len = 8;

        let ciphertext_and_tag =
            Aes128Ccm::encrypt(&key, &nonce, &plaintext, &aad, tag_len).unwrap();
        let result = Aes128Ccm::decrypt(&key, &nonce, &ciphertext_and_tag, &wrong_aad, tag_len);
        assert_eq!(result, Err(CcmError::AuthenticationFailed));
    }

    #[test]
    fn test_aes256_ccm_basic() {
        let key = hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = hex!("00000003020100A0A1A2A3A4A5");
        let plaintext = hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        let aad = hex!("0001020304050607");
        let tag_len = 16;

        let ciphertext_and_tag =
            Aes256Ccm::encrypt(&key, &nonce, &plaintext, &aad, tag_len).unwrap();
        let decrypted =
            Aes256Ccm::decrypt(&key, &nonce, &ciphertext_and_tag, &aad, tag_len).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_ccm_various_tag_lengths() {
        let key = hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = hex!("00000003020100A0A1A2A3A4A5");
        let plaintext = hex!("08090A0B0C0D0E0F");
        let aad = hex!("0001020304050607");

        for &tag_len in &[4, 6, 8, 10, 12, 14, 16] {
            let ciphertext_and_tag =
                Aes128Ccm::encrypt(&key, &nonce, &plaintext, &aad, tag_len).unwrap();
            let decrypted =
                Aes128Ccm::decrypt(&key, &nonce, &ciphertext_and_tag, &aad, tag_len).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }
}
