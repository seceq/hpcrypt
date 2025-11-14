//! AES Block Cipher Modes of Operation
//!
//! Implements standard modes: CBC, CTR, CFB, OFB, XTS
//! Based on NIST SP 800-38A and NIST SP 800-38E
//!
//! NOTE: AES-ECB has been removed due to NIST deprecation (SP 800-131A Rev3)
//! and fundamental security issues (pattern leakage, not semantically secure).
//! Use AES-GCM for authenticated encryption or AES-CTR for stream encryption.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use hpcrypt_aead::aes::{Aes, AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE};
use hpcrypt_core::error::CipherError;

/// IV/Nonce size for AES modes (128 bits)
pub const IV_SIZE: usize = BLOCK_SIZE;

// ============================================================================
// AES-CBC (Cipher Block Chaining Mode)
// Most common mode - each block depends on previous block
// ============================================================================

/// AES-128-CBC cipher
#[derive(Debug)]
pub struct AesCbc128 {
    cipher: Aes,
}

impl AesCbc128 {
    /// Create a new AES-128-CBC cipher
    ///
    /// # Arguments
    ///
    /// * `key` - 128-bit (16-byte) encryption key
    ///
    /// # Security
    ///
    /// - Use a cryptographically secure random key
    /// - Never derive keys from passwords directly (use PBKDF2/Argon2)
    /// - Store keys securely (use OS key storage when available)
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_cipher::AesCbc128;
    /// use hpcrypt_rng::OsRng;
    ///
    /// let key = OsRng::generate_bytes::<16>();
    /// let cipher = AesCbc128::new(&key);
    /// ```
    pub fn new(key: &[u8; AES128_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_128(key),
        }
    }

    /// Encrypt plaintext using CBC mode
    ///
    /// # Critical Security Requirements
    ///
    /// 1. IV MUST be unpredictable - use cryptographically secure random generator
    /// 2. NEVER reuse IV with same key - generates new random IV for each encryption
    /// 3. NO authentication - ciphertext can be modified without detection
    ///
    /// # Arguments
    ///
    /// * `iv` - 128-bit (16-byte) initialization vector
    ///   - Must be unpredictable (use `OsRng::generate_bytes()`)
    ///   - Must be unique for each encryption with the same key
    ///   - Can be transmitted in plaintext alongside ciphertext
    /// * `plaintext` - Data to encrypt
    ///   - **MUST be multiple of 16 bytes** (block-aligned)
    ///   - Apply PKCS#7 padding if needed before calling this function
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)` - Encrypted ciphertext (same length as plaintext)
    /// - `Err(CipherError::InvalidPlaintextLength)` - If plaintext is not block-aligned
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_cipher::AesCbc128;
    /// use hpcrypt_rng::OsRng;
    ///
    /// let key = OsRng::generate_bytes::<16>();
    /// let cipher = AesCbc128::new(&key);
    ///
    /// // Plaintext must be block-aligned (16 bytes)
    /// let plaintext = b"Exactly 16 bytes";
    ///
    /// // Generate random IV for each encryption
    /// let iv = OsRng::generate_bytes::<16>();
    /// let ciphertext = cipher.encrypt(&iv, plaintext)?;
    ///
    /// // Store/transmit: [IV || ciphertext]
    /// let mut encrypted_message = iv.to_vec();
    /// encrypted_message.extend_from_slice(&ciphertext);
    /// # Ok::<(), hpcrypt_core::error::CipherError>(())
    /// ```
    ///
    /// # Security Warning
    ///
    /// CBC mode is vulnerable to:
    /// - **Padding oracle attacks** if decryption errors leak timing information
    /// - **Bit-flipping attacks** without authentication
    ///
    /// **Recommendation:** Use `AES-GCM` from `hpcrypt-aead` instead for authenticated encryption.
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if plaintext.len() % BLOCK_SIZE != 0 {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: plaintext.len(),
            });
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut prev_block = *iv;

        for chunk in plaintext.chunks_exact(BLOCK_SIZE) {
            // XOR plaintext with previous ciphertext block (or IV)
            let mut block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                block[i] = chunk[i] ^ prev_block[i];
            }

            // Encrypt
            let encrypted = self.cipher.encrypt_block(&block);
            ciphertext.extend_from_slice(&encrypted);
            prev_block = encrypted;
        }

        Ok(ciphertext)
    }

    /// Decrypt ciphertext using CBC mode
    ///
    /// # Arguments
    ///
    /// * `iv` - 128-bit (16-byte) initialization vector used during encryption
    ///   - Must be the **same IV** used for encryption
    ///   - IV is not secret, can be stored/transmitted in plaintext
    /// * `ciphertext` - Encrypted data to decrypt
    ///   - **MUST be multiple of 16 bytes** (block-aligned)
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)` - Decrypted plaintext (same length as ciphertext)
    ///   - **May contain padding** - remove PKCS#7 padding if you added it during encryption
    /// - `Err(CipherError::InvalidPlaintextLength)` - If ciphertext is not block-aligned
    ///
    /// # Security Warning
    ///
    /// - **DO NOT** expose padding validation errors to attackers (timing or error messages)
    /// - Padding oracle attacks can recover plaintext if decryption errors leak information
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: ciphertext.len(),
            });
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut prev_block = *iv;

        for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
            let block: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();

            // Decrypt
            let decrypted = self.cipher.decrypt_block(&block);

            // XOR with previous ciphertext block (or IV)
            let mut plain_block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                plain_block[i] = decrypted[i] ^ prev_block[i];
            }

            plaintext.extend_from_slice(&plain_block);
            prev_block = block;
        }

        Ok(plaintext)
    }
}

/// AES-192-CBC cipher
#[derive(Debug)]
pub struct AesCbc192 {
    cipher: Aes,
}

impl AesCbc192 {
    /// Create a new AES-192-CBC cipher
    pub fn new(key: &[u8; AES192_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_192(key),
        }
    }

    /// Encrypt with CBC mode
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if plaintext.len() % BLOCK_SIZE != 0 {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: plaintext.len(),
            });
        }
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut prev_block = *iv;
        for chunk in plaintext.chunks_exact(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                block[i] = chunk[i] ^ prev_block[i];
            }
            let encrypted = self.cipher.encrypt_block(&block);
            ciphertext.extend_from_slice(&encrypted);
            prev_block = encrypted;
        }
        Ok(ciphertext)
    }

    /// Decrypt ciphertext using CBC mode
    ///
    /// # Arguments
    ///
    /// * `iv` - 128-bit (16-byte) initialization vector used during encryption
    ///   - Must be the **same IV** used for encryption
    ///   - IV is not secret, can be stored/transmitted in plaintext
    /// * `ciphertext` - Encrypted data to decrypt
    ///   - **MUST be multiple of 16 bytes** (block-aligned)
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)` - Decrypted plaintext (same length as ciphertext)
    ///   - **May contain padding** - remove PKCS#7 padding if you added it during encryption
    /// - `Err(CipherError::InvalidPlaintextLength)` - If ciphertext is not block-aligned
    ///
    /// # Security Warning
    ///
    /// - **DO NOT** expose padding validation errors to attackers (timing or error messages)
    /// - Padding oracle attacks can recover plaintext if decryption errors leak information
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: ciphertext.len(),
            });
        }
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut prev_block = *iv;
        for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
            let block: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
            let decrypted = self.cipher.decrypt_block(&block);
            let mut plain_block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                plain_block[i] = decrypted[i] ^ prev_block[i];
            }
            plaintext.extend_from_slice(&plain_block);
            prev_block = block;
        }
        Ok(plaintext)
    }
}

/// AES-256-CBC cipher
#[derive(Debug)]
pub struct AesCbc256 {
    cipher: Aes,
}

impl AesCbc256 {
    /// Create a new AES-256-CBC cipher
    pub fn new(key: &[u8; AES256_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_256(key),
        }
    }

    /// Encrypt with CBC mode
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if plaintext.len() % BLOCK_SIZE != 0 {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: plaintext.len(),
            });
        }
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut prev_block = *iv;
        for chunk in plaintext.chunks_exact(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                block[i] = chunk[i] ^ prev_block[i];
            }
            let encrypted = self.cipher.encrypt_block(&block);
            ciphertext.extend_from_slice(&encrypted);
            prev_block = encrypted;
        }
        Ok(ciphertext)
    }

    /// Decrypt ciphertext using CBC mode
    ///
    /// # Arguments
    ///
    /// * `iv` - 128-bit (16-byte) initialization vector used during encryption
    ///   - Must be the **same IV** used for encryption
    ///   - IV is not secret, can be stored/transmitted in plaintext
    /// * `ciphertext` - Encrypted data to decrypt
    ///   - **MUST be multiple of 16 bytes** (block-aligned)
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)` - Decrypted plaintext (same length as ciphertext)
    ///   - **May contain padding** - remove PKCS#7 padding if you added it during encryption
    /// - `Err(CipherError::InvalidPlaintextLength)` - If ciphertext is not block-aligned
    ///
    /// # Security Warning
    ///
    /// - **DO NOT** expose padding validation errors to attackers (timing or error messages)
    /// - Padding oracle attacks can recover plaintext if decryption errors leak information
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: ciphertext.len(),
            });
        }
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut prev_block = *iv;
        for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
            let block: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
            let decrypted = self.cipher.decrypt_block(&block);
            let mut plain_block = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                plain_block[i] = decrypted[i] ^ prev_block[i];
            }
            plaintext.extend_from_slice(&plain_block);
            prev_block = block;
        }
        Ok(plaintext)
    }
}

// ============================================================================
// AES-CTR (Counter Mode)
// Turns block cipher into stream cipher - can process any length
// ============================================================================

/// AES-128-CTR cipher
#[derive(Debug)]
pub struct AesCtr128 {
    cipher: Aes,
}

impl AesCtr128 {
    /// Create a new AES-128-CTR cipher
    pub fn new(key: &[u8; AES128_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_128(key),
        }
    }

    /// Encrypt/Decrypt with CTR mode (same operation for both)
    #[cfg(feature = "alloc")]
    pub fn process(&self, nonce: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut counter = *nonce;

        for chunk in data.chunks(BLOCK_SIZE) {
            // Encrypt counter
            let keystream = self.cipher.encrypt_block(&counter);

            // XOR with data
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[i]);
            }

            // Increment counter (big-endian)
            increment_counter(&mut counter);
        }

        output
    }
}

/// AES-192-CTR cipher
#[derive(Debug)]
pub struct AesCtr192 {
    cipher: Aes,
}

impl AesCtr192 {
    /// Create a new AES-192-CTR cipher
    pub fn new(key: &[u8; AES192_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_192(key),
        }
    }

    /// Encrypt/Decrypt with CTR mode
    #[cfg(feature = "alloc")]
    pub fn process(&self, nonce: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut counter = *nonce;
        for chunk in data.chunks(BLOCK_SIZE) {
            let keystream = self.cipher.encrypt_block(&counter);
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[i]);
            }
            increment_counter(&mut counter);
        }
        output
    }
}

/// AES-256-CTR cipher
#[derive(Debug)]
pub struct AesCtr256 {
    cipher: Aes,
}

impl AesCtr256 {
    /// Create a new AES-256-CTR cipher
    pub fn new(key: &[u8; AES256_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_256(key),
        }
    }

    /// Encrypt/Decrypt with CTR mode
    #[cfg(feature = "alloc")]
    pub fn process(&self, nonce: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut counter = *nonce;
        for chunk in data.chunks(BLOCK_SIZE) {
            let keystream = self.cipher.encrypt_block(&counter);
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[i]);
            }
            increment_counter(&mut counter);
        }
        output
    }
}

/// Increment counter block (treat as 128-bit big-endian integer)
fn increment_counter(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

// ============================================================================
// AES-CFB (Cipher Feedback Mode)
// Stream cipher mode - encrypts feedback register, then XORs with plaintext
// ============================================================================

/// AES-128-CFB cipher (CFB-128: full block feedback)
#[derive(Debug)]
pub struct AesCfb128 {
    cipher: Aes,
}

impl AesCfb128 {
    /// Create a new AES-128-CFB cipher
    pub fn new(key: &[u8; AES128_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_128(key),
        }
    }

    /// Encrypt with CFB mode
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut feedback = *iv;

        for chunk in plaintext.chunks(BLOCK_SIZE) {
            // Encrypt the feedback register
            let keystream = self.cipher.encrypt_block(&feedback);

            // XOR with plaintext to get ciphertext
            let mut output_block = [0u8; BLOCK_SIZE];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ keystream[i];
            }

            ciphertext.extend_from_slice(&output_block[..chunk.len()]);

            // Update feedback register
            // For full blocks, use the ciphertext
            if chunk.len() == BLOCK_SIZE {
                feedback = output_block;
            } else {
                // For partial blocks, shift and append
                feedback.copy_within(chunk.len().., 0);
                feedback[BLOCK_SIZE - chunk.len()..].copy_from_slice(&output_block[..chunk.len()]);
            }
        }

        ciphertext
    }

    /// Decrypt with CFB mode
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut feedback = *iv;

        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            // Encrypt the feedback register
            let keystream = self.cipher.encrypt_block(&feedback);

            // XOR with ciphertext to get plaintext
            let mut output_block = [0u8; BLOCK_SIZE];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ keystream[i];
            }

            plaintext.extend_from_slice(&output_block[..chunk.len()]);

            // Update feedback register with ciphertext
            if chunk.len() == BLOCK_SIZE {
                feedback.copy_from_slice(chunk);
            } else {
                // For partial blocks, shift and append
                feedback.copy_within(chunk.len().., 0);
                feedback[BLOCK_SIZE - chunk.len()..].copy_from_slice(chunk);
            }
        }

        plaintext
    }
}

/// AES-192-CFB cipher
#[derive(Debug)]
pub struct AesCfb192 {
    cipher: Aes,
}

impl AesCfb192 {
    /// Create a new AES-192-CFB cipher
    pub fn new(key: &[u8; AES192_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_192(key),
        }
    }

    /// Encrypt with CFB mode
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut feedback = *iv;
        for chunk in plaintext.chunks(BLOCK_SIZE) {
            let keystream = self.cipher.encrypt_block(&feedback);
            let mut output_block = [0u8; BLOCK_SIZE];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ keystream[i];
            }
            ciphertext.extend_from_slice(&output_block[..chunk.len()]);
            if chunk.len() == BLOCK_SIZE {
                feedback = output_block;
            } else {
                feedback.copy_within(chunk.len().., 0);
                feedback[BLOCK_SIZE - chunk.len()..].copy_from_slice(&output_block[..chunk.len()]);
            }
        }
        ciphertext
    }

    /// Decrypt with CFB mode
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut feedback = *iv;
        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let keystream = self.cipher.encrypt_block(&feedback);
            let mut output_block = [0u8; BLOCK_SIZE];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ keystream[i];
            }
            plaintext.extend_from_slice(&output_block[..chunk.len()]);
            if chunk.len() == BLOCK_SIZE {
                feedback.copy_from_slice(chunk);
            } else {
                feedback.copy_within(chunk.len().., 0);
                feedback[BLOCK_SIZE - chunk.len()..].copy_from_slice(chunk);
            }
        }
        plaintext
    }
}

/// AES-256-CFB cipher
#[derive(Debug)]
pub struct AesCfb256 {
    cipher: Aes,
}

impl AesCfb256 {
    /// Create a new AES-256-CFB cipher
    pub fn new(key: &[u8; AES256_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_256(key),
        }
    }

    /// Encrypt with CFB mode
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut feedback = *iv;
        for chunk in plaintext.chunks(BLOCK_SIZE) {
            let keystream = self.cipher.encrypt_block(&feedback);
            let mut output_block = [0u8; BLOCK_SIZE];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ keystream[i];
            }
            ciphertext.extend_from_slice(&output_block[..chunk.len()]);
            if chunk.len() == BLOCK_SIZE {
                feedback = output_block;
            } else {
                feedback.copy_within(chunk.len().., 0);
                feedback[BLOCK_SIZE - chunk.len()..].copy_from_slice(&output_block[..chunk.len()]);
            }
        }
        ciphertext
    }

    /// Decrypt with CFB mode
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut feedback = *iv;
        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let keystream = self.cipher.encrypt_block(&feedback);
            let mut output_block = [0u8; BLOCK_SIZE];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ keystream[i];
            }
            plaintext.extend_from_slice(&output_block[..chunk.len()]);
            if chunk.len() == BLOCK_SIZE {
                feedback.copy_from_slice(chunk);
            } else {
                feedback.copy_within(chunk.len().., 0);
                feedback[BLOCK_SIZE - chunk.len()..].copy_from_slice(chunk);
            }
        }
        plaintext
    }
}

// ============================================================================
// AES-OFB (Output Feedback Mode)
// Stream cipher mode - encrypts IV repeatedly, XORs output with plaintext
// ============================================================================

/// AES-128-OFB cipher
#[derive(Debug)]
pub struct AesOfb128 {
    cipher: Aes,
}

impl AesOfb128 {
    /// Create a new AES-128-OFB cipher
    pub fn new(key: &[u8; AES128_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_128(key),
        }
    }

    /// Encrypt/Decrypt with OFB mode (same operation for both)
    #[cfg(feature = "alloc")]
    pub fn process(&self, iv: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut feedback = *iv;

        for chunk in data.chunks(BLOCK_SIZE) {
            // Encrypt the feedback register
            feedback = self.cipher.encrypt_block(&feedback);

            // XOR with data
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ feedback[i]);
            }
        }

        output
    }
}

/// AES-192-OFB cipher
#[derive(Debug)]
pub struct AesOfb192 {
    cipher: Aes,
}

impl AesOfb192 {
    /// Create a new AES-192-OFB cipher
    pub fn new(key: &[u8; AES192_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_192(key),
        }
    }

    /// Encrypt/Decrypt with OFB mode
    #[cfg(feature = "alloc")]
    pub fn process(&self, iv: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut feedback = *iv;
        for chunk in data.chunks(BLOCK_SIZE) {
            feedback = self.cipher.encrypt_block(&feedback);
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ feedback[i]);
            }
        }
        output
    }
}

/// AES-256-OFB cipher
#[derive(Debug)]
pub struct AesOfb256 {
    cipher: Aes,
}

impl AesOfb256 {
    /// Create a new AES-256-OFB cipher
    pub fn new(key: &[u8; AES256_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes::new_256(key),
        }
    }

    /// Encrypt/Decrypt with OFB mode
    #[cfg(feature = "alloc")]
    pub fn process(&self, iv: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut feedback = *iv;
        for chunk in data.chunks(BLOCK_SIZE) {
            feedback = self.cipher.encrypt_block(&feedback);
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ feedback[i]);
            }
        }
        output
    }
}

// ============================================================================
// AES-XTS (XEX-based Tweaked Codebook Mode with Ciphertext Stealing)
// For disk/storage encryption - NIST SP 800-38E
// Requires two independent keys (key1 for encryption, key2 for tweak)
// ============================================================================

/// AES-128-XTS cipher (uses 256-bit key: two 128-bit keys)
#[derive(Debug)]
pub struct AesXts128 {
    cipher1: Aes, // Data encryption key
    cipher2: Aes, // Tweak encryption key
}

impl AesXts128 {
    /// Create a new AES-128-XTS cipher
    /// Key must be 256 bits (32 bytes): first 128 bits for data, second 128 bits for tweak
    pub fn new(key: &[u8; 32]) -> Self {
        let key1: [u8; AES128_KEY_SIZE] = key[..16].try_into().unwrap();
        let key2: [u8; AES128_KEY_SIZE] = key[16..].try_into().unwrap();
        Self {
            cipher1: Aes::new_128(&key1),
            cipher2: Aes::new_128(&key2),
        }
    }

    /// Encrypt with XTS mode
    /// tweak: 128-bit value (typically sector/block number for disk encryption)
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, tweak: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if plaintext.len() < BLOCK_SIZE {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: plaintext.len(),
            });
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());

        // Encrypt tweak to get initial alpha
        let mut alpha = self.cipher2.encrypt_block(tweak);

        let full_blocks = plaintext.len() / BLOCK_SIZE;
        let has_partial = plaintext.len() % BLOCK_SIZE != 0;

        // Process full blocks
        let blocks_to_process = if has_partial {
            full_blocks - 1
        } else {
            full_blocks
        };

        for i in 0..blocks_to_process {
            let block: [u8; BLOCK_SIZE] = plaintext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                .try_into()
                .unwrap();

            // XOR plaintext with alpha
            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = block[j] ^ alpha[j];
            }

            // Encrypt
            let encrypted = self.cipher1.encrypt_block(&xored);

            // XOR with alpha again
            let mut final_block = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                final_block[j] = encrypted[j] ^ alpha[j];
            }

            ciphertext.extend_from_slice(&final_block);

            // Multiply alpha by x in GF(2^128)
            alpha = gf128_mul_x(&alpha);
        }

        // Handle ciphertext stealing if there's a partial block
        if has_partial {
            let remaining_len = plaintext.len() % BLOCK_SIZE;
            let last_full_block_idx = full_blocks - 1;

            // Encrypt the last full block (Pm-1)
            let block: [u8; BLOCK_SIZE] = plaintext
                [last_full_block_idx * BLOCK_SIZE..(last_full_block_idx + 1) * BLOCK_SIZE]
                .try_into()
                .unwrap();

            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = block[j] ^ alpha[j];
            }
            let encrypted = self.cipher1.encrypt_block(&xored);
            let mut cc = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                cc[j] = encrypted[j] ^ alpha[j];
            }

            // Ciphertext stealing: construct PP from partial plaintext + tail of CC
            let partial_start = (full_blocks) * BLOCK_SIZE;
            let partial_plaintext = &plaintext[partial_start..];

            let mut pp = [0u8; BLOCK_SIZE];
            // Copy partial plaintext to beginning of PP
            pp[..remaining_len].copy_from_slice(partial_plaintext);
            // Copy tail of CC to fill the rest
            pp[remaining_len..].copy_from_slice(&cc[remaining_len..]);

            // Multiply alpha by x for encrypting PP
            alpha = gf128_mul_x(&alpha);

            // Encrypt PP
            let mut xored2 = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored2[j] = pp[j] ^ alpha[j];
            }
            let encrypted2 = self.cipher1.encrypt_block(&xored2);
            let mut cp = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                cp[j] = encrypted2[j] ^ alpha[j];
            }

            // Output: CP (full block) || first remaining_len bytes of CC
            ciphertext.extend_from_slice(&cp);
            ciphertext.extend_from_slice(&cc[..remaining_len]);
        }

        Ok(ciphertext)
    }

    /// Decrypt with XTS mode
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, tweak: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() < BLOCK_SIZE {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: ciphertext.len(),
            });
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());

        // Encrypt tweak to get initial alpha
        let mut alpha = self.cipher2.encrypt_block(tweak);

        let full_blocks = ciphertext.len() / BLOCK_SIZE;
        let has_partial = ciphertext.len() % BLOCK_SIZE != 0;

        // Process full blocks
        let blocks_to_process = if has_partial {
            full_blocks - 1
        } else {
            full_blocks
        };

        for i in 0..blocks_to_process {
            let block: [u8; BLOCK_SIZE] = ciphertext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                .try_into()
                .unwrap();

            // XOR ciphertext with alpha
            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = block[j] ^ alpha[j];
            }

            // Decrypt
            let decrypted = self.cipher1.decrypt_block(&xored);

            // XOR with alpha again
            let mut final_block = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                final_block[j] = decrypted[j] ^ alpha[j];
            }

            plaintext.extend_from_slice(&final_block);

            // Multiply alpha by x in GF(2^128)
            alpha = gf128_mul_x(&alpha);
        }

        // Handle ciphertext stealing if there's a partial block
        if has_partial {
            let remaining_len = ciphertext.len() % BLOCK_SIZE;
            let cp_idx = (full_blocks - 1) * BLOCK_SIZE;

            // Get CP (the last full block of ciphertext)
            let cp: [u8; BLOCK_SIZE] = ciphertext[cp_idx..cp_idx + BLOCK_SIZE].try_into().unwrap();

            // Multiply alpha by x for decrypting CP
            alpha = gf128_mul_x(&alpha);

            // Decrypt CP
            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = cp[j] ^ alpha[j];
            }
            let decrypted_cp = self.cipher1.decrypt_block(&xored);
            let mut pp = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                pp[j] = decrypted_cp[j] ^ alpha[j];
            }

            // Get the partial ciphertext
            let cc_partial = &ciphertext[cp_idx + BLOCK_SIZE..];

            // Construct CC by combining partial ciphertext with tail of PP
            let mut cc = [0u8; BLOCK_SIZE];
            cc[..remaining_len].copy_from_slice(cc_partial);
            cc[remaining_len..].copy_from_slice(&pp[remaining_len..]);

            // Go back to previous alpha (multiply by x^-1 which is the same as going back)
            // Actually we need the original alpha before the multiplication
            // Let's use a different approach: save alpha before multiplication
            // We need to go back, so let's recalculate from the beginning
            let mut alpha_prev = self.cipher2.encrypt_block(tweak);
            for _ in 0..blocks_to_process {
                alpha_prev = gf128_mul_x(&alpha_prev);
            }

            // Decrypt CC with previous alpha
            let mut xored2 = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored2[j] = cc[j] ^ alpha_prev[j];
            }
            let decrypted_cc = self.cipher1.decrypt_block(&xored2);
            let mut pm = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                pm[j] = decrypted_cc[j] ^ alpha_prev[j];
            }

            // Output: Pm-1 (full block) || first remaining_len bytes of PP
            plaintext.extend_from_slice(&pm);
            plaintext.extend_from_slice(&pp[..remaining_len]);
        }

        Ok(plaintext)
    }
}

/// AES-256-XTS cipher (uses 512-bit key: two 256-bit keys)
#[derive(Debug)]
pub struct AesXts256 {
    cipher1: Aes,
    cipher2: Aes,
}

impl AesXts256 {
    /// Create a new AES-256-XTS cipher
    /// Key must be 512 bits (64 bytes): first 256 bits for data, second 256 bits for tweak
    pub fn new(key: &[u8; 64]) -> Self {
        let key1: [u8; AES256_KEY_SIZE] = key[..32].try_into().unwrap();
        let key2: [u8; AES256_KEY_SIZE] = key[32..].try_into().unwrap();
        Self {
            cipher1: Aes::new_256(&key1),
            cipher2: Aes::new_256(&key2),
        }
    }

    /// Encrypt with XTS mode
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, tweak: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if plaintext.len() < BLOCK_SIZE {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: plaintext.len(),
            });
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut alpha = self.cipher2.encrypt_block(tweak);

        let full_blocks = plaintext.len() / BLOCK_SIZE;
        let has_partial = plaintext.len() % BLOCK_SIZE != 0;
        let blocks_to_process = if has_partial {
            full_blocks - 1
        } else {
            full_blocks
        };

        for i in 0..blocks_to_process {
            let block: [u8; BLOCK_SIZE] = plaintext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                .try_into()
                .unwrap();

            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = block[j] ^ alpha[j];
            }
            let encrypted = self.cipher1.encrypt_block(&xored);
            let mut final_block = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                final_block[j] = encrypted[j] ^ alpha[j];
            }
            ciphertext.extend_from_slice(&final_block);
            alpha = gf128_mul_x(&alpha);
        }

        if has_partial {
            let remaining_len = plaintext.len() % BLOCK_SIZE;
            let last_full_block_idx = full_blocks - 1;
            let block: [u8; BLOCK_SIZE] = plaintext
                [last_full_block_idx * BLOCK_SIZE..(last_full_block_idx + 1) * BLOCK_SIZE]
                .try_into()
                .unwrap();

            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = block[j] ^ alpha[j];
            }
            let encrypted = self.cipher1.encrypt_block(&xored);
            let mut cc = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                cc[j] = encrypted[j] ^ alpha[j];
            }

            let partial_start = (full_blocks) * BLOCK_SIZE;
            let partial_plaintext = &plaintext[partial_start..];

            let mut pp = [0u8; BLOCK_SIZE];
            pp[..remaining_len].copy_from_slice(partial_plaintext);
            pp[remaining_len..].copy_from_slice(&cc[remaining_len..]);

            alpha = gf128_mul_x(&alpha);

            let mut xored2 = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored2[j] = pp[j] ^ alpha[j];
            }
            let encrypted2 = self.cipher1.encrypt_block(&xored2);
            let mut cp = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                cp[j] = encrypted2[j] ^ alpha[j];
            }

            ciphertext.extend_from_slice(&cp);
            ciphertext.extend_from_slice(&cc[..remaining_len]);
        }

        Ok(ciphertext)
    }

    /// Decrypt with XTS mode
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, tweak: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() < BLOCK_SIZE {
            return Err(CipherError::InvalidPlaintextLength {
                block_size: BLOCK_SIZE,
                actual: ciphertext.len(),
            });
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut alpha = self.cipher2.encrypt_block(tweak);

        let full_blocks = ciphertext.len() / BLOCK_SIZE;
        let has_partial = ciphertext.len() % BLOCK_SIZE != 0;
        let blocks_to_process = if has_partial {
            full_blocks - 1
        } else {
            full_blocks
        };

        for i in 0..blocks_to_process {
            let block: [u8; BLOCK_SIZE] = ciphertext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                .try_into()
                .unwrap();

            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = block[j] ^ alpha[j];
            }
            let decrypted = self.cipher1.decrypt_block(&xored);
            let mut final_block = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                final_block[j] = decrypted[j] ^ alpha[j];
            }
            plaintext.extend_from_slice(&final_block);
            alpha = gf128_mul_x(&alpha);
        }

        if has_partial {
            let remaining_len = ciphertext.len() % BLOCK_SIZE;
            let cp_idx = (full_blocks - 1) * BLOCK_SIZE;
            let cp: [u8; BLOCK_SIZE] = ciphertext[cp_idx..cp_idx + BLOCK_SIZE].try_into().unwrap();

            alpha = gf128_mul_x(&alpha);

            let mut xored = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored[j] = cp[j] ^ alpha[j];
            }
            let decrypted_cp = self.cipher1.decrypt_block(&xored);
            let mut pp = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                pp[j] = decrypted_cp[j] ^ alpha[j];
            }

            let cc_partial = &ciphertext[cp_idx + BLOCK_SIZE..];

            let mut cc = [0u8; BLOCK_SIZE];
            cc[..remaining_len].copy_from_slice(cc_partial);
            cc[remaining_len..].copy_from_slice(&pp[remaining_len..]);

            let mut alpha_prev = self.cipher2.encrypt_block(tweak);
            for _ in 0..blocks_to_process {
                alpha_prev = gf128_mul_x(&alpha_prev);
            }

            let mut xored2 = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                xored2[j] = cc[j] ^ alpha_prev[j];
            }
            let decrypted_cc = self.cipher1.decrypt_block(&xored2);
            let mut pm = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                pm[j] = decrypted_cc[j] ^ alpha_prev[j];
            }

            plaintext.extend_from_slice(&pm);
            plaintext.extend_from_slice(&pp[..remaining_len]);
        }

        Ok(plaintext)
    }
}

/// Multiply a GF(2^128) element by x
/// Used in XTS mode for generating the tweak sequence
fn gf128_mul_x(block: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut carry = 0u8;

    // Shift left by 1 bit (little-endian byte order)
    for i in 0..16 {
        result[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }

    // If there was a carry, XOR with the reduction polynomial (0x87 in LSB)
    if carry != 0 {
        result[0] ^= 0x87;
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = b"Hello, World!!!!"; //16 bytes

        let cipher = AesCbc128::new(&key);
        let ciphertext = cipher.encrypt(&iv, plaintext).unwrap();
        let decrypted = cipher.decrypt(&iv, &ciphertext).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes128_ctr_roundtrip() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let nonce = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = b"Hello, World! This is a test of CTR mode.";

        let cipher = AesCtr128::new(&key);
        let ciphertext = cipher.process(&nonce, plaintext);
        let decrypted = cipher.process(&nonce, &ciphertext);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = b"AES-256-CBC test";

        let cipher = AesCbc256::new(&key);
        let ciphertext = cipher.encrypt(&iv, plaintext).unwrap();
        let decrypted = cipher.decrypt(&iv, &ciphertext).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_ctr_any_length() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let nonce = [0x00; 16];

        // Test with various lengths
        for len in [1, 7, 15, 16, 17, 31, 32, 100] {
            let plaintext = vec![0x42; len];
            let cipher = AesCtr256::new(&key);
            let ciphertext = cipher.process(&nonce, &plaintext);
            let decrypted = cipher.process(&nonce, &ciphertext);
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_counter_increment() {
        let mut counter = [0u8; 16];
        counter[15] = 0xFF;

        increment_counter(&mut counter);
        assert_eq!(counter[15], 0);
        assert_eq!(counter[14], 1);

        // Test overflow propagation
        counter = [0xFF; 16];
        increment_counter(&mut counter);
        assert_eq!(counter, [0u8; 16]);
    }

    // ============================================================================
    // CFB Mode Tests
    // ============================================================================

    #[test]
    fn test_aes128_cfb_roundtrip() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = b"Hello, World! This is a test of CFB mode with various lengths.";

        let cipher = AesCfb128::new(&key);
        let ciphertext = cipher.encrypt(&iv, plaintext);
        let decrypted = cipher.decrypt(&iv, &ciphertext);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_cfb_roundtrip() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv = [0x00; 16];
        let plaintext = b"CFB mode test";

        let cipher = AesCfb256::new(&key);
        let ciphertext = cipher.encrypt(&iv, plaintext);
        let decrypted = cipher.decrypt(&iv, &ciphertext);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes128_cfb_various_lengths() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [0x00; 16];

        // Test with various lengths
        for len in [1, 7, 15, 16, 17, 31, 32, 48, 64, 100] {
            let plaintext = vec![0x42; len];
            let cipher = AesCfb128::new(&key);
            let ciphertext = cipher.encrypt(&iv, &plaintext);
            let decrypted = cipher.decrypt(&iv, &ciphertext);
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }

    // ============================================================================
    // OFB Mode Tests
    // ============================================================================

    #[test]
    fn test_aes128_ofb_roundtrip() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = b"Hello, World! This is a test of OFB mode.";

        let cipher = AesOfb128::new(&key);
        let ciphertext = cipher.process(&iv, plaintext);
        let decrypted = cipher.process(&iv, &ciphertext);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_ofb_roundtrip() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv = [0x00; 16];
        let plaintext = b"OFB mode test";

        let cipher = AesOfb256::new(&key);
        let ciphertext = cipher.process(&iv, plaintext);
        let decrypted = cipher.process(&iv, &ciphertext);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes128_ofb_various_lengths() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [0x00; 16];

        // Test with various lengths
        for len in [1, 7, 15, 16, 17, 31, 32, 48, 64, 100] {
            let plaintext = vec![0x42; len];
            let cipher = AesOfb128::new(&key);
            let ciphertext = cipher.process(&iv, &plaintext);
            let decrypted = cipher.process(&iv, &ciphertext);
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }

    // ============================================================================
    // XTS Mode Tests
    // ============================================================================

    #[test]
    fn test_aes128_xts_roundtrip() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let tweak = [0x00; 16];
        let plaintext = b"Hello, World!!!!"; // 16 bytes (1 block)

        let cipher = AesXts128::new(&key);
        let ciphertext = cipher.encrypt(&tweak, plaintext).unwrap();
        let decrypted = cipher.decrypt(&tweak, &ciphertext).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes256_xts_roundtrip() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let tweak = [0x00; 16];
        let plaintext = b"XTS mode test for AES-256 with multiple blocks!!!!";

        let cipher = AesXts256::new(&key);
        let ciphertext = cipher.encrypt(&tweak, plaintext).unwrap();
        let decrypted = cipher.decrypt(&tweak, &ciphertext).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes128_xts_with_partial_block() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let tweak = [0x01; 16];

        // Test with 21 bytes (1 full block + 5 byte partial)
        let plaintext = b"XTS partial block!!!"; // 20 bytes

        let cipher = AesXts128::new(&key);
        let ciphertext = cipher.encrypt(&tweak, plaintext).unwrap();
        let decrypted = cipher.decrypt(&tweak, &ciphertext).unwrap();

        assert_eq!(&decrypted[..], &plaintext[..]);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_xts_various_lengths() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let tweak = [0x00; 16];

        // Test with various lengths (XTS requires minimum 16 bytes)
        for len in [16, 17, 20, 31, 32, 33, 48, 64, 100] {
            let plaintext = vec![0x42; len];
            let cipher = AesXts128::new(&key);
            let ciphertext = cipher.encrypt(&tweak, &plaintext).unwrap();
            let decrypted = cipher.decrypt(&tweak, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }

    #[test]
    fn test_aes128_xts_minimum_length_error() {
        let key = [0x00; 32];
        let tweak = [0x00; 16];
        let plaintext = b"Short"; // Less than 16 bytes

        let cipher = AesXts128::new(&key);
        let result = cipher.encrypt(&tweak, plaintext);

        assert!(result.is_err());
    }

    #[test]
    fn test_gf128_mul_x() {
        // Test basic multiplication by x
        let input = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let expected = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(gf128_mul_x(&input), expected);

        // Test with carry and reduction
        let input = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let expected = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(gf128_mul_x(&input), expected);

        // Test with reduction polynomial
        let input = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x80,
        ];
        let expected = [
            0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(gf128_mul_x(&input), expected);
    }

    #[test]
    fn test_xts_tweak_independence() {
        let key = [0x00; 32];
        let tweak1 = [0x00; 16];
        let mut tweak2 = [0x00; 16];
        tweak2[0] = 0x01;
        let plaintext = b"Testing tweak independence in XTS mode!!";

        let cipher = AesXts128::new(&key);
        let ciphertext1 = cipher.encrypt(&tweak1, plaintext).unwrap();
        let ciphertext2 = cipher.encrypt(&tweak2, plaintext).unwrap();

        // Different tweaks should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }
}
