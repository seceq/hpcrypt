//! AES (Advanced Encryption Standard) block cipher with automatic hardware dispatch
//!
//! This module provides AES encryption with automatic selection of the best
//! available implementation:
//!
//! - **AES-NI** on x86/x86_64 with hardware support
//! - **ARM NEON** on aarch64 with crypto extensions
//! - **Fixslice** (constant-time software fallback) otherwise
//!
//! # Example
//!
//! ```
//! use hpcrypt_cipher::Aes;
//!
//! let key = [0u8; 16];
//! let cipher = Aes::new_128(&key);
//! let plaintext = [0u8; 16];
//! let ciphertext = cipher.encrypt_block(&plaintext);
//! let decrypted = cipher.decrypt_block(&ciphertext);
//! assert_eq!(plaintext, decrypted);
//! ```

use crate::aes_fixslice::AesFixslice;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use hpcrypt_core::cpufeatures::has_aesni;

#[cfg(target_arch = "aarch64")]
use hpcrypt_core::cpufeatures::has_aes_neon;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::intrinsics::aesni::{AesNi128, AesNi192, AesNi256};

#[cfg(target_arch = "aarch64")]
use crate::intrinsics::neon::{AesNeon128, AesNeon192, AesNeon256};

// Re-export constants from fixslice
pub use crate::aes_fixslice::{AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE};

/// AES cipher with automatic hardware dispatch
///
/// Automatically selects the best available implementation:
/// - AES-NI on x86/x86_64 when available
/// - ARM NEON crypto extensions on aarch64 when available
/// - Constant-time fixslice software implementation otherwise
#[derive(Clone)]
pub enum Aes {
    /// Software fixslice implementation (constant-time fallback)
    Fixslice(AesFixslice),
    /// AES-128 using AES-NI (x86/x86_64)
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    AesNi128(AesNi128),
    /// AES-192 using AES-NI (x86/x86_64)
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    AesNi192(AesNi192),
    /// AES-256 using AES-NI (x86/x86_64)
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    AesNi256(AesNi256),
    /// AES-128 using ARM NEON (aarch64)
    #[cfg(target_arch = "aarch64")]
    AesNeon128(AesNeon128),
    /// AES-192 using ARM NEON (aarch64)
    #[cfg(target_arch = "aarch64")]
    AesNeon192(AesNeon192),
    /// AES-256 using ARM NEON (aarch64)
    #[cfg(target_arch = "aarch64")]
    AesNeon256(AesNeon256),
}

impl core::fmt::Debug for Aes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Aes::Fixslice(_) => f.debug_struct("Aes").field("impl", &"Fixslice").finish(),
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi128(_) => f.debug_struct("Aes").field("impl", &"AesNi128").finish(),
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi192(_) => f.debug_struct("Aes").field("impl", &"AesNi192").finish(),
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi256(_) => f.debug_struct("Aes").field("impl", &"AesNi256").finish(),
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon128(_) => f.debug_struct("Aes").field("impl", &"AesNeon128").finish(),
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon192(_) => f.debug_struct("Aes").field("impl", &"AesNeon192").finish(),
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon256(_) => f.debug_struct("Aes").field("impl", &"AesNeon256").finish(),
        }
    }
}

impl Aes {
    /// Create a new AES-128 cipher with automatic implementation selection
    pub fn new_128(key: &[u8; 16]) -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        if has_aesni() {
            // SAFETY: has_aesni() verified AES-NI is available
            return Aes::AesNi128(unsafe { AesNi128::new(key) });
        }

        #[cfg(target_arch = "aarch64")]
        if has_aes_neon() {
            // SAFETY: has_aes_neon() verified ARM crypto extensions are available
            return Aes::AesNeon128(unsafe { AesNeon128::new(key) });
        }

        Aes::Fixslice(AesFixslice::new_128(key))
    }

    /// Create a new AES-192 cipher with automatic implementation selection
    pub fn new_192(key: &[u8; 24]) -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        if has_aesni() {
            // SAFETY: has_aesni() verified AES-NI is available
            return Aes::AesNi192(unsafe { AesNi192::new(key) });
        }

        #[cfg(target_arch = "aarch64")]
        if has_aes_neon() {
            // SAFETY: has_aes_neon() verified ARM crypto extensions are available
            return Aes::AesNeon192(unsafe { AesNeon192::new(key) });
        }

        Aes::Fixslice(AesFixslice::new_192(key))
    }

    /// Create a new AES-256 cipher with automatic implementation selection
    pub fn new_256(key: &[u8; 32]) -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        if has_aesni() {
            // SAFETY: has_aesni() verified AES-NI is available
            return Aes::AesNi256(unsafe { AesNi256::new(key) });
        }

        #[cfg(target_arch = "aarch64")]
        if has_aes_neon() {
            // SAFETY: has_aes_neon() verified ARM crypto extensions are available
            return Aes::AesNeon256(unsafe { AesNeon256::new(key) });
        }

        Aes::Fixslice(AesFixslice::new_256(key))
    }

    /// Encrypt a single block
    #[inline]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        match self {
            Aes::Fixslice(cipher) => cipher.encrypt_block(block),
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi128(cipher) => {
                let mut out = *block;
                // SAFETY: AesNi128 was created with has_aesni() check
                unsafe { cipher.encrypt_block(&mut out) };
                out
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi192(cipher) => {
                let mut out = *block;
                // SAFETY: AesNi192 was created with has_aesni() check
                unsafe { cipher.encrypt_block(&mut out) };
                out
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi256(cipher) => {
                let mut out = *block;
                // SAFETY: AesNi256 was created with has_aesni() check
                unsafe { cipher.encrypt_block(&mut out) };
                out
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon128(cipher) => {
                let mut out = *block;
                // SAFETY: AesNeon128 was created with has_aes_neon() check
                unsafe { cipher.encrypt_block(&mut out) };
                out
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon192(cipher) => {
                let mut out = *block;
                // SAFETY: AesNeon192 was created with has_aes_neon() check
                unsafe { cipher.encrypt_block(&mut out) };
                out
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon256(cipher) => {
                let mut out = *block;
                // SAFETY: AesNeon256 was created with has_aes_neon() check
                unsafe { cipher.encrypt_block(&mut out) };
                out
            }
        }
    }

    /// Decrypt a single block
    #[inline]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        match self {
            Aes::Fixslice(cipher) => cipher.decrypt_block(block),
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi128(cipher) => {
                let mut out = *block;
                // SAFETY: AesNi128 was created with has_aesni() check
                unsafe { cipher.decrypt_block(&mut out) };
                out
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi192(cipher) => {
                let mut out = *block;
                // SAFETY: AesNi192 was created with has_aesni() check
                unsafe { cipher.decrypt_block(&mut out) };
                out
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi256(cipher) => {
                let mut out = *block;
                // SAFETY: AesNi256 was created with has_aesni() check
                unsafe { cipher.decrypt_block(&mut out) };
                out
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon128(cipher) => {
                let mut out = *block;
                // SAFETY: AesNeon128 was created with has_aes_neon() check
                unsafe { cipher.decrypt_block(&mut out) };
                out
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon192(cipher) => {
                let mut out = *block;
                // SAFETY: AesNeon192 was created with has_aes_neon() check
                unsafe { cipher.decrypt_block(&mut out) };
                out
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon256(cipher) => {
                let mut out = *block;
                // SAFETY: AesNeon256 was created with has_aes_neon() check
                unsafe { cipher.decrypt_block(&mut out) };
                out
            }
        }
    }

    /// Encrypt 4 blocks in parallel (for optimal performance)
    #[inline]
    pub fn encrypt_blocks_4(&self, blocks: &mut [[u8; 16]; 4]) {
        match self {
            Aes::Fixslice(cipher) => cipher.encrypt_blocks_4(blocks),
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi128(cipher) => {
                // AES-NI processes 8 blocks, but we only have 4
                for block in blocks.iter_mut() {
                    // SAFETY: AesNi128 was created with has_aesni() check
                    unsafe { cipher.encrypt_block(block) };
                }
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi192(cipher) => {
                for block in blocks.iter_mut() {
                    // SAFETY: AesNi192 was created with has_aesni() check
                    unsafe { cipher.encrypt_block(block) };
                }
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi256(cipher) => {
                for block in blocks.iter_mut() {
                    // SAFETY: AesNi256 was created with has_aesni() check
                    unsafe { cipher.encrypt_block(block) };
                }
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon128(cipher) => {
                // SAFETY: AesNeon128 was created with has_aes_neon() check
                unsafe { cipher.encrypt_4_blocks(blocks) };
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon192(cipher) => {
                // SAFETY: AesNeon192 was created with has_aes_neon() check
                unsafe { cipher.encrypt_4_blocks(blocks) };
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon256(cipher) => {
                // SAFETY: AesNeon256 was created with has_aes_neon() check
                unsafe { cipher.encrypt_4_blocks(blocks) };
            }
        }
    }

    /// Decrypt 4 blocks in parallel (for optimal performance)
    #[inline]
    pub fn decrypt_blocks_4(&self, blocks: &mut [[u8; 16]; 4]) {
        match self {
            Aes::Fixslice(cipher) => cipher.decrypt_blocks_4(blocks),
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi128(cipher) => {
                for block in blocks.iter_mut() {
                    // SAFETY: AesNi128 was created with has_aesni() check
                    unsafe { cipher.decrypt_block(block) };
                }
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi192(cipher) => {
                for block in blocks.iter_mut() {
                    // SAFETY: AesNi192 was created with has_aesni() check
                    unsafe { cipher.decrypt_block(block) };
                }
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi256(cipher) => {
                for block in blocks.iter_mut() {
                    // SAFETY: AesNi256 was created with has_aesni() check
                    unsafe { cipher.decrypt_block(block) };
                }
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon128(cipher) => {
                // SAFETY: AesNeon128 was created with has_aes_neon() check
                unsafe { cipher.decrypt_4_blocks(blocks) };
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon192(cipher) => {
                // SAFETY: AesNeon192 was created with has_aes_neon() check
                unsafe { cipher.decrypt_4_blocks(blocks) };
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon256(cipher) => {
                // SAFETY: AesNeon256 was created with has_aes_neon() check
                unsafe { cipher.decrypt_4_blocks(blocks) };
            }
        }
    }

    /// Encrypt 8 blocks in parallel (optimal for AES-NI)
    ///
    /// This is the most efficient method on x86/x86_64 with AES-NI.
    /// On other platforms, it processes blocks in smaller batches.
    #[inline]
    pub fn encrypt_blocks_8(&self, blocks: &mut [[u8; 16]; 8]) {
        match self {
            Aes::Fixslice(cipher) => {
                // Fixslice processes 4 blocks at a time
                let (first, second) = blocks.split_at_mut(4);
                cipher.encrypt_blocks_4(first.try_into().unwrap());
                cipher.encrypt_blocks_4(second.try_into().unwrap());
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi128(cipher) => {
                // SAFETY: AesNi128 was created with has_aesni() check
                unsafe { cipher.encrypt_8_blocks(blocks) };
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi192(cipher) => {
                // SAFETY: AesNi192 was created with has_aesni() check
                unsafe { cipher.encrypt_8_blocks(blocks) };
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi256(cipher) => {
                // SAFETY: AesNi256 was created with has_aesni() check
                unsafe { cipher.encrypt_8_blocks(blocks) };
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon128(cipher) => {
                // NEON processes 4 blocks at a time
                let (first, second) = blocks.split_at_mut(4);
                // SAFETY: AesNeon128 was created with has_aes_neon() check
                unsafe {
                    cipher.encrypt_4_blocks(first.try_into().unwrap());
                    cipher.encrypt_4_blocks(second.try_into().unwrap());
                }
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon192(cipher) => {
                let (first, second) = blocks.split_at_mut(4);
                // SAFETY: AesNeon192 was created with has_aes_neon() check
                unsafe {
                    cipher.encrypt_4_blocks(first.try_into().unwrap());
                    cipher.encrypt_4_blocks(second.try_into().unwrap());
                }
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon256(cipher) => {
                let (first, second) = blocks.split_at_mut(4);
                // SAFETY: AesNeon256 was created with has_aes_neon() check
                unsafe {
                    cipher.encrypt_4_blocks(first.try_into().unwrap());
                    cipher.encrypt_4_blocks(second.try_into().unwrap());
                }
            }
        }
    }

    /// Decrypt 8 blocks in parallel (optimal for AES-NI)
    ///
    /// This is the most efficient method on x86/x86_64 with AES-NI.
    /// On other platforms, it processes blocks in smaller batches.
    #[inline]
    pub fn decrypt_blocks_8(&self, blocks: &mut [[u8; 16]; 8]) {
        match self {
            Aes::Fixslice(cipher) => {
                // Fixslice processes 4 blocks at a time
                let (first, second) = blocks.split_at_mut(4);
                cipher.decrypt_blocks_4(first.try_into().unwrap());
                cipher.decrypt_blocks_4(second.try_into().unwrap());
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi128(cipher) => {
                // SAFETY: AesNi128 was created with has_aesni() check
                unsafe { cipher.decrypt_8_blocks(blocks) };
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi192(cipher) => {
                // SAFETY: AesNi192 was created with has_aesni() check
                unsafe { cipher.decrypt_8_blocks(blocks) };
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Aes::AesNi256(cipher) => {
                // SAFETY: AesNi256 was created with has_aesni() check
                unsafe { cipher.decrypt_8_blocks(blocks) };
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon128(cipher) => {
                let (first, second) = blocks.split_at_mut(4);
                // SAFETY: AesNeon128 was created with has_aes_neon() check
                unsafe {
                    cipher.decrypt_4_blocks(first.try_into().unwrap());
                    cipher.decrypt_4_blocks(second.try_into().unwrap());
                }
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon192(cipher) => {
                let (first, second) = blocks.split_at_mut(4);
                // SAFETY: AesNeon192 was created with has_aes_neon() check
                unsafe {
                    cipher.decrypt_4_blocks(first.try_into().unwrap());
                    cipher.decrypt_4_blocks(second.try_into().unwrap());
                }
            }
            #[cfg(target_arch = "aarch64")]
            Aes::AesNeon256(cipher) => {
                let (first, second) = blocks.split_at_mut(4);
                // SAFETY: AesNeon256 was created with has_aes_neon() check
                unsafe {
                    cipher.decrypt_4_blocks(first.try_into().unwrap());
                    cipher.decrypt_4_blocks(second.try_into().unwrap());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_roundtrip() {
        let key = [0x00u8; 16];
        let cipher = Aes::new_128(&key);
        let plaintext = [0x42u8; 16];
        let ciphertext = cipher.encrypt_block(&plaintext);
        let decrypted = cipher.decrypt_block(&ciphertext);
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes192_roundtrip() {
        let key = [0x00u8; 24];
        let cipher = Aes::new_192(&key);
        let plaintext = [0x42u8; 16];
        let ciphertext = cipher.encrypt_block(&plaintext);
        let decrypted = cipher.decrypt_block(&ciphertext);
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes256_roundtrip() {
        let key = [0x00u8; 32];
        let cipher = Aes::new_256(&key);
        let plaintext = [0x42u8; 16];
        let ciphertext = cipher.encrypt_block(&plaintext);
        let decrypted = cipher.decrypt_block(&ciphertext);
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes128_blocks_4_roundtrip() {
        let key = [0x00u8; 16];
        let cipher = Aes::new_128(&key);
        let original = [[0x42u8; 16]; 4];
        let mut blocks = original;
        cipher.encrypt_blocks_4(&mut blocks);
        cipher.decrypt_blocks_4(&mut blocks);
        assert_eq!(blocks, original);
    }

    #[test]
    fn test_aes128_blocks_8_roundtrip() {
        let key = [0x00u8; 16];
        let cipher = Aes::new_128(&key);
        let original = [[0x42u8; 16]; 8];
        let mut blocks = original;
        cipher.encrypt_blocks_8(&mut blocks);
        cipher.decrypt_blocks_8(&mut blocks);
        assert_eq!(blocks, original);
    }

    #[test]
    fn test_aes256_blocks_8_roundtrip() {
        let key = [0x00u8; 32];
        let cipher = Aes::new_256(&key);
        let original = [[0x42u8; 16]; 8];
        let mut blocks = original;
        cipher.encrypt_blocks_8(&mut blocks);
        cipher.decrypt_blocks_8(&mut blocks);
        assert_eq!(blocks, original);
    }
}
