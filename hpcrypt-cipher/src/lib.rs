//! Block Cipher Modes of Operation
//!
//! This crate provides standard modes of operation for block ciphers,
//! primarily focused on AES (Advanced Encryption Standard).
//!
//! # Security Warning
//!
//! IMPORTANT: None of these modes provide authentication. They only provide
//! confidentiality. An attacker can modify ciphertext without detection.
//!
//! For most applications, use authenticated encryption instead:
//! - Recommended: `AES-GCM` (from `hpcrypt-aead`) - provides both encryption and authentication
//! - Alternative: `ChaCha20-Poly1305` (from `hpcrypt-aead`) - faster on systems without AES-NI
//!
//! Only use these modes if:
//! 1. You need raw block cipher modes for specific protocols
//! 2. You will add authentication separately (HMAC, etc.)
//! 3. You understand the security implications
//!
//! # Mode Selection Guide
//!
//! | Mode | Use Case | IV Requirements | Parallel | Streaming |
//! |------|----------|-----------------|----------|-----------|
//! | **CTR** | General purpose | Random nonce, never reuse | Encrypt only | Yes |
//! | **CBC** | Legacy protocols | Random, unpredictable | No | No |
//! | **CFB** | Stream encryption | Random, unpredictable | Decrypt only | Yes |
//! | **OFB** | Stream encryption | Random, unpredictable | No | Yes |
//! | **XTS** | Disk encryption | Sector/block number | Yes | No |
//!
//! Recommendation: Use CTR mode for general-purpose encryption (with HMAC for authentication).
//!
//! # Critical: IV/Nonce Management
//!
//! ## CBC, CFB, OFB Modes
//!
//! CATASTROPHIC FAILURE if IV is reused with the same key!
//!
//! - IV must be unpredictable (use cryptographically secure random generator)
//! - Never reuse an IV with the same key
//! - IV can be transmitted in plaintext alongside ciphertext
//! - Generate new random IV for each encryption operation
//!
//! ```rust
//! use hpcrypt_cipher::AesCbc128;
//! use hpcrypt_rng::OsRng;
//!
//! let cipher = AesCbc128::new(&key);
//!
//! // Generate new random IV each time
//! let iv1 = OsRng::generate_bytes::<16>();
//! let ciphertext1 = cipher.encrypt(&iv1, plaintext1)?;
//!
//! let iv2 = OsRng::generate_bytes::<16>();
//! let ciphertext2 = cipher.encrypt(&iv2, plaintext2)?;
//! # Ok::<(), hpcrypt_core::error::CipherError>(())
//! ```
//!
//! ## CTR Mode
//!
//! CATASTROPHIC FAILURE if nonce is reused with the same key!
//!
//! - Nonce must be unique for each encryption
//! - Nonce can be a counter, random value, or combination
//! - Common pattern: 96-bit random prefix + 32-bit counter
//!
//! ## XTS Mode
//!
//! - Tweak should be sector/block number (for disk encryption)
//! - Each sector gets a unique tweak value
//! - Tweak can be sequential (sector 0, 1, 2, ...)
//!
//! # Padding
//!
//! Important: This crate does not handle padding automatically.
//!
//! - CBC, ECB: Require plaintext to be block-aligned (multiple of 16 bytes)
//! - CTR, CFB, OFB: Work with any plaintext length (stream ciphers)
//! - XTS: Minimum 16 bytes, supports ciphertext stealing for non-aligned
//!
//! For CBC mode, you must pad plaintext yourself (PKCS#7, ISO/IEC 7816-4, etc.)
//!
//! # Examples
//!
//! ## AES-CTR (Recommended)
//!
//! ```rust
//! use hpcrypt_cipher::AesCtr128;
//! use hpcrypt_rng::OsRng;
//!
//! // Generate key (store securely!)
//! let key = OsRng::generate_bytes::<16>();
//! let cipher = AesCtr128::new(&key);
//!
//! // Encryption
//! let nonce = OsRng::generate_bytes::<16>();  // Unique nonce
//! let plaintext = b"Secret message of any length";
//! let ciphertext = cipher.encrypt(&nonce, plaintext);
//!
//! // Decryption (CTR mode: encrypt = decrypt)
//! let recovered = cipher.encrypt(&nonce, &ciphertext);
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), hpcrypt_core::error::CipherError>(())
//! ```
//!
//! ## AES-CBC (Legacy)
//!
//! ```rust
//! use hpcrypt_cipher::AesCbc256;
//! use hpcrypt_rng::OsRng;
//!
//! let key = OsRng::generate_bytes::<32>();
//! let cipher = AesCbc256::new(&key);
//!
//! // Plaintext MUST be padded to block size (16 bytes)
//! let plaintext = b"Exactly 16 bytes";  // Already aligned
//! let iv = OsRng::generate_bytes::<16>();  // Random IV
//!
//! let ciphertext = cipher.encrypt(&iv, plaintext)?;
//! let recovered = cipher.decrypt(&iv, &ciphertext)?;
//! assert_eq!(&recovered[..], plaintext);
//! # Ok::<(), hpcrypt_core::error::CipherError>(())
//! ```
//!
//! ## XTS for Disk Encryption
//!
//! ```rust
//! use hpcrypt_cipher::AesXts256;
//!
//! // XTS requires 512-bit key (two 256-bit keys)
//! let key = [0u8; 64];  // In practice: derive from master key
//! let cipher = AesXts256::new(&key);
//!
//! // Encrypt sector 0
//! let sector_number = 0u128;
//! let tweak = sector_number.to_le_bytes();
//! let sector_data = [0u8; 512];  // Typical sector size
//!
//! let encrypted_sector = cipher.encrypt(&tweak, &sector_data)?;
//! let decrypted_sector = cipher.decrypt(&tweak, &encrypted_sector)?;
//! # Ok::<(), hpcrypt_core::error::CipherError>(())
//! ```
//!
//! # Standards References
//!
//! - **NIST SP 800-38A**: Recommendation for Block Cipher Modes (CBC, CFB, OFB, CTR)
//! - **NIST SP 800-38E**: XTS-AES Mode for Storage Devices
//! - **NIST SP 800-131A Rev 2**: Do not use ECB mode
//!
//! # Why Not AES-GCM?
//!
//! If you're asking "should I use AES-CBC or AES-GCM?", the answer is always AES-GCM.
//!
//! AES-GCM (in `hpcrypt-aead`) provides:
//! - Encryption (confidentiality)
//! - Authentication (integrity + authenticity)
//! - Protection against tampering
//! - Widely supported and standardized
//!
//! Only use modes from this crate if you have a specific reason (legacy protocol,
//! custom authentication, disk encryption, etc.).
//!
//! NOTE: FF1 (Format-Preserving Encryption) has been moved to the `hpcrypt-fpe` crate.

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod aes_modes;

pub use aes_modes::{
    AesCbc128, AesCbc192, AesCbc256, AesCfb128, AesCfb192, AesCfb256, AesCtr128, AesCtr192,
    AesCtr256, AesOfb128, AesOfb192, AesOfb256, AesXts128, AesXts256,
};
