//! RSA Public-Key Cryptography
//!
//! This module provides RSA encryption, decryption, and digital signatures.
//!
//! # Supported Features
//!
//! - **RSA-PSS** - Probabilistic Signature Scheme (PKCS#1 v2.2, RFC 8017)
//! - **RSA-OAEP** - Optimal Asymmetric Encryption Padding (PKCS#1 v2.2)
//! - **PKCS#1 v1.5** - Legacy support for compatibility
//! - **Key Generation** - 2048, 3072, 4096-bit keys
//!
//! # Security
//!
//! - Key sizes: Minimum 2048 bits (recommended 3072+ for long-term)
//! - Constant-time operations where possible
//! - Side-channel resistant implementation
//! - Secure random number generation
//!
//! # Examples
//!
//! ## RSA-PSS Signatures
//!
//! ```rust
//! use hpcrypt_rsa::{RsaPrivateKey, RsaPublicKey};
//! use hpcrypt_hash::sha256::Sha256;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a 2048-bit RSA key pair
//! let private_key = RsaPrivateKey::generate(2048)?;
//! let public_key = private_key.public_key();
//!
//! // Sign a message using RSA-PSS with SHA-256
//! let message = b"Hello, RSA!";
//! let signature = private_key.sign_pss::<Sha256>(message)?;
//!
//! // Verify the signature
//! assert!(public_key.verify_pss::<Sha256>(message, &signature)?);
//! # Ok(())
//! # }
//! ```
//!
//! ## RSA-OAEP Encryption
//!
//! ```rust
//! use hpcrypt_rsa::{RsaPrivateKey, RsaPublicKey};
//! use hpcrypt_hash::sha256::Sha256;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a key pair
//! let private_key = RsaPrivateKey::generate(2048)?;
//! let public_key = private_key.public_key();
//!
//! // Encrypt a message
//! let plaintext = b"Secret message";
//! let ciphertext = public_key.encrypt_oaep::<Sha256>(plaintext, None)?;
//!
//! // Decrypt
//! let decrypted = private_key.decrypt_oaep::<Sha256>(&ciphertext, None)?;
//! assert_eq!(plaintext, &decrypted[..]);
//! # Ok(())
//! # }
//! ```
//!
//! # Standards Compliance
//!
//! - **PKCS#1 v2.2** (RFC 8017) - RSA-PSS, RSA-OAEP
//! - **FIPS 186-4** - Digital Signature Standard
//! - **NIST SP 800-56B** - Key establishment
//!
//! # Performance
//!
//! Approximate performance on modern x86_64 (single-threaded):
//!
//! | Operation | 2048-bit | 3072-bit | 4096-bit |
//! |-----------|----------|----------|----------|
//! | Key Gen | ~100 ms | ~500 ms | ~2 sec |
//! | Sign | ~1 ms | ~3 ms | ~7 ms |
//! | Verify | ~50 µs | ~100 µs | ~200 µs |
//! | Encrypt | ~50 µs | ~100 µs | ~200 µs |
//! | Decrypt | ~1 ms | ~3 ms | ~7 ms |
//!
//! Note: Verification and encryption use public exponent e=65537 (fast)

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

mod error;
mod keygen;
mod montgomery;
pub mod oaep;
pub mod pkcs1v15;
pub mod pss;
mod primitives;
mod public_key;
mod private_key;

pub use error::{RsaError, Result};
pub use public_key::RsaPublicKey;
pub use private_key::RsaPrivateKey;

/// Minimum supported RSA key size in bits
///
/// Keys smaller than 2048 bits are considered insecure and are not supported.
pub const MIN_KEY_SIZE: usize = 2048;

/// Maximum supported RSA key size in bits
///
/// This is a practical limit for performance reasons.
pub const MAX_KEY_SIZE: usize = 8192;

/// Default public exponent (65537 = 0x10001)
///
/// This is the most common public exponent, offering a good balance between
/// security and performance. It has only two bits set, making modular
/// exponentiation very fast.
pub const DEFAULT_PUBLIC_EXPONENT: u64 = 65537;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MIN_KEY_SIZE, 2048);
        assert_eq!(MAX_KEY_SIZE, 8192);
        assert_eq!(DEFAULT_PUBLIC_EXPONENT, 65537);
    }
}
