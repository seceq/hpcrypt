//! # ECIES (Elliptic Curve Integrated Encryption Scheme)
//!
//! This crate provides ECIES implementation following SEC 1 v2.0 standard.
//!
//! ## Overview
//!
//! ECIES is a hybrid encryption scheme that combines:
//! - **ECDH** for key agreement
//! - **KDF** for key derivation (ANSI X9.63)
//! - **AEAD** for authenticated encryption (AES-GCM)
//!
//! ## Supported Curves
//!
//! - **secp256k1** (Bitcoin/Ethereum curve) - 128-bit security
//! - **P-256** (NIST P-256 / secp256r1) - 128-bit security
//! - **P-384** (NIST P-384 / secp384r1) - 192-bit security
//! - **P-521** (NIST P-521 / secp521r1) - 256-bit security
//!
//! ## Security
//!
//! - **IND-CCA2 secure** (indistinguishable under adaptive chosen-ciphertext attack)
//! - **Authenticated encryption** (AES-GCM provides confidentiality + integrity)
//! - **Forward secrecy** (ephemeral key pairs)
//!
//! ## Example
//!
//! ```rust,no_run
//! use hpcrypt_ecies::EciesP256;
//! use rand::thread_rng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = thread_rng();
//!
//! // Generate recipient key pair
//! let (recipient_secret, recipient_public) = EciesP256::generate_keypair(&mut rng)?;
//!
//! // Encrypt message
//! let message = b"Hello, ECIES!";
//! let ciphertext = EciesP256::encrypt(&recipient_public, message, &[], &mut rng)?;
//!
//! // Decrypt message
//! let plaintext = EciesP256::decrypt(&recipient_secret, &ciphertext, &[])?;
//! assert_eq!(plaintext, message);
//! # Ok(())
//! # }
//! ```

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod error;
pub mod p256;
pub mod p384;
pub mod p521;
pub mod secp256k1;

pub use error::{EciesError, Result};
pub use p256::EciesP256;
pub use p384::EciesP384;
pub use p521::EciesP521;
pub use secp256k1::EciesSecp256k1;
