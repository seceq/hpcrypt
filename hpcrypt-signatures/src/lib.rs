//! Digital Signature Algorithms
//!
//! This crate provides production-ready implementations of ECDSA (Elliptic Curve
//! Digital Signature Algorithm) for multiple curves.
//!
//! # Supported Algorithms
//!
//! - **ECDSA P-256** - NIST P-256 signatures (FIPS 186-4)
//! - **ECDSA P-384** - NIST P-384 signatures (FIPS 186-4)
//! - **ECDSA P-521** - NIST P-521 signatures (FIPS 186-4)
//! - **ECDSA secp256k1** - Bitcoin/Ethereum signatures
//!
//! # Examples
//!
//! ## ECDSA P-256 Signature
//!
//! ```ignore
//! use hpcrypt_signatures::ecdsa::Ecdsa;
//! use hpcrypt_curves::p256::{Scalar, Point};
//!
//! # fn main() {
//! // Generate keypair (use hpcrypt-rng in production)
//! let private_key = Scalar::from_bytes(&[1u8; 32]);
//! let public_key = Point::generator().scalar_mul(&private_key);
//!
//! // Hash your message first (e.g., with SHA-256)
//! let message_hash = [0u8; 32];
//!
//! // Generate deterministic nonce (RFC 6979 recommended)
//! let k = Scalar::from_bytes(&[2u8; 32]);
//!
//! // Sign the message hash
//! let signature = Ecdsa::sign(&private_key, &message_hash, &k);
//!
//! // Verify the signature
//! let is_valid = Ecdsa::verify(&public_key, &message_hash, &signature);
//! assert!(is_valid);
//! # }
//! ```
//!
//! ## ECDSA P-384 Signature
//!
//! ```ignore
//! use hpcrypt_signatures::ecdsa_p384::EcdsaP384;
//! use hpcrypt_curves::p384::{Scalar, Point};
//!
//! # fn main() {
//! // Generate keypair
//! let private_key = Scalar::from_bytes(&[1u8; 48]);
//! let public_key = Point::generator().scalar_mul(&private_key);
//!
//! // Hash your message first (e.g., with SHA-384)
//! let message_hash = [0u8; 48];
//! let k = Scalar::from_bytes(&[2u8; 48]);
//!
//! // Sign and verify
//! let signature = EcdsaP384::sign(&private_key, &message_hash, &k);
//! let is_valid = EcdsaP384::verify(&public_key, &message_hash, &signature);
//! assert!(is_valid);
//! # }
//! ```
//!
//! ## ECDSA secp256k1 Signature
//!
//! ```ignore
//! use hpcrypt_signatures::ecdsa_secp256k1::EcdsaSecp256k1;
//! use hpcrypt_curves::secp256k1::{Scalar, Point};
//!
//! # fn main() {
//! // Generate keypair
//! let private_key = Scalar::from_bytes(&[1u8; 32]);
//! let public_key = Point::generator().scalar_mul(&private_key);
//!
//! // Hash your message first (e.g., with SHA-256 for Bitcoin)
//! let message_hash = [0u8; 32];
//! let k = Scalar::from_bytes(&[2u8; 32]);
//!
//! // Sign and verify
//! let signature = EcdsaSecp256k1::sign(&private_key, &message_hash, &k);
//! let is_valid = EcdsaSecp256k1::verify(&public_key, &message_hash, &signature);
//! assert!(is_valid);
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## Critical: Nonce Generation
//!
//! **NEVER reuse nonces!** Reusing a nonce with the same private key allows
//! recovery of the private key. Use one of these approaches:
//!
//! 1. **RFC 6979 (Recommended)**: Deterministic nonce generation
//!    - Derives k from private key + message hash
//!    - No randomness needed, fully deterministic
//!    - Prevents nonce reuse attacks
//!
//! 2. **True Randomness**: Generate k using CSPRNG
//!    - Must use cryptographically secure RNG
//!    - Risk: Implementation bugs or RNG failures
//!
//! ## Message Hashing
//!
//! Always hash messages before signing:
//! - **P-256/P-384**: Use SHA-256 or SHA-384
//! - **secp256k1**: Use SHA-256 (Bitcoin/Ethereum standard)
//!
//! Never sign raw messages directly - the signature scheme expects a hash.
//!
//! ## Private Key Storage
//!
//! - Generate keys using `hpcrypt-rng` or equivalent CSPRNG
//! - Store private keys encrypted at rest
//! - Clear private key memory after use (zeroize)
//! - Use hardware security modules (HSMs) for high-value keys
//!
//! # Performance
//!
//! Typical performance on modern x86_64 CPUs:
//!
//! | Operation | P-256 | P-384 | secp256k1 |
//! |-----------|-------|-------|-----------|
//! | Sign | ~150 μs | ~300 μs | ~120 μs |
//! | Verify | ~300 μs | ~600 μs | ~250 μs |
//! | Verify (GLV) | - | - | ~150 μs |
//!
//! # Standards Compliance
//!
//! - **FIPS 186-4**: Digital Signature Standard (P-256, P-384)
//! - **SEC 1**: Elliptic Curve Cryptography (all curves)
//! - **SEC 2**: Recommended Elliptic Curve Domain Parameters
//! - **RFC 6979**: Deterministic ECDSA (recommended for all curves)

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

//#[cfg(feature = "alloc")]
//extern crate alloc;

/// ECDSA signatures for NIST P-256
pub mod ecdsa;
/// ECDSA signatures for NIST P-384
pub mod ecdsa_p384;
/// ECDSA signatures for NIST P-521
pub mod ecdsa_p521;
/// ECDSA signatures for secp256k1 (Bitcoin/Ethereum)
pub mod ecdsa_secp256k1;
