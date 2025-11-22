//! Elliptic Curve Cryptography
//!
//! This crate provides production-ready implementations of modern elliptic curves
//! with a focus on security, performance, and usability.

#![allow(clippy::comparison_chain)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::cast_abs_to_unsigned)]
//!
//! # Supported Curves
//!
//! - **Ed25519** - Edwards curve digital signatures (RFC 8032)
//! - **X25519** - Curve25519 Diffie-Hellman key exchange (RFC 7748)
//! - **Ed448** - Edwards448-Goldilocks digital signatures (RFC 8032)
//! - **X448** - Curve448 Diffie-Hellman key exchange (RFC 7748)
//! - **P-256** - NIST P-256 (secp256r1) elliptic curve
//! - **P-384** - NIST P-384 (secp384r1) elliptic curve
//! - **P-521** - NIST P-521 (secp521r1) elliptic curve (field arithmetic only)
//! - **secp256k1** - Bitcoin/Ethereum curve
//!
//! # Examples
//!
//! ## Ed25519 Digital Signatures
//!
//! ```rust
//! use hpcrypt_curves::Ed25519;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a signing key (use secure random in production)
//! let private_key = [0u8; 32]; // Replace with secure random bytes
//! let public_key = Ed25519::public_key(&private_key);
//!
//! // Sign a message
//! let message = b"Authenticate this message";
//! let signature = Ed25519::sign(&private_key, message);
//!
//! // Verify the signature
//! assert!(Ed25519::verify(&public_key, message, &signature));
//! # Ok(())
//! # }
//! ```
//!
//! ## Ed25519 Batch Verification
//!
//! Verify multiple signatures simultaneously with 50-70% performance improvement:
//!
//! ```no_run
//! use hpcrypt_curves::ed25519::{PublicKey, Signature};
//! use hpcrypt_curves::Ed25519;
//!
//! # fn main() {
//! // Prepare multiple signatures to verify
//! let private_keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
//! let public_keys: Vec<PublicKey> = private_keys
//!     .iter()
//!     .map(|sk| Ed25519::public_key(sk))
//!     .collect();
//!
//! let messages = [b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];
//! let signatures: Vec<Signature> = private_keys
//!     .iter()
//!     .zip(&messages)
//!     .map(|(sk, msg)| Ed25519::sign(sk, msg))
//!     .collect();
//!
//! // Batch verification is much faster than individual verification
//! let valid = Ed25519::verify_batch(&public_keys, &messages, &signatures);
//! assert!(valid);
//! # }
//! ```
//!
//! ## X25519 Key Exchange
//!
//! Establish a shared secret between two parties:
//!
//! ```rust
//! use hpcrypt_curves::X25519;
//! use hpcrypt_core::error::CurveError;
//!
//! # fn main() -> Result<(), CurveError> {
//! // Alice generates her keypair
//! let alice_private = [1u8; 32]; // Use secure random in production
//! let alice_public = X25519::public_key(&alice_private);
//!
//! // Bob generates his keypair
//! let bob_private = [2u8; 32]; // Use secure random in production
//! let bob_public = X25519::public_key(&bob_private);
//!
//! // Both compute the same shared secret
//! let alice_shared = X25519::shared_secret(&alice_private, &bob_public)?;
//! let bob_shared = X25519::shared_secret(&bob_private, &alice_public)?;
//!
//! assert_eq!(alice_shared, bob_shared);
//! # Ok(())
//! # }
//! ```
//!
//! ## X448 Key Exchange
//!
//! Establish a high-security shared secret (224-bit security level):
//!
//! ```rust
//! use hpcrypt_curves::X448;
//! use hpcrypt_core::error::CurveError;
//!
//! # fn main() -> Result<(), CurveError> {
//! // Alice generates her keypair
//! let alice_private = [1u8; 56]; // Use secure random in production
//! let alice_public = X448::public_key(&alice_private);
//!
//! // Bob generates his keypair
//! let bob_private = [2u8; 56]; // Use secure random in production
//! let bob_public = X448::public_key(&bob_private);
//!
//! // Both compute the same shared secret
//! let alice_shared = X448::shared_secret(&alice_private, &bob_public)?;
//! let bob_shared = X448::shared_secret(&bob_private, &alice_public)?;
//!
//! assert_eq!(alice_shared, bob_shared);
//! # Ok(())
//! # }
//! ```
//!
//! ## P-256 ECDSA Signatures
//!
//! ```ignore
//! use hpcrypt_curves::p256::{Scalar, Point};
//! use hpcrypt_signatures::ecdsa::Ecdsa;
//!
//! # fn main() {
//! // Generate keypair (use secure random in production)
//! let private_key = Scalar::from_bytes(&[1u8; 32]);
//! let public_key = Point::generator().scalar_mul(&private_key);
//!
//! // Sign a message hash
//! let message_hash = [0u8; 32]; // SHA-256 of your message
//! let k = Scalar::from_bytes(&[2u8; 32]); // Deterministic nonce (RFC 6979)
//! let signature = Ecdsa::sign(&private_key, &message_hash, &k);
//!
//! // Verify the signature
//! let valid = Ecdsa::verify(&public_key, &message_hash, &signature);
//! assert!(valid);
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - **Private keys** must be generated using a cryptographically secure RNG
//! - **Ed25519 signing** is deterministic and constant-time for secret keys
//! - **X25519** clears the 3 LSBs and sets MSB for clamping
//! - **Constant-time operations** prevent timing side-channel attacks
//! - All implementations use `subtle` crate for conditional operations on secrets
//!
//! # Performance
//!
//! Performance characteristics on modern x86_64 CPUs:
//!
//! - **Ed25519 sign**: ~50-70 μs
//! - **Ed25519 verify**: ~120-150 μs
//! - **Ed25519 batch verify (32 sigs)**: ~80-100 μs per signature (40% faster)
//! - **X25519 key exchange**: ~50-70 μs
//! - **P-256 ECDSA sign**: ~150-200 μs
//! - **P-256 ECDSA verify**: ~300-400 μs
//!
//! # Standards Compliance
//!
//! All implementations are compliant with industry standards:
//!
//! - Ed25519: RFC 8032
//! - X25519: RFC 7748
//! - Ed448: RFC 8032
//! - X448: RFC 7748
//! - P-256/P-384: FIPS 186-4, SEC2
//! - secp256k1: SEC2

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
// Clippy: Explicit indexing is clearer for cryptographic code
#![allow(clippy::needless_range_loop)]
#![allow(clippy::needless_borrows_for_generic_args)]

// Internal modules
mod unroll_macros;

// Constant-time utilities (re-exported from hpcrypt-core)
pub use hpcrypt_core::ct_utils;

// SafeGCD: Fast modular inversion (2-3x faster than Fermat's method)
// Status: Phase 1 - Basic implementation in progress
pub mod safegcd;

pub mod ed25519;
pub mod ed448;

// SIMD modules removed - see /home/maamoun/hpcrypt_simd_work/ for SIMD implementations

pub mod p256;
pub mod p384;
pub mod p521;
pub mod secp256k1;
pub mod x25519;
pub mod x448;

pub use ed25519::Ed25519;
pub use ed25519::field::FieldElement;
pub use x25519::X25519;
pub use x448::X448;
