//! # HPCrypt - High-Performance Cryptography Library
//!
//! A pure Rust cryptography library focused on performance and security.
//!
//! ## Features
//!
//! - **Pure Rust**: No C dependencies, fully memory-safe
//! - **Constant-time**: Side-channel resistant implementations
//! - **High Performance**: Optimized at Rust level
//! - **no_std**: Works in embedded and bare-metal environments
//!
//! ## Algorithms
//!
//! ### Hash Functions
//! - BLAKE3 (fastest general-purpose hash)
//! - BLAKE2b/BLAKE2s
//! - SHA-2 family
//! - SHA-3 family
//!
//! ### Authenticated Encryption
//! - ChaCha20-Poly1305
//! - XChaCha20-Poly1305
//! - AES-GCM
//! - AES-GCM-SIV
//!
//! ### Message Authentication
//! - HMAC
//! - Poly1305
//!
//! ### Key Derivation
//! - HKDF
//! - Argon2
//! - scrypt
//! - PBKDF2
//!
//! ### Digital Signatures
//! - Ed25519
//! - ECDSA (P-256, P-384, secp256k1)
//!
//! ### Key Exchange
//! - X25519
//! - ECDH (P-256, P-384)

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

//#[cfg(feature = "alloc")]
//extern crate alloc;

// Re-export core
pub use hpcrypt_core as core;

// Re-export algorithm crates
#[cfg(feature = "hash")]
pub use hpcrypt_hash as hash;

#[cfg(feature = "mac")]
pub use hpcrypt_mac as mac;

#[cfg(feature = "aead")]
pub use hpcrypt_aead as aead;

#[cfg(feature = "kdf")]
pub use hpcrypt_kdf as kdf;

#[cfg(feature = "curves")]
pub use hpcrypt_curves as curves;

#[cfg(feature = "signatures")]
pub use hpcrypt_signatures as signatures;

#[cfg(feature = "kex")]
pub use hpcrypt_kex as kex;
