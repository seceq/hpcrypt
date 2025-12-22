//! # ML-KEM: Module-Lattice-Based Key Encapsulation Mechanism
//!
//! Pure Rust implementation of the ML-KEM (FIPS 203) post-quantum cryptographic standard.
//!
//! ML-KEM, formerly known as CRYSTALS-KYBER, is a lattice-based key encapsulation mechanism
//! selected by NIST for standardization as part of the post-quantum cryptography project.
//!
//! ## Overview
//!
//! This crate provides a pure Rust implementation of ML-KEM with:
//! - Three security levels (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
//! - Constant-time operations for side-channel resistance
//! - `no_std` compatibility for embedded systems
//!
//! ## Security Levels
//!
//! | Parameter Set | NIST Level | Public Key | Secret Key | Ciphertext |
//! |--------------|------------|------------|------------|------------|
//! | ML-KEM-512   | 1          | 800 bytes  | 1632 bytes | 768 bytes  |
//! | ML-KEM-768   | 3          | 1184 bytes | 2400 bytes | 1088 bytes |
//! | ML-KEM-1024  | 5          | 1568 bytes | 3168 bytes | 1568 bytes |
//!
//! ## Usage Example
//!
//! ```no_run
//! use hpcrypt_mlkem::params::MlKem768;
//! use hpcrypt_mlkem::keygen::ml_kem_keygen;
//! use hpcrypt_mlkem::encaps::ml_kem_encaps;
//! use hpcrypt_mlkem::decaps::ml_kem_decaps;
//!
//! // Key generation
//! let keypair = ml_kem_keygen::<MlKem768>(None);
//!
//! // Encapsulation (sender side)
//! let result = ml_kem_encaps::<MlKem768>(&keypair.ek, None);
//!
//! // Decapsulation (receiver side)
//! let ss_receiver = ml_kem_decaps::<MlKem768>(&keypair.dk, &result.ciphertext);
//!
//! // Both parties now share the same secret
//! assert_eq!(result.shared_secret, ss_receiver);
//! ```
//!
//! ## Features
//!
//! - `std` - Enable standard library support (default: no_std)
//! - `zeroize` - Enable automatic secret zeroization (default: enabled)
//! - `getrandom` - Enable OS RNG support (default: enabled)
//! - `serde` - Enable serde serialization support
//!
//! ## References
//!
//! - [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM specification

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// Public modules
pub mod params;

// Internal modules
pub mod symmetric;
pub mod sampling;
pub mod poly;
pub mod ntt;
pub mod compress;
pub mod serialize;
pub mod ct_verify;
pub mod utils;

// SIMD intrinsics
pub mod intrinsics;

// Core operations
pub mod keygen;
pub mod encaps;
pub mod decaps;

// Test API for CAVP validation (only with cavp feature)
#[cfg(feature = "cavp")]
pub mod test_api;

// Re-export RNG functionality from hpcrypt-rng
pub use hpcrypt_rng::generate_random_bytes as fill_random;
pub use hpcrypt_rng::generate_key as random_bytes_32;

// Re-export commonly used types
pub use params::{MlKem512, MlKem768, MlKem1024, Params, N, Q};
pub use poly::{Poly, PolyVec, PolyMat};
pub use keygen::{kpke_keygen, ml_kem_keygen, KeyPair, KpkeKeyPair};
pub use encaps::{kpke_encrypt, ml_kem_encaps, EncapsResult};
pub use decaps::{kpke_decrypt, ml_kem_decaps};
