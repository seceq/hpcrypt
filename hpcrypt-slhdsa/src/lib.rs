//! # hpcrypt_slhdsa
//!
//! High-performance implementation of SLH-DSA (SPHINCS+) in Rust.
//!
//! This library provides a pure Rust implementation of the SLH-DSA (Stateless
//! Hash-based Digital Signature Algorithm), also known as SPHINCS+, as
//! standardized in FIPS 205.
//!
//! ## Features
//!
//! - **All 12 FIPS 205 parameter sets** (SHA2 and SHAKE variants, 128/192/256-bit security)
//! - **Optimized for performance** using Rust-level optimizations
//! - **Comprehensive testing** including NIST Known Answer Tests
//! - **Extensive benchmarking** with Criterion
//! - **No hardware dependencies** (pure Rust, portable)
//!
//! ## Example
//!
//! ```no_run
//! use hpcrypt_slhdsa::{Sha2_128f, KeyPair, sign, verify};
//! use hpcrypt_rng::OsRng;
//!
//! let mut rng = OsRng;
//!
//! // Generate a key pair
//! let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
//!
//! // Sign a message
//! let message = b"Hello, world!";
//! let signature = sign(&keypair.secret_key, message);
//!
//! // Verify the signature
//! assert!(verify(&keypair.public_key, message, &signature));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

// Core modules
pub mod address;
pub mod hash;
pub mod params;
pub mod utils;
pub mod wots;
pub mod merkle;
pub mod merkle_cache;
pub mod fors;
pub mod hypertree;
pub mod slhdsa;
pub mod prehash;

// Test API (for CAVP testing)
#[cfg(feature = "cavp")]
pub mod test_api;

// Re-exports
pub use params::{
    ParameterSet, HashType,
    Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f,
    Shake128s, Shake128f, Shake192s, Shake192f, Shake256s, Shake256f,
};

pub use slhdsa::{KeyPair, SecretKey, PublicKey, sign, sign_ctx, sign_internal, sign_prehash, verify, verify_ctx, verify_internal};
pub use utils::SignatureError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_sets() {
        // Verify all parameter sets are accessible
        assert_eq!(Sha2_128s::N, 16);
        assert_eq!(Sha2_256s::N, 32);
        assert_eq!(Shake128f::N, 16);
        assert_eq!(Shake256f::N, 32);
    }
}
