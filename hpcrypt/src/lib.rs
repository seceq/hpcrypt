//! # HPCrypt - High-Performance Cryptography Library
//!
//! HPCrypt is a pure-Rust cryptography library focused on performance, security, and correctness.
//! It provides both classical and post-quantum cryptographic primitives with a unified interface.
//!
//! ## Features
//!
//! - **No unsafe code**: 100% safe Rust implementations
//! - **no_std compatible**: Works in embedded and bare-metal environments
//! - **Post-quantum ready**: NIST-standardized PQC algorithms (ML-KEM, ML-DSA, SLH-DSA)
//! - **High performance**: Optimized implementations with comprehensive benchmarks
//! - **Well documented**: Production-ready with extensive documentation
//!
//! ## Quick Start
//!
//! ### Post-Quantum Key Encapsulation (ML-KEM)
//!
//! ```rust,ignore
//! use hpcrypt::mlkem::{MlKem768, KeyPair};
//!
//! // Generate a key pair
//! let keypair = KeyPair::generate::<MlKem768>();
//!
//! // Encapsulate a shared secret
//! let (ciphertext, shared_secret_sender) = keypair.encapsulate::<MlKem768>();
//!
//! // Decapsulate to recover the shared secret
//! let shared_secret_receiver = keypair.decapsulate::<MlKem768>(&ciphertext);
//!
//! assert_eq!(shared_secret_sender, shared_secret_receiver);
//! ```
//!
//! ### Classical ECDSA Signatures
//!
//! ```rust,ignore
//! use hpcrypt::signatures::ecdsa::{EcdsaP256, SigningKey};
//!
//! // Generate signing key
//! let signing_key = SigningKey::<EcdsaP256>::generate();
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let message = b"Hello, world!";
//! let signature = signing_key.sign(message);
//!
//! // Verify the signature
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! ```
//!
//! ### Cryptographic Hashing
//!
//! ```rust
//! use hpcrypt::hash::{Sha256, Digest};
//!
//! let mut hasher = Sha256::new();
//! hasher.update(b"hello world");
//! let result = hasher.finalize();
//! ```
//!
//! ## Crate Organization
//!
//! HPCrypt is organized into focused sub-crates:
//!
//! ### Core Components (always included)
//! - [`core`] - Common utilities and error types
//! - [`hash`] - Cryptographic hash functions (SHA-2, SHA-3, BLAKE2, BLAKE3)
//! - [`rng`] - Cryptographically secure random number generation
//!
//! ### Classical Cryptography (feature: `classical`)
//! - [`curves`] - Elliptic curve implementations (P-256, P-384, P-521, secp256k1, Ed25519, Ed448)
//! - [`signatures`] - Digital signature schemes (ECDSA, EdDSA)
//!
//! ### Post-Quantum Cryptography (feature: `pq`)
//! - [`mlkem`] - ML-KEM key encapsulation (FIPS 203)
//! - [`mldsa`] - ML-DSA signatures (FIPS 204)
//! - [`slhdsa`] - SLH-DSA signatures (FIPS 205)
//!
//! ## Feature Flags
//!
//! - `std` (default): Enable standard library support
//! - `curves`: Enable elliptic curve primitives
//! - `signatures`: Enable classical signature schemes (requires `curves`)
//! - `pq-kem`: Enable post-quantum key encapsulation (ML-KEM)
//! - `pq-sig`: Enable all post-quantum signatures (ML-DSA + SLH-DSA)
//! - `pq`: Enable all post-quantum cryptography
//! - `classical`: Enable all classical cryptography (curves + signatures)
//! - `full`: Enable everything (classical + post-quantum)
//!
//! ## Security Considerations
//!
//! - All implementations avoid unsafe code
//! - Constant-time operations where cryptographically relevant
//! - Comprehensive test coverage including known answer tests
//! - Regular security audits and updates
//!
//! ## Performance
//!
//! HPCrypt prioritizes both security and performance:
//! - Optimized field arithmetic for elliptic curves
//! - Vectorized operations where beneficial
//! - Cache-friendly data structures
//! - Comprehensive benchmarks to prevent regressions
//!
//! See individual crate documentation for detailed performance characteristics.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]

// Re-export core components (always available)
pub use hpcrypt_core as core;
pub use hpcrypt_hash as hash;
pub use hpcrypt_rng as rng;

// Re-export optional components
#[cfg(feature = "curves")]
pub use hpcrypt_curves as curves;

#[cfg(feature = "signatures")]
pub use hpcrypt_signatures as signatures;

#[cfg(feature = "pq-kem")]
pub use hpcrypt_mlkem as mlkem;

#[cfg(feature = "pq-sig-mldsa")]
pub use hpcrypt_mldsa as mldsa;

#[cfg(feature = "pq-sig-slhdsa")]
pub use hpcrypt_slhdsa as slhdsa;

/// Prelude module with commonly used types
///
/// Import this module to get quick access to the most frequently used types:
///
/// ```rust
/// use hpcrypt::prelude::*;
/// ```
pub mod prelude {
    // Core types
    pub use crate::hash::{Digest, Sha256, Sha512};
    pub use crate::rng::{generate_random_bytes, generate_key};

    // Classical crypto
    #[cfg(feature = "curves")]
    pub use crate::curves::{P256Point, Secp256k1Point};

    #[cfg(feature = "signatures")]
    pub use crate::signatures::ecdsa::{EcdsaP256, SigningKey, VerifyingKey};

    // Post-quantum crypto
    #[cfg(feature = "pq-kem")]
    pub use crate::mlkem::{MlKem768, KeyPair as MlKemKeyPair};

    #[cfg(feature = "pq-sig-mldsa")]
    pub use crate::mldsa::{MlDsa65, SigningKey as MlDsaSigningKey};

    #[cfg(feature = "pq-sig-slhdsa")]
    pub use crate::slhdsa::{SlhDsa128s, SigningKey as SlhDsaSigningKey};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_available() {
        // Just verify that core modules are accessible
        use crate::hash::Digest;
        let _ = hash::Sha256::new();
    }

    #[cfg(feature = "pq-kem")]
    #[test]
    fn test_mlkem_available() {
        use crate::mlkem::{MlKem768, KeyPair};
        let keypair = KeyPair::generate::<MlKem768>();
        let (ct, ss1) = keypair.encapsulate::<MlKem768>();
        let ss2 = keypair.decapsulate::<MlKem768>(&ct);
        assert_eq!(ss1, ss2);
    }
}
