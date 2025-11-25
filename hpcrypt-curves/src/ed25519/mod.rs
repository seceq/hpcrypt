//! Ed25519 Digital Signature Algorithm
//!
//! Implementation of Ed25519 signatures following RFC 8032.
//! Ed25519 uses the edwards25519 elliptic curve with the twisted Edwards form:
//!     -x^2 + y^2 = 1 + d*x^2*y^2
//! where d = -121665/121666 mod p
//!
//! # Security
//!
//! Ed25519 provides ~128-bit security level and is designed to be:
//! - Fast: signing and verification are efficient
//! - Secure: resistant to timing attacks
//! - Simple: deterministic signatures, no randomness needed

pub mod constants;
pub mod field;
pub mod point;
pub mod scalar;
pub mod sign;

// Re-export main types
pub use field::FieldElement;
pub use point::{base_point, scalar_mul_base_comb, EdwardsPoint, NielsPoint};
pub use scalar::Scalar;
pub use sign::{Ed25519, PrivateKey, PublicKey, Signature};

#[cfg(feature = "std")]
pub use point::CombTable;

// Convenience module-level functions

/// Generate a public key from a private key (seed)
pub fn public_key(private_key: &PrivateKey) -> PublicKey {
    Ed25519::public_key(private_key)
}

/// Sign a message with a private key
pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Signature {
    Ed25519::sign(private_key, message)
}

/// Verify a signature on a message with a public key
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    Ed25519::verify(public_key, message, signature)
}
