//! Ed448-Goldilocks Edwards Curve
//!
//! This module implements the Ed448 Edwards curve as specified in RFC 8032.
//! Ed448 provides approximately 224 bits of security, significantly higher
//! than Ed25519's 128 bits.
//!
//! # Security Level
//!
//! Ed448 offers very high security:
//! - 224-bit security level
//! - Resistant to quantum attacks (112-bit post-quantum security)
//! - Suitable for long-term security requirements
//!
//! # Curve Equation
//!
//! x² + y² = 1 - 39081·x²·y²
//!
//! # Performance
//!
//! Ed448 is approximately 2-3x slower than Ed25519 due to:
//! - Larger field (448-bit vs 256-bit)
//! - More expensive operations
//!
//! However, the Goldilocks prime (2^448 - 2^224 - 1) enables very efficient
//! field arithmetic, making Ed448 faster than you might expect.
//!
//! # Example Usage
//!
//! ```ignore
//! use hpcrypt_curves::ed448::Ed448;
//!
//! // Generate keypair (use secure random in production)
//! let private_key = [0u8; 57];
//! let public_key = Ed448::public_key(&private_key);
//!
//! // Sign message
//! let message = b"Hello, Ed448!";
//! let signature = Ed448::sign(&private_key, message);
//!
//! // Verify signature
//! assert!(Ed448::verify(&public_key, message, &signature));
//! ```

pub mod constants;
pub mod field;
pub mod point;
pub mod scalar;
pub mod sign;
pub mod sliding;

pub use constants::*;
pub use field::FieldElement;
pub use point::{scalar_mul_base_comb, NielsPoint, Point};
pub use scalar::Scalar;
pub use sign::{public_key, sign, verify, PublicKey, Signature};

#[cfg(feature = "std")]
pub use point::CombTable;
