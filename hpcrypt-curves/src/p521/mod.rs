//! P-521 (secp521r1) Elliptic Curve
//!
//! This module implements the NIST P-521 elliptic curve as specified in FIPS 186-4.
//!
//! P-521 is a 521-bit elliptic curve that provides approximately 260 bits of security.
//! It uses a Mersenne prime p = 2^521 - 1, which enables very efficient modular reduction.
//!
//! # Security Level
//!
//! P-521 offers the highest security level among the NIST curves:
//! - 260-bit security (vs 128-bit for P-256, 192-bit for P-384)
//! - Suitable for long-term security requirements
//! - Used in applications requiring maximum security
//!
//! # Curve Equation
//!
//! y² = x³ - 3x + b (mod p)
//!
//! Where:
//! - p = 2^521 - 1 (Mersenne prime)
//! - a = p - 3
//! - b = see constants module
//!
//! # Performance
//!
//! P-521 is faster than you might expect due to the Mersenne prime:
//! - Field operations are very efficient
//! - Modular reduction is simpler than P-256
//! - About 2-3x slower than P-256 overall
//!
//! # Example Usage
//!
//! ```ignore
//! use hpcrypt_curves::p521::{FieldElement, Scalar, Point};
//!
//! // Field arithmetic
//! let a = FieldElement::from_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0]);
//! let b = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
//! let c = a.add(&b);  // c = 3
//!
//! // Point operations (when implemented)
//! // let g = Point::generator();
//! // let k = Scalar::from_bytes(&[...]);
//! // let public_key = g.scalar_mul(&k);
//! ```

pub mod batch;
pub mod constants;
pub mod field;
pub mod field_montgomery_native;
pub mod field_ops;
pub mod point;
pub mod precomputed;
pub mod scalar;
pub mod wnaf;

// SIMD modules removed - see /home/maamoun/hpcrypt_simd_work/ for SIMD implementations

pub use constants::*;
pub use field::FieldElement;
pub use point::{AffinePoint, Point};
pub use precomputed::generator_mul;
pub use scalar::Scalar;
