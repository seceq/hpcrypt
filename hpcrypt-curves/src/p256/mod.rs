//! NIST P-256 (secp256r1) Elliptic Curve
//!
//! This module implements the NIST P-256 elliptic curve as specified in
//! FIPS 186-4: Digital Signature Standard (DSS).
//!
//! # Security
//!
//! - All operations are designed to be constant-time to prevent timing attacks
//! - Field arithmetic uses the `subtle` crate for constant-time operations
//! - Point arithmetic will use complete addition formulas
//!
//! # Standards Compliance
//!
//! - **FIPS 186-4**: Digital Signature Standard
//! - **SEC 2**: Recommended Elliptic Curve Domain Parameters
//! - **RFC 5480**: Elliptic Curve Cryptography Subject Public Key Information
//!
//! # Example
//!
//! ```rust
//! use hpcrypt_curves::p256::FieldElement;
//!
//! // Create field elements
//! let a = FieldElement::from_u64(42);
//! let b = FieldElement::from_u64(58);
//!
//! // Add them
//! let c = a + b;
//!
//! // Should equal 100
//! assert_eq!(c, FieldElement::from_u64(100));
//! ```

pub mod constants;
pub mod field;
pub mod field_ops;
// pub mod field_montgomery; // fiat-crypto Montgomery implementation (deprecated, kept for reference)
pub mod field_lazy;
pub mod field_montgomery_native; // Native high-performance Montgomery implementation // Lazy reduction for optimized add/sub chains

// SIMD modules removed - see /home/maamoun/hpcrypt_simd_work/ for SIMD implementations

/// Elliptic curve point operations for P-256.
///
/// This module provides point addition, doubling, and scalar multiplication
/// operations for the NIST P-256 elliptic curve in Jacobian coordinates.
///
/// All operations are designed to be constant-time to resist side-channel attacks.
pub mod point;

/// Scalar arithmetic modulo the curve order n.
///
/// This module provides modular arithmetic operations for scalars used in
/// ECDSA signature generation and verification.
pub mod scalar;

/// Precomputed tables for fast generator multiplication.
///
/// This module provides optimized scalar multiplication for the base point (generator)
/// using precomputed tables and windowed multiplication. This is 5-10x faster than
/// generic scalar multiplication and is critical for ECDSA signing performance.
pub mod precomputed;

/// Window Non-Adjacent Form (wNAF) for optimized scalar multiplication.
///
/// This module provides wNAF-based scalar multiplication which reduces the number
/// of point additions by ~60% compared to the binary method. Expected speedup: ~35%
/// for variable-base scalar multiplication.
pub mod wnaf;

/// Multi-Scalar Multiplication (MSM) for computing linear combinations efficiently.
///
/// This module implements the Strauss-Shamir algorithm (Shamir's trick) to compute
/// k₁·P₁ + k₂·P₂ approximately 30% faster than separate scalar multiplications.
/// Critical for ECDSA verification performance.
pub mod msm;

/// Batch operations for P-256.
///
/// This module provides optimized batch operations, primarily batch inversion
/// using Montgomery's trick. Batch inversion inverts N field elements at the cost
/// of 1 inversion + 3(N-1) multiplications, providing massive speedups for batch
/// operations like signature verification.
pub mod batch;

pub use batch::batch_invert;
pub use constants::{P256_A, P256_B, P256_GX, P256_GY, P256_MODULUS, P256_ORDER};
pub use field::FieldElement;
pub use field_lazy::LazyFieldElement;
pub use field_montgomery_native::MontgomeryFieldElement;
pub use msm::msm_2_points;
pub use point::{AffinePoint, Point, PointMontgomery};
pub use precomputed::{scalar_mul_generator, scalar_mul_generator_compressed};
pub use scalar::Scalar;
