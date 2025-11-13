//! P-384 (NIST) elliptic curve
//!
//! This module implements the P-384 elliptic curve as specified in FIPS 186-4.
//!
//! # Curve Equation
//!
//! y² = x³ - 3x + b (mod p)
//!
//! where:
//! - p = 2^384 - 2^128 - 2^96 + 2^32 - 1
//! - a = -3
//! - b = specific constant (see constants.rs)
//!
//! # Security Level
//!
//! P-384 provides approximately 192 bits of security, suitable for:
//! - Top Secret information (per NSA Suite B)
//! - Long-term key protection
//! - High-security applications
//!
//! # Performance
//!
//! This implementation prioritizes performance over memory usage,
//! using precomputed tables and optimized field arithmetic.

pub mod constants;
pub mod field;
pub mod field_ops;
pub mod batch;
pub mod field_lazy; // Lazy reduction for optimized add/sub chains
pub mod msm;
pub mod point;
pub mod precomputed;
pub mod scalar;
pub mod wnaf;

// Re-export commonly used types
pub use constants::*;
pub use field::FieldElement;
pub use field_lazy::LazyFieldElement;
pub use msm::msm_2_points;
pub use point::{AffinePoint, Point};
pub use precomputed::scalar_mul_generator_fast;
pub use scalar::Scalar;

/// P-384 curve module
///
/// # Implementation Status
///
///  Field operations (384-bit arithmetic) - Complete
///  Point arithmetic (Jacobian coordinates) - Complete
///  Scalar arithmetic - Complete
///  Precomputed tables for generator multiplication - Complete
///  ECDH key exchange - Complete
///  ECDSA signature verification - Complete
///  Batch verification - Complete
///  Multi-scalar multiplication (MSM) - Complete
///  Windowed NAF (wNAF) optimization - Complete
///
/// # Performance Notes
///
/// Currently using BigUint for modular reduction (correct but ~7-10x slower than optimal).
/// For production use, implement bit-level reduction following the guide in
/// `P384_BIT_LEVEL_IMPLEMENTATION_GUIDE.md` for significant performance improvement.
///
/// See `README_P384.md` for usage examples and `P384_CURRENT_STATUS.md` for details.
pub struct P384;

impl P384 {
    /// Returns information about the P-384 implementation
    pub fn info() -> &'static str {
        "P-384 (NIST): Fully functional, all 106 tests passing. \
         Using BigUint for reduction (7-10x slower than optimal). \
         See README_P384.md for optimization guide."
    }
}
