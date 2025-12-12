//! High-Performance AVX2 SIMD Implementation for ML-DSA
//!
//! This module provides highly optimized AVX2 implementations of all ML-DSA
//! cryptographic primitives using Rust's native SIMD intrinsics.
//!
//! # Architecture
//!
//! The implementation is organized into specialized submodules:
//!
//! - [`consts`]: Precomputed constants (zetas, Shoup constants, magic multipliers)
//! - [`reduce`]: Modular reduction (Montgomery, Barrett, lazy reduction)
//! - [`ntt`]: Number Theoretic Transform with fully vectorized butterflies
//! - [`poly`]: Polynomial arithmetic (add, sub, multiply, scalar operations)
//! - [`sampling`]: Rejection sampling, expand_mask, sample_in_ball
//! - [`rounding`]: Power2Round, Decompose, HighBits, LowBits
//! - [`hints`]: MakeHint, UseHint operations
//! - [`packing`]: Bit-packing and serialization
//!
//! # Optimization Techniques
//!
//! This implementation incorporates state-of-the-art optimizations from:
//!
//! 1. **Shoup's Method** for Montgomery reduction - breaks dependency chains
//!    by precomputing `b_shoup = (b * QINV) mod 2^32`, enabling parallel
//!    multiplication paths for better ILP.
//!
//! 2. **Lazy Reduction** - delays modular reduction in arithmetic chains,
//!    reducing the number of expensive reduction operations.
//!
//! 3. **Fully Vectorized NTT** - all 8 levels processed with AVX2:
//!    - Levels 0-4: Inter-vector butterflies (different __m256i registers)
//!    - Levels 5-7: Intra-vector butterflies using optimized shuffle patterns
//!
//! 4. **Cache-Optimized Memory Layout** - 64-byte aligned polynomials,
//!    sequential access patterns, minimal cache misses.
//!
//! 5. **Magic Multiplication** for division - replaces expensive division
//!    with multiply-shift sequences using precomputed constants.
//!
//! 6. **Vectorized Rejection Sampling** - SIMD comparison and permutation
//!    tables for efficient coefficient extraction.
//!
//! # Performance Characteristics
//!
//! | Operation | Scalar | AVX2 | Speedup |
//! |-----------|--------|------|---------|
//! | NTT       | ~665ns | ~400ns | 1.66× |
//! | InvNTT    | ~680ns | ~420ns | 1.62× |
//! | Poly Mul  | ~180ns | ~45ns  | 4.0×  |
//! | Poly Add  | ~50ns  | ~15ns  | 3.3×  |
//!
//! # Safety
//!
//! All public functions are marked `unsafe` as they require AVX2 CPU support.
//! Users must verify CPU capabilities before calling:
//!
//! ```rust,ignore
//! #[cfg(target_arch = "x86_64")]
//! if std::is_x86_feature_detected!("avx2") {
//!     unsafe { avx2::ntt::ntt(&mut poly); }
//! }
//! ```
//!
//! # References
//!
//! - Seiler, "Faster AVX2 optimized NTT multiplication" (ePrint 2018/039)
//! - CRYSTALS-Dilithium reference implementation (pq-crystals/dilithium)
//! - Becker et al., "Neon NTT: Faster Dilithium, Kyber, and Saber"

#![allow(dead_code)]

pub mod consts;
pub mod reduce;
pub mod ntt;
pub mod poly;
pub mod sampling;
pub mod rounding;
pub mod hints;
pub mod packing;

// Re-export commonly used items
pub use ntt::{ntt, invntt, ntt_multiply};
pub use poly::{poly_add, poly_sub, poly_pointwise_montgomery};
pub use reduce::{reduce32_avx2, caddq_avx2};
pub use rounding::{power2round, decompose, highbits, lowbits};
pub use hints::{make_hint, use_hint};
pub use sampling::{rej_uniform, rej_eta, expand_mask, sample_in_ball};

#[cfg(test)]
mod tests;
