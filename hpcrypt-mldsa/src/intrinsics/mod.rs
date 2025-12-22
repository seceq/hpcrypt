//! High-Performance SIMD Intrinsics for ML-DSA
//!
//! This module provides optimized implementations using CPU-specific
//! SIMD intrinsics for maximum performance.
//!
//! # Supported Architectures
//!
//! - **x86_64 AVX2**: 256-bit SIMD for Intel/AMD processors (Sandy Bridge+)
//! - **aarch64 NEON**: 128-bit SIMD for ARM processors (Apple Silicon, Cortex-A, etc.)

// x86_64 AVX2 implementation
#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
pub mod avx2;

// ARM64 NEON implementation
#[cfg(all(feature = "neon", target_arch = "aarch64"))]
pub mod neon;

/// Runtime dispatch helpers
///
/// Re-exports from `hpcrypt-core::cpufeatures` for runtime CPU feature detection.
pub mod dispatch {
    pub use hpcrypt_core::cpufeatures::{has_avx2, has_neon};
}
