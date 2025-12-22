//! Hardware intrinsics implementations for MAC algorithms
//!
//! This module provides optimized implementations using CPU-specific
//! SIMD instructions when available.
//!
//! Runtime dispatch is used to select the best implementation at runtime
//! based on detected CPU features.

// Intrinsics require unsafe code
#![allow(unsafe_code)]

// x86/x86_64 AVX2 + PCLMULQDQ implementation
// Always compile on x86/x86_64 targets for runtime dispatch
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod avx2;

// ARM64 NEON + PMULL implementation
// Always compile on aarch64 for runtime dispatch
#[cfg(target_arch = "aarch64")]
pub mod neon;

/// Runtime dispatch helpers
///
/// Re-exports from `hpcrypt-core::cpufeatures` for runtime CPU feature detection.
pub mod dispatch {
    pub use hpcrypt_core::cpufeatures::{
        has_avx2, has_avx2_pclmulqdq, has_neon, has_neon_aes, best_clmul_tier, SimdTier,
    };
}
