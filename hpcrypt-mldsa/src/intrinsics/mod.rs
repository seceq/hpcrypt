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
pub mod dispatch {
    /// Check if AVX2 is available at runtime
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub fn has_avx2() -> bool {
        #[cfg(feature = "avx2")]
        {
            #[cfg(feature = "std")]
            {
                std::arch::is_x86_feature_detected!("avx2")
            }
            #[cfg(not(feature = "std"))]
            {
                // In no_std mode, assume AVX2 if feature enabled
                true
            }
        }
        #[cfg(not(feature = "avx2"))]
        {
            false
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline]
    pub fn has_avx2() -> bool {
        false
    }

    /// Check if NEON is available at runtime
    #[cfg(target_arch = "aarch64")]
    #[inline]
    pub fn has_neon() -> bool {
        #[cfg(feature = "neon")]
        {
            true // NEON is always available on AArch64
        }
        #[cfg(not(feature = "neon"))]
        {
            false
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    pub fn has_neon() -> bool {
        false
    }
}
