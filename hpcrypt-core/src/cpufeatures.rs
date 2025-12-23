//! CPU feature detection for SIMD optimizations
//!
//! This module provides runtime detection of CPU features to enable
//! dynamic dispatch to optimized implementations.
//!
//! # Supported Features
//!
//! - **AVX2**: 256-bit SIMD for x86_64 (Intel Haswell+, AMD Excavator+)
//! - **PCLMULQDQ**: Carry-less multiplication for AES-GCM/GHASH (Intel Westmere+)
//! - **NEON**: 128-bit SIMD for ARM (always available on AArch64)
//! - **AES**: AES instructions for ARM (AESE/AESD/PMULL)
//!
//! # Usage
//!
//! ```
//! use hpcrypt_core::cpufeatures;
//!
//! if cpufeatures::has_avx2() {
//!     // Use AVX2 optimized implementation
//! } else {
//!     // Fall back to portable implementation
//! }
//! ```

/// Check if AVX2 is available at runtime
///
/// Returns `true` if:
/// - Target is x86_64 AND
/// - Either compiled with `target_feature = "avx2"` OR
/// - Runtime detection confirms AVX2 support (requires `std` feature)
#[inline]
pub fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_feature = "avx2")]
        {
            true
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            #[cfg(feature = "std")]
            {
                std::arch::is_x86_feature_detected!("avx2")
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Check if PCLMULQDQ (carry-less multiplication) is available at runtime
///
/// Required for hardware-accelerated GHASH/POLYVAL implementations.
///
/// Returns `true` if:
/// - Target is x86/x86_64 AND
/// - Either compiled with `target_feature = "pclmulqdq"` OR
/// - Runtime detection confirms PCLMULQDQ support (requires `std` feature)
#[inline]
pub fn has_pclmulqdq() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(target_feature = "pclmulqdq")]
        {
            true
        }
        #[cfg(not(target_feature = "pclmulqdq"))]
        {
            #[cfg(feature = "std")]
            {
                std::arch::is_x86_feature_detected!("pclmulqdq")
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Check if both AVX2 and PCLMULQDQ are available
///
/// This combination is required for AVX2-accelerated GHASH/POLYVAL.
#[inline]
pub fn has_avx2_pclmulqdq() -> bool {
    has_avx2() && has_pclmulqdq()
}

/// Check if NEON is available at runtime
///
/// Returns `true` if:
/// - Target is AArch64 (NEON is mandatory) OR
/// - Target is ARM32 with NEON support detected
#[inline]
pub fn has_neon() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        true // NEON is always available on AArch64
    }

    #[cfg(target_arch = "arm")]
    {
        #[cfg(target_feature = "neon")]
        {
            true
        }
        #[cfg(not(target_feature = "neon"))]
        {
            #[cfg(feature = "std")]
            {
                std::arch::is_arm_feature_detected!("neon")
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        }
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    {
        false
    }
}

/// Check if ARM AES/PMULL instructions are available
///
/// Required for hardware-accelerated GHASH/POLYVAL on ARM.
/// On AArch64, this checks for the `aes` feature which includes PMULL.
#[inline]
pub fn has_arm_aes() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        #[cfg(target_feature = "aes")]
        {
            true
        }
        #[cfg(not(target_feature = "aes"))]
        {
            #[cfg(feature = "std")]
            {
                std::arch::is_aarch64_feature_detected!("aes")
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Check if NEON with AES/PMULL is available
///
/// This combination is required for NEON-accelerated GHASH/POLYVAL.
#[inline]
pub fn has_neon_aes() -> bool {
    has_neon() && has_arm_aes()
}

/// SIMD capability tier for dispatch decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdTier {
    /// AVX2 with 256-bit vectors (x86_64)
    Avx2,
    /// NEON with 128-bit vectors (ARM)
    Neon,
    /// No SIMD available, use portable implementation
    None,
}

/// Returns the best available SIMD tier for general computation
#[inline]
pub fn best_simd_tier() -> SimdTier {
    if has_avx2() {
        SimdTier::Avx2
    } else if has_neon() {
        SimdTier::Neon
    } else {
        SimdTier::None
    }
}

/// Returns the best available SIMD tier for polynomial multiplication (GHASH/POLYVAL)
///
/// This requires PCLMULQDQ on x86 or AES/PMULL on ARM.
#[inline]
pub fn best_clmul_tier() -> SimdTier {
    if has_avx2_pclmulqdq() {
        SimdTier::Avx2
    } else if has_neon_aes() {
        SimdTier::Neon
    } else {
        SimdTier::None
    }
}

/// Returns whether any SIMD acceleration is available
#[inline]
pub fn simd_available() -> bool {
    best_simd_tier() != SimdTier::None
}

/// Returns a human-readable name for the best available SIMD tier
#[inline]
pub fn best_simd_name() -> &'static str {
    match best_simd_tier() {
        SimdTier::Avx2 => "AVX2",
        SimdTier::Neon => "NEON",
        SimdTier::None => "None",
    }
}

// =============================================================================
// AES Hardware Acceleration Detection
// =============================================================================

/// Check if AES-NI is available at runtime (x86/x86_64)
///
/// Returns `true` if:
/// - Target is x86/x86_64 AND
/// - AES-NI instructions are available (requires SSE2 as well)
#[inline]
pub fn has_aesni() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        #[cfg(all(target_feature = "aes", target_feature = "sse2"))]
        {
            true
        }
        #[cfg(not(all(target_feature = "aes", target_feature = "sse2")))]
        {
            #[cfg(feature = "std")]
            {
                std::arch::is_x86_feature_detected!("aes")
                    && std::arch::is_x86_feature_detected!("sse2")
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

/// Check if ARM NEON AES is available (aarch64)
///
/// Returns `true` if:
/// - Target is aarch64 AND
/// - AES crypto extensions are available (requires NEON as well)
#[inline]
pub fn has_aes_neon() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        #[cfg(target_feature = "aes")]
        {
            true
        }
        #[cfg(not(target_feature = "aes"))]
        {
            #[cfg(feature = "std")]
            {
                std::arch::is_aarch64_feature_detected!("aes")
                    && std::arch::is_aarch64_feature_detected!("neon")
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// AES implementation selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesImpl {
    /// Software fixslice (constant-time fallback)
    Fixslice,
    /// AES-NI (x86/x86_64)
    AesNi,
    /// ARM NEON with crypto extensions (aarch64)
    AesNeon,
}

/// Selects the optimal AES implementation for the current CPU
#[inline]
pub fn select_aes_impl() -> AesImpl {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    if has_aesni() {
        return AesImpl::AesNi;
    }
    #[cfg(target_arch = "aarch64")]
    if has_aes_neon() {
        return AesImpl::AesNeon;
    }
    AesImpl::Fixslice
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_detection_does_not_panic() {
        // Just verify detection doesn't crash
        let _avx2 = has_avx2();
        let _pclmulqdq = has_pclmulqdq();
        let _neon = has_neon();
        let _arm_aes = has_arm_aes();
        let _tier = best_simd_tier();
        let _clmul_tier = best_clmul_tier();
        let _name = best_simd_name();
    }

    #[test]
    fn test_simd_tier_consistency() {
        let tier = best_simd_tier();
        match tier {
            SimdTier::Avx2 => assert!(has_avx2()),
            SimdTier::Neon => assert!(has_neon()),
            SimdTier::None => assert!(!has_avx2() && !has_neon()),
        }
    }

    #[test]
    fn test_clmul_tier_consistency() {
        let tier = best_clmul_tier();
        match tier {
            SimdTier::Avx2 => assert!(has_avx2_pclmulqdq()),
            SimdTier::Neon => assert!(has_neon_aes()),
            SimdTier::None => assert!(!has_avx2_pclmulqdq() && !has_neon_aes()),
        }
    }

    #[test]
    fn test_aes_detection_does_not_panic() {
        let _aesni = has_aesni();
        let _aes_neon = has_aes_neon();
        let _impl = select_aes_impl();
    }

    #[test]
    fn test_aes_impl_consistency() {
        let impl_choice = select_aes_impl();
        match impl_choice {
            AesImpl::AesNi => assert!(has_aesni()),
            AesImpl::AesNeon => assert!(has_aes_neon()),
            AesImpl::Fixslice => {}
        }
    }
}
