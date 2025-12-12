//! SIMD Intrinsics Implementations for ML-KEM
//!
//! This module contains highly-optimized SIMD implementations using
//! hardware intrinsics. Currently supports:
//!
//! - **AVX2**: x86-64 256-bit SIMD (Intel Haswell+, AMD Zen+)
//! - **NEON**: ARM 128-bit SIMD (AArch64)
//!
//! # Module Organization
//!
//! ```text
//! intrinsics/
//! ├── mod.rs          (this file)
//! ├── avx2/           (AVX2 implementation)
//! │   ├── mod.rs      (module root, re-exports)
//! │   ├── consts.rs   (pre-computed constants)
//! │   ├── arith.rs    (Montgomery/Barrett arithmetic)
//! │   ├── ntt.rs      (NTT/INTT transforms)
//! │   ├── poly.rs     (polynomial operations)
//! │   ├── sampling.rs (CBD, rejection sampling)
//! │   ├── compress.rs (compression/decompression)
//! │   └── serialize.rs(byte encoding/decoding)
//! └── neon/           (NEON implementation - faster functions only)
//!     ├── mod.rs      (module root, re-exports)
//!     ├── consts.rs   (pre-computed constants)
//!     ├── arith.rs    (Montgomery/Barrett arithmetic)
//!     ├── ntt.rs      (NTT/INTT - 1.06-1.19x faster)
//!     ├── sampling.rs (CBD2 only - 1.82x faster)
//!     └── compress.rs (compress_d10 - 8% faster)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use hpcrypt_mlkem::intrinsics;
//!
//! // Check for AVX2 support
//! if intrinsics::avx2::is_available() {
//!     unsafe {
//!         intrinsics::avx2::ntt::ntt_inplace(&mut coeffs);
//!     }
//! }
//! ```
//!
//! # Performance
//!
//! | Operation | Portable | AVX2 | Speedup |
//! |-----------|----------|------|---------|
//! | NTT | ~1500 cycles | ~320 cycles | 4.7x |
//! | INTT | ~1500 cycles | ~290 cycles | 5.2x |
//! | Basemul | ~800 cycles | ~180 cycles | 4.4x |
//! | Full Keygen | ~40 µs | ~10 µs | 4.0x |
//!
//! # CPU Support
//!
//! - **AVX2**: Intel Haswell (2013) and later, AMD Zen (2017) and later.
//!
//! # Safety
//!
//! All functions in the SIMD modules require appropriate CPU support.
//! Using them on unsupported CPUs will cause illegal instruction faults.
//! Always check `is_available()` or compile with appropriate target features.

#[cfg(target_arch = "x86_64")]
pub mod avx2;

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub mod neon;

/// Check if any SIMD intrinsics are available on this platform
pub fn simd_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        avx2::is_available()
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        neon::is_available()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
    {
        false
    }
}

/// Check if AVX2 is available
#[cfg(target_arch = "x86_64")]
pub fn avx2_available() -> bool {
    avx2::is_available()
}

/// Get the name of the best available SIMD implementation
pub fn best_simd_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if avx2::is_available() {
            "AVX2"
        } else {
            "None"
        }
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        if neon::is_available() {
            "NEON"
        } else {
            "None"
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
    {
        "None"
    }
}

/// SIMD tier enum for dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdTier {
    /// AVX2 (256-bit vectors, 16 i16 per vector)
    Avx2,
    /// NEON (128-bit vectors, 8 i16 per vector)
    Neon,
    /// No SIMD, portable fallback
    None,
}

/// Get the best available SIMD tier
pub fn best_simd_tier() -> SimdTier {
    #[cfg(target_arch = "x86_64")]
    {
        if avx2::is_available() {
            SimdTier::Avx2
        } else {
            SimdTier::None
        }
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        if neon::is_available() {
            SimdTier::Neon
        } else {
            SimdTier::None
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
    {
        SimdTier::None
    }
}
