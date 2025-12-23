//! Hardware-accelerated AES implementations.
//!
//! Provides SIMD-optimized AES using platform-specific intrinsics with
//! runtime feature detection.
//!
//! # Platforms
//!
//! - **x86/x86_64**: AES-NI with 8-block parallel processing
//! - **aarch64**: ARM NEON with 4-block parallel processing
//!
//! # Security
//!
//! All implementations are constant-time with no table lookups.

// Re-export CPU feature detection from hpcrypt-core
pub use hpcrypt_core::cpufeatures::{has_aes_neon, has_aesni};

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod aesni;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use aesni::{AesNi128, AesNi192, AesNi256};

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub type AesNi = AesNi128;

#[cfg(target_arch = "aarch64")]
pub mod neon;

#[cfg(target_arch = "aarch64")]
pub use neon::{AesNeon128, AesNeon192, AesNeon256};
