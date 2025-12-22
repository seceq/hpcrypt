//! Hardware-accelerated Keccak implementations.
//!
//! Provides SIMD-optimized Keccak-f[1600] permutation using platform intrinsics.
//! Dispatch logic is handled by the calling code (e.g., `sha3.rs`).
//!
//! # Supported Platforms
//!
//! - **x86/x86_64 with AVX2**: Single-state and 4-way parallel Keccak
//! - **AArch64 with NEON**: Single-state and 4-way parallel Keccak
//!
//! # Usage
//!
//! The raw unsafe functions are re-exported here. Callers are responsible for
//! runtime CPU feature detection before calling these functions.

// x86/x86_64 AVX2 support
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod avx2;

// AArch64 NEON support
#[cfg(target_arch = "aarch64")]
pub mod neon;

// Re-export CPU feature detection from hpcrypt-core
pub use hpcrypt_core::cpufeatures::{has_avx2, has_neon};

/// Returns `true` if running on an AMD CPU.
///
/// Used to select appropriate implementations since AVX2 single-state Keccak
/// performs poorly on AMD due to port binding constraints.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[inline]
pub fn is_amd_cpu() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let cpuid = unsafe { core::arch::x86_64::__cpuid(0) };
        let ebx = cpuid.ebx.to_le_bytes();
        let edx = cpuid.edx.to_le_bytes();
        let ecx = cpuid.ecx.to_le_bytes();
        ebx == *b"Auth" && edx == *b"enti" && ecx == *b"cAMD"
    }
    #[cfg(target_arch = "x86")]
    {
        let cpuid = unsafe { core::arch::x86::__cpuid(0) };
        let ebx = cpuid.ebx.to_le_bytes();
        let edx = cpuid.edx.to_le_bytes();
        let ecx = cpuid.ecx.to_le_bytes();
        ebx == *b"Auth" && edx == *b"enti" && ecx == *b"cAMD"
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
#[inline]
pub fn is_amd_cpu() -> bool {
    false
}

// =============================================================================
// AVX2 re-exports (x86/x86_64)
// =============================================================================

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use avx2::{keccak_f1600_avx2, keccak_p12_avx2, keccak_f1600_x4, keccak_f1600_x4_states, KeccakState4};

// =============================================================================
// NEON re-exports (AArch64)
// =============================================================================

#[cfg(target_arch = "aarch64")]
pub use neon::{keccak_f1600_neon, keccak_p12_neon, keccak_f1600_x4_neon, keccak_f1600_x4_states_neon, KeccakState4Neon};
