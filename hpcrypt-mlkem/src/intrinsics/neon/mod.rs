//! ARM NEON Intrinsics Implementation for ML-KEM
//!
//! This module provides optimized ARM NEON SIMD implementations for ML-KEM.
//! Only functions that are **faster** than portable code are included.
//!
//! # Included Functions (Faster than Portable)
//!
//! | Function | Speedup | Used In |
//! |----------|---------|---------|
//! | `ntt_inplace` | 1.06x | All parameter sets |
//! | `intt_inplace` | 1.19x | All parameter sets |
//! | `cbd2` | 1.82x | ML-KEM-768/1024 |
//! | `compress_d10` | 1.08x | ML-KEM-768/1024 |
//!
//! # Excluded Functions (Same or Slower than Portable)
//!
//! - `cbd3` - 15% slower (ML-KEM-512 uses portable)
//! - `decompress_*` - Same performance (portable auto-vectorizes)
//! - `poly_add/sub` - Same performance
//! - `serialize` functions - 3-4x slower
//! - `ct_compare/ct_select` - Same or slower

#![allow(clippy::too_many_arguments)]

pub mod consts;
pub mod arith;
pub mod ntt;
pub mod sampling;
pub mod compress;

// Re-export faster functions
pub use ntt::{ntt_inplace, intt_inplace};
pub use sampling::cbd2;
pub use compress::compress_d10;

/// Check if NEON is available at runtime
#[inline]
pub fn is_available() -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "std"))]
    {
        true // NEON is mandatory on AArch64
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "std")))]
    {
        true // Assume NEON is available on AArch64
    }
    #[cfg(all(target_arch = "arm", feature = "std"))]
    {
        std::arch::is_arm_feature_detected!("neon")
    }
    #[cfg(all(target_arch = "arm", not(feature = "std")))]
    {
        cfg!(target_feature = "neon")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    {
        false
    }
}
