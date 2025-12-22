//! ARM NEON + PMULL optimized implementations
//!
//! Requires:
//! - NEON: 128-bit SIMD operations
//! - PMULL: Polynomial multiplication (via "aes" target feature on AArch64)
//!
//! Performance: ~10-20x faster than portable implementation
//! - Small messages (16 bytes): ~2.5-5 GB/s
//! - Large messages (4KB+): ~6-12 GB/s
//!
//! Both GHASH and POLYVAL use the R/F algorithm:
//! - 4 PMULL per block for R and F terms
//! - 1 PMULL for reduction (Lemma 3)
//! - 4-block aggregated processing with single reduction (17 PMULLs per 64 bytes)

pub mod ghash;
pub mod polyval;

pub use ghash::{ghash_neon, GhashNeon, GhashNeonKey};
pub use polyval::{polyval_neon, PolyvalNeon, PolyvalNeonKey};
