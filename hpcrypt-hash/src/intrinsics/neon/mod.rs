//! NEON-optimized Keccak/SHA-3 implementations.
//!
//! Provides SIMD-optimized Keccak-f[1600] permutation for AArch64 platforms.
//!
//! # Single-State vs Parallel
//!
//! For single-state operations, scalar code with unrolled loops outperforms NEON
//! due to vector load/store overhead. The 4-way parallel implementation provides
//! approximately 2x speedup when processing multiple independent states.
//!
//! # NEON Register Layout
//!
//! NEON provides 128-bit registers (`uint64x2_t` = 2 x u64). For 4-way parallel:
//! - `lo[i]` holds lanes from states 0 and 1
//! - `hi[i]` holds lanes from states 2 and 3

mod keccak;

pub use keccak::*;
