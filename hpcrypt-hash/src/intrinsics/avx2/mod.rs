//! AVX2-optimized Keccak/SHA-3 implementations.
//!
//! Provides SIMD-optimized Keccak-f[1600] permutation for x86/x86_64 platforms.
//!
//! # Single-State vs Parallel
//!
//! For single-state operations, scalar code with unrolled loops outperforms AVX2
//! due to vector load/store overhead. The 4-way parallel implementation provides
//! 3-4x speedup when processing multiple independent states.
//!
//! # Platform Notes
//!
//! On AMD CPUs, single-state AVX2 Keccak is slower than scalar. The safe wrapper
//! functions automatically detect this and use the scalar path.

mod keccak;

pub use keccak::*;
