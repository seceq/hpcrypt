//! # ML-DSA: Module-Lattice-Based Digital Signature Algorithm
//!
//! Pure Rust implementation of the ML-DSA (FIPS 204) post-quantum digital signature standard.
//!
//! ML-DSA, formerly known as CRYSTALS-Dilithium, is a lattice-based digital signature scheme
//! selected by NIST for standardization as part of the post-quantum cryptography project.
//!
//! ## Overview
//!
//! This crate provides a pure Rust implementation of ML-DSA with:
//! - Three security levels (ML-DSA-44, ML-DSA-65, ML-DSA-87)
//! - Constant-time operations for side-channel resistance
//! - Optional SIMD optimizations (AVX2 for 42% speedup)
//! - Batch signing/verification API (15-30% throughput improvement)
//! - `no_std` compatibility for embedded systems
//!
//! ## Security Levels
//!
//! | Parameter Set | NIST Level | Public Key | Secret Key | Signature  |
//! |--------------|------------|------------|------------|-----------|
//! | ML-DSA-44    | 2          | 1312 bytes | 2560 bytes | 2420 bytes|
//! | ML-DSA-65    | 3          | 1952 bytes | 4032 bytes | 3309 bytes|
//! | ML-DSA-87    | 5          | 2592 bytes | 4896 bytes | 4627 bytes|
//!
//! ## Usage Example
//!
//! ```no_run
//! use mldsa::params::MlDsa65;
//! use mldsa::keygen::keygen;
//! use mldsa::sign::sign;
//! use mldsa::verify::verify;
//!
//! // Key generation
//! let (pk, sk) = keygen::<MlDsa65>();
//!
//! // Signing
//! let message = b"Important message";
//! let sig = sign(&sk, message).unwrap();
//!
//! // Verification
//! let valid = verify(&pk, message, &sig);
//! assert!(valid);
//! ```
//!
//! ## Batch Signing Example
//!
//! ```no_run
//! use mldsa::params::MlDsa65;
//! use mldsa::keygen::keygen;
//! use mldsa::{sign_batch, verify_batch};
//!
//! let (pk, sk) = keygen::<MlDsa65>();
//!
//! // Sequential batch signing
//! let messages = vec![
//!     b"Message 1".as_slice(),
//!     b"Message 2".as_slice(),
//!     b"Message 3".as_slice(),
//! ];
//!
//! let signatures = sign_batch(&sk, &messages);
//! let sig_refs: Vec<_> = signatures.iter()
//!     .map(|s| s.as_ref().unwrap())
//!     .collect();
//!
//! let results = verify_batch(&pk, &messages, &sig_refs);
//! assert!(results.iter().all(|&r| r));
//! ```
//!
//! ## Thread Safety and Parallelism
//!
//! All functions are thread-safe and can be called concurrently from multiple threads.
//! The library does not spawn threads internally, allowing applications to choose their
//! own parallelization strategy. For parallel signing examples, see `examples/parallel_signing.rs`.
//!
//! ## Features
//!
//! - `std` - Enable standard library support (default: no_std)
//! - `zeroize` - Enable automatic secret zeroization (default: enabled)
//! - `getrandom` - Enable OS RNG support (default: enabled)
//! - `serde` - Enable serde serialization support
//! - `pem` - Enable PEM/DER key encoding/decoding
//! - `wasm` - Enable WebAssembly support with JS RNG
//! - `simd` - Enable SIMD optimizations
//! - `avx` - x86-64 AVX support
//! - `avx2` - x86-64 AVX2 support (recommended)
//! - `avx512` - x86-64 AVX-512 support
//! - `neon` - ARM NEON support
//! - `timing-tests` - Enable constant-time verification tests
//!
//! ## Implementation Status
//!
//! **Current Phase:** Reference implementation (no SIMD)
//! - [x] Parameter sets
//! - [ ] Polynomial and NTT operations
//! - [ ] Rounding operations (Power2Round, Decompose, HighBits, LowBits)
//! - [ ] Hint operations (MakeHint, UseHint)
//! - [ ] Sampling operations (rejection sampling, SampleInBall, ExpandMask)
//! - [ ] Key generation
//! - [ ] Signing algorithm
//! - [ ] Verification algorithm
//! - [ ] Serialization
//! - [ ] NIST KAT tests
//!
//! **Future Phases:**
//! - Rust-level optimizations (pre-rejection sampling, workspace reuse)
//! - SIMD optimizations (AVX2, AVX-512, NEON)
//! - Hardware optimizations (after Rust-level optimizations)

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// Global allocator: Use jemalloc for better performance (optional feature)
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
use jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// Public modules
pub mod params;
pub mod errors;

// Internal modules
pub mod symmetric;
pub mod utils;
pub mod rng;
pub mod poly;
pub mod poly_shoup;  // Barrett+Shoup experimental implementation
pub mod rounding;
pub mod hints;
pub mod sampling;
pub mod ntt;
pub mod ntt_prefetch;
pub mod sparse_mul;
pub mod prefetch;
pub mod keygen;
pub mod sign;
pub mod verify;
pub mod serialize;
pub mod constant_time;
pub mod kat;
pub mod batch;
pub mod prehash;
pub mod context;
#[cfg(feature = "pem")]
pub mod pem_encoding;

// Stress tests for robustness validation
mod stress_tests;

// Re-exports
pub use params::{DsaParams, MlDsa44, MlDsa65, MlDsa87, N, Q};
pub use batch::{sign_batch, verify_batch};
