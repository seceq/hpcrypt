//! Hash function implementations for SLH-DSA.
//!
//! This module provides both SHA2-256 and SHAKE256 based hash functions
//! with optimizations for context reuse and minimal overhead.

pub mod optimized;
pub mod sha2;
pub mod shake;
pub mod traits;

pub use optimized::PreInitializedSha2;
pub use sha2::Sha2HashFunction;
pub use shake::ShakeHashFunction;
pub use traits::{HashFunction, HashFunctionContext, PrefixedHash};
