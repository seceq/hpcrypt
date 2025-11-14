//! AES (Advanced Encryption Standard) block cipher
//!
//! This module re-exports the fixslice implementation for high performance
//! and constant-time execution.
//!
//! The fixslice implementation provides:
//! - 3-4x speedup through parallel processing of 4 blocks
//! - Constant-time execution (immune to cache-timing attacks)
//! - Bitsliced operations for modern processors

// Re-export AesFixslice as Aes for transparent integration
pub use crate::aes_fixslice::AesFixslice as Aes;

// Re-export constants from fixslice
pub use crate::aes_fixslice::{AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE};
