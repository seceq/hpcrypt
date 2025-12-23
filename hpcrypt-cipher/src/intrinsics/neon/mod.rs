//! ARM NEON AES implementation using ARMv8 Cryptographic Extensions.
//!
//! Provides hardware-accelerated AES with 4-block parallel processing.
//! All operations are constant-time.

mod keysched;
mod encrypt;
mod decrypt;

#[cfg(test)]
mod tests;

pub use keysched::{AesNeon128, AesNeon192, AesNeon256};
