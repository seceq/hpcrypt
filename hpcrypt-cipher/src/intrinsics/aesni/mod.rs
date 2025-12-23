//! AES-NI hardware-accelerated implementation.
//!
//! Provides AES using Intel AES-NI instructions with 8-block parallel
//! processing. All operations are constant-time.

mod keysched;
mod encrypt;
mod decrypt;

#[cfg(test)]
mod tests;

pub use keysched::{AesNi128, AesNi192, AesNi256};

/// Type alias for AES-128.
pub type AesNi = AesNi128;
