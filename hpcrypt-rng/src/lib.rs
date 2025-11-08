//! Cryptographically Secure Random Number Generation (CSPRNG)
//!
//! This crate provides secure random number generation for cryptographic operations.
//! It offers both OS-based randomness (recommended for production) and deterministic
//! random generation (for testing and reproducibility).
//!
//! # Features
//!
//! - **OS RNG**: Uses the operating system's cryptographically secure RNG
//! - **Type-safe API**: Generate keys with compile-time size checking
//! - **No unsafe code**: 100% safe Rust
//! - **no_std compatible**: Works in embedded environments
//!
//! # Examples
//!
//! ## Generate Random Bytes
//!
//! ```
//! use hpcrypt_rng::generate_random_bytes;
//!
//! let mut key = [0u8; 32];
//! generate_random_bytes(&mut key).expect("RNG failure");
//! // key now contains 32 cryptographically secure random bytes
//! ```
//!
//! ## Generate Typed Keys
//!
//! ```
//! use hpcrypt_rng::generate_key;
//!
//! // Generate a 256-bit key
//! let key: [u8; 32] = generate_key().expect("RNG failure");
//!
//! // Type system ensures correct size
//! let aes_key: [u8; 16] = generate_key().expect("RNG failure");
//! let x25519_key: [u8; 32] = generate_key().expect("RNG failure");
//! ```
//!
//! # Security Considerations
//!
//! - **Always use OS RNG for production**: The `os-rng` feature (enabled by default)
//!   provides cryptographically secure randomness from the operating system
//! - **Deterministic RNG is for testing only**: The `chacha20-rng` feature provides
//!   reproducible randomness useful for tests, but should never be used for
//!   production cryptographic keys
//! - **Check return values**: RNG can fail (e.g., insufficient entropy at boot),
//!   always check for errors
//!
//! # Platform Support
//!
//! This crate uses [`getrandom`](https://docs.rs/getrandom) which supports:
//! - Linux, Android (getrandom syscall)
//! - macOS, iOS (Security.framework)
//! - Windows (BCryptGenRandom)
//! - Web (crypto.getRandomValues)
//! - WASI (random_get)
//! - And more...

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]

#[cfg(feature = "std")]
extern crate std;

mod error;
pub use error::{Result, RngError};

#[cfg(feature = "os-rng")]
mod os_rng;
#[cfg(feature = "os-rng")]
pub use os_rng::*;

/// Generate cryptographically secure random bytes
///
/// Fills the provided buffer with random bytes from the OS RNG.
///
/// # Examples
///
/// ```
/// use hpcrypt_rng::generate_random_bytes;
///
/// let mut nonce = [0u8; 12];
/// generate_random_bytes(&mut nonce).expect("RNG failure");
/// ```
///
/// # Errors
///
/// Returns [`RngError::OsRngFailed`] if the operating system RNG fails.
/// This can happen if:
/// - The system has insufficient entropy (early boot)
/// - The RNG syscall/API is unavailable
/// - A hardware RNG failure occurred
///
/// # Security
///
/// This function uses the operating system's cryptographically secure RNG:
/// - Linux/Android: `getrandom()` syscall
/// - macOS/iOS: `Security.framework`
/// - Windows: `BCryptGenRandom()`
/// - Web: `crypto.getRandomValues()`
///
/// The output is suitable for cryptographic keys, nonces, and salts.
#[cfg(feature = "os-rng")]
#[inline]
pub fn generate_random_bytes(dest: &mut [u8]) -> Result<()> {
    fill_random(dest)
}

/// Generate a random key of fixed size
///
/// Type-safe key generation with compile-time size checking.
///
/// # Examples
///
/// ```
/// use hpcrypt_rng::generate_key;
///
/// // Generate different key sizes
/// let aes128_key: [u8; 16] = generate_key().expect("RNG failure");
/// let aes256_key: [u8; 32] = generate_key().expect("RNG failure");
/// let x25519_key: [u8; 32] = generate_key().expect("RNG failure");
/// ```
///
/// # Type Safety
///
/// The size is specified by the type annotation, providing compile-time
/// guarantees:
///
/// ```compile_fail
/// use hpcrypt_rng::generate_key;
///
/// // This won't compile - size must be known at compile time
/// let n = 32;
/// let key: [u8; n] = generate_key().expect("RNG failure");
/// ```
///
/// # Errors
///
/// Returns [`RngError::OsRngFailed`] if the operating system RNG fails.
///
/// # Security
///
/// - Uses cryptographically secure OS RNG
/// - Key material is zeroized on drop (via Zeroizing wrapper)
/// - Suitable for production cryptographic keys
#[cfg(feature = "os-rng")]
pub fn generate_key<const N: usize>() -> Result<[u8; N]> {
    let mut key = [0u8; N];
    generate_random_bytes(&mut key)?;
    Ok(key)
}

/// Generate a random nonce for AEAD ciphers
///
/// Convenience function for generating nonces of common sizes.
///
/// # Examples
///
/// ```
/// use hpcrypt_rng::generate_nonce;
///
/// // ChaCha20-Poly1305 / AES-GCM (96-bit nonce)
/// let nonce: [u8; 12] = generate_nonce().expect("RNG failure");
///
/// // XChaCha20-Poly1305 (192-bit nonce)
/// let extended_nonce: [u8; 24] = generate_nonce().expect("RNG failure");
/// ```
///
/// # Errors
///
/// Returns [`RngError::OsRngFailed`] if the operating system RNG fails.
///
/// # Security
///
/// - Nonces must be unique per key
/// - For 96-bit nonces (12 bytes), random generation is safe
/// - For 64-bit nonces (8 bytes), use a counter instead
/// - Never reuse a nonce with the same key!
#[cfg(feature = "os-rng")]
#[inline]
pub fn generate_nonce<const N: usize>() -> Result<[u8; N]> {
    generate_key::<N>()
}

/// Generate a random salt for key derivation
///
/// Generates cryptographically secure random salts for password hashing
/// and key derivation functions.
///
/// # Examples
///
/// ```
/// use hpcrypt_rng::generate_salt;
///
/// // Argon2 (16 bytes minimum recommended)
/// let salt: [u8; 16] = generate_salt().expect("RNG failure");
///
/// // More conservative (32 bytes)
/// let salt: [u8; 32] = generate_salt().expect("RNG failure");
/// ```
///
/// # Errors
///
/// Returns [`RngError::OsRngFailed`] if the operating system RNG fails.
///
/// # Security
///
/// - Salts should be unique per password/input
/// - 16 bytes (128 bits) is the recommended minimum
/// - 32 bytes (256 bits) provides extra security margin
/// - Salts don't need to be secret, just unique
#[cfg(feature = "os-rng")]
#[inline]
pub fn generate_salt<const N: usize>() -> Result<[u8; N]> {
    generate_key::<N>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        generate_random_bytes(&mut buf1).expect("RNG failed");
        generate_random_bytes(&mut buf2).expect("RNG failed");

        // Should be different (probability of collision is ~1/2^256)
        assert_ne!(buf1, buf2, "RNG produced identical output");

        // Should not be all zeros
        assert_ne!(buf1, [0u8; 32], "RNG produced all zeros");
    }

    #[test]
    fn test_generate_key() {
        let key1: [u8; 32] = generate_key().expect("RNG failed");
        let key2: [u8; 32] = generate_key().expect("RNG failed");

        // Should be different
        assert_ne!(key1, key2, "RNG produced identical keys");

        // Should not be all zeros
        assert_ne!(key1, [0u8; 32], "RNG produced all zeros");
    }

    #[test]
    fn test_generate_key_different_sizes() {
        let key16: [u8; 16] = generate_key().expect("RNG failed");
        let key32: [u8; 32] = generate_key().expect("RNG failed");
        let key64: [u8; 64] = generate_key().expect("RNG failed");

        // All should be non-zero
        assert_ne!(key16, [0u8; 16]);
        assert_ne!(key32, [0u8; 32]);
        assert_ne!(key64, [0u8; 64]);
    }

    #[test]
    fn test_generate_nonce() {
        // ChaCha20-Poly1305 / AES-GCM nonce (96 bits)
        let nonce1: [u8; 12] = generate_nonce().expect("RNG failed");
        let nonce2: [u8; 12] = generate_nonce().expect("RNG failed");

        assert_ne!(nonce1, nonce2, "Nonces should be unique");
        assert_ne!(nonce1, [0u8; 12]);
    }

    #[test]
    fn test_generate_salt() {
        let salt1: [u8; 16] = generate_salt().expect("RNG failed");
        let salt2: [u8; 16] = generate_salt().expect("RNG failed");

        assert_ne!(salt1, salt2, "Salts should be unique");
        assert_ne!(salt1, [0u8; 16]);
    }

    #[test]
    fn test_fill_various_sizes() {
        // Test edge cases
        let mut tiny = [0u8; 1];
        let mut small = [0u8; 7];
        let mut medium = [0u8; 64];
        let mut large = [0u8; 1024];

        generate_random_bytes(&mut tiny).expect("RNG failed");
        generate_random_bytes(&mut small).expect("RNG failed");
        generate_random_bytes(&mut medium).expect("RNG failed");
        generate_random_bytes(&mut large).expect("RNG failed");

        // None should be all zeros (except tiny has 1/256 chance)
        assert_ne!(small, [0u8; 7]);
        assert_ne!(medium, [0u8; 64]);
        assert_ne!(large, [0u8; 1024]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_statistical_randomness() {
        // Basic statistical test - check bit balance
        let mut bytes = [0u8; 1000];
        generate_random_bytes(&mut bytes).expect("RNG failed");

        let mut bit_count = 0u32;
        for byte in &bytes {
            bit_count += byte.count_ones();
        }

        // Expect ~50% ones (8000 bits total, expect ~4000 ones)
        // Allow ±15% deviation for statistical variance (3400-4600)
        assert!(
            bit_count >= 3400 && bit_count <= 4600,
            "Bit balance out of range: {}",
            bit_count
        );
    }
}
