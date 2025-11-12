//! Cryptographically Secure Random Number Generator
//!
//! This module provides a CSPRNG interface using the `getrandom` crate,
//! which provides access to the operating system's secure random number generator.
//!
//! # Platform Support
//!
//! - **Linux/Android**: Uses `getrandom()` syscall
//! - **macOS/iOS**: Uses `getentropy()` or `SecRandomCopyBytes()`
//! - **Windows**: Uses `BCryptGenRandom()`
//! - **WASM**: Requires `wasm-bindgen` feature for `crypto.getRandomValues()`
//!
//! # Security
//!
//! This module uses the operating system's CSPRNG, which is suitable for
//! cryptographic key generation and signing randomness. The randomness source is:
//! - Cryptographically secure
//! - Non-blocking on modern systems
//! - Properly seeded by the OS

/// Error type for RNG failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// The RNG is unavailable or failed to generate random bytes
    Unavailable,
}

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RngError::Unavailable => write!(f, "RNG unavailable or failed to generate random bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RngError {}

/// Fill a buffer with cryptographically secure random bytes (non-panicking)
///
/// This function uses the operating system's CSPRNG to fill the provided
/// buffer with random bytes. It is suitable for generating cryptographic keys,
/// nonces, and other security-sensitive random values.
///
/// # Arguments
///
/// * `dest` - The destination buffer to fill with random bytes
///
/// # Returns
///
/// * `Ok(())` if successful
/// * `Err(RngError::Unavailable)` if the RNG fails or getrandom feature is not enabled
///
/// # Examples
///
/// ```
/// use mldsa::rng::try_fill_random;
///
/// let mut buffer = [0u8; 32];
/// try_fill_random(&mut buffer).expect("RNG failure");
/// // buffer now contains 32 cryptographically secure random bytes
/// ```
#[inline]
pub fn try_fill_random(dest: &mut [u8]) -> Result<(), RngError> {
    #[cfg(feature = "getrandom")]
    {
        getrandom::getrandom(dest).map_err(|_| RngError::Unavailable)
    }
    #[cfg(not(feature = "getrandom"))]
    {
        Err(RngError::Unavailable)
    }
}

/// Fill a buffer with cryptographically secure random bytes
///
/// # Panics
///
/// Panics if the RNG fails or getrandom feature is not enabled.
/// For non-panicking version, use `try_fill_random()`.
///
/// # Arguments
///
/// * `dest` - The destination buffer to fill with random bytes
///
/// # Examples
///
/// ```
/// use mldsa::rng::fill_random;
///
/// let mut buffer = [0u8; 32];
/// fill_random(&mut buffer);
/// ```
#[inline]
pub fn fill_random(dest: &mut [u8]) {
    #[cfg(feature = "getrandom")]
    {
        getrandom::getrandom(dest).expect("Failed to generate random bytes from OS CSPRNG")
    }
    #[cfg(not(feature = "getrandom"))]
    {
        panic!("getrandom feature not enabled - cannot generate random bytes")
    }
}

/// Generate a random 32-byte array (non-panicking)
///
/// # Returns
///
/// * `Ok([u8; 32])` - 32 bytes of random data
/// * `Err(RngError)` - RNG failure
#[inline]
pub fn try_random_bytes_32() -> Result<[u8; 32], RngError> {
    let mut bytes = [0u8; 32];
    try_fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Generate a random 32-byte array
///
/// # Panics
///
/// Panics if RNG fails. For non-panicking version, use `try_random_bytes_32()`.
#[inline]
pub fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    bytes
}

/// Generate a random 64-byte array (non-panicking)
///
/// # Returns
///
/// * `Ok([u8; 64])` - 64 bytes of random data
/// * `Err(RngError)` - RNG failure
#[inline]
pub fn try_random_bytes_64() -> Result<[u8; 64], RngError> {
    let mut bytes = [0u8; 64];
    try_fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Generate a random 64-byte array
///
/// # Panics
///
/// Panics if RNG fails. For non-panicking version, use `try_random_bytes_64()`.
#[inline]
pub fn random_bytes_64() -> [u8; 64] {
    let mut bytes = [0u8; 64];
    fill_random(&mut bytes);
    bytes
}

mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_fill_random() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        fill_random(&mut buf1);
        fill_random(&mut buf2);

        // Extremely unlikely that two random 32-byte sequences are identical
        assert_ne!(buf1, buf2);

        // Check that the buffers were actually modified
        assert_ne!(buf1, [0u8; 32]);
        assert_ne!(buf2, [0u8; 32]);
    }

    #[test]
    fn test_try_fill_random() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        try_fill_random(&mut buf1).unwrap();
        try_fill_random(&mut buf2).unwrap();

        assert_ne!(buf1, buf2);
        assert_ne!(buf1, [0u8; 32]);
        assert_ne!(buf2, [0u8; 32]);
    }

    #[test]
    fn test_fill_random_different_sizes() {
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 64];

        fill_random(&mut buf1);
        fill_random(&mut buf2);

        assert_ne!(buf1, [0u8; 16]);
        assert_ne!(buf2, [0u8; 64]);
    }

    #[test]
    fn test_random_bytes_32() {
        let bytes1 = random_bytes_32();
        let bytes2 = random_bytes_32();

        // Should be different
        assert_ne!(bytes1, bytes2);

        // Should not be all zeros
        assert_ne!(bytes1, [0u8; 32]);
        assert_ne!(bytes2, [0u8; 32]);
    }

    #[test]
    fn test_try_random_bytes_32() {
        let bytes1 = try_random_bytes_32().unwrap();
        let bytes2 = try_random_bytes_32().unwrap();

        assert_ne!(bytes1, bytes2);
        assert_ne!(bytes1, [0u8; 32]);
        assert_ne!(bytes2, [0u8; 32]);
    }

    #[test]
    fn test_random_bytes_64() {
        let bytes1 = random_bytes_64();
        let bytes2 = random_bytes_64();

        // Should be different
        assert_ne!(bytes1, bytes2);

        // Should not be all zeros
        assert_ne!(bytes1, [0u8; 64]);
        assert_ne!(bytes2, [0u8; 64]);
    }

    #[test]
    fn test_random_bytes_32_multiple_calls() {
        let mut results = Vec::new();
        for _ in 0..10 {
            results.push(random_bytes_32());
        }

        // Check that all results are unique (extremely high probability)
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                assert_ne!(results[i], results[j], "Generated duplicate random values");
            }
        }
    }

    #[test]
    fn test_fill_random_empty_buffer() {
        let mut buf = [];
        fill_random(&mut buf); // Should not panic
    }

    #[test]
    fn test_fill_random_single_byte() {
        let mut buf1 = [0u8; 1];
        let mut buf2 = [0u8; 1];

        fill_random(&mut buf1);
        fill_random(&mut buf2);

        // At least one should be non-zero (very high probability)
        assert!(buf1[0] != 0 || buf2[0] != 0);
    }
}
