//! Operating system random number generator
//!
//! Uses the OS's cryptographically secure RNG via the `getrandom` crate.

use crate::{Result, RngError};

/// Fill buffer with random bytes from OS RNG
///
/// This is the core OS RNG function that all other functions use.
///
/// # Platform Support
///
/// - **Linux/Android**: `getrandom()` syscall
/// - **macOS/iOS**: `Security.framework`
/// - **Windows**: `BCryptGenRandom()`
/// - **Web**: `crypto.getRandomValues()`
/// - **WASI**: `random_get()`
///
/// # Errors
///
/// Returns [`RngError::OsRngFailed`] if:
/// - The system has insufficient entropy
/// - The RNG syscall is unavailable
/// - A hardware failure occurred
///
/// # Examples
///
/// ```
/// use hpcrypt_rng::generate_random_bytes;
///
/// let mut key = [0u8; 32];
/// generate_random_bytes(&mut key).expect("RNG failed");
/// ```
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    getrandom::getrandom(dest).map_err(|_| RngError::OsRngFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random() {
        let mut buf = [0u8; 64];
        fill_random(&mut buf).expect("OS RNG failed");

        // Should not be all zeros
        assert_ne!(buf, [0u8; 64], "RNG produced all zeros");
    }

    #[test]
    fn test_fill_random_multiple_calls() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        fill_random(&mut buf1).expect("OS RNG failed");
        fill_random(&mut buf2).expect("OS RNG failed");

        // Should produce different output
        assert_ne!(buf1, buf2, "RNG produced identical output");
    }

    #[test]
    fn test_fill_random_empty() {
        let mut buf = [];
        // Should succeed with empty buffer
        fill_random(&mut buf).expect("OS RNG failed with empty buffer");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fill_random_large() {
        let mut buf = std::vec![0u8; 10000];
        fill_random(&mut buf).expect("OS RNG failed with large buffer");

        // Check that not all bytes are the same
        let first = buf[0];
        let all_same = buf.iter().all(|&b| b == first);
        assert!(!all_same, "All bytes are identical");
    }
}
