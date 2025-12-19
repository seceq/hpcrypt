//! Operating system random number generator
//!
//! Uses the OS's cryptographically secure RNG via the `getrandom` crate.

use crate::{Result, RngError};
use rand_core::{CryptoRng, RngCore};

/// OS-based cryptographically secure RNG compatible with rand_core
///
/// This is a zero-sized type that implements `RngCore` and `CryptoRng` traits
/// from the `rand_core` crate, making it compatible with the broader Rust
/// cryptography ecosystem.
///
/// # Examples
///
/// ```
/// use hpcrypt_rng::OsRng;
/// use rand_core::RngCore;
///
/// let mut rng = OsRng;
/// let mut key = [0u8; 32];
/// rng.fill_bytes(&mut key);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest).expect("OS RNG failed - this should never happen in normal operation");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        fill_random(dest).map_err(|_| rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
    }
}

// Mark as cryptographically secure
impl CryptoRng for OsRng {}

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
