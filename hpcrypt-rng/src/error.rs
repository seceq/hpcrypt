//! Error types for random number generation

use core::fmt;

/// Result type for RNG operations
pub type Result<T> = core::result::Result<T, RngError>;

/// Errors that can occur during random number generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// Operating system RNG failed
    ///
    /// This can occur if:
    /// - The system has insufficient entropy (e.g., early in boot process)
    /// - The RNG syscall/API is unavailable
    /// - A hardware RNG failure occurred
    /// - The platform doesn't support the RNG
    OsRngFailed,

    /// Deterministic RNG not properly initialized
    ///
    /// The ChaCha20-based DRBG must be seeded before use
    NotSeeded,

    /// Invalid seed length
    ///
    /// ChaCha20-DRBG requires exactly 32 bytes of seed
    InvalidSeedLength,

    /// Hardware RNG not supported
    ///
    /// The CPU does not support RDRAND/RDSEED instructions
    /// - RDRAND: Requires Intel Ivy Bridge (2012+) or AMD Excavator (2015+)
    /// - RDSEED: Requires Intel Broadwell (2014+) or AMD Zen (2017+)
    HardwareRngNotSupported,

    /// Hardware RNG failed
    ///
    /// The RDRAND/RDSEED instruction failed to produce randomness
    /// This is extremely rare and may indicate hardware failure
    HardwareRngFailed,

    /// RNG internal error
    ///
    /// An unexpected error occurred in the RNG implementation
    InternalError,
}

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RngError::OsRngFailed => {
                write!(
                    f,
                    "Operating system RNG failed - insufficient entropy or unavailable"
                )
            }
            RngError::NotSeeded => {
                write!(f, "Deterministic RNG not seeded - call seed() first")
            }
            RngError::InvalidSeedLength => {
                write!(f, "Invalid seed length - expected 32 bytes")
            }
            RngError::HardwareRngNotSupported => {
                write!(
                    f,
                    "Hardware RNG (RDRAND/RDSEED) not supported on this CPU"
                )
            }
            RngError::HardwareRngFailed => {
                write!(
                    f,
                    "Hardware RNG (RDRAND/RDSEED) instruction failed - possible hardware fault"
                )
            }
            RngError::InternalError => {
                write!(f, "Internal RNG error")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RngError {}

impl From<getrandom::Error> for RngError {
    fn from(_: getrandom::Error) -> Self {
        RngError::OsRngFailed
    }
}
