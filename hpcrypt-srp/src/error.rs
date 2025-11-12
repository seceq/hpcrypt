//! Error types for SRP operations

use core::fmt;

/// Result type for SRP operations
pub type Result<T> = core::result::Result<T, SrpError>;

/// Errors that can occur during SRP operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpError {
    /// Invalid username format
    InvalidUsername,
    /// Invalid password format
    InvalidPassword,
    /// Invalid public key (A or B = 0 mod N)
    InvalidPublicKey,
    /// Invalid verifier format
    InvalidVerifier,
    /// Invalid salt format
    InvalidSalt,
    /// Authentication proof verification failed
    ProofVerificationFailed,
    /// Invalid state transition
    InvalidState,
    /// Group parameter validation failed
    InvalidGroupParameter,
    /// Computation error (e.g., modular exponentiation)
    ComputationError,
    /// RNG error during key generation
    RngError,
    /// Session key not yet derived
    SessionKeyNotAvailable,
}

impl fmt::Display for SrpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUsername => write!(f, "Invalid username format"),
            Self::InvalidPassword => write!(f, "Invalid password format"),
            Self::InvalidPublicKey => write!(f, "Invalid public key (must not be 0 mod N)"),
            Self::InvalidVerifier => write!(f, "Invalid verifier format"),
            Self::InvalidSalt => write!(f, "Invalid salt format"),
            Self::ProofVerificationFailed => write!(f, "Authentication proof verification failed"),
            Self::InvalidState => write!(f, "Invalid state transition"),
            Self::InvalidGroupParameter => write!(f, "Group parameter validation failed"),
            Self::ComputationError => write!(f, "Computation error"),
            Self::RngError => write!(f, "RNG error during key generation"),
            Self::SessionKeyNotAvailable => write!(f, "Session key not yet derived"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SrpError {}
