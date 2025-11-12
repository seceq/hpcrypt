//! Error types for RSA operations

use core::fmt;

/// Result type for RSA operations
pub type Result<T> = core::result::Result<T, RsaError>;

/// Errors that can occur during RSA operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaError {
    /// Invalid key size (too small or too large)
    InvalidKeySize,

    /// Invalid public exponent
    InvalidPublicExponent,

    /// Key generation failed (e.g., couldn't find suitable primes)
    KeyGenerationFailed,

    /// Message too long for the key size
    MessageTooLong,

    /// Invalid ciphertext
    InvalidCiphertext,

    /// Decryption failed
    DecryptionFailed,

    /// Signature verification failed
    VerificationFailed,

    /// Invalid padding
    InvalidPadding,

    /// Invalid signature format
    InvalidSignature,

    /// Invalid label for OAEP
    InvalidLabel,

    /// Random number generation failed
    RngError,

    /// Internal error
    InternalError,
}

impl fmt::Display for RsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RsaError::InvalidKeySize => write!(f, "Invalid RSA key size"),
            RsaError::InvalidPublicExponent => write!(f, "Invalid public exponent"),
            RsaError::KeyGenerationFailed => write!(f, "RSA key generation failed"),
            RsaError::MessageTooLong => write!(f, "Message too long for key size"),
            RsaError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            RsaError::DecryptionFailed => write!(f, "RSA decryption failed"),
            RsaError::VerificationFailed => write!(f, "Signature verification failed"),
            RsaError::InvalidPadding => write!(f, "Invalid padding"),
            RsaError::InvalidSignature => write!(f, "Invalid signature format"),
            RsaError::InvalidLabel => write!(f, "Invalid label for OAEP"),
            RsaError::RngError => write!(f, "Random number generation failed"),
            RsaError::InternalError => write!(f, "Internal RSA error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RsaError {}
