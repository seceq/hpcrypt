//! Error types for HPKE operations

use core::fmt;

/// Result type for HPKE operations
pub type Result<T> = core::result::Result<T, HpkeError>;

/// Errors that can occur during HPKE operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeError {
    /// Validation error during setup or parameter validation
    ValidationError,

    /// Key encapsulation failed
    EncapError,

    /// Key decapsulation failed
    DecapError,

    /// AEAD decryption failed (authentication failed)
    OpenError,

    /// Message sequence number limit reached
    MessageLimitReached,

    /// Invalid public key format or value
    InvalidPublicKey,

    /// Invalid secret key format or value
    InvalidSecretKey,

    /// Invalid ciphertext length or format
    InvalidCiphertext,

    /// Invalid PSK (pre-shared key) or PSK ID
    InvalidPsk,

    /// Internal error during cryptographic operations
    InternalError,

    /// RNG error during key generation
    RngError,

    /// Unsupported mode or configuration
    UnsupportedMode,
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HpkeError::ValidationError => write!(f, "Validation error"),
            HpkeError::EncapError => write!(f, "Key encapsulation failed"),
            HpkeError::DecapError => write!(f, "Key decapsulation failed"),
            HpkeError::OpenError => write!(f, "AEAD decryption failed"),
            HpkeError::MessageLimitReached => write!(f, "Message sequence limit reached"),
            HpkeError::InvalidPublicKey => write!(f, "Invalid public key"),
            HpkeError::InvalidSecretKey => write!(f, "Invalid secret key"),
            HpkeError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            HpkeError::InvalidPsk => write!(f, "Invalid pre-shared key"),
            HpkeError::InternalError => write!(f, "Internal error"),
            HpkeError::RngError => write!(f, "RNG error"),
            HpkeError::UnsupportedMode => write!(f, "Unsupported mode"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}
