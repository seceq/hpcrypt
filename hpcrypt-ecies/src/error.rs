//! Error types for ECIES operations

use core::fmt;

/// Result type for ECIES operations
pub type Result<T> = core::result::Result<T, EciesError>;

/// Error types for ECIES operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EciesError {
    /// Invalid public key
    InvalidPublicKey,

    /// Invalid ciphertext (malformed or corrupted)
    InvalidCiphertext,

    /// Ciphertext too short
    CiphertextTooShort,

    /// Message too long for the given parameters
    MessageTooLong,

    /// Key derivation failed
    KeyDerivationFailed,

    /// AEAD encryption failed
    EncryptionFailed,

    /// AEAD decryption failed (authentication failed)
    DecryptionFailed,

    /// Shared secret computation failed
    SharedSecretFailed,

    /// Random number generation failed
    RngError,

    /// Internal error
    InternalError,
}

impl fmt::Display for EciesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            Self::CiphertextTooShort => write!(f, "Ciphertext too short"),
            Self::MessageTooLong => write!(f, "Message too long"),
            Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed (authentication failed)"),
            Self::SharedSecretFailed => write!(f, "Shared secret computation failed"),
            Self::RngError => write!(f, "Random number generation failed"),
            Self::InternalError => write!(f, "Internal error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EciesError {}
