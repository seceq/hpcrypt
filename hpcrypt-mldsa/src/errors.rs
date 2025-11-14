//! Error types for ML-DSA operations
//!
//! This module provides descriptive error types for signing and verification
//! operations, following RustCrypto patterns for better error handling.

use core::fmt;

/// Errors that can occur during signing operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// Rejection sampling failed after maximum attempts
    ///
    /// This occurs when the signing process fails to produce a valid signature
    /// within the allowed number of rejection sampling attempts (typically 576).
    /// This is extremely rare in normal operation (< 0.01% probability).
    RejectionSamplingFailed {
        /// Number of attempts made before failing
        attempts: usize,
    },

    /// Invalid secret key format or parameters
    InvalidSecretKey,

    /// Message too large for signing operation
    MessageTooLarge,

    /// Internal cryptographic operation failed
    ///
    /// This indicates an unexpected failure in the underlying cryptographic
    /// operations and should not occur under normal circumstances.
    InternalError,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::RejectionSamplingFailed { attempts } => {
                write!(
                    f,
                    "Signature rejection sampling failed after {} attempts",
                    attempts
                )
            }
            SignError::InvalidSecretKey => write!(f, "Invalid secret key provided"),
            SignError::MessageTooLarge => write!(f, "Message exceeds maximum size"),
            SignError::InternalError => write!(f, "Internal cryptographic error occurred"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {}

/// Errors that can occur during verification operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Signature verification failed - signature is invalid
    ///
    /// This indicates that the signature does not match the message and public key.
    /// This is the expected result for tampered or forged signatures.
    InvalidSignature,

    /// Invalid public key format or parameters
    InvalidPublicKey,

    /// Invalid signature format or encoding
    ///
    /// The signature bytes do not conform to the expected ML-DSA format.
    MalformedSignature,

    /// Message too large for verification operation
    MessageTooLarge,

    /// Hint bits exceed maximum allowed value
    ///
    /// The number of hint bits (omega) in the signature exceeds the
    /// parameter set's maximum (τ).
    HintBitsExceeded {
        /// Number of hint bits in signature
        hint_count: usize,
        /// Maximum allowed for this parameter set
        max_allowed: usize,
    },

    /// Internal cryptographic operation failed
    ///
    /// This indicates an unexpected failure in the underlying cryptographic
    /// operations and should not occur under normal circumstances.
    InternalError,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::InvalidSignature => {
                write!(f, "Signature verification failed - signature is invalid")
            }
            VerifyError::InvalidPublicKey => write!(f, "Invalid public key provided"),
            VerifyError::MalformedSignature => {
                write!(f, "Signature format is malformed or invalid")
            }
            VerifyError::MessageTooLarge => write!(f, "Message exceeds maximum size"),
            VerifyError::HintBitsExceeded {
                hint_count,
                max_allowed,
            } => {
                write!(
                    f,
                    "Hint bits ({}) exceed maximum allowed ({}) for this parameter set",
                    hint_count, max_allowed
                )
            }
            VerifyError::InternalError => write!(f, "Internal cryptographic error occurred"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}

/// Errors that can occur during key generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyGenError {
    /// Random number generation failed
    RngFailure,

    /// Invalid seed provided for deterministic key generation
    InvalidSeed,

    /// Internal cryptographic operation failed
    InternalError,
}

impl fmt::Display for KeyGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyGenError::RngFailure => write!(f, "Random number generation failed"),
            KeyGenError::InvalidSeed => write!(f, "Invalid seed provided"),
            KeyGenError::InternalError => write!(f, "Internal cryptographic error occurred"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeyGenError {}

/// Errors that can occur during serialization/deserialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationError {
    /// Input buffer has incorrect length
    InvalidLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        actual: usize,
    },

    /// Invalid encoding format
    InvalidFormat,

    /// PEM encoding error
    PemError,

    /// DER encoding error
    DerError,
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid buffer length: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
            SerializationError::InvalidFormat => write!(f, "Invalid encoding format"),
            SerializationError::PemError => write!(f, "PEM encoding/decoding error"),
            SerializationError::DerError => write!(f, "DER encoding/decoding error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SerializationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    extern crate alloc;
    use alloc::string::ToString;

    #[test]
    fn test_sign_error_display() {
        let err = SignError::RejectionSamplingFailed { attempts: 576 };
        assert!(err.to_string().contains("576"));

        let err = SignError::InvalidSecretKey;
        assert!(err.to_string().contains("Invalid secret key"));
    }

    #[test]
    fn test_verify_error_display() {
        let err = VerifyError::InvalidSignature;
        assert!(err.to_string().contains("invalid"));

        let err = VerifyError::HintBitsExceeded {
            hint_count: 100,
            max_allowed: 80,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("80"));
    }

    #[test]
    fn test_serialization_error_display() {
        let err = SerializationError::InvalidLength {
            expected: 1952,
            actual: 1000,
        };
        assert!(err.to_string().contains("1952"));
        assert!(err.to_string().contains("1000"));
    }

    #[test]
    fn test_error_equality() {
        let err1 = SignError::RejectionSamplingFailed { attempts: 100 };
        let err2 = SignError::RejectionSamplingFailed { attempts: 100 };
        assert_eq!(err1, err2);

        let err3 = SignError::RejectionSamplingFailed { attempts: 200 };
        assert_ne!(err1, err3);
    }
}
