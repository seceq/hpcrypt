//! Error types for HPCrypt cryptographic operations
//!
//! This module provides structured error types for all cryptographic operations
//! in HPCrypt. All error types are:
//! - no_std compatible - Work in embedded environments
//! - Informative - Include context about what went wrong
//! - Actionable - Help users understand and fix the problem
//! - Type-safe - Enable exhaustive pattern matching
//!
//! # Design Philosophy
//!
//! Instead of returning `Option<T>` (which provides no error information),
//! all HPCrypt operations return `Result<T, E>` with specific error types.
//!
//! # Example
//!
//! ```
//! use hpcrypt_core::error::AeadError;
//!
//! fn decrypt_data(ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
//!     // ... decryption logic ...
//!     # Ok(vec![])
//! }
//!
//! match decrypt_data(&[]) {
//!     Ok(plaintext) => println!("Success!"),
//!     Err(AeadError::AuthenticationFailed) => {
//!         eprintln!("Ciphertext was tampered with!");
//!     }
//!     Err(e) => eprintln!("Decryption failed: {}", e),
//! }
//! ```

#![allow(missing_docs)]

use core::fmt;

/// Errors from AEAD (Authenticated Encryption with Associated Data) operations
///
/// Used by AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, etc.
///
/// # Security Note
///
/// **NEVER** ignore `AuthenticationFailed` errors! This indicates the ciphertext
/// has been tampered with or corrupted. Do not return partial plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication tag verification failed (ciphertext tampered or corrupted)
    ///
    /// # Common Causes
    /// - Ciphertext was modified (intentionally or due to corruption)
    /// - Wrong key used for decryption
    /// - Wrong nonce used for decryption
    /// - AAD doesn't match what was used during encryption
    ///
    /// # Security Implications
    /// This error MUST NOT be ignored. It indicates tampering or corruption.
    /// Never return partial plaintext when authentication fails.
    AuthenticationFailed,

    /// Nonce size incorrect for this algorithm
    ///
    /// # Expected Sizes
    /// - **AES-GCM**: 12 bytes (96 bits) recommended, other sizes supported
    /// - **ChaCha20-Poly1305**: 12 bytes (96 bits) only
    /// - **XChaCha20-Poly1305**: 24 bytes (192 bits) only
    InvalidNonceLength {
        /// Expected nonce length in bytes
        expected: usize,
        /// Actual nonce length provided
        actual: usize,
    },

    /// Key size incorrect for this algorithm
    ///
    /// # Expected Sizes
    /// - **AES-128-GCM**: 16 bytes
    /// - **AES-192-GCM**: 24 bytes
    /// - **AES-256-GCM**: 32 bytes
    /// - **ChaCha20-Poly1305**: 32 bytes
    /// - **XChaCha20-Poly1305**: 32 bytes
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length provided
        actual: usize,
    },

    /// Ciphertext too short (must include authentication tag)
    ///
    /// All AEAD ciphers append an authentication tag to the ciphertext.
    /// The minimum valid ciphertext length is the tag size (16 bytes for
    /// Poly1305 and GCM).
    InvalidCiphertextLength {
        /// Minimum ciphertext length (tag size)
        minimum: usize,
        /// Actual ciphertext length provided
        actual: usize,
    },

    /// Additional authenticated data (AAD) too large
    ///
    /// # Limits
    /// - **AES-GCM**: 2^36 - 31 bytes (~64 GB)
    /// - **ChaCha20-Poly1305**: 2^64 - 1 bytes (practically unlimited)
    AadTooLarge {
        /// Maximum AAD length for this algorithm
        maximum: u64,
        /// Actual AAD length provided
        actual: u64,
    },

    /// Plaintext too large for this algorithm
    ///
    /// # Limits
    /// - **AES-GCM**: 2^36 - 32 bytes (~64 GB)
    /// - **ChaCha20-Poly1305**: 2^32 - 1 bytes (~4 GB)
    PlaintextTooLarge {
        /// Maximum plaintext length for this algorithm
        maximum: u64,
        /// Actual plaintext length provided
        actual: u64,
    },
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => {
                write!(
                    f,
                    "Authentication failed: ciphertext has been tampered with or corrupted"
                )
            }
            Self::InvalidNonceLength { expected, actual } => {
                write!(
                    f,
                    "Invalid nonce length: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid key length: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
            Self::InvalidCiphertextLength { minimum, actual } => {
                write!(
                    f,
                    "Invalid ciphertext length: minimum {} bytes (tag size), got {} bytes",
                    minimum, actual
                )
            }
            Self::AadTooLarge { maximum, actual } => {
                write!(
                    f,
                    "AAD too large: maximum {} bytes, got {} bytes",
                    maximum, actual
                )
            }
            Self::PlaintextTooLarge { maximum, actual } => {
                write!(
                    f,
                    "Plaintext too large: maximum {} bytes, got {} bytes",
                    maximum, actual
                )
            }
        }
    }
}

/// Errors from elliptic curve operations
///
/// Used by X25519, Ed25519, P-256, P-384, P-521, etc.
///
/// # Security Note
///
/// Low-order points and identity points MUST be rejected in key exchange
/// protocols as they contribute no entropy to the shared secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveError {
    /// Point is not on the curve (failed curve equation check)
    ///
    /// # Curve Equations
    /// - **Montgomery curves** (X25519): By² = x³ + Ax² + x
    /// - **Edwards curves** (Ed25519): ax² + y² = 1 + dx²y²
    /// - **Weierstrass curves** (P-256): y² = x³ + ax + b
    ///
    /// This error indicates the point coordinates don't satisfy the curve equation.
    NotOnCurve,

    /// Point has low order (contributes no entropy to shared secret)
    ///
    /// # Security Implications
    /// Low-order points have small multiplicative order (e.g., 2, 4, 8).
    /// In key exchange, they result in predictable shared secrets.
    ///
    /// # Affected Operations
    /// - **X25519**: Must reject low-order points in public keys
    /// - **Ed25519**: Invalid public keys for signatures
    LowOrderPoint,

    /// Point is the identity element (point at infinity)
    ///
    /// # Implications
    /// - **X25519**: Results in all-zero shared secret (security failure)
    /// - **Ed25519**: Invalid public key
    /// - **P-curves**: Point at infinity is not a valid public key
    ///
    /// This error prevents trivial key exchange attacks.
    IdentityPoint,

    /// Scalar is invalid (wrong length or forbidden value)
    ///
    /// # Expected Lengths
    /// - **X25519**: 32 bytes
    /// - **Ed25519 private key**: 32 bytes
    /// - **Ed25519 signature (r,s)**: 64 bytes total
    /// - **P-256 scalar**: 32 bytes
    InvalidScalar {
        /// Expected scalar length in bytes
        expected: usize,
        /// Actual scalar length provided
        actual: usize,
    },

    /// Point encoding is invalid (wrong length or format)
    ///
    /// # Encoding Formats
    /// - **X25519**: 32 bytes (u-coordinate, little-endian)
    /// - **Ed25519**: 32 bytes (compressed y-coordinate + sign bit)
    /// - **P-256 compressed**: 33 bytes (0x02/0x03 prefix + x-coordinate)
    /// - **P-256 uncompressed**: 65 bytes (0x04 prefix + x + y)
    InvalidEncoding {
        /// Description of expected encoding format
        expected: &'static str,
        /// Actual encoding length provided
        actual: usize,
    },

    /// Signature verification failed (signature invalid or message tampered)
    ///
    /// # Common Causes
    /// - Message was modified after signing
    /// - Signature was corrupted
    /// - Wrong public key used for verification
    /// - Signature was forged
    ///
    /// # Security Note
    /// This does NOT necessarily indicate malicious activity - signatures
    /// can fail verification due to bugs, corrupted data, or wrong keys.
    InvalidSignature,

    /// Point decompression failed (y-coordinate not derivable)
    ///
    /// # Causes
    /// - **Ed25519**: sqrt() returned None (x³ + ax + b not a quadratic residue)
    /// - **P-curves**: y² ≠ x³ + ax + b (point not on curve)
    ///
    /// This indicates the compressed point encoding is invalid.
    DecompressionFailed,

    /// Non-canonical encoding (value >= field modulus)
    ///
    /// # Explanation
    /// Field elements must be in range [0, p) where p is the field modulus.
    /// Values >= p are "non-canonical" and must be rejected for:
    /// - Constant-time operations (timing attack resistance)
    /// - Deterministic signature schemes (Ed25519)
    /// - Protocol correctness
    ///
    /// # Example
    /// For Curve25519, p = 2^255 - 19. Any value >= p is rejected.
    NonCanonicalEncoding,
}

impl fmt::Display for CurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOnCurve => {
                write!(f, "Point is not on the curve")
            }
            Self::LowOrderPoint => {
                write!(f, "Point has low order (contributes no entropy)")
            }
            Self::IdentityPoint => {
                write!(f, "Point is the identity element (point at infinity)")
            }
            Self::InvalidScalar { expected, actual } => {
                write!(
                    f,
                    "Invalid scalar: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
            Self::InvalidEncoding { expected, actual } => {
                write!(
                    f,
                    "Invalid point encoding: expected {}, got {} bytes",
                    expected, actual
                )
            }
            Self::InvalidSignature => {
                write!(f, "Signature verification failed")
            }
            Self::DecompressionFailed => {
                write!(f, "Point decompression failed: y-coordinate not derivable")
            }
            Self::NonCanonicalEncoding => {
                write!(f, "Non-canonical encoding: value >= field modulus")
            }
        }
    }
}

/// Errors from key derivation functions (KDF)
///
/// Used by Argon2, PBKDF2, HKDF, etc.
///
/// # Security Note
///
/// Many KDF errors indicate security-critical parameter validation failures.
/// Do not ignore parameter range errors - they exist to prevent weak key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// Output length invalid for this KDF
    ///
    /// # Limits
    /// - **Argon2**: minimum 4 bytes, maximum 2^32 - 1 bytes
    /// - **PBKDF2**: maximum (2^32 - 1) * hash_len bytes
    /// - **HKDF**: maximum 255 * hash_len bytes
    InvalidOutputLength {
        /// Minimum output length in bytes
        minimum: usize,
        /// Maximum output length in bytes
        maximum: usize,
        /// Actual output length requested
        actual: usize,
    },

    /// Salt too short (security concern)
    ///
    /// # Recommendations
    /// - **Argon2**: minimum 8 bytes, 16 bytes recommended
    /// - **PBKDF2**: minimum 16 bytes recommended
    /// - **HKDF**: minimum 16 bytes recommended
    ///
    /// Short salts reduce resistance to rainbow table attacks.
    SaltTooShort {
        /// Minimum recommended salt length
        minimum: usize,
        /// Actual salt length provided
        actual: usize,
    },

    /// Password too long
    ///
    /// # Limits
    /// - **Argon2**: maximum 2^32 - 1 bytes
    /// - **PBKDF2**: practically unlimited
    /// - **HKDF**: hash_len bytes (longer passwords hashed first)
    PasswordTooLong {
        /// Maximum password length in bytes
        maximum: usize,
        /// Actual password length provided
        actual: usize,
    },

    /// Memory cost too low (security concern)
    ///
    /// # Argon2 Requirements
    /// - Minimum: 8 * parallelism (KiB)
    /// - Recommended: 65536 KiB (64 MiB) for interactive use
    /// - Recommended: 262144 KiB (256 MiB) for sensitive operations
    ///
    /// Low memory cost makes parallel brute-force attacks feasible.
    MemoryCostTooLow {
        /// Minimum memory cost (KiB)
        minimum: u32,
        /// Actual memory cost provided
        actual: u32,
    },

    /// Time cost too low (security concern)
    ///
    /// # Argon2 Requirements
    /// - Minimum: 1 iteration
    /// - Recommended: 3 iterations for interactive use
    /// - Recommended: 10+ iterations for sensitive operations
    ///
    /// Low iteration count makes brute-force attacks faster.
    TimeCostTooLow {
        /// Minimum time cost (iterations)
        minimum: u32,
        /// Actual time cost provided
        actual: u32,
    },

    /// Parallelism parameter invalid
    ///
    /// # Argon2 Requirements
    /// - Minimum: 1 (sequential execution)
    /// - Maximum: 2^24 - 1
    /// - Recommended: Number of CPU cores (1-4 typical)
    InvalidParallelism {
        /// Minimum parallelism value
        minimum: u32,
        /// Maximum parallelism value
        maximum: u32,
        /// Actual parallelism provided
        actual: u32,
    },

    /// Argon2 version not supported
    ///
    /// # Supported Versions
    /// - **0x13 (19)**: Argon2 version 1.3 (latest, recommended)
    /// - **0x10 (16)**: Argon2 version 1.0 (deprecated)
    UnsupportedVersion {
        /// Version number provided
        version: u32,
    },

    /// HKDF input key material (IKM) too short
    ///
    /// # Recommendation
    /// IKM should have at least as much entropy as the hash output size:
    /// - **SHA-256**: minimum 32 bytes
    /// - **SHA-512**: minimum 64 bytes
    IkmTooShort {
        /// Minimum recommended IKM length
        minimum: usize,
        /// Actual IKM length provided
        actual: usize,
    },
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOutputLength {
                minimum,
                maximum,
                actual,
            } => {
                write!(
                    f,
                    "Invalid output length: must be in range [{}, {}], got {}",
                    minimum, maximum, actual
                )
            }
            Self::SaltTooShort { minimum, actual } => {
                write!(
                    f,
                    "Salt too short: minimum {} bytes recommended, got {} bytes",
                    minimum, actual
                )
            }
            Self::PasswordTooLong { maximum, actual } => {
                write!(
                    f,
                    "Password too long: maximum {} bytes, got {} bytes",
                    maximum, actual
                )
            }
            Self::MemoryCostTooLow { minimum, actual } => {
                write!(
                    f,
                    "Memory cost too low: minimum {} KiB, got {} KiB",
                    minimum, actual
                )
            }
            Self::TimeCostTooLow { minimum, actual } => {
                write!(
                    f,
                    "Time cost too low: minimum {} iterations, got {} iterations",
                    minimum, actual
                )
            }
            Self::InvalidParallelism {
                minimum,
                maximum,
                actual,
            } => {
                write!(
                    f,
                    "Invalid parallelism: must be in range [{}, {}], got {}",
                    minimum, maximum, actual
                )
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "Unsupported Argon2 version: 0x{:x}", version)
            }
            Self::IkmTooShort { minimum, actual } => {
                write!(
                    f,
                    "IKM too short: minimum {} bytes recommended, got {} bytes",
                    minimum, actual
                )
            }
        }
    }
}

/// Errors from hash functions
///
/// Most hash functions have no runtime errors. These errors are primarily
/// for XOF (eXtendable-Output Functions) like SHAKE128/256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    /// Output length invalid for this hash function
    ///
    /// # Constraints
    /// - **Fixed-output** (SHA-256, SHA-512): Must match algorithm output size
    /// - **XOF** (SHAKE128, SHAKE256): Any length supported
    InvalidOutputLength {
        /// Expected output length (None for XOFs)
        expected: Option<usize>,
        /// Actual output length requested
        actual: usize,
    },

    /// Hash context already finalized (can't update)
    ///
    /// After calling `finalize()`, no more data can be added with `update()`.
    /// Create a new hash context if you need to hash more data.
    AlreadyFinalized,

    /// Hash context not finalized yet (can't read output)
    ///
    /// Call `finalize()` before reading the hash output.
    NotFinalized,
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOutputLength { expected, actual } => match expected {
                Some(exp) => write!(
                    f,
                    "Invalid output length: expected {} bytes, got {} bytes",
                    exp, actual
                ),
                None => write!(f, "Invalid output length: {} bytes", actual),
            },
            Self::AlreadyFinalized => {
                write!(f, "Hash context already finalized (can't update)")
            }
            Self::NotFinalized => {
                write!(f, "Hash context not finalized yet (can't read output)")
            }
        }
    }
}

/// Errors from block cipher operations
///
/// Used by AES-ECB, AES-CBC, AES-CTR, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// Key size incorrect for this algorithm
    ///
    /// # AES Key Sizes
    /// - **AES-128**: 16 bytes
    /// - **AES-192**: 24 bytes
    /// - **AES-256**: 32 bytes
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length provided
        actual: usize,
    },

    /// IV (Initialization Vector) or nonce size incorrect
    ///
    /// # Common Sizes
    /// - **AES-CBC**: 16 bytes (one AES block)
    /// - **AES-CTR**: 16 bytes (counter block)
    /// - **AES-GCM**: 12 bytes recommended (see AeadError for AEAD modes)
    InvalidIvLength {
        /// Expected IV length in bytes
        expected: usize,
        /// Actual IV length provided
        actual: usize,
    },

    /// Plaintext length invalid for this mode
    ///
    /// # Constraints
    /// - **AES-ECB/CBC**: Must be multiple of 16 bytes (block size)
    /// - **AES-CTR**: Any length supported
    InvalidPlaintextLength {
        /// Block size in bytes
        block_size: usize,
        /// Actual plaintext length (not a multiple of block size)
        actual: usize,
    },

    /// Padding invalid (PKCS#7 padding check failed)
    ///
    /// # PKCS#7 Padding
    /// The last N bytes must all have value N (1 ≤ N ≤ block_size).
    ///
    /// # Common Causes
    /// - Ciphertext was tampered with
    /// - Wrong key used for decryption
    /// - Wrong mode used (trying to decrypt CTR as CBC)
    InvalidPadding,
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid key length: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
            Self::InvalidIvLength { expected, actual } => {
                write!(
                    f,
                    "Invalid IV length: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
            Self::InvalidPlaintextLength { block_size, actual } => {
                write!(
                    f,
                    "Invalid plaintext length: must be multiple of {} bytes, got {} bytes",
                    block_size, actual
                )
            }
            Self::InvalidPadding => {
                write!(f, "Invalid PKCS#7 padding")
            }
        }
    }
}

/// Top-level error type for all HPCrypt operations
///
/// This unified error type allows handling errors from different cryptographic
/// primitives in a uniform way. Use this when you need generic error handling
/// across multiple HPCrypt crates.
///
/// # Example
///
/// ```
/// use hpcrypt_core::error::{CryptoError, AeadError};
///
/// fn process_encrypted_data() -> Result<(), CryptoError> {
///     // ... operations that might fail ...
///     # Ok(())
/// }
///
/// match process_encrypted_data() {
///     Ok(()) => println!("Success"),
///     Err(CryptoError::Aead(AeadError::AuthenticationFailed)) => {
///         eprintln!("Authentication failed!");
///     }
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD cipher error
    Aead(AeadError),
    /// Elliptic curve error
    Curve(CurveError),
    /// Key derivation error
    Kdf(KdfError),
    /// Hash function error
    Hash(HashError),
    /// Block cipher error
    Cipher(CipherError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead(e) => write!(f, "AEAD error: {}", e),
            Self::Curve(e) => write!(f, "Curve error: {}", e),
            Self::Kdf(e) => write!(f, "KDF error: {}", e),
            Self::Hash(e) => write!(f, "Hash error: {}", e),
            Self::Cipher(e) => write!(f, "Cipher error: {}", e),
        }
    }
}

// Convenience conversions for unified error handling
impl From<AeadError> for CryptoError {
    fn from(e: AeadError) -> Self {
        CryptoError::Aead(e)
    }
}

impl From<CurveError> for CryptoError {
    fn from(e: CurveError) -> Self {
        CryptoError::Curve(e)
    }
}

impl From<KdfError> for CryptoError {
    fn from(e: KdfError) -> Self {
        CryptoError::Kdf(e)
    }
}

impl From<HashError> for CryptoError {
    fn from(e: HashError) -> Self {
        CryptoError::Hash(e)
    }
}

impl From<CipherError> for CryptoError {
    fn from(e: CipherError) -> Self {
        CryptoError::Cipher(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    extern crate alloc;
    #[cfg(feature = "alloc")]
    use alloc::format;

    // Test that all error types implement required traits
    #[test]
    fn test_error_traits() {
        fn assert_error_traits<T: fmt::Debug + fmt::Display + Clone + PartialEq + Eq>() {}

        assert_error_traits::<AeadError>();
        assert_error_traits::<CurveError>();
        assert_error_traits::<KdfError>();
        assert_error_traits::<HashError>();
        assert_error_traits::<CipherError>();
        assert_error_traits::<CryptoError>();
    }

    // Test AEAD error display messages
    #[test]
    #[cfg(feature = "alloc")]
    fn test_aead_error_display() {
        let err = AeadError::AuthenticationFailed;
        let msg = format!("{}", err);
        assert!(msg.contains("Authentication failed"));
        assert!(msg.contains("tampered"));

        let err = AeadError::InvalidNonceLength {
            expected: 12,
            actual: 8,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("12 bytes"));
        assert!(msg.contains("8 bytes"));
    }

    // Test Curve error display messages
    #[test]
    #[cfg(feature = "alloc")]
    fn test_curve_error_display() {
        let err = CurveError::NotOnCurve;
        let msg = format!("{}", err);
        assert!(msg.contains("not on the curve"));

        let err = CurveError::InvalidSignature;
        let msg = format!("{}", err);
        assert!(msg.contains("Signature verification failed"));
    }

    // Test KDF error display messages
    #[test]
    #[cfg(feature = "alloc")]
    fn test_kdf_error_display() {
        let err = KdfError::SaltTooShort {
            minimum: 16,
            actual: 8,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("16 bytes"));
        assert!(msg.contains("8 bytes"));
    }

    // Test error conversions
    #[test]
    fn test_error_conversions() {
        let aead_err = AeadError::AuthenticationFailed;
        let crypto_err: CryptoError = aead_err.into();
        assert_eq!(
            crypto_err,
            CryptoError::Aead(AeadError::AuthenticationFailed)
        );

        let curve_err = CurveError::NotOnCurve;
        let crypto_err: CryptoError = curve_err.into();
        assert_eq!(crypto_err, CryptoError::Curve(CurveError::NotOnCurve));
    }

    // Test error equality
    #[test]
    fn test_error_equality() {
        let err1 = AeadError::InvalidNonceLength {
            expected: 12,
            actual: 8,
        };
        let err2 = AeadError::InvalidNonceLength {
            expected: 12,
            actual: 8,
        };
        let err3 = AeadError::InvalidNonceLength {
            expected: 12,
            actual: 10,
        };

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    // Test error cloning
    #[test]
    fn test_error_cloning() {
        let err1 = AeadError::AuthenticationFailed;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }
}
