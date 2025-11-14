//! Context API for ML-DSA with Domain Separation
//!
//! This module implements the context string parameter from FIPS 204,
//! providing domain separation for different use cases of ML-DSA signatures.
//!
//! # Purpose
//!
//! The context string (ctx) allows applications to:
//! - Distinguish between different signature types or purposes
//! - Prevent signature reuse across different domains
//! - Provide additional domain separation beyond the message itself
//!
//! # FIPS 204 Specification
//!
//! According to FIPS 204:
//! - Context strings can be up to 255 bytes long
//! - By default, the context is an empty string
//! - The message encoding is: 0x00 || len(ctx) || ctx || message
//!
//! # Example
//!
//! ```no_run
//! use mldsa::params::MlDsa65;
//! use mldsa::keygen::keygen;
//! use mldsa::context::{sign_with_context, verify_with_context};
//!
//! let (pk, sk) = keygen::<MlDsa65>();
//!
//! // Sign with context for domain separation
//! let context = b"email-signature-v1";
//! let message = b"Important email content";
//! let sig = sign_with_context(&sk, message, context).unwrap();
//!
//! // Verify with same context
//! let valid = verify_with_context(&pk, message, context, &sig);
//! assert!(valid);
//!
//! // Verification with different context fails
//! let wrong_context = b"document-signature-v1";
//! let invalid = verify_with_context(&pk, message, wrong_context, &sig);
//! assert!(!invalid);
//! ```

extern crate alloc;
use alloc::vec::Vec;

use crate::keygen::{PublicKey, SecretKey};
use crate::params::DsaParams;
use crate::sign::{sign, sign_deterministic, Signature};
use crate::verify::verify;

/// Maximum context string length as per FIPS 204
pub const MAX_CONTEXT_LENGTH: usize = 255;

/// Error type for context operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    /// Context string exceeds maximum length of 255 bytes
    ContextTooLong,
}

/// Encode message with context string as per FIPS 204
///
/// Format: 0x00 || len(ctx) || ctx || message
///
/// # Arguments
/// * `message` - Original message
/// * `context` - Context string (max 255 bytes)
///
/// # Returns
/// * Encoded message or error if context is too long
fn encode_message_with_context(message: &[u8], context: &[u8]) -> Result<Vec<u8>, ContextError> {
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err(ContextError::ContextTooLong);
    }

    // Allocate: 1 byte (0x00) + 1 byte (len) + context + message
    let mut encoded = Vec::with_capacity(2 + context.len() + message.len());

    // FIPS 204 encoding: 0x00 || len(ctx) || ctx || M
    encoded.push(0x00);
    encoded.push(context.len() as u8);
    encoded.extend_from_slice(context);
    encoded.extend_from_slice(message);

    Ok(encoded)
}

/// Sign a message with context string for domain separation
///
/// This implements the context parameter from FIPS 204, encoding the
/// message as: 0x00 || len(ctx) || ctx || M
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message to sign
/// * `context` - Context string (max 255 bytes) for domain separation
///
/// # Returns
/// * Signature or None if signing fails
///
/// # Errors
/// * Returns None if context exceeds 255 bytes
/// * Returns None if signing fails after max rejection sampling attempts
///
/// # Example
///
/// ```no_run
/// use mldsa::params::MlDsa65;
/// use mldsa::keygen::keygen;
/// use mldsa::context::sign_with_context;
///
/// let (pk, sk) = keygen::<MlDsa65>();
/// let context = b"email-v1";
/// let message = b"Important email";
/// let sig = sign_with_context(&sk, message, context).unwrap();
/// ```
pub fn sign_with_context<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
    context: &[u8],
) -> Option<Signature<P>> {
    // Encode message with context
    let encoded = encode_message_with_context(message, context).ok()?;

    // Sign the encoded message
    sign(sk, &encoded)
}

/// Verify a signature with context string
///
/// The context must match the context used during signing for verification
/// to succeed.
///
/// # Arguments
/// * `pk` - Public key
/// * `message` - Original message
/// * `context` - Context string (must match signing context)
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid with this context, `false` otherwise
///
/// # Example
///
/// ```no_run
/// use mldsa::params::MlDsa65;
/// use mldsa::keygen::keygen;
/// use mldsa::context::{sign_with_context, verify_with_context};
///
/// let (pk, sk) = keygen::<MlDsa65>();
/// let context = b"api-token-v2";
/// let message = b"Token data";
/// let sig = sign_with_context(&sk, message, context).unwrap();
///
/// assert!(verify_with_context(&pk, message, context, &sig));
/// assert!(!verify_with_context(&pk, message, b"wrong-context", &sig));
/// ```
pub fn verify_with_context<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    context: &[u8],
    signature: &Signature<P>,
) -> bool {
    // Encode message with context
    let Ok(encoded) = encode_message_with_context(message, context) else {
        return false; // Context too long
    };

    // Verify the encoded message
    verify(pk, &encoded, signature)
}

/// Sign a message deterministically with context string
///
/// This is the deterministic variant of sign_with_context, useful for testing.
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message to sign
/// * `context` - Context string (max 255 bytes)
/// * `rnd` - 32-byte deterministic randomness seed
///
/// # Returns
/// * Signature or None if signing fails or context is too long
pub fn sign_with_context_deterministic<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
    context: &[u8],
    rnd: &[u8; 32],
) -> Option<Signature<P>> {
    // Encode message with context
    let encoded = encode_message_with_context(message, context).ok()?;

    // Sign deterministically
    sign_deterministic(sk, &encoded, rnd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::keygen::keygen;
    use crate::params::MlDsa65;

    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_context_basic() {
        let (pk, sk) = keygen::<MlDsa65>();

        let context = b"test-context-v1";
        let message = b"Test message";

        let sig = sign_with_context(&sk, message, context).expect("Signing failed");

        let valid = verify_with_context(&pk, message, context, &sig);
        assert!(valid, "Valid signature with context should verify");
    }

    #[test]
    fn test_context_empty() {
        let (pk, sk) = keygen::<MlDsa65>();

        let context = b"";
        let message = b"Test message with empty context";

        let sig = sign_with_context(&sk, message, context).expect("Signing failed");

        let valid = verify_with_context(&pk, message, context, &sig);
        assert!(valid, "Valid signature with empty context should verify");
    }

    #[test]
    fn test_context_mismatch() {
        let (pk, sk) = keygen::<MlDsa65>();

        let context1 = b"email-signature";
        let context2 = b"document-signature";
        let message = b"Same message";

        let sig = sign_with_context(&sk, message, context1).expect("Signing failed");

        // Verification with wrong context should fail
        let valid = verify_with_context(&pk, message, context2, &sig);
        assert!(!valid, "Signature with different context should not verify");
    }

    #[test]
    fn test_context_domain_separation() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Transfer $1000";
        let email_context = b"email-v1";
        let api_context = b"api-v1";

        // Sign for email use
        let email_sig = sign_with_context(&sk, message, email_context).expect("Signing failed");

        // Sign for API use
        let api_sig = sign_with_context(&sk, message, api_context).expect("Signing failed");

        // Email signature doesn't verify with API context
        assert!(verify_with_context(&pk, message, email_context, &email_sig));
        assert!(!verify_with_context(&pk, message, api_context, &email_sig));

        // API signature doesn't verify with email context
        assert!(verify_with_context(&pk, message, api_context, &api_sig));
        assert!(!verify_with_context(&pk, message, email_context, &api_sig));
    }

    #[test]
    fn test_context_max_length() {
        let (pk, sk) = keygen::<MlDsa65>();

        // Maximum length context (255 bytes)
        let max_context = vec![0x42u8; MAX_CONTEXT_LENGTH];
        let message = b"Test with max context";

        let sig =
            sign_with_context(&sk, message, &max_context).expect("Signing with max context failed");

        let valid = verify_with_context(&pk, message, &max_context, &sig);
        assert!(valid, "Signature with max-length context should verify");
    }

    #[test]
    fn test_context_too_long() {
        let (_pk, sk) = keygen::<MlDsa65>();

        // Context exceeding maximum length (256 bytes)
        let too_long_context = vec![0x42u8; MAX_CONTEXT_LENGTH + 1];
        let message = b"Test";

        let result = sign_with_context(&sk, message, &too_long_context);
        assert!(
            result.is_none(),
            "Signing with too-long context should fail"
        );
    }

    #[test]
    fn test_context_deterministic() {
        let (pk, sk) = keygen::<MlDsa65>();

        let context = b"deterministic-test";
        let message = b"Deterministic message";
        let rnd = [99u8; 32];

        let sig1 =
            sign_with_context_deterministic(&sk, message, context, &rnd).expect("Signing failed");
        let sig2 =
            sign_with_context_deterministic(&sk, message, context, &rnd).expect("Signing failed");

        // Deterministic signing should produce identical signatures
        assert_eq!(
            sig1.c_tilde, sig2.c_tilde,
            "Deterministic signatures should be identical"
        );

        let valid = verify_with_context(&pk, message, context, &sig1);
        assert!(valid, "Deterministic signature with context should verify");
    }

    #[test]
    fn test_encode_message_format() {
        let message = b"Hello";
        let context = b"test";

        let encoded = encode_message_with_context(message, context).unwrap();

        // Check format: 0x00 || len(ctx) || ctx || M
        assert_eq!(encoded[0], 0x00, "First byte should be 0x00");
        assert_eq!(
            encoded[1],
            context.len() as u8,
            "Second byte should be context length"
        );
        assert_eq!(
            &encoded[2..2 + context.len()],
            context,
            "Context should follow"
        );
        assert_eq!(
            &encoded[2 + context.len()..],
            message,
            "Message should be at end"
        );
    }
}
