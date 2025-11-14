//! QUIC Key Derivation Functions
//!
//! This module implements QUIC-specific key derivation functions as defined in RFC 9001.
//!
//! # HKDF-Expand-Label for QUIC

#![allow(clippy::manual_div_ceil)] // MSRV 1.70 compatibility - div_ceil stabilized in 1.73
//!
//! QUIC uses the same HKDF-Expand-Label structure as TLS 1.3, but with "quic " prefix
//! instead of "tls13 ":
//!
//! ```text
//! HKDF-Expand-Label(Secret, Label, Context, Length) =
//!     HKDF-Expand(Secret, HkdfLabel, Length)
//!
//! Where HkdfLabel is:
//!   struct {
//!       uint16 length = Length;
//!       opaque label<7..255> = "quic " + Label;  // Note: "quic " not "tls13 "
//!       opaque context<0..255> = Context;
//!   } HkdfLabel;
//! ```
//!
//! # Example
//!
//! ```rust
//! use hpcrypt_kdf::quic::{hkdf_expand_label_sha256, hkdf_expand_label_sha384};
//!
//! // Derive QUIC key from traffic secret (with SHA-256)
//! let traffic_secret = [0u8; 32];
//! let key = hkdf_expand_label_sha256(&traffic_secret, "quic key", &[], 16);
//! assert_eq!(key.len(), 16);
//!
//! // Derive with SHA-384 (for AES-256-GCM cipher suites)
//! let traffic_secret_384 = [0u8; 48];
//! let key_384 = hkdf_expand_label_sha384(&traffic_secret_384, "quic key", &[], 32);
//! assert_eq!(key_384.len(), 32);
//! ```

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;

use hpcrypt_hash::{HmacSha256, HmacSha384, HmacSha512};

/// HKDF-Expand-Label with SHA-256 for QUIC
///
/// This is used with QUIC cipher suites based on SHA-256.
///
/// # Arguments
///
/// * `secret` - The secret (PRK) to expand from
/// * `label` - The label string (without "quic " prefix)
/// * `context` - The context data
/// * `length` - The desired output length in bytes
///
/// # Examples
///
/// ```rust
/// use hpcrypt_kdf::quic::hkdf_expand_label_sha256;
///
/// // Derive QUIC key
/// let traffic_secret = [0u8; 32];
/// let key = hkdf_expand_label_sha256(&traffic_secret, "quic key", &[], 16);
///
/// // Derive QUIC IV
/// let iv = hkdf_expand_label_sha256(&traffic_secret, "quic iv", &[], 12);
///
/// // Derive header protection key
/// let hp = hkdf_expand_label_sha256(&traffic_secret, "quic hp", &[], 16);
/// ```
pub fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    // Construct HkdfLabel structure
    let mut hkdf_label = Vec::new();

    // uint16 length (big-endian)
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    // opaque label<7..255> = "quic " + Label
    let full_label = format!("quic {}", label);
    assert!(full_label.len() <= 255, "Label too long");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());

    // opaque context<0..255> = Context
    assert!(context.len() <= 255, "Context too long");
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // HKDF-Expand(secret, HkdfLabel, length)
    hkdf_expand_sha256(secret, &hkdf_label, length as usize)
}

/// HKDF-Expand-Label with SHA-384 for QUIC
///
/// This is used with QUIC cipher suites based on SHA-384.
///
/// # Arguments
///
/// * `secret` - The secret (PRK) to expand from (48 bytes for SHA-384)
/// * `label` - The label string (without "quic " prefix)
/// * `context` - The context data
/// * `length` - The desired output length in bytes
pub fn hkdf_expand_label_sha384(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    let full_label = format!("quic {}", label);
    assert!(full_label.len() <= 255, "Label too long");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());

    assert!(context.len() <= 255, "Context too long");
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand_sha384(secret, &hkdf_label, length as usize)
}

/// HKDF-Expand-Label with SHA-512 for QUIC
///
/// This is not used in standard QUIC cipher suites, but provided for completeness.
pub fn hkdf_expand_label_sha512(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    let full_label = format!("quic {}", label);
    assert!(full_label.len() <= 255, "Label too long");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());

    assert!(context.len() <= 255, "Context too long");
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand_sha512(secret, &hkdf_label, length as usize)
}

// Internal HKDF-Expand implementation for SHA-256
fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 32;
    let n = (length + hash_len - 1) / hash_len;

    if n > 255 {
        panic!("HKDF output too long");
    }

    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i as u8);

        let hmac = HmacSha256::new(prk);
        t = hmac.compute(&data).to_vec();

        let to_copy = core::cmp::min(hash_len, length - output.len());
        output.extend_from_slice(&t[..to_copy]);
    }

    output
}

// Internal HKDF-Expand implementation for SHA-384
fn hkdf_expand_sha384(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 48;
    let n = (length + hash_len - 1) / hash_len;

    if n > 255 {
        panic!("HKDF output too long");
    }

    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i as u8);

        let hmac = HmacSha384::new(prk);
        t = hmac.compute(&data).to_vec();

        let to_copy = core::cmp::min(hash_len, length - output.len());
        output.extend_from_slice(&t[..to_copy]);
    }

    output
}

// Internal HKDF-Expand implementation for SHA-512
fn hkdf_expand_sha512(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 64;
    let n = (length + hash_len - 1) / hash_len;

    if n > 255 {
        panic!("HKDF output too long");
    }

    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i as u8);

        let hmac = HmacSha512::new(prk);
        t = hmac.compute(&data).to_vec();

        let to_copy = core::cmp::min(hash_len, length - output.len());
        output.extend_from_slice(&t[..to_copy]);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_expand_label_sha256_basic() {
        // Basic functionality test
        let secret = [0u8; 32];
        let output = hkdf_expand_label_sha256(&secret, "quic key", &[], 16);
        assert_eq!(output.len(), 16);
    }

    #[test]
    fn test_quic_labels() {
        // Test QUIC-specific labels
        let secret = [0x42; 32];

        // Derive key
        let key = hkdf_expand_label_sha256(&secret, "quic key", &[], 16);
        assert_eq!(key.len(), 16);

        // Derive IV
        let iv = hkdf_expand_label_sha256(&secret, "quic iv", &[], 12);
        assert_eq!(iv.len(), 12);

        // Derive header protection key
        let hp = hkdf_expand_label_sha256(&secret, "quic hp", &[], 16);
        assert_eq!(hp.len(), 16);

        // Verify they're all different
        assert_ne!(key.to_vec(), iv[..12].to_vec());
        assert_ne!(key.to_vec(), hp.to_vec());
        assert_ne!(iv[..12].to_vec(), hp[..12].to_vec());
    }

    #[test]
    fn test_quic_vs_tls13_prefix() {
        // Verify QUIC uses different prefix than TLS 1.3
        let secret = [0x42; 32];

        let quic_key = hkdf_expand_label_sha256(&secret, "key", &[], 16);

        // Manually construct TLS 1.3 version for comparison
        use crate::tls13::hkdf_expand_label_sha256 as tls13_expand;
        let tls13_key = tls13_expand(&secret, "key", &[], 16);

        // They should be different due to different prefixes
        assert_ne!(
            quic_key, tls13_key,
            "QUIC and TLS 1.3 should use different prefixes"
        );
    }

    #[test]
    fn test_hkdf_expand_label_sha384() {
        // Test with SHA-384
        let secret = [0u8; 48];

        let key = hkdf_expand_label_sha384(&secret, "quic key", &[], 32);
        assert_eq!(key.len(), 32);

        let iv = hkdf_expand_label_sha384(&secret, "quic iv", &[], 12);
        assert_eq!(iv.len(), 12);

        let hp = hkdf_expand_label_sha384(&secret, "quic hp", &[], 32);
        assert_eq!(hp.len(), 32);
    }

    #[test]
    fn test_various_lengths() {
        let secret = [0u8; 32];

        // Test various output lengths
        for length in [1, 8, 16, 32, 48, 64, 128, 255] {
            let output = hkdf_expand_label_sha256(&secret, "quic test", &[], length);
            assert_eq!(output.len(), length as usize);
        }
    }

    #[test]
    fn test_context_affects_output() {
        let secret = [1u8; 32];
        let context1 = [0u8; 32];
        let context2 = [1u8; 32];

        let out1 = hkdf_expand_label_sha256(&secret, "quic key", &context1, 16);
        let out2 = hkdf_expand_label_sha256(&secret, "quic key", &context2, 16);

        assert_ne!(
            out1, out2,
            "Different contexts should produce different outputs"
        );
    }

    #[test]
    #[should_panic(expected = "Label too long")]
    fn test_label_too_long() {
        let secret = [0u8; 32];
        let long_label = "a".repeat(251); // "quic " + this = 256 > 255
        hkdf_expand_label_sha256(&secret, &long_label, &[], 16);
    }

    #[test]
    #[should_panic(expected = "Context too long")]
    fn test_context_too_long() {
        let secret = [0u8; 32];
        let long_context = alloc::vec![0u8; 256];
        hkdf_expand_label_sha256(&secret, "quic key", &long_context, 16);
    }

    #[test]
    fn test_quic_initial_keys() {
        // Simulate QUIC initial key derivation
        // This follows RFC 9001 Section 5.2
        let initial_secret = [0x42; 32];

        // Derive client initial keys
        let client_key = hkdf_expand_label_sha256(&initial_secret, "quic key", &[], 16);
        let client_iv = hkdf_expand_label_sha256(&initial_secret, "quic iv", &[], 12);
        let client_hp = hkdf_expand_label_sha256(&initial_secret, "quic hp", &[], 16);

        assert_eq!(client_key.len(), 16); // AES-128 key
        assert_eq!(client_iv.len(), 12); // AEAD nonce
        assert_eq!(client_hp.len(), 16); // Header protection key

        // Verify all three are different
        assert_ne!(client_key, client_hp);
        assert_ne!(&client_key[..12], &client_iv[..]);
        assert_ne!(&client_hp[..12], &client_iv[..]);
    }

    #[test]
    fn test_quic_aes256_keys() {
        // Simulate QUIC AES-256-GCM key derivation
        let secret = [0x42; 48];

        // Derive keys for AES-256-GCM
        let key = hkdf_expand_label_sha384(&secret, "quic key", &[], 32);
        let iv = hkdf_expand_label_sha384(&secret, "quic iv", &[], 12);
        let hp = hkdf_expand_label_sha384(&secret, "quic hp", &[], 32);

        assert_eq!(key.len(), 32); // AES-256 key
        assert_eq!(iv.len(), 12); // AEAD nonce
        assert_eq!(hp.len(), 32); // Header protection key for AES-256
    }

    #[test]
    fn test_label_variations() {
        // Test different QUIC label formats
        let secret = [0x42; 32];

        let key1 = hkdf_expand_label_sha256(&secret, "quic key", &[], 16);
        let key2 = hkdf_expand_label_sha256(&secret, "quic ku", &[], 16);
        let key3 = hkdf_expand_label_sha256(&secret, "key", &[], 16);

        // All should be different
        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }
}
