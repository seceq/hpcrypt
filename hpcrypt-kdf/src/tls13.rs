//! TLS 1.3 Key Derivation Functions
//!
//! This module implements TLS 1.3 specific key derivation functions as defined in RFC 8446.
//!
//! # HKDF-Expand-Label

#![allow(clippy::manual_div_ceil)] // MSRV 1.70 compatibility - div_ceil stabilized in 1.73
//!
//! TLS 1.3 uses a wrapper around HKDF-Expand called HKDF-Expand-Label:
//!
//! ```text
//! HKDF-Expand-Label(Secret, Label, Context, Length) =
//!     HKDF-Expand(Secret, HkdfLabel, Length)
//!
//! Where HkdfLabel is:
//!   struct {
//!       uint16 length = Length;
//!       opaque label<7..255> = "tls13 " + Label;
//!       opaque context<0..255> = Context;
//!   } HkdfLabel;
//! ```
//!
//! # Example
//!
//! ```rust
//! use hpcrypt_kdf::tls13::{hkdf_expand_label_sha256, hkdf_expand_label_sha384};
//!
//! // Derive key from traffic secret (with SHA-256)
//! let traffic_secret = [0u8; 32];
//! let key = hkdf_expand_label_sha256(&traffic_secret, "key", &[], 16);
//! assert_eq!(key.len(), 16);
//!
//! // Derive key with SHA-384 (for AES-256-GCM cipher suites)
//! let traffic_secret_384 = [0u8; 48];
//! let key_384 = hkdf_expand_label_sha384(&traffic_secret_384, "key", &[], 32);
//! assert_eq!(key_384.len(), 32);
//! ```

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;

use hpcrypt_mac::{HmacSha256, HmacSha384, HmacSha512};

/// HKDF-Expand-Label with SHA-256
///
/// This is used with TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256 cipher suites.
///
/// # Arguments
///
/// * `secret` - The secret (PRK) to expand from
/// * `label` - The label string (without "tls13 " prefix)
/// * `context` - The context data (usually transcript hash)
/// * `length` - The desired output length in bytes
///
/// # Examples
///
/// ```rust
/// use hpcrypt_kdf::tls13::hkdf_expand_label_sha256;
///
/// // Derive handshake traffic secret
/// let handshake_secret = [0u8; 32];
/// let transcript_hash = [0u8; 32];
///
/// let client_secret = hkdf_expand_label_sha256(
///     &handshake_secret,
///     "c hs traffic",
///     &transcript_hash,
///     32
/// );
///
/// // Derive key from traffic secret
/// let key = hkdf_expand_label_sha256(&client_secret, "key", &[], 16);
///
/// // Derive IV from traffic secret
/// let iv = hkdf_expand_label_sha256(&client_secret, "iv", &[], 12);
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

    // opaque label<7..255> = "tls13 " + Label
    let full_label = format!("tls13 {}", label);
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

/// HKDF-Expand-Label with SHA-384
///
/// This is used with TLS_AES_256_GCM_SHA384 cipher suite.
///
/// # Arguments
///
/// * `secret` - The secret (PRK) to expand from (48 bytes for SHA-384)
/// * `label` - The label string (without "tls13 " prefix)
/// * `context` - The context data (usually transcript hash)
/// * `length` - The desired output length in bytes
pub fn hkdf_expand_label_sha384(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    let full_label = format!("tls13 {}", label);
    assert!(full_label.len() <= 255, "Label too long");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());

    assert!(context.len() <= 255, "Context too long");
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand_sha384(secret, &hkdf_label, length as usize)
}

/// HKDF-Expand-Label with SHA-512
///
/// This is not used in standard TLS 1.3 cipher suites, but provided for completeness.
pub fn hkdf_expand_label_sha512(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    let full_label = format!("tls13 {}", label);
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
    use hex_literal::hex;

    #[test]
    fn test_hkdf_expand_label_sha256_basic() {
        // Basic functionality test
        let secret = [0u8; 32];
        let output = hkdf_expand_label_sha256(&secret, "key", &[], 16);
        assert_eq!(output.len(), 16);
    }

    #[test]
    fn test_hkdf_expand_label_sha256_rfc8448() {
        // Test vector from RFC 8448 Section 3 (Simple 1-RTT Handshake)
        // Server handshake traffic secret
        let server_secret = hex!(
            "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
             e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"
        );

        // Derive "key"
        let key = hkdf_expand_label_sha256(&server_secret, "key", &[], 16);
        let expected_key = hex!("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc");
        assert_eq!(key, expected_key);

        // Derive "iv"
        let iv = hkdf_expand_label_sha256(&server_secret, "iv", &[], 12);
        let expected_iv = hex!("5d 31 3e b2 67 12 76 ee 13 00 0b 30");
        assert_eq!(iv, expected_iv);
    }

    #[test]
    fn test_hkdf_expand_label_sha256_with_context() {
        // Test with non-empty context
        let secret = hex!(
            "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
             10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"
        );

        let context = hex!(
            "e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
             27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55"
        );

        let client_secret = hkdf_expand_label_sha256(&secret, "c hs traffic", &context, 32);

        // Verify it produces 32 bytes
        assert_eq!(client_secret.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_label_sha384() {
        // Test with SHA-384 (used with AES-256-GCM cipher suites)
        let secret = [0u8; 48];

        let key = hkdf_expand_label_sha384(&secret, "key", &[], 32);
        assert_eq!(key.len(), 32);

        let iv = hkdf_expand_label_sha384(&secret, "iv", &[], 12);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_hkdf_expand_label_sha256_various_lengths() {
        let secret = [0u8; 32];

        // Test various output lengths
        for length in [1, 8, 16, 32, 48, 64, 128, 255] {
            let output = hkdf_expand_label_sha256(&secret, "test", &[], length);
            assert_eq!(output.len(), length as usize);
        }
    }

    #[test]
    fn test_label_prefix() {
        // Verify "tls13 " prefix is added correctly
        let secret = [1u8; 32];

        // These should produce different outputs (different labels)
        let out1 = hkdf_expand_label_sha256(&secret, "key", &[], 16);
        let out2 = hkdf_expand_label_sha256(&secret, "iv", &[], 16);

        assert_ne!(
            out1, out2,
            "Different labels should produce different outputs"
        );
    }

    #[test]
    fn test_context_affects_output() {
        let secret = [1u8; 32];
        let context1 = [0u8; 32];
        let context2 = [1u8; 32];

        let out1 = hkdf_expand_label_sha256(&secret, "key", &context1, 16);
        let out2 = hkdf_expand_label_sha256(&secret, "key", &context2, 16);

        assert_ne!(
            out1, out2,
            "Different contexts should produce different outputs"
        );
    }

    #[test]
    #[should_panic(expected = "Label too long")]
    fn test_label_too_long() {
        let secret = [0u8; 32];
        let long_label = "a".repeat(250); // "tls13 " + this = 256 > 255
        hkdf_expand_label_sha256(&secret, &long_label, &[], 16);
    }

    #[test]
    #[should_panic(expected = "Context too long")]
    fn test_context_too_long() {
        let secret = [0u8; 32];
        let long_context = alloc::vec![0u8; 256];
        hkdf_expand_label_sha256(&secret, "key", &long_context, 16);
    }

    #[test]
    fn test_tls13_cipher_suite_sha256() {
        // Simulate TLS_AES_128_GCM_SHA256 key derivation
        let handshake_secret = [0x42; 32];
        let transcript_hash = [0x11; 32];

        // Derive client handshake traffic secret
        let client_hs_traffic =
            hkdf_expand_label_sha256(&handshake_secret, "c hs traffic", &transcript_hash, 32);

        // Derive key and IV from traffic secret
        let key = hkdf_expand_label_sha256(&client_hs_traffic, "key", &[], 16);
        let iv = hkdf_expand_label_sha256(&client_hs_traffic, "iv", &[], 12);

        assert_eq!(key.len(), 16); // AES-128 key
        assert_eq!(iv.len(), 12); // GCM nonce
    }

    #[test]
    fn test_tls13_cipher_suite_sha384() {
        // Simulate TLS_AES_256_GCM_SHA384 key derivation
        let handshake_secret = [0x42; 48];
        let transcript_hash = [0x11; 48];

        // Derive server handshake traffic secret
        let server_hs_traffic =
            hkdf_expand_label_sha384(&handshake_secret, "s hs traffic", &transcript_hash, 48);

        // Derive key and IV from traffic secret
        let key = hkdf_expand_label_sha384(&server_hs_traffic, "key", &[], 32);
        let iv = hkdf_expand_label_sha384(&server_hs_traffic, "iv", &[], 12);

        assert_eq!(key.len(), 32); // AES-256 key
        assert_eq!(iv.len(), 12); // GCM nonce
    }
}
