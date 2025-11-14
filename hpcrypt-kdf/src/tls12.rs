//! TLS 1.2 Key Derivation Functions
//!
//! This module implements TLS 1.2 specific key derivation functions as defined in RFC 5246.
//!
//! # TLS 1.2 PRF (Pseudo-Random Function)
//!
//! TLS 1.2 uses a PRF based on HMAC for key derivation:
//!
//! ```text
//! PRF(secret, label, seed) = P_<hash>(secret, label + seed)
//!
//! P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//!                        HMAC_hash(secret, A(2) + seed) +
//!                        HMAC_hash(secret, A(3) + seed) + ...
//!
//! Where:
//!   A(0) = seed
//!   A(i) = HMAC_hash(secret, A(i-1))
//! ```
//!
//! # Example
//!
//! ```rust
//! use hpcrypt_kdf::tls12::{prf_sha256, prf_sha384};
//!
//! // TLS 1.2 master secret derivation (simplified)
//! let pre_master_secret = [0u8; 48];
//! let client_random = [0u8; 32];
//! let server_random = [0u8; 32];
//!
//! let mut seed = Vec::new();
//! seed.extend_from_slice(&client_random);
//! seed.extend_from_slice(&server_random);
//!
//! let mut master_secret = [0u8; 48];
//! prf_sha256(&pre_master_secret, "master secret", &seed, &mut master_secret);
//! ```

extern crate alloc;
use alloc::vec::Vec;

use hpcrypt_mac::{HmacSha256, HmacSha384, HmacSha512};

/// TLS 1.2 PRF using SHA-256
///
/// This is used with most TLS 1.2 cipher suites (default PRF since TLS 1.2).
///
/// # Arguments
///
/// * `secret` - The secret value (e.g., pre_master_secret)
/// * `label` - ASCII label string (e.g., "master secret", "key expansion")
/// * `seed` - Seed data (typically client_random + server_random)
/// * `output` - Output buffer to fill with derived key material
///
/// # Examples
///
/// ```rust
/// use hpcrypt_kdf::tls12::prf_sha256;
///
/// // Derive master secret (TLS 1.2)
/// let pre_master_secret = [0u8; 48];
/// let label = "master secret";
/// let mut seed = Vec::new();
/// seed.extend_from_slice(&[0u8; 32]); // client_random
/// seed.extend_from_slice(&[0u8; 32]); // server_random
///
/// let mut master_secret = [0u8; 48];
/// prf_sha256(&pre_master_secret, label, &seed, &mut master_secret);
/// ```
pub fn prf_sha256(secret: &[u8], label: &str, seed: &[u8], output: &mut [u8]) {
    // Construct full seed: label + seed
    let mut full_seed = Vec::new();
    full_seed.extend_from_slice(label.as_bytes());
    full_seed.extend_from_slice(seed);

    // P_SHA256(secret, label + seed)
    p_hash_sha256(secret, &full_seed, output);
}

/// TLS 1.2 PRF using SHA-384
///
/// This is used with SHA-384 based cipher suites (e.g., TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
///
/// # Arguments
///
/// * `secret` - The secret value
/// * `label` - ASCII label string
/// * `seed` - Seed data
/// * `output` - Output buffer to fill
pub fn prf_sha384(secret: &[u8], label: &str, seed: &[u8], output: &mut [u8]) {
    let mut full_seed = Vec::new();
    full_seed.extend_from_slice(label.as_bytes());
    full_seed.extend_from_slice(seed);

    p_hash_sha384(secret, &full_seed, output);
}

/// TLS 1.2 PRF using SHA-512
///
/// This is rarely used but provided for completeness.
pub fn prf_sha512(secret: &[u8], label: &str, seed: &[u8], output: &mut [u8]) {
    let mut full_seed = Vec::new();
    full_seed.extend_from_slice(label.as_bytes());
    full_seed.extend_from_slice(seed);

    p_hash_sha512(secret, &full_seed, output);
}

// Internal P_hash implementation for SHA-256
fn p_hash_sha256(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let hash_len = 32; // SHA-256 output size
    let mut a = seed.to_vec(); // A(0) = seed
    let mut offset = 0;

    while offset < output.len() {
        // A(i) = HMAC(secret, A(i-1))
        let hmac = HmacSha256::new(secret);
        a = hmac.compute(&a).to_vec();

        // P_hash chunk = HMAC(secret, A(i) + seed)
        let mut data = Vec::new();
        data.extend_from_slice(&a);
        data.extend_from_slice(seed);

        let hmac = HmacSha256::new(secret);
        let chunk = hmac.compute(&data);

        let to_copy = core::cmp::min(hash_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&chunk[..to_copy]);
        offset += to_copy;
    }
}

// Internal P_hash implementation for SHA-384
fn p_hash_sha384(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let hash_len = 48; // SHA-384 output size
    let mut a = seed.to_vec();
    let mut offset = 0;

    while offset < output.len() {
        let hmac = HmacSha384::new(secret);
        a = hmac.compute(&a).to_vec();

        let mut data = Vec::new();
        data.extend_from_slice(&a);
        data.extend_from_slice(seed);

        let hmac = HmacSha384::new(secret);
        let chunk = hmac.compute(&data);

        let to_copy = core::cmp::min(hash_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&chunk[..to_copy]);
        offset += to_copy;
    }
}

// Internal P_hash implementation for SHA-512
fn p_hash_sha512(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let hash_len = 64; // SHA-512 output size
    let mut a = seed.to_vec();
    let mut offset = 0;

    while offset < output.len() {
        let hmac = HmacSha512::new(secret);
        a = hmac.compute(&a).to_vec();

        let mut data = Vec::new();
        data.extend_from_slice(&a);
        data.extend_from_slice(seed);

        let hmac = HmacSha512::new(secret);
        let chunk = hmac.compute(&data);

        let to_copy = core::cmp::min(hash_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&chunk[..to_copy]);
        offset += to_copy;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_prf_sha256_basic() {
        // Basic functionality test
        let secret = [0u8; 32];
        let label = "test label";
        let seed = [0u8; 32];

        let mut output = [0u8; 64];
        prf_sha256(&secret, label, &seed, &mut output);

        // Should produce deterministic output
        let mut output2 = [0u8; 64];
        prf_sha256(&secret, label, &seed, &mut output2);

        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_sha256_rfc5246() {
        // Test vector from RFC 5246 Section 8.1
        // This is a simplified test - RFC 5246 doesn't provide direct PRF test vectors
        // but we can verify the function produces consistent output

        let secret = b"secret";
        let label = "label";
        let seed = b"seed";

        let mut output = [0u8; 100];
        prf_sha256(secret, label, seed, &mut output);

        // Verify it's not all zeros (basic sanity check)
        assert_ne!(output, [0u8; 100]);
    }

    #[test]
    fn test_prf_sha256_master_secret() {
        // Simulate master secret derivation
        let pre_master_secret = [0x42; 48];
        let client_random = [0x01; 32];
        let server_random = [0x02; 32];

        let mut seed = Vec::new();
        seed.extend_from_slice(&client_random);
        seed.extend_from_slice(&server_random);

        let mut master_secret = [0u8; 48];
        prf_sha256(
            &pre_master_secret,
            "master secret",
            &seed,
            &mut master_secret,
        );

        assert_eq!(master_secret.len(), 48);
        assert_ne!(master_secret, [0u8; 48]);
    }

    #[test]
    fn test_prf_sha256_key_expansion() {
        // Simulate key expansion
        let master_secret = [0x42; 48];
        let server_random = [0x01; 32];
        let client_random = [0x02; 32];

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);

        // Derive enough material for keys + IVs + MACs
        let mut key_material = [0u8; 104];
        prf_sha256(&master_secret, "key expansion", &seed, &mut key_material);

        assert_ne!(key_material, [0u8; 104]);
    }

    #[test]
    fn test_prf_sha384_basic() {
        let secret = [0u8; 48];
        let label = "test label";
        let seed = [0u8; 32];

        let mut output = [0u8; 96];
        prf_sha384(&secret, label, &seed, &mut output);

        // Should produce deterministic output
        let mut output2 = [0u8; 96];
        prf_sha384(&secret, label, &seed, &mut output2);

        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_different_labels_produce_different_output() {
        let secret = [0x42; 32];
        let seed = [0x01; 32];

        let mut output1 = [0u8; 48];
        prf_sha256(&secret, "master secret", &seed, &mut output1);

        let mut output2 = [0u8; 48];
        prf_sha256(&secret, "key expansion", &seed, &mut output2);

        assert_ne!(
            output1, output2,
            "Different labels should produce different outputs"
        );
    }

    #[test]
    fn test_prf_different_seeds_produce_different_output() {
        let secret = [0x42; 32];
        let label = "master secret";

        let seed1 = [0x01; 32];
        let mut output1 = [0u8; 48];
        prf_sha256(&secret, label, &seed1, &mut output1);

        let seed2 = [0x02; 32];
        let mut output2 = [0u8; 48];
        prf_sha256(&secret, label, &seed2, &mut output2);

        assert_ne!(
            output1, output2,
            "Different seeds should produce different outputs"
        );
    }

    #[test]
    fn test_prf_variable_output_lengths() {
        let secret = [0x42; 32];
        let label = "test";
        let seed = [0x01; 32];

        // Test various output lengths
        for length in [1, 16, 32, 48, 64, 100, 200] {
            let mut output = vec![0u8; length];
            prf_sha256(&secret, label, &seed, &mut output);
            assert_ne!(
                output,
                vec![0u8; length],
                "Output should not be all zeros for length {}",
                length
            );
        }
    }

    #[test]
    fn test_prf_sha256_vs_sha384_different() {
        let secret = [0x42; 48];
        let label = "test";
        let seed = [0x01; 32];

        let mut output_sha256 = [0u8; 48];
        prf_sha256(&secret, label, &seed, &mut output_sha256);

        let mut output_sha384 = [0u8; 48];
        prf_sha384(&secret, label, &seed, &mut output_sha384);

        assert_ne!(
            output_sha256, output_sha384,
            "SHA-256 and SHA-384 PRFs should produce different outputs"
        );
    }

    #[test]
    fn test_prf_empty_label() {
        // Test with empty label (edge case)
        let secret = [0x42; 32];
        let label = "";
        let seed = [0x01; 32];

        let mut output = [0u8; 32];
        prf_sha256(&secret, label, &seed, &mut output);

        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_prf_long_label() {
        // Test with long label
        let secret = [0x42; 32];
        let label = "this is a very long label that might be used in some custom TLS extension";
        let seed = [0x01; 32];

        let mut output = [0u8; 64];
        prf_sha256(&secret, label, &seed, &mut output);

        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_prf_tls12_typical_workflow() {
        // Simulate typical TLS 1.2 key derivation workflow

        // 1. Derive master secret
        let pre_master_secret = [0x42; 48];
        let client_random = [0x01; 32];
        let server_random = [0x02; 32];

        let mut master_secret_seed = Vec::new();
        master_secret_seed.extend_from_slice(&client_random);
        master_secret_seed.extend_from_slice(&server_random);

        let mut master_secret = [0u8; 48];
        prf_sha256(
            &pre_master_secret,
            "master secret",
            &master_secret_seed,
            &mut master_secret,
        );

        // 2. Derive key material
        let mut key_expansion_seed = Vec::new();
        key_expansion_seed.extend_from_slice(&server_random);
        key_expansion_seed.extend_from_slice(&client_random);

        let mut key_material = [0u8; 104]; // Enough for AES-256-CBC + HMAC-SHA256
        prf_sha256(
            &master_secret,
            "key expansion",
            &key_expansion_seed,
            &mut key_material,
        );

        // Verify we got non-zero material
        assert_ne!(master_secret, [0u8; 48]);
        assert_ne!(key_material, [0u8; 104]);

        // Verify master secret and key material are different
        assert_ne!(&master_secret[..48], &key_material[..48]);
    }
}
