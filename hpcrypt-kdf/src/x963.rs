//! ANSI X9.63 Key Derivation Function
//!
//! Implements the KDF specified in ANSI X9.63-2001 and SEC 1 v2.0.
//! Used primarily for ECIES (Elliptic Curve Integrated Encryption Scheme).

use alloc::vec::Vec;

/// ANSI X9.63 KDF using a specified hash function
///
/// # Arguments
///
/// * `shared_secret` - The shared secret from ECDH
/// * `shared_info` - Optional shared information (can be empty)
/// * `key_len` - Desired output length in bytes
/// * `hash_fn` - Hash function to use
///
/// # Algorithm
///
/// ```text
/// KDF(Z, SharedInfo, keyLen):
///   1. counter = 1
///   2. output = empty
///   3. while len(output) < keyLen:
///       output = output || Hash(Z || counter || SharedInfo)
///       counter = counter + 1
///   4. return first keyLen bytes of output
/// ```
///
/// # Security
///
/// - Use SHA-256 or stronger hash function
/// - Shared info provides domain separation
/// - Counter ensures each block is unique
///
/// # Example
///
/// ```ignore
/// use hpcrypt_kdf::x963::x963_kdf_sha256;
///
/// let shared_secret = b"shared secret from ECDH";
/// let shared_info = b"optional context";
/// let key = x963_kdf_sha256(shared_secret, shared_info, 32);
/// ```
pub fn x963_kdf<H>(
    shared_secret: &[u8],
    shared_info: &[u8],
    key_len: usize,
    hash_fn: H,
) -> Vec<u8>
where
    H: Fn(&[u8]) -> Vec<u8>,
{
    let mut output = Vec::new();
    let mut counter = 1u32;

    while output.len() < key_len {
        // Build input: Z || counter || SharedInfo
        let mut input = Vec::new();
        input.extend_from_slice(shared_secret);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(shared_info);

        // Hash and append
        let hash_output = hash_fn(&input);
        output.extend_from_slice(&hash_output);

        counter += 1;
    }

    // Truncate to requested length
    output.truncate(key_len);
    output
}

/// X9.63 KDF with SHA-256
pub fn x963_kdf_sha256(
    shared_secret: &[u8],
    shared_info: &[u8],
    key_len: usize,
) -> Vec<u8> {
    x963_kdf(shared_secret, shared_info, key_len, |input| {
        // Use hpcrypt-hash SHA-256
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    })
}

/// X9.63 KDF with SHA-384
pub fn x963_kdf_sha384(
    shared_secret: &[u8],
    shared_info: &[u8],
    key_len: usize,
) -> Vec<u8> {
    x963_kdf(shared_secret, shared_info, key_len, |input| {
        use sha2::{Sha384, Digest};
        let mut hasher = Sha384::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    })
}

/// X9.63 KDF with SHA-512
pub fn x963_kdf_sha512(
    shared_secret: &[u8],
    shared_info: &[u8],
    key_len: usize,
) -> Vec<u8> {
    x963_kdf(shared_secret, shared_info, key_len, |input| {
        use sha2::{Sha512, Digest};
        let mut hasher = Sha512::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x963_kdf_sha256_basic() {
        let shared_secret = b"shared secret";
        let shared_info = b"";
        let key = x963_kdf_sha256(shared_secret, shared_info, 32);

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_x963_kdf_sha256_with_info() {
        let shared_secret = b"shared secret";
        let shared_info = b"context info";
        let key = x963_kdf_sha256(shared_secret, shared_info, 32);

        assert_eq!(key.len(), 32);

        // Different info should produce different key
        let shared_info2 = b"different info";
        let key2 = x963_kdf_sha256(shared_secret, shared_info2, 32);

        assert_ne!(key, key2);
    }

    #[test]
    fn test_x963_kdf_different_lengths() {
        let shared_secret = b"shared secret";
        let shared_info = b"";

        let key16 = x963_kdf_sha256(shared_secret, shared_info, 16);
        let key32 = x963_kdf_sha256(shared_secret, shared_info, 32);
        let key64 = x963_kdf_sha256(shared_secret, shared_info, 64);

        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);

        // First 16 bytes of key32 should match key16
        assert_eq!(key16, &key32[..16]);

        // First 32 bytes of key64 should match key32
        assert_eq!(key32, &key64[..32]);
    }

    #[test]
    fn test_x963_kdf_sha256_deterministic() {
        let shared_secret = b"shared secret";
        let shared_info = b"info";

        let key1 = x963_kdf_sha256(shared_secret, shared_info, 32);
        let key2 = x963_kdf_sha256(shared_secret, shared_info, 32);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_x963_kdf_sha384() {
        let shared_secret = b"shared secret";
        let shared_info = b"";
        let key = x963_kdf_sha384(shared_secret, shared_info, 48);

        assert_eq!(key.len(), 48);
    }

    #[test]
    fn test_x963_kdf_sha512() {
        let shared_secret = b"shared secret";
        let shared_info = b"";
        let key = x963_kdf_sha512(shared_secret, shared_info, 64);

        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_x963_kdf_multiple_blocks() {
        // Request more bytes than one hash output (SHA-256 = 32 bytes)
        let shared_secret = b"secret";
        let shared_info = b"";

        // Request 100 bytes (requires 4 hash calls: 32+32+32+4)
        let key = x963_kdf_sha256(shared_secret, shared_info, 100);
        assert_eq!(key.len(), 100);
    }

    #[test]
    fn test_x963_kdf_empty_secret() {
        let shared_secret = b"";
        let shared_info = b"info";
        let key = x963_kdf_sha256(shared_secret, shared_info, 32);

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_x963_kdf_empty_info() {
        let shared_secret = b"secret";
        let shared_info = b"";
        let key = x963_kdf_sha256(shared_secret, shared_info, 32);

        assert_eq!(key.len(), 32);
    }

    // Test vectors from NIST SP 800-56A (if available)
    // Note: X9.63 is equivalent to SP 800-56A Concatenation KDF with counter
}
