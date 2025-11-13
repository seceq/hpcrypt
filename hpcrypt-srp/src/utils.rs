//! Utility functions for SRP protocol

use crate::SrpHashFunction;
use alloc::vec::Vec;
use hpcrypt_hash::{sha1, sha256, sha512};
use num_bigint::BigUint;

/// Internal helper to hash data with the specified hash function
fn hash_data(data: &[u8], hash_fn: SrpHashFunction) -> Vec<u8> {
    match hash_fn {
        SrpHashFunction::Sha1 => sha1(data).to_vec(),
        SrpHashFunction::Sha256 => sha256(data).to_vec(),
        SrpHashFunction::Sha512 => sha512(data).to_vec(),
    }
}

/// PAD function from RFC 5054
/// If the length of the number is not a multiple of the group length,
/// pad with leading zeros to match the group length
pub fn pad(n: &BigUint, group_byte_len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();

    if bytes.len() >= group_byte_len {
        bytes
    } else {
        let mut padded = vec![0u8; group_byte_len];
        let offset = group_byte_len - bytes.len();
        padded[offset..].copy_from_slice(&bytes);
        padded
    }
}

/// Compute k = H(N | PAD(g)) for SRP-6a
///
/// Where H can be SHA-1 (RFC 5054), SHA-256, or SHA-512
pub fn compute_k(
    n: &BigUint,
    g: &BigUint,
    group_byte_len: usize,
    hash_fn: SrpHashFunction,
) -> BigUint {
    let mut input = Vec::new();
    input.extend_from_slice(&pad(n, group_byte_len));
    input.extend_from_slice(&pad(g, group_byte_len));

    let hash = hash_data(&input, hash_fn);
    BigUint::from_bytes_be(&hash)
}

/// Compute u = H(PAD(A) | PAD(B))
///
/// Where H can be SHA-1 (RFC 5054), SHA-256, or SHA-512
pub fn compute_u(
    a_pub: &BigUint,
    b_pub: &BigUint,
    group_byte_len: usize,
    hash_fn: SrpHashFunction,
) -> BigUint {
    let mut input = Vec::new();
    input.extend_from_slice(&pad(a_pub, group_byte_len));
    input.extend_from_slice(&pad(b_pub, group_byte_len));

    let hash = hash_data(&input, hash_fn);
    BigUint::from_bytes_be(&hash)
}

/// Compute x = H(s | H(I | ":" | P))
///
/// Where H can be SHA-1 (RFC 5054), SHA-256, or SHA-512
pub fn compute_x(
    username: &[u8],
    password: &[u8],
    salt: &[u8],
    hash_fn: SrpHashFunction,
) -> BigUint {
    // First hash: H(I | ":" | P)
    let mut inner = Vec::new();
    inner.extend_from_slice(username);
    inner.push(b':');
    inner.extend_from_slice(password);
    let inner_hash = hash_data(&inner, hash_fn);

    // Second hash: H(s | inner_hash)
    let mut outer = Vec::new();
    outer.extend_from_slice(salt);
    outer.extend_from_slice(&inner_hash);
    let outer_hash = hash_data(&outer, hash_fn);

    BigUint::from_bytes_be(&outer_hash)
}

/// Interleave hash function for computing K from S
/// This is the SRP session key derivation
///
/// K = H(S) where H can be SHA-1 (RFC 5054), SHA-256, or SHA-512
pub fn compute_k_from_s(s: &BigUint, group_byte_len: usize, hash_fn: SrpHashFunction) -> Vec<u8> {
    // S is hashed to produce the session key K
    // K = H(S)
    let s_bytes = pad(s, group_byte_len);
    hash_data(&s_bytes, hash_fn)
}

/// Compute M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
///
/// Where H can be SHA-1 (RFC 5054), SHA-256, or SHA-512
#[allow(clippy::too_many_arguments)]
pub fn compute_m1(
    n: &BigUint,
    g: &BigUint,
    username: &[u8],
    salt: &[u8],
    a_pub: &BigUint,
    b_pub: &BigUint,
    k: &[u8],
    group_byte_len: usize,
    hash_fn: SrpHashFunction,
) -> Vec<u8> {
    // Hash N and g
    let n_bytes = pad(n, group_byte_len);
    let g_bytes = pad(g, group_byte_len);
    let hash_n = hash_data(&n_bytes, hash_fn);
    let hash_g = hash_data(&g_bytes, hash_fn);

    // XOR hash_n and hash_g (works for any hash size)
    let hash_len = hash_fn.output_size();
    let mut xor_result = vec![0u8; hash_len];
    for i in 0..hash_len {
        xor_result[i] = hash_n[i] ^ hash_g[i];
    }

    // Hash username
    let hash_i = hash_data(username, hash_fn);

    // Concatenate all parts
    let mut input = Vec::new();
    input.extend_from_slice(&xor_result);
    input.extend_from_slice(&hash_i);
    input.extend_from_slice(salt);
    input.extend_from_slice(&pad(a_pub, group_byte_len));
    input.extend_from_slice(&pad(b_pub, group_byte_len));
    input.extend_from_slice(k);

    hash_data(&input, hash_fn)
}

/// Compute M2 = H(A | M1 | K)
///
/// Where H can be SHA-1 (RFC 5054), SHA-256, or SHA-512
pub fn compute_m2(
    a_pub: &BigUint,
    m1: &[u8],
    k: &[u8],
    group_byte_len: usize,
    hash_fn: SrpHashFunction,
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&pad(a_pub, group_byte_len));
    input.extend_from_slice(m1);
    input.extend_from_slice(k);

    hash_data(&input, hash_fn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad() {
        let n = BigUint::from(255u32);
        let padded = pad(&n, 4);
        assert_eq!(padded, vec![0, 0, 0, 255]);

        let n = BigUint::from(65535u32);
        let padded = pad(&n, 4);
        assert_eq!(padded, vec![0, 0, 255, 255]);
    }

    #[test]
    fn test_compute_x() {
        let username = b"alice";
        let password = b"password123";
        let salt = &[1, 2, 3, 4];

        // Test with SHA-256 (recommended)
        let x = compute_x(username, password, salt, SrpHashFunction::Sha256);
        assert!(x > BigUint::from(0u32));

        // Test with SHA-512
        let x512 = compute_x(username, password, salt, SrpHashFunction::Sha512);
        assert!(x512 > BigUint::from(0u32));

        // Test with SHA-1 (legacy)
        let x1 = compute_x(username, password, salt, SrpHashFunction::Sha1);
        assert!(x1 > BigUint::from(0u32));

        // Different hash functions should produce different results
        assert_ne!(x, x512);
        assert_ne!(x, x1);
    }
}
