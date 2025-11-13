//! Shamir Secret Sharing Scheme
//!
//! Implementation of Shamir's Secret Sharing algorithm over GF(256).
//!
//! This module provides (k, n)-threshold secret sharing where:
//! - A secret is split into n shares
//! - Any k shares can reconstruct the secret
//! - k-1 shares reveal no information about the secret
//!
//! # Security Properties
//!
//! - Information-theoretic security: k-1 shares provide zero information
//! - Perfect secrecy: All possible secrets are equally likely given k-1 shares
//! - No computational assumptions required
//!
//! # Limitations
//!
//! - Works in GF(256), so each share is the same size as the secret
//! - Maximum 255 shares (due to GF(256) arithmetic)
//! - Not suitable for very large secrets (consider hybrid approaches)

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use hpcrypt_core::error::CurveError;
use hpcrypt_rng::generate_random_bytes;
use zeroize::Zeroize;

/// A share in Shamir Secret Sharing
///
/// Contains an x-coordinate (share index) and y-coordinate (share value).
/// The secret can be reconstructed using Lagrange interpolation from k shares.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    /// Share index (x-coordinate), must be non-zero
    pub x: u8,
    /// Share value (y-coordinates for each byte of the secret)
    pub y: Vec<u8>,
}

/// Split a secret into n shares requiring k shares to reconstruct
///
/// # Arguments
///
/// * `secret` - The secret to split (any byte array)
/// * `threshold` - Minimum number of shares required to reconstruct (k)
/// * `num_shares` - Total number of shares to create (n)
///
/// # Returns
///
/// A vector of n shares, where any k shares can reconstruct the secret.
///
/// # Errors
///
/// Returns error if:
/// - threshold < 2 (need at least 2 shares)
/// - threshold > num_shares (can't require more shares than exist)
/// - num_shares > 255 (GF(256) limitation)
/// - secret is empty
///
/// # Example
///
/// ```
/// use hpcrypt_shamir::shamir::split_secret;
///
/// let secret = b"my secret data";
/// let shares = split_secret(secret, 3, 5).unwrap();
/// assert_eq!(shares.len(), 5);
/// ```
pub fn split_secret(
    secret: &[u8],
    threshold: usize,
    num_shares: usize,
) -> Result<Vec<Share>, CurveError> {
    // Validate parameters
    if threshold < 2 {
        return Err(CurveError::InvalidEncoding {
            expected: "threshold >= 2",
            actual: threshold,
        });
    }
    if threshold > num_shares {
        return Err(CurveError::InvalidEncoding {
            expected: "threshold <= num_shares",
            actual: threshold,
        });
    }
    if num_shares > 255 {
        return Err(CurveError::InvalidEncoding {
            expected: "num_shares <= 255",
            actual: num_shares,
        });
    }
    if secret.is_empty() {
        return Err(CurveError::InvalidEncoding {
            expected: "non-empty secret",
            actual: 0,
        });
    }

    let secret_len = secret.len();
    let mut shares = Vec::with_capacity(num_shares);

    // Initialize share data for all shares
    for share_idx in 1..=num_shares {
        shares.push(Share {
            x: share_idx as u8,
            y: Vec::with_capacity(secret_len),
        });
    }

    // For each byte of the secret, generate a random polynomial and evaluate at each share's x
    for &secret_byte in secret.iter() {
        // Generate a random polynomial of degree (threshold-1)
        // p(x) = a0 + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        // where a0 = secret_byte

        let mut coefficients = vec![secret_byte];
        for _ in 1..threshold {
            let mut rand_byte = [0u8; 1];
            generate_random_bytes(&mut rand_byte).map_err(|_| CurveError::InvalidEncoding {
                expected: "random number generation",
                actual: 0,
            })?;
            coefficients.push(rand_byte[0]);
        }

        // Evaluate polynomial at each share's x coordinate
        for share in shares.iter_mut() {
            let y = eval_polynomial(&coefficients, share.x);
            share.y.push(y);
        }
    }

    Ok(shares)
}

/// Reconstruct a secret from k shares
///
/// # Arguments
///
/// * `shares` - At least k shares from the original split
///
/// # Returns
///
/// The reconstructed secret.
///
/// # Errors
///
/// Returns error if:
/// - Less than 2 shares provided
/// - Shares have different lengths
/// - Duplicate share indices
///
/// # Example
///
/// ```
/// use hpcrypt_shamir::shamir::{split_secret, reconstruct_secret};
///
/// let secret = b"my secret data";
/// let shares = split_secret(secret, 3, 5).unwrap();
///
/// // Reconstruct from first 3 shares
/// let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
/// assert_eq!(&reconstructed[..], secret);
/// ```
pub fn reconstruct_secret(shares: &[Share]) -> Result<Vec<u8>, CurveError> {
    if shares.len() < 2 {
        return Err(CurveError::InvalidEncoding {
            expected: "at least 2 shares",
            actual: shares.len(),
        });
    }

    // Check all shares have the same length
    let secret_len = shares[0].y.len();
    if !shares.iter().all(|s| s.y.len() == secret_len) {
        return Err(CurveError::InvalidEncoding {
            expected: "all shares same length",
            actual: shares.len(),
        });
    }

    // Check for duplicate x values
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].x == shares[j].x {
                return Err(CurveError::InvalidEncoding {
                    expected: "unique share indices",
                    actual: shares.len(),
                });
            }
        }
    }

    let mut secret = Vec::with_capacity(secret_len);

    // Reconstruct each byte using Lagrange interpolation
    for byte_idx in 0..secret_len {
        // Collect (x, y) points for this byte
        let points: Vec<(u8, u8)> = shares
            .iter()
            .map(|share| (share.x, share[byte_idx]))
            .collect();

        // Lagrange interpolation at x=0 gives us the secret
        let secret_byte = lagrange_interpolate(&points, 0);
        secret.push(secret_byte);
    }

    Ok(secret)
}

/// Evaluate a polynomial at a given x value in GF(256)
///
/// Computes p(x) = a0 + a1*x + a2*x^2 + ... using Horner's method
fn eval_polynomial(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;

    // Horner's method: p(x) = a0 + x*(a1 + x*(a2 + x*(...)))
    for &coeff in coefficients.iter().rev() {
        result = gf256_add(gf256_mul(result, x), coeff);
    }

    result
}

/// Lagrange interpolation at x=0 in GF(256)
///
/// Given points (x1, y1), (x2, y2), ..., (xk, yk), compute p(0)
/// where p is the unique polynomial of degree < k passing through all points.
fn lagrange_interpolate(points: &[(u8, u8)], x: u8) -> u8 {
    let mut result = 0u8;

    for (i, &(xi, yi)) in points.iter().enumerate() {
        // Compute Lagrange basis polynomial Li(x)
        let mut numerator = 1u8;
        let mut denominator = 1u8;

        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                numerator = gf256_mul(numerator, gf256_sub(x, xj));
                denominator = gf256_mul(denominator, gf256_sub(xi, xj));
            }
        }

        // Li(x) = numerator / denominator
        let li = gf256_mul(numerator, gf256_inv(denominator));

        // Add yi * Li(x) to result
        result = gf256_add(result, gf256_mul(yi, li));
    }

    result
}

// GF(256) arithmetic using AES polynomial (x^8 + x^4 + x^3 + x + 1)

/// Addition in GF(256) is XOR
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in GF(256) is XOR (same as addition)
#[inline]
fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(256)
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;

    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }

        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B; // AES polynomial: x^8 + x^4 + x^3 + x + 1
        }

        b >>= 1;
    }

    result
}

/// Multiplicative inverse in GF(256)
///
/// Uses precomputed lookup table for constant-time operation
fn gf256_inv(a: u8) -> u8 {
    // Precomputed inverse table for GF(256) with AES polynomial
    // Generated using: inv[i] = i^254 mod (x^8 + x^4 + x^3 + x + 1)
    const INV_TABLE: [u8; 256] = [
        0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5,
        0xc7, 0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40,
        0xee, 0xb2, 0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30,
        0x44, 0xa2, 0xc2, 0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f,
        0x77, 0xbb, 0x59, 0x19, 0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab,
        0x13, 0x54, 0x25, 0xe9, 0x09, 0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e,
        0x22, 0xf0, 0x51, 0xec, 0x61, 0x17, 0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4,
        0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b, 0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c,
        0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82, 0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe,
        0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4, 0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a,
        0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a, 0xfb, 0x7c, 0x2e, 0xc3, 0x8f,
        0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62, 0x0c, 0xe0, 0x1f, 0xef,
        0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57, 0x0b, 0x28, 0x2f,
        0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04, 0x1b, 0xfc, 0xac, 0xe6, 0x7a, 0x07,
        0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b, 0xb1,
        0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,
        0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41,
        0x1c,
    ];

    INV_TABLE[a as usize]
}

impl core::ops::Index<usize> for Share {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.y[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_add() {
        assert_eq!(gf256_add(3, 5), 6);
        assert_eq!(gf256_add(10, 10), 0);
    }

    #[test]
    fn test_gf256_mul() {
        assert_eq!(gf256_mul(3, 5), 15);
        assert_eq!(gf256_mul(0x53, 0xCA), 0x01);
    }

    #[test]
    fn test_gf256_inv() {
        assert_eq!(gf256_mul(3, gf256_inv(3)), 1);
        assert_eq!(gf256_mul(100, gf256_inv(100)), 1);
    }

    #[test]
    fn test_split_reconstruct_simple() {
        let secret = b"Hello, World!";
        let shares = split_secret(secret, 3, 5).unwrap();

        // Reconstruct with first 3 shares
        let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed[..], secret);

        // Reconstruct with last 3 shares
        let reconstructed = reconstruct_secret(&shares[2..5]).unwrap();
        assert_eq!(&reconstructed[..], secret);
    }

    #[test]
    fn test_split_reconstruct_all_shares() {
        let secret = b"Secret message";
        let shares = split_secret(secret, 2, 5).unwrap();

        // Reconstruct with all shares
        let reconstructed = reconstruct_secret(&shares).unwrap();
        assert_eq!(&reconstructed[..], secret);
    }

    #[test]
    fn test_minimum_threshold() {
        let secret = b"test";
        let shares = split_secret(secret, 2, 2).unwrap();
        let reconstructed = reconstruct_secret(&shares).unwrap();
        assert_eq!(&reconstructed[..], secret);
    }

    #[test]
    fn test_invalid_parameters() {
        let secret = b"test";

        // Threshold too small
        assert!(split_secret(secret, 1, 5).is_err());

        // Threshold larger than num_shares
        assert!(split_secret(secret, 6, 5).is_err());

        // Too many shares
        assert!(split_secret(secret, 3, 256).is_err());
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"test";
        let shares = split_secret(secret, 3, 5).unwrap();

        // Only provide 1 share (need at least 2)
        assert!(reconstruct_secret(&shares[0..1]).is_err());
    }

    #[test]
    fn test_binary_secret() {
        let secret = [0u8, 255u8, 128u8, 42u8];
        let shares = split_secret(&secret, 3, 5).unwrap();
        let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed[..], &secret[..]);
    }
}
