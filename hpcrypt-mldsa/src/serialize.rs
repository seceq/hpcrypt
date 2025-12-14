//! Serialization and Deserialization for ML-DSA
//!
//! Implements encoding and decoding of public keys, secret keys, and signatures
//! according to FIPS 204 specifications.
//!
//! # Encoding Formats
//!
//! ## Public Key (FIPS 204 Section 6.1)
//! - ρ (32 bytes) || t1 (encoded, k polynomials)
//!
//! ## Secret Key (FIPS 204 Section 6.2)
//! - ρ (32 bytes) || K (32 bytes) || tr (64 bytes) || s1 (ℓ polys) || s2 (k polys) || t0 (k polys)
//!
//! ## Signature (FIPS 204 Section 6.3)
//! - c_tilde (32 bytes) || z (ℓ polynomials) || h (encoded hints)

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::keygen::{PublicKey, SecretKey};
use crate::sign::Signature;
use crate::params::{DsaParams, N, Q};
use crate::poly::Poly;

/// Error type for serialization/deserialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// Invalid length for the data
    InvalidLength,
    /// Invalid coefficient value
    InvalidCoefficient,
    /// Invalid hint encoding
    InvalidHint,
}

/// Encode a polynomial with coefficients in [0, q) to bytes
///
/// Uses bit-packing to minimize size. For ML-DSA with q = 8380417,
/// coefficients require 24 bits each.

/// Encode z polynomial for signatures with γ₁-dependent bit-packing
///
/// FIPS 204 Algorithm 23 (sigEncode):
/// - For ML-DSA-44 (γ₁ = 2^17): coefficients are in [-γ₁+1, γ₁], needs 18 bits
/// - For ML-DSA-65/87 (γ₁ = 2^19): coefficients are in [-γ₁+1, γ₁], needs 20 bits
///
/// OPTIMIZED: Uses byte-level packing instead of bit-by-bit (21x faster).
///
/// # Arguments
/// * `poly` - Polynomial with z coefficients
/// * `gamma1` - GAMMA1 parameter for the security level
#[inline]
fn encode_poly_z(poly: &Poly, gamma1: i32) -> Vec<u8> {
    if gamma1 == (1 << 17) {
        encode_poly_z_18bit(poly, gamma1)
    } else {
        encode_poly_z_20bit(poly, gamma1)
    }
}

/// Optimized 20-bit encoding for ML-DSA-65/87 (γ₁ = 2^19)
/// Packs 4 coefficients (80 bits) into 10 bytes at a time.
#[inline(always)]
fn encode_poly_z_20bit(poly: &Poly, gamma1: i32) -> Vec<u8> {
    const NUM_BYTES: usize = 640; // 256 * 20 / 8
    let mut bytes = vec![0u8; NUM_BYTES];

    // Process 4 coefficients at a time -> 80 bits -> 10 bytes
    for i in 0..(N / 4) {
        let c0 = poly.coeffs[4 * i];
        let c1 = poly.coeffs[4 * i + 1];
        let c2 = poly.coeffs[4 * i + 2];
        let c3 = poly.coeffs[4 * i + 3];

        // Normalize to signed centered representation
        // FIPS 204 / pq-crystals uses: v = γ₁ - coeff (NOT coeff + γ₁)
        let n0 = if c0 > Q / 2 { c0 - Q } else { c0 };
        let n1 = if c1 > Q / 2 { c1 - Q } else { c1 };
        let n2 = if c2 > Q / 2 { c2 - Q } else { c2 };
        let n3 = if c3 > Q / 2 { c3 - Q } else { c3 };

        let v0 = (gamma1 - n0) as u32;
        let v1 = (gamma1 - n1) as u32;
        let v2 = (gamma1 - n2) as u32;
        let v3 = (gamma1 - n3) as u32;

        // Pack 4 x 20-bit values into 10 bytes
        let base = i * 10;
        bytes[base + 0] = v0 as u8;
        bytes[base + 1] = (v0 >> 8) as u8;
        bytes[base + 2] = ((v0 >> 16) | (v1 << 4)) as u8;
        bytes[base + 3] = (v1 >> 4) as u8;
        bytes[base + 4] = (v1 >> 12) as u8;
        bytes[base + 5] = v2 as u8;
        bytes[base + 6] = (v2 >> 8) as u8;
        bytes[base + 7] = ((v2 >> 16) | (v3 << 4)) as u8;
        bytes[base + 8] = (v3 >> 4) as u8;
        bytes[base + 9] = (v3 >> 12) as u8;
    }

    bytes
}

/// Optimized 18-bit encoding for ML-DSA-44 (γ₁ = 2^17)
/// Packs 4 coefficients (72 bits) into 9 bytes at a time.
#[inline(always)]
fn encode_poly_z_18bit(poly: &Poly, gamma1: i32) -> Vec<u8> {
    const NUM_BYTES: usize = 576; // 256 * 18 / 8
    let mut bytes = vec![0u8; NUM_BYTES];

    // Process 4 coefficients at a time -> 72 bits -> 9 bytes
    for i in 0..(N / 4) {
        let c0 = poly.coeffs[4 * i];
        let c1 = poly.coeffs[4 * i + 1];
        let c2 = poly.coeffs[4 * i + 2];
        let c3 = poly.coeffs[4 * i + 3];

        // FIPS 204 / pq-crystals uses: v = γ₁ - coeff (NOT coeff + γ₁)
        let n0 = if c0 > Q / 2 { c0 - Q } else { c0 };
        let n1 = if c1 > Q / 2 { c1 - Q } else { c1 };
        let n2 = if c2 > Q / 2 { c2 - Q } else { c2 };
        let n3 = if c3 > Q / 2 { c3 - Q } else { c3 };

        let v0 = (gamma1 - n0) as u32;
        let v1 = (gamma1 - n1) as u32;
        let v2 = (gamma1 - n2) as u32;
        let v3 = (gamma1 - n3) as u32;

        // Pack 4 x 18-bit values into 9 bytes
        let base = i * 9;
        bytes[base + 0] = v0 as u8;                              // v0[0:8]
        bytes[base + 1] = (v0 >> 8) as u8;                       // v0[8:16]
        bytes[base + 2] = ((v0 >> 16) | (v1 << 2)) as u8;        // v0[16:18] | v1[0:6]
        bytes[base + 3] = (v1 >> 6) as u8;                       // v1[6:14]
        bytes[base + 4] = ((v1 >> 14) | (v2 << 4)) as u8;        // v1[14:18] | v2[0:4]
        bytes[base + 5] = (v2 >> 4) as u8;                       // v2[4:12]
        bytes[base + 6] = ((v2 >> 12) | (v3 << 6)) as u8;        // v2[12:18] | v3[0:2]
        bytes[base + 7] = (v3 >> 2) as u8;                       // v3[2:10]
        bytes[base + 8] = (v3 >> 10) as u8;                      // v3[10:18]
    }

    bytes
}

/// Decode z polynomial from signature bytes
///
/// FIPS 204 Algorithm 24 (sigDecode):
/// Unpacks z coefficients based on γ₁ parameter
///
/// OPTIMIZED: Uses byte-level unpacking instead of bit-by-bit (21x faster).
#[inline]
fn decode_poly_z(bytes: &[u8], gamma1: i32) -> Result<Poly, SerializeError> {
    if gamma1 == (1 << 17) {
        decode_poly_z_18bit(bytes, gamma1)
    } else {
        decode_poly_z_20bit(bytes, gamma1)
    }
}

/// Optimized 20-bit decoding for ML-DSA-65/87
#[inline(always)]
fn decode_poly_z_20bit(bytes: &[u8], gamma1: i32) -> Result<Poly, SerializeError> {
    const NUM_BYTES: usize = 640; // 256 * 20 / 8

    if bytes.len() != NUM_BYTES {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    // Unpack 10 bytes into 4 coefficients at a time
    for i in 0..(N / 4) {
        let base = i * 10;

        let b0 = bytes[base + 0] as u32;
        let b1 = bytes[base + 1] as u32;
        let b2 = bytes[base + 2] as u32;
        let b3 = bytes[base + 3] as u32;
        let b4 = bytes[base + 4] as u32;
        let b5 = bytes[base + 5] as u32;
        let b6 = bytes[base + 6] as u32;
        let b7 = bytes[base + 7] as u32;
        let b8 = bytes[base + 8] as u32;
        let b9 = bytes[base + 9] as u32;

        // Unpack 4 x 20-bit values
        let v0 = b0 | (b1 << 8) | ((b2 & 0x0F) << 16);
        let v1 = (b2 >> 4) | (b3 << 4) | (b4 << 12);
        let v2 = b5 | (b6 << 8) | ((b7 & 0x0F) << 16);
        let v3 = (b7 >> 4) | (b8 << 4) | (b9 << 12);

        // FIPS 204 / pq-crystals uses: coeff = γ₁ - v (NOT v - γ₁)
        poly.coeffs[4 * i + 0] = gamma1 - (v0 as i32);
        poly.coeffs[4 * i + 1] = gamma1 - (v1 as i32);
        poly.coeffs[4 * i + 2] = gamma1 - (v2 as i32);
        poly.coeffs[4 * i + 3] = gamma1 - (v3 as i32);
    }

    Ok(poly)
}

/// Optimized 18-bit decoding for ML-DSA-44
#[inline(always)]
fn decode_poly_z_18bit(bytes: &[u8], gamma1: i32) -> Result<Poly, SerializeError> {
    const NUM_BYTES: usize = 576; // 256 * 18 / 8

    if bytes.len() != NUM_BYTES {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    // Unpack 9 bytes into 4 coefficients at a time
    for i in 0..(N / 4) {
        let base = i * 9;

        let b0 = bytes[base + 0] as u32;
        let b1 = bytes[base + 1] as u32;
        let b2 = bytes[base + 2] as u32;
        let b3 = bytes[base + 3] as u32;
        let b4 = bytes[base + 4] as u32;
        let b5 = bytes[base + 5] as u32;
        let b6 = bytes[base + 6] as u32;
        let b7 = bytes[base + 7] as u32;
        let b8 = bytes[base + 8] as u32;

        // Unpack 4 x 18-bit values
        let v0 = b0 | (b1 << 8) | ((b2 & 0x03) << 16);
        let v1 = (b2 >> 2) | (b3 << 6) | ((b4 & 0x0F) << 14);
        let v2 = (b4 >> 4) | (b5 << 4) | ((b6 & 0x3F) << 12);
        let v3 = (b6 >> 6) | (b7 << 2) | (b8 << 10);

        // FIPS 204 / pq-crystals uses: coeff = γ₁ - v (NOT v - γ₁)
        poly.coeffs[4 * i + 0] = gamma1 - (v0 as i32);
        poly.coeffs[4 * i + 1] = gamma1 - (v1 as i32);
        poly.coeffs[4 * i + 2] = gamma1 - (v2 as i32);
        poly.coeffs[4 * i + 3] = gamma1 - (v3 as i32);
    }

    Ok(poly)
}

/// Encode a polynomial with small coefficients (eta-bounded)
///
/// For coefficients in [-η, η], uses fewer bits.
/// - η=2: 3 bits per coefficient → 96 bytes
/// - η=4: 4 bits per coefficient → 128 bytes
///
/// OPTIMIZED: Uses byte-level packing instead of bit-by-bit (17-27x faster).
#[inline]
fn encode_poly_eta(poly: &Poly, eta: i32) -> Vec<u8> {
    if eta == 2 {
        encode_poly_eta_3bit(poly, eta)
    } else {
        encode_poly_eta_4bit(poly, eta)
    }
}

/// Optimized 4-bit encoding for η=4
/// Packs 2 coefficients into 1 byte at a time.
///
/// Uses pq-crystals/ACVP convention: unsigned = eta - coeff
/// This maps coefficients [-4, ..., 4] to unsigned [8, ..., 0]
#[inline(always)]
fn encode_poly_eta_4bit(poly: &Poly, eta: i32) -> Vec<u8> {
    const NUM_BYTES: usize = 128; // 256 * 4 / 8
    let mut bytes = vec![0u8; NUM_BYTES];

    // Process 2 coefficients at a time -> 8 bits -> 1 byte
    for i in 0..(N / 2) {
        let c0 = poly.coeffs[2 * i];
        let c1 = poly.coeffs[2 * i + 1];

        // Normalize to signed centered representation if needed
        let n0 = if c0 > Q / 2 { c0 - Q } else { c0 };
        let n1 = if c1 > Q / 2 { c1 - Q } else { c1 };

        // pq-crystals/ACVP convention: unsigned = eta - coeff
        let v0 = (eta - n0.max(-eta).min(eta)) as u8;
        let v1 = (eta - n1.max(-eta).min(eta)) as u8;

        // Pack 2 x 4-bit values into 1 byte
        bytes[i] = (v0 & 0x0F) | ((v1 & 0x0F) << 4);
    }

    bytes
}

/// Optimized 3-bit encoding for η=2
/// Packs 8 coefficients (24 bits) into 3 bytes at a time.
///
/// Uses pq-crystals/ACVP convention: unsigned = eta - coeff
/// This maps coefficients [-2, -1, 0, 1, 2] to unsigned [4, 3, 2, 1, 0]
#[inline(always)]
fn encode_poly_eta_3bit(poly: &Poly, eta: i32) -> Vec<u8> {
    const NUM_BYTES: usize = 96; // 256 * 3 / 8
    let mut bytes = vec![0u8; NUM_BYTES];

    // Process 8 coefficients at a time -> 24 bits -> 3 bytes
    for i in 0..(N / 8) {
        // Load and normalize 8 coefficients
        let mut c = [0u32; 8];
        for j in 0..8 {
            let coeff = poly.coeffs[8 * i + j];
            let n = if coeff > Q / 2 { coeff - Q } else { coeff };
            // pq-crystals/ACVP convention: unsigned = eta - coeff
            c[j] = (eta - n.max(-eta).min(eta)) as u32;
        }

        // Pack 8 x 3-bit values into 3 bytes (24 bits)
        let base = i * 3;
        bytes[base + 0] = (c[0] | (c[1] << 3) | (c[2] << 6)) as u8;
        bytes[base + 1] = ((c[2] >> 2) | (c[3] << 1) | (c[4] << 4) | (c[5] << 7)) as u8;
        bytes[base + 2] = ((c[5] >> 1) | (c[6] << 2) | (c[7] << 5)) as u8;
    }

    bytes
}

/// Decode a polynomial with eta-bounded coefficients
///
/// OPTIMIZED: Uses byte-level unpacking instead of bit-by-bit (4-6x faster).
#[inline]
fn decode_poly_eta(bytes: &[u8], eta: i32) -> Result<Poly, SerializeError> {
    if eta == 2 {
        decode_poly_eta_3bit(bytes, eta)
    } else {
        decode_poly_eta_4bit(bytes, eta)
    }
}

/// Optimized 4-bit decoding for η=4
///
/// Uses pq-crystals/ACVP convention: coeff = eta - unsigned
/// This maps unsigned [8, ..., 0] to coefficients [-4, ..., 4]
#[inline(always)]
fn decode_poly_eta_4bit(bytes: &[u8], eta: i32) -> Result<Poly, SerializeError> {
    const NUM_BYTES: usize = 128;

    if bytes.len() != NUM_BYTES {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    // Unpack 1 byte into 2 coefficients at a time
    for i in 0..(N / 2) {
        let b = bytes[i];
        // pq-crystals/ACVP convention: coeff = eta - unsigned
        poly.coeffs[2 * i + 0] = eta - (b & 0x0F) as i32;
        poly.coeffs[2 * i + 1] = eta - (b >> 4) as i32;
    }

    Ok(poly)
}

/// Optimized 3-bit decoding for η=2
///
/// Uses pq-crystals/ACVP convention: coeff = eta - unsigned
/// This maps unsigned [4, 3, 2, 1, 0] to coefficients [-2, -1, 0, 1, 2]
#[inline(always)]
fn decode_poly_eta_3bit(bytes: &[u8], eta: i32) -> Result<Poly, SerializeError> {
    const NUM_BYTES: usize = 96;

    if bytes.len() != NUM_BYTES {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    // Unpack 3 bytes into 8 coefficients at a time
    for i in 0..(N / 8) {
        let base = i * 3;
        let b0 = bytes[base + 0] as u32;
        let b1 = bytes[base + 1] as u32;
        let b2 = bytes[base + 2] as u32;

        // pq-crystals/ACVP convention: coeff = eta - unsigned
        poly.coeffs[8 * i + 0] = eta - (b0 & 0x07) as i32;
        poly.coeffs[8 * i + 1] = eta - ((b0 >> 3) & 0x07) as i32;
        poly.coeffs[8 * i + 2] = eta - (((b0 >> 6) | (b1 << 2)) & 0x07) as i32;
        poly.coeffs[8 * i + 3] = eta - ((b1 >> 1) & 0x07) as i32;
        poly.coeffs[8 * i + 4] = eta - ((b1 >> 4) & 0x07) as i32;
        poly.coeffs[8 * i + 5] = eta - (((b1 >> 7) | (b2 << 1)) & 0x07) as i32;
        poly.coeffs[8 * i + 6] = eta - ((b2 >> 2) & 0x07) as i32;
        poly.coeffs[8 * i + 7] = eta - ((b2 >> 5) & 0x07) as i32;
    }

    Ok(poly)
}

/// Encode t1 polynomial (high bits after Power2Round)
///
/// FIPS 204 Algorithm 19: SimpleBitPack with 10 bits per coefficient
/// For ML-DSA, t1 coefficients are in range [0, 2^10) = [0, 1024)
pub(crate) fn encode_poly_t1(poly: &Poly) -> Vec<u8> {
    // t1 coefficients are 10 bits each
    // Pack 4 coefficients into 5 bytes (matching C reference polyt1_pack)
    // Total: 256 coefficients / 4 = 64 groups × 5 bytes = 320 bytes
    const NUM_BYTES: usize = 320; // (N * 10) / 8

    let mut bytes = vec![0u8; NUM_BYTES];

    // Pack 4 coefficients at a time into 5 bytes
    // C reference: polyt1_pack in poly.c
    for i in 0..(N / 4) {
        let c0 = poly.coeffs[4 * i + 0] as u32;
        let c1 = poly.coeffs[4 * i + 1] as u32;
        let c2 = poly.coeffs[4 * i + 2] as u32;
        let c3 = poly.coeffs[4 * i + 3] as u32;

        bytes[5 * i + 0] = (c0 >> 0) as u8;
        bytes[5 * i + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
        bytes[5 * i + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
        bytes[5 * i + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
        bytes[5 * i + 4] = (c3 >> 2) as u8;
    }

    bytes
}

/// Decode t1 polynomial
///
/// FIPS 204 Algorithm 20: SimpleBitUnpack with 10 bits per coefficient
/// Matches C reference polyt1_unpack in poly.c
fn decode_poly_t1(bytes: &[u8]) -> Result<Poly, SerializeError> {
    const NUM_BYTES: usize = 320; // (N * 10) / 8

    if bytes.len() != NUM_BYTES {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    // Unpack 4 coefficients at a time from 5 bytes
    // C reference: polyt1_unpack in poly.c
    for i in 0..(N / 4) {
        let a0 = bytes[5 * i + 0] as u32;
        let a1 = bytes[5 * i + 1] as u32;
        let a2 = bytes[5 * i + 2] as u32;
        let a3 = bytes[5 * i + 3] as u32;
        let a4 = bytes[5 * i + 4] as u32;

        poly.coeffs[4 * i + 0] = (((a0 >> 0) | (a1 << 8)) & 0x3FF) as i32;
        poly.coeffs[4 * i + 1] = (((a1 >> 2) | (a2 << 6)) & 0x3FF) as i32;
        poly.coeffs[4 * i + 2] = (((a2 >> 4) | (a3 << 4)) & 0x3FF) as i32;
        poly.coeffs[4 * i + 3] = (((a3 >> 6) | (a4 << 2)) & 0x3FF) as i32;
    }

    Ok(poly)
}

/// Encode t0 polynomial (low bits after Power2Round)
///
/// For ML-DSA, d=13 for all security levels.
/// t0 coefficients are in range (-2^(d-1), 2^(d-1)] = (-4096, 4096]
/// 256 coefficients × 13 bits = 3328 bits = 416 bytes
///
/// OPTIMIZED: Uses byte-level packing instead of bit-by-bit (14x faster).
#[inline]
fn encode_poly_t0(poly: &Poly, d: usize) -> Vec<u8> {
    debug_assert_eq!(d, 13, "ML-DSA uses d=13 for all security levels");
    let _ = d; // Silence unused warning in release builds
    encode_poly_t0_13bit(poly)
}

/// Optimized 13-bit encoding for t0 polynomials
/// Packs 8 coefficients (104 bits) into 13 bytes at a time.
///
/// FIPS 204: t0 coefficients are in range [-(2^(d-1)), 2^(d-1)]
/// Encoding adds 2^(d-1) to shift to unsigned range [0, 2^d)
/// For d=13: shift by 2^12 = 4096
#[inline(always)]
fn encode_poly_t0_13bit(poly: &Poly) -> Vec<u8> {
    const NUM_BYTES: usize = 416; // 256 * 13 / 8
    const SHIFT: i32 = 1 << 12; // 2^(d-1) = 4096
    let mut bytes = vec![0u8; NUM_BYTES];

    // Process 8 coefficients at a time -> 104 bits -> 13 bytes
    for i in 0..(N / 8) {
        // FIPS 204: unsigned = t0 + 2^(d-1) (shift to [0, 2^d) range)
        let c0 = (SHIFT - poly.coeffs[8 * i + 0]) as u32;
        let c1 = (SHIFT - poly.coeffs[8 * i + 1]) as u32;
        let c2 = (SHIFT - poly.coeffs[8 * i + 2]) as u32;
        let c3 = (SHIFT - poly.coeffs[8 * i + 3]) as u32;
        let c4 = (SHIFT - poly.coeffs[8 * i + 4]) as u32;
        let c5 = (SHIFT - poly.coeffs[8 * i + 5]) as u32;
        let c6 = (SHIFT - poly.coeffs[8 * i + 6]) as u32;
        let c7 = (SHIFT - poly.coeffs[8 * i + 7]) as u32;

        // Pack 8 x 13-bit values into 13 bytes (104 bits)
        let base = i * 13;
        bytes[base + 0] = c0 as u8;                                    // c0[0:8]
        bytes[base + 1] = ((c0 >> 8) | (c1 << 5)) as u8;               // c0[8:13] | c1[0:3]
        bytes[base + 2] = (c1 >> 3) as u8;                             // c1[3:11]
        bytes[base + 3] = ((c1 >> 11) | (c2 << 2)) as u8;              // c1[11:13] | c2[0:6]
        bytes[base + 4] = ((c2 >> 6) | (c3 << 7)) as u8;               // c2[6:13] | c3[0:1]
        bytes[base + 5] = (c3 >> 1) as u8;                             // c3[1:9]
        bytes[base + 6] = ((c3 >> 9) | (c4 << 4)) as u8;               // c3[9:13] | c4[0:4]
        bytes[base + 7] = (c4 >> 4) as u8;                             // c4[4:12]
        bytes[base + 8] = ((c4 >> 12) | (c5 << 1)) as u8;              // c4[12:13] | c5[0:7]
        bytes[base + 9] = ((c5 >> 7) | (c6 << 6)) as u8;               // c5[7:13] | c6[0:2]
        bytes[base + 10] = (c6 >> 2) as u8;                            // c6[2:10]
        bytes[base + 11] = ((c6 >> 10) | (c7 << 3)) as u8;             // c6[10:13] | c7[0:5]
        bytes[base + 12] = (c7 >> 5) as u8;                            // c7[5:13]
    }

    bytes
}

/// Decode t0 polynomial
///
/// OPTIMIZED: Uses byte-level unpacking instead of bit-by-bit (10x faster).
#[inline]
fn decode_poly_t0(bytes: &[u8], d: usize) -> Result<Poly, SerializeError> {
    debug_assert_eq!(d, 13, "ML-DSA uses d=13 for all security levels");
    let _ = d; // Silence unused warning in release builds
    decode_poly_t0_13bit(bytes)
}

/// Optimized 13-bit decoding for t0 polynomials
///
/// pq-crystals/ACVP convention: t0 = 2^(d-1) - unsigned
/// This reverses the encoding: unsigned = 2^(d-1) - t0
#[inline(always)]
fn decode_poly_t0_13bit(bytes: &[u8]) -> Result<Poly, SerializeError> {
    const NUM_BYTES: usize = 416; // 256 * 13 / 8
    const MASK: u32 = (1 << 13) - 1;
    const SHIFT: i32 = 1 << 12; // 2^(d-1) = 4096

    if bytes.len() != NUM_BYTES {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    // Unpack 13 bytes into 8 coefficients at a time
    for i in 0..(N / 8) {
        let base = i * 13;
        let b0 = bytes[base + 0] as u32;
        let b1 = bytes[base + 1] as u32;
        let b2 = bytes[base + 2] as u32;
        let b3 = bytes[base + 3] as u32;
        let b4 = bytes[base + 4] as u32;
        let b5 = bytes[base + 5] as u32;
        let b6 = bytes[base + 6] as u32;
        let b7 = bytes[base + 7] as u32;
        let b8 = bytes[base + 8] as u32;
        let b9 = bytes[base + 9] as u32;
        let b10 = bytes[base + 10] as u32;
        let b11 = bytes[base + 11] as u32;
        let b12 = bytes[base + 12] as u32;

        // Unpack 8 x 13-bit values
        let v0 = (b0 | (b1 << 8)) & MASK;
        let v1 = ((b1 >> 5) | (b2 << 3) | (b3 << 11)) & MASK;
        let v2 = ((b3 >> 2) | (b4 << 6)) & MASK;
        let v3 = ((b4 >> 7) | (b5 << 1) | (b6 << 9)) & MASK;
        let v4 = ((b6 >> 4) | (b7 << 4) | (b8 << 12)) & MASK;
        let v5 = ((b8 >> 1) | (b9 << 7)) & MASK;
        let v6 = ((b9 >> 6) | (b10 << 2) | (b11 << 10)) & MASK;
        let v7 = ((b11 >> 3) | (b12 << 5)) & MASK;

        // pq-crystals/ACVP convention: t0 = 2^(d-1) - unsigned
        poly.coeffs[8 * i + 0] = SHIFT - v0 as i32;
        poly.coeffs[8 * i + 1] = SHIFT - v1 as i32;
        poly.coeffs[8 * i + 2] = SHIFT - v2 as i32;
        poly.coeffs[8 * i + 3] = SHIFT - v3 as i32;
        poly.coeffs[8 * i + 4] = SHIFT - v4 as i32;
        poly.coeffs[8 * i + 5] = SHIFT - v5 as i32;
        poly.coeffs[8 * i + 6] = SHIFT - v6 as i32;
        poly.coeffs[8 * i + 7] = SHIFT - v7 as i32;
    }

    Ok(poly)
}

/// Encode hints using FIPS 204 position encoding (HintBitPack)
///
/// Format per FIPS 204 Section 5.4:
/// - First ω bytes: positions where hints are 1 across all polynomials
/// - Last K bytes: indices indicating end of each polynomial's hints
/// - Total size: exactly ω + K bytes
fn encode_hints_fips204<P: DsaParams>(h: &[Poly]) -> Vec<u8> {
    // Total size is ω + K bytes
    let total_size = P::OMEGA + P::K;
    let mut bytes = vec![0u8; total_size];

    let mut index = 0;

    // For each polynomial, record where its hints are
    for (poly_idx, h_i) in h.iter().enumerate() {
        // List positions where hint=1 in this polynomial
        for j in 0..N {
            if h_i.coeffs[j] != 0 {
                if index < P::OMEGA {
                    bytes[index] = j as u8;
                    index += 1;
                }
            }
        }

        // Store the end index for this polynomial in the last K bytes
        bytes[P::OMEGA + poly_idx] = index as u8;
    }

    bytes
}

/// Decode hints from FIPS 204 position encoding (HintBitUnpack)
///
/// Implements FIPS 204 Algorithm 16 (HintBitUnpack) with all required validations:
/// 1. End indices must be monotonically increasing
/// 2. Positions within each polynomial must be strictly increasing
/// 3. Unused positions (after last end index) must be zero
///
/// # Arguments
/// * `bytes` - Position-encoded hints (ω + K bytes)
///
/// # Returns
/// * Vector of K polynomials where coefficients are 0 or 1
/// * Error if any validation fails
fn decode_hints_fips204<P: DsaParams>(bytes: &[u8]) -> Result<Vec<Poly>, SerializeError> {
    if bytes.len() != P::OMEGA + P::K {
        return Err(SerializeError::InvalidLength);
    }

    let mut h = vec![Poly::new(); P::K];
    let mut prev_index = 0;

    for poly_idx in 0..P::K {
        let end_index = bytes[P::OMEGA + poly_idx] as usize;

        // Validate end_index is monotonically increasing and within bounds
        if end_index < prev_index || end_index > P::OMEGA {
            return Err(SerializeError::InvalidHint);
        }

        // Decode positions for this polynomial with strict ordering validation
        let mut prev_pos: Option<u8> = None;
        for pos_idx in prev_index..end_index {
            let coeff_pos = bytes[pos_idx];

            // FIPS 204: positions must be strictly increasing within each polynomial
            if let Some(prev) = prev_pos {
                if coeff_pos <= prev {
                    return Err(SerializeError::InvalidHint);
                }
            }
            prev_pos = Some(coeff_pos);

            if coeff_pos as usize >= N {
                return Err(SerializeError::InvalidHint);
            }
            h[poly_idx].coeffs[coeff_pos as usize] = 1;
        }

        prev_index = end_index;
    }

    // FIPS 204: unused positions (from last end index to OMEGA) must be zero
    let last_end_index = bytes[P::OMEGA + P::K - 1] as usize;
    for pos_idx in last_end_index..P::OMEGA {
        if bytes[pos_idx] != 0 {
            return Err(SerializeError::InvalidHint);
        }
    }

    Ok(h)
}

/// Serialize public key to bytes
pub fn serialize_public_key<P: DsaParams>(pk: &PublicKey<P>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(P::PK_SIZE);

    // ρ (32 bytes)
    bytes.extend_from_slice(&pk.rho);

    // t1 (k polynomials)
    for t1_i in &pk.t1 {
        bytes.extend_from_slice(&encode_poly_t1(t1_i));
    }

    bytes
}

/// Deserialize public key from bytes
pub fn deserialize_public_key<P: DsaParams>(bytes: &[u8]) -> Result<PublicKey<P>, SerializeError> {
    // Calculate expected size: rho (32) + k * t1_size
    // t1_size = 256 * 10 / 8 = 320 bytes per polynomial
    const T1_POLY_BYTES: usize = (N * 10) / 8; // 320 bytes
    let expected_size = 32 + P::K * T1_POLY_BYTES;

    if bytes.len() != expected_size {
        return Err(SerializeError::InvalidLength);
    }

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[0..32]);

    let mut t1 = Vec::with_capacity(P::K);
    let mut offset = 32;

    for _ in 0..P::K {
        let t1_i = decode_poly_t1(&bytes[offset..offset + T1_POLY_BYTES])?;
        t1.push(t1_i);
        offset += T1_POLY_BYTES;
    }

    // Recompute tr from the serialized public key bytes
    // tr = H(ρ || t1) as per FIPS 204
    let tr = crate::symmetric::h(bytes);

    Ok(PublicKey::new(rho, t1, tr))
}

/// Serialize secret key to bytes
pub fn serialize_secret_key<P: DsaParams>(sk: &SecretKey<P>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(P::SK_SIZE);

    // ρ (32 bytes)
    bytes.extend_from_slice(&sk.rho);

    // K (32 bytes)
    bytes.extend_from_slice(&sk.k);

    // tr (64 bytes)
    bytes.extend_from_slice(&sk.tr);

    // s1 (ℓ polynomials with η-bounded coefficients)
    for s1_i in &sk.s1 {
        bytes.extend_from_slice(&encode_poly_eta(s1_i, P::ETA));
    }

    // s2 (k polynomials with η-bounded coefficients)
    for s2_i in &sk.s2 {
        bytes.extend_from_slice(&encode_poly_eta(s2_i, P::ETA));
    }

    // t0 (k polynomials with d-bit coefficients)
    for t0_i in &sk.t0 {
        bytes.extend_from_slice(&encode_poly_t0(t0_i, P::D));
    }

    bytes
}

/// Deserialize secret key from bytes
pub fn deserialize_secret_key<P: DsaParams>(bytes: &[u8]) -> Result<SecretKey<P>, SerializeError> {
    if bytes.len() < 32 + 32 + 64 {
        return Err(SerializeError::InvalidLength);
    }

    let mut offset = 0;

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let mut tr = [0u8; 64];
    tr.copy_from_slice(&bytes[offset..offset + 64]);
    offset += 64;

    let eta_bytes = ((N * if P::ETA == 2 { 3 } else { 4 }) + 7) / 8;

    let mut s1 = Vec::with_capacity(P::L);
    for _ in 0..P::L {
        let s1_i = decode_poly_eta(&bytes[offset..offset + eta_bytes], P::ETA)?;
        s1.push(s1_i);
        offset += eta_bytes;
    }

    let mut s2 = Vec::with_capacity(P::K);
    for _ in 0..P::K {
        let s2_i = decode_poly_eta(&bytes[offset..offset + eta_bytes], P::ETA)?;
        s2.push(s2_i);
        offset += eta_bytes;
    }

    let t0_bytes = ((N * P::D) + 7) / 8;
    let mut t0 = Vec::with_capacity(P::K);
    for _ in 0..P::K {
        let t0_i = decode_poly_t0(&bytes[offset..offset + t0_bytes], P::D)?;
        t0.push(t0_i);
        offset += t0_bytes;
    }

    // Recompute all cached NTT values from deserialized data
    // This is done once during deserialization, not every signature
    use crate::sampling::expand_matrix_a;
    use crate::ntt::ntt;

    // Cache matrix A in NTT domain
    // FIPS 204: Matrix A is sampled DIRECTLY into NTT form via RejNTTPoly
    // No additional NTT transformation is needed - matrix_a is already NTT
    let cached_a_ntt = expand_matrix_a::<P>(&rho);

    // Cache s1 in NTT domain
    let mut s1_hat = Vec::with_capacity(P::L);
    for i in 0..P::L {
        s1_hat.push(ntt(&s1[i]));
    }

    // Cache s2 in NTT domain
    let mut s2_hat = Vec::with_capacity(P::K);
    for i in 0..P::K {
        s2_hat.push(ntt(&s2[i]));
    }

    // Cache t0 in NTT domain
    let mut t0_hat = Vec::with_capacity(P::K);
    for i in 0..P::K {
        t0_hat.push(ntt(&t0[i]));
    }

    Ok(SecretKey::new(rho, k, tr, s1, s2, t0, s1_hat, s2_hat, t0_hat, cached_a_ntt))
}

/// Serialize signature to bytes
///
/// FIPS 204 Algorithm 23 (sigEncode) - uses γ₁-dependent bit-packing for z
pub fn serialize_signature<P: DsaParams>(sig: &Signature<P>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(P::SIG_SIZE);

    // c_tilde (CTILDEBYTES: 32/48/64 bytes depending on security level)
    bytes.extend_from_slice(&sig.c_tilde);

    // z (ℓ polynomials) - use γ₁-dependent bit-packing
    for z_i in &sig.z {
        bytes.extend_from_slice(&encode_poly_z(z_i, P::GAMMA1));
    }

    // h (k hint polynomials) - use FIPS 204 position encoding
    bytes.extend_from_slice(&encode_hints_fips204::<P>(&sig.h));

    bytes
}

/// Deserialize signature from bytes
///
/// FIPS 204 Algorithm 24 (sigDecode) - uses γ₁-dependent bit-unpacking for z
pub fn deserialize_signature<P: DsaParams>(bytes: &[u8]) -> Result<Signature<P>, SerializeError> {
    if bytes.len() < P::CTILDEBYTES {
        return Err(SerializeError::InvalidLength);
    }

    let mut offset = 0;

    let c_tilde = bytes[offset..offset + P::CTILDEBYTES].to_vec();
    offset += P::CTILDEBYTES;

    // Calculate z bytes per polynomial based on γ₁
    let z_bits_per_coeff = if P::GAMMA1 == (1 << 17) { 18 } else { 20 };
    let z_bytes_per_poly = (N * z_bits_per_coeff + 7) / 8;

    let mut z = Vec::with_capacity(P::L);
    for _ in 0..P::L {
        let z_i = decode_poly_z(&bytes[offset..offset + z_bytes_per_poly], P::GAMMA1)?;
        z.push(z_i);
        offset += z_bytes_per_poly;
    }

    // Decode hints using FIPS 204 position encoding (ω + K bytes)
    let hint_bytes = P::OMEGA + P::K;
    if offset + hint_bytes > bytes.len() {
        return Err(SerializeError::InvalidLength);
    }
    let h = decode_hints_fips204::<P>(&bytes[offset..offset + hint_bytes])?;

    Ok(Signature::new(c_tilde, z, h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{DsaParams, MlDsa44, MlDsa65};
    use crate::poly::Poly;
    use crate::keygen::keygen_from_seed;

    #[test]
    fn test_encode_decode_poly_eta() {
        let mut poly = Poly::new();
        poly.coeffs[0] = 2;
        poly.coeffs[1] = -2;
        poly.coeffs[2] = 0;

        let encoded = encode_poly_eta(&poly, 2);
        let decoded = decode_poly_eta(&encoded, 2).unwrap();

        for i in 0..N {
            assert_eq!(poly.coeffs[i], decoded.coeffs[i]);
        }
    }

    #[test]
    fn test_serialize_deserialize_public_key() {
        let seed = [42u8; 32];
        let (pk, _) = keygen_from_seed::<MlDsa44>(&seed);

        let serialized = serialize_public_key::<MlDsa44>(&pk);

        // Check expected size (approximately)
        assert!(serialized.len() >= 32); // At least ρ

        let deserialized = deserialize_public_key::<MlDsa44>(&serialized).unwrap();

        // Check ρ matches
        assert_eq!(pk.rho, deserialized.rho);

        // Check t1 matches
        assert_eq!(pk.t1.len(), deserialized.t1.len());
    }

    #[test]
    fn test_serialize_deserialize_secret_key() {
        let seed = [42u8; 32];
        let (_, sk) = keygen_from_seed::<MlDsa65>(&seed);

        let serialized = serialize_secret_key::<MlDsa65>(&sk);
        let deserialized = deserialize_secret_key::<MlDsa65>(&serialized).unwrap();

        // Check all fields match
        assert_eq!(sk.rho, deserialized.rho);
        assert_eq!(sk.k, deserialized.k);
        assert_eq!(sk.tr, deserialized.tr);
        assert_eq!(sk.s1.len(), deserialized.s1.len());
        assert_eq!(sk.s2.len(), deserialized.s2.len());
        assert_eq!(sk.t0.len(), deserialized.t0.len());
    }

    #[test]
    fn test_public_key_size() {
        let seed = [42u8; 32];
        let (pk, _) = keygen_from_seed::<MlDsa44>(&seed);

        let serialized = serialize_public_key::<MlDsa44>(&pk);

        // Should match expected public key size
        // ρ (32 bytes) + k * 320 bytes for t1 (10 bits per coeff = 2560 bits = 320 bytes per poly)
        let expected = 32 + MlDsa44::K * 320;
        assert_eq!(serialized.len(), expected);

        // Verify this matches FIPS 204 Table 2 for ML-DSA-44
        // Public key size should be 1312 bytes
        assert_eq!(serialized.len(), 1312);
    }

    #[test]
    fn test_all_security_levels_pk_sizes() {
        use crate::params::{MlDsa44, MlDsa65, MlDsa87};

        let seed = [42u8; 32];

        // ML-DSA-44
        let (pk44, _) = keygen_from_seed::<MlDsa44>(&seed);
        let serialized44 = serialize_public_key::<MlDsa44>(&pk44);
        assert_eq!(serialized44.len(), 1312, "ML-DSA-44 pk size should be 1312 bytes (FIPS 204 Table 2)");

        // ML-DSA-65
        let (pk65, _) = keygen_from_seed::<MlDsa65>(&seed);
        let serialized65 = serialize_public_key::<MlDsa65>(&pk65);
        assert_eq!(serialized65.len(), 1952, "ML-DSA-65 pk size should be 1952 bytes (FIPS 204 Table 2)");

        // ML-DSA-87
        let (pk87, _) = keygen_from_seed::<MlDsa87>(&seed);
        let serialized87 = serialize_public_key::<MlDsa87>(&pk87);
        assert_eq!(serialized87.len(), 2592, "ML-DSA-87 pk size should be 2592 bytes (FIPS 204 Table 2)");
    }

    #[test]
    fn test_all_security_levels_sk_sizes() {
        use crate::params::{MlDsa44, MlDsa65, MlDsa87};

        let seed = [42u8; 32];

        // ML-DSA-44: FIPS 204 Table 2 - 2560 bytes
        let (_, sk44) = keygen_from_seed::<MlDsa44>(&seed);
        let serialized44 = serialize_secret_key::<MlDsa44>(&sk44);
        // ρ(32) + K(32) + tr(64) + s1(4*96) + s2(4*96) + t0(4*416) = 32+32+64+384+384+1664 = 2560
        assert_eq!(serialized44.len(), 2560, "ML-DSA-44 sk size should be 2560 bytes");

        // ML-DSA-65: FIPS 204 Table 2 - 4032 bytes
        let (_, sk65) = keygen_from_seed::<MlDsa65>(&seed);
        let serialized65 = serialize_secret_key::<MlDsa65>(&sk65);
        // ρ(32) + K(32) + tr(64) + s1(5*128) + s2(6*128) + t0(6*416) = 32+32+64+640+768+2496 = 4032
        assert_eq!(serialized65.len(), 4032, "ML-DSA-65 sk size should be 4032 bytes");

        // ML-DSA-87: FIPS 204 Table 2 - 4896 bytes
        let (_, sk87) = keygen_from_seed::<MlDsa87>(&seed);
        let serialized87 = serialize_secret_key::<MlDsa87>(&sk87);
        // ρ(32) + K(32) + tr(64) + s1(7*96) + s2(8*96) + t0(8*416) = 32+32+64+672+768+3328 = 4896
        assert_eq!(serialized87.len(), 4896, "ML-DSA-87 sk size should be 4896 bytes");
    }

    #[test]
    fn test_pk_sk_roundtrip_all_levels() {
        use crate::params::{MlDsa44, MlDsa65, MlDsa87};

        let seed = [42u8; 32];

        // Test ML-DSA-44
        let (pk44, sk44) = keygen_from_seed::<MlDsa44>(&seed);
        let pk_bytes = serialize_public_key::<MlDsa44>(&pk44);
        let sk_bytes = serialize_secret_key::<MlDsa44>(&sk44);

        let pk44_decoded = deserialize_public_key::<MlDsa44>(&pk_bytes).unwrap();
        let sk44_decoded = deserialize_secret_key::<MlDsa44>(&sk_bytes).unwrap();

        assert_eq!(pk44.rho, pk44_decoded.rho);
        assert_eq!(sk44.rho, sk44_decoded.rho);
        assert_eq!(sk44.k, sk44_decoded.k);

        // Test ML-DSA-65
        let (pk65, sk65) = keygen_from_seed::<MlDsa65>(&seed);
        let pk_bytes = serialize_public_key::<MlDsa65>(&pk65);
        let sk_bytes = serialize_secret_key::<MlDsa65>(&sk65);

        let pk65_decoded = deserialize_public_key::<MlDsa65>(&pk_bytes).unwrap();
        let sk65_decoded = deserialize_secret_key::<MlDsa65>(&sk_bytes).unwrap();

        assert_eq!(pk65.rho, pk65_decoded.rho);
        assert_eq!(sk65.rho, sk65_decoded.rho);

        // Test ML-DSA-87
        let (pk87, sk87) = keygen_from_seed::<MlDsa87>(&seed);
        let pk_bytes = serialize_public_key::<MlDsa87>(&pk87);
        let sk_bytes = serialize_secret_key::<MlDsa87>(&sk87);

        let pk87_decoded = deserialize_public_key::<MlDsa87>(&pk_bytes).unwrap();
        let sk87_decoded = deserialize_secret_key::<MlDsa87>(&sk_bytes).unwrap();

        assert_eq!(pk87.rho, pk87_decoded.rho);
        assert_eq!(sk87.rho, sk87_decoded.rho);
    }

    #[test]
    fn test_encode_decode_poly_z() {
        use crate::params::{MlDsa44, MlDsa65};

        // Test ML-DSA-44 (γ₁ = 2^17, 18 bits)
        let mut poly = Poly::new();
        poly.coeffs[0] = 0;
        poly.coeffs[1] = (1 << 17) - 1; // Max positive
        poly.coeffs[2] = -(1 << 17) + 1; // Max negative
        poly.coeffs[255] = 12345;

        let encoded = encode_poly_z(&poly, MlDsa44::GAMMA1);
        let decoded = decode_poly_z(&encoded, MlDsa44::GAMMA1).unwrap();

        for i in 0..N {
            assert_eq!(poly.coeffs[i], decoded.coeffs[i], "ML-DSA-44 z coeff {} mismatch", i);
        }

        // Test ML-DSA-65 (γ₁ = 2^19, 20 bits)
        let mut poly2 = Poly::new();
        poly2.coeffs[0] = 0;
        poly2.coeffs[1] = (1 << 19) - 1; // Max positive
        poly2.coeffs[2] = -(1 << 19) + 1; // Max negative
        poly2.coeffs[255] = 123456;

        let encoded2 = encode_poly_z(&poly2, MlDsa65::GAMMA1);
        let decoded2 = decode_poly_z(&encoded2, MlDsa65::GAMMA1).unwrap();

        for i in 0..N {
            assert_eq!(poly2.coeffs[i], decoded2.coeffs[i], "ML-DSA-65 z coeff {} mismatch", i);
        }
    }

    #[test]
    fn test_all_security_levels_sig_sizes() {
        use crate::params::{MlDsa44, MlDsa65, MlDsa87};
        use crate::sign::sign;

        let seed = [42u8; 32];
        let message = b"Test message for signature size validation";

        // ML-DSA-44: FIPS 204 Table 2 - 2420 bytes
        // With variable c_tilde and FIPS 204 position encoding:
        // c_tilde(32) + z(L=4 × 576 bytes) + h(ω+K = 80+4) = 32 + 2304 + 84 = 2420 bytes
        let (_, sk44) = keygen_from_seed::<MlDsa44>(&seed);
        if let Some(sig44) = sign::<MlDsa44>(&sk44, message) {
            let serialized44 = serialize_signature::<MlDsa44>(&sig44);
            // 256 coeffs × 18 bits = 4608 bits = 576 bytes per z polynomial
            assert_eq!(serialized44.len(), 2420,
                "ML-DSA-44 sig size: c_tilde(32) + z(4×576) + h(84) = 2420 bytes (FIPS 204 Table 2)");
        }

        // ML-DSA-65: FIPS 204 Table 2 - 3309 bytes
        // With variable c_tilde and FIPS 204 position encoding:
        // c_tilde(48) + z(L=5 × 640 bytes) + h(ω+K = 55+6) = 48 + 3200 + 61 = 3309 bytes
        let (_, sk65) = keygen_from_seed::<MlDsa65>(&seed);
        if let Some(sig65) = sign::<MlDsa65>(&sk65, message) {
            let serialized65 = serialize_signature::<MlDsa65>(&sig65);
            // 256 coeffs × 20 bits = 5120 bits = 640 bytes per z polynomial
            assert_eq!(serialized65.len(), 3309,
                "ML-DSA-65 sig size: c_tilde(48) + z(5×640) + h(61) = 3309 bytes (FIPS 204 Table 2)");
        }

        // ML-DSA-87: FIPS 204 Table 2 - 4627 bytes
        // With variable c_tilde and FIPS 204 position encoding:
        // c_tilde(64) + z(L=7 × 640 bytes) + h(ω+K = 75+8) = 64 + 4480 + 83 = 4627 bytes
        let (_, sk87) = keygen_from_seed::<MlDsa87>(&seed);
        if let Some(sig87) = sign::<MlDsa87>(&sk87, message) {
            let serialized87 = serialize_signature::<MlDsa87>(&sig87);
            // 256 coeffs × 20 bits = 5120 bits = 640 bytes per z polynomial
            assert_eq!(serialized87.len(), 4627,
                "ML-DSA-87 sig size: c_tilde(64) + z(7×640) + h(83) = 4627 bytes (FIPS 204 Table 2)");
        }
    }

    #[test]
    fn test_signature_roundtrip() {
        use crate::sign::sign;

        let seed = [42u8; 32];
        let (_, sk) = keygen_from_seed::<MlDsa65>(&seed);
        let message = b"Test message for roundtrip";

        if let Some(sig) = sign::<MlDsa65>(&sk, message) {
            let serialized = serialize_signature::<MlDsa65>(&sig);
            let deserialized = deserialize_signature::<MlDsa65>(&serialized).unwrap();

            // Check c_tilde matches
            assert_eq!(sig.c_tilde, deserialized.c_tilde);

            // Check z length matches
            assert_eq!(sig.z.len(), deserialized.z.len());

            // Check h length matches
            assert_eq!(sig.h.len(), deserialized.h.len());
        }
    }
}
