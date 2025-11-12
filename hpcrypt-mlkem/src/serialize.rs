//! Serialization and deserialization for ML-KEM
//!
//! This module implements the encoding and decoding functions for polynomials,
//! polynomial vectors, keys, and ciphertexts as specified in FIPS 203.
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;


use crate::compress::{compress, decompress};
use crate::params::{N, Q};
use crate::poly::{Poly, PolyVec};

/// Encode polynomial coefficients into bytes (12 bits per coefficient)
///
/// Algorithm: ByteEncode₁₂
/// Encodes 256 coefficients (each 12 bits) into 384 bytes
///
/// # Arguments
/// * `poly` - Polynomial with coefficients in [0, q)
///
/// # Returns
/// 384-byte encoding
pub fn encode_poly_12(poly: &Poly) -> [u8; 384] {
    let mut bytes = [0u8; 384];

    for i in 0..(N / 2) {
        // Ensure coefficients are in valid range [0, Q)
        let c0 = ((poly.coeffs[2 * i] as i32 % Q as i32 + Q as i32) % Q as i32) as u16;
        let c1 = ((poly.coeffs[2 * i + 1] as i32 % Q as i32 + Q as i32) % Q as i32) as u16;

        debug_assert!(c0 < Q as u16);
        debug_assert!(c1 < Q as u16);

        // Pack two 12-bit values into 3 bytes
        bytes[3 * i] = (c0 & 0xFF) as u8;
        bytes[3 * i + 1] = ((c0 >> 8) | ((c1 & 0x0F) << 4)) as u8;
        bytes[3 * i + 2] = (c1 >> 4) as u8;
    }

    bytes
}

/// Decode polynomial coefficients from bytes (12 bits per coefficient)
///
/// Algorithm: ByteDecode₁₂
/// Decodes 384 bytes into 256 coefficients (each 12 bits)
///
/// # Arguments
/// * `bytes` - 384-byte encoding
///
/// # Returns
/// Polynomial with coefficients in [0, q)
#[inline]
pub fn decode_poly_12(bytes: &[u8; 384]) -> Poly {
    let mut poly = Poly::new();

    // 12-bit values range from 0 to 4095, Q = 3329
    // So only values >= 3329 need reduction
    const Q_U16: u16 = Q as u16;

    for i in 0..(N / 2) {
        // Unpack 3 bytes into two 12-bit values
        let c0 = (bytes[3 * i] as u16) | (((bytes[3 * i + 1] as u16) & 0x0F) << 8);
        let c1 = ((bytes[3 * i + 1] as u16) >> 4) | ((bytes[3 * i + 2] as u16) << 4);

        // Only reduce if needed (most values are already < Q)
        poly.coeffs[2 * i] = if c0 < Q_U16 { c0 as i16 } else { (c0 % Q_U16) as i16 };
        poly.coeffs[2 * i + 1] = if c1 < Q_U16 { c1 as i16 } else { (c1 % Q_U16) as i16 };
    }

    poly
}

/// Encode compressed polynomial coefficients
///
/// Generic encoding for d-bit compressed coefficients
///
/// # Arguments
/// * `poly` - Polynomial with coefficients in [0, q)
/// * `d` - Number of bits per coefficient
///
/// # Returns
/// Encoded bytes (32 * d bytes)
pub fn encode_poly_compressed(poly: &Poly, d: u32) -> Vec<u8> {
    let num_bytes = (32 * d) as usize;
    let mut bytes = vec![0u8; num_bytes];

    // Compress each coefficient to d bits
    let mut bit_idx = 0;

    for &coeff in &poly.coeffs {
        let compressed = compress(coeff, d);

        // Pack d bits into the byte array
        for bit in 0..d {
            let bit_val = ((compressed >> bit) & 1) as u8;
            let byte_idx = bit_idx / 8;
            let bit_pos = bit_idx % 8;

            bytes[byte_idx] |= bit_val << bit_pos;
            bit_idx += 1;
        }
    }

    bytes
}

/// Decode compressed polynomial coefficients for d=4 (optimized)
///
/// Specialized for d=4 (used in ML-KEM-512/768 DV parameter)
///
/// # Arguments
/// * `bytes` - Encoded bytes (128 bytes for d=4, N=256)
///
/// # Returns
/// Polynomial with coefficients in [0, q)
#[inline]
fn decode_poly_compressed_d4(bytes: &[u8]) -> Poly {
    const Q: u32 = crate::params::Q as u32;
    const HALF: u32 = 1u32 << 3; // 2^(4-1) = 8

    let mut poly = Poly::new();

    // For d=4: each byte contains 2 coefficients (4 bits each)
    // Inline the decompression to avoid function call overhead
    for (i, &byte) in bytes.iter().enumerate().take(N / 2) {
        let y0 = (byte & 0xF) as u32;
        let y1 = (byte >> 4) as u32;

        let numerator0 = Q * y0 + HALF;
        let numerator1 = Q * y1 + HALF;

        poly.coeffs[2 * i] = (numerator0 >> 4) as i16;
        poly.coeffs[2 * i + 1] = (numerator1 >> 4) as i16;
    }

    poly
}

/// Decode compressed polynomial coefficients for d=10 (optimized)
///
/// Specialized for d=10 (used in ML-KEM-768 DU parameter)
///
/// # Arguments
/// * `bytes` - Encoded bytes (320 bytes for d=10, N=256)
///
/// # Returns
/// Polynomial with coefficients in [0, q)
#[inline]
fn decode_poly_compressed_d10(bytes: &[u8]) -> Poly {
    const Q: u32 = crate::params::Q as u32;
    const HALF: u32 = 1u32 << 9; // 2^(10-1) = 512

    let mut poly = Poly::new();

    // For d=10: 5 bytes encode 4 coefficients (10 bits each = 40 bits total)
    // Inline the decompression to avoid function call overhead
    for i in 0..(N / 4) {
        let base = i * 5;

        // Extract 4 x 10-bit values from 5 bytes
        // Layout: [AAAAAAAA][BBBBBBAA][CCCCBBBB][DDCCCCCC][DDDDDDDD]
        let y0 = (bytes[base] as u32) | (((bytes[base + 1] as u32) & 0x03) << 8);
        let y1 = ((bytes[base + 1] as u32) >> 2) | (((bytes[base + 2] as u32) & 0x0F) << 6);
        let y2 = ((bytes[base + 2] as u32) >> 4) | (((bytes[base + 3] as u32) & 0x3F) << 4);
        let y3 = ((bytes[base + 3] as u32) >> 6) | ((bytes[base + 4] as u32) << 2);

        poly.coeffs[4 * i] = ((Q * y0 + HALF) >> 10) as i16;
        poly.coeffs[4 * i + 1] = ((Q * y1 + HALF) >> 10) as i16;
        poly.coeffs[4 * i + 2] = ((Q * y2 + HALF) >> 10) as i16;
        poly.coeffs[4 * i + 3] = ((Q * y3 + HALF) >> 10) as i16;
    }

    poly
}

/// Decode compressed polynomial coefficients
///
/// Generic decoding for d-bit compressed coefficients
///
/// # Arguments
/// * `bytes` - Encoded bytes (32 * d bytes)
/// * `d` - Number of bits per coefficient
///
/// # Returns
/// Polynomial with coefficients in [0, q)
#[inline]
pub fn decode_poly_compressed(bytes: &[u8], d: u32) -> Poly {
    // Use optimized versions for common cases
    if d == 4 {
        return decode_poly_compressed_d4(bytes);
    } else if d == 10 {
        return decode_poly_compressed_d10(bytes);
    }

    let mut poly = Poly::new();
    let mut bit_idx = 0;

    for i in 0..N {
        let mut compressed = 0u16;

        // Extract d bits from the byte array
        for bit in 0..d {
            let byte_idx = bit_idx / 8;
            let bit_pos = bit_idx % 8;
            let bit_val = (bytes[byte_idx] >> bit_pos) & 1;

            compressed |= (bit_val as u16) << bit;
            bit_idx += 1;
        }

        poly.coeffs[i] = decompress(compressed, d);
    }

    poly
}

/// Encode polynomial vector (K polynomials, 12 bits each)
///
/// # Arguments
/// * `vec` - Polynomial vector with compile-time size K
///
/// # Returns
/// Encoded bytes (384 * K bytes)
pub fn encode_polyvec_12<const K: usize>(vec: &PolyVec<K>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(384 * K);

    for poly in &vec.polys {
        bytes.extend_from_slice(&encode_poly_12(poly));
    }

    bytes
}

/// Decode polynomial vector (K polynomials, 12 bits each)
///
/// # Arguments
/// * `bytes` - Encoded bytes (384 * K bytes)
///
/// # Returns
/// Polynomial vector with K polynomials
pub fn decode_polyvec_12<const K: usize>(bytes: &[u8]) -> PolyVec<K> {
    debug_assert_eq!(bytes.len(), 384 * K);

    let mut vec = PolyVec::new();

    for i in 0..K {
        let chunk: [u8; 384] = bytes[i * 384..(i + 1) * 384]
            .try_into()
            .expect("Slice length mismatch");
        vec.polys[i] = decode_poly_12(&chunk);
    }

    vec
}

/// Encode compressed polynomial vector
///
/// # Arguments
/// * `vec` - Polynomial vector with compile-time size K
/// * `d` - Number of bits per coefficient
///
/// # Returns
/// Encoded bytes (32 * d * K bytes)
pub fn encode_polyvec_compressed<const K: usize>(vec: &PolyVec<K>, d: u32) -> Vec<u8> {
    let mut bytes = Vec::new();

    for poly in &vec.polys {
        bytes.extend(encode_poly_compressed(poly, d));
    }

    bytes
}

/// Decode compressed polynomial vector
///
/// # Arguments
/// * `bytes` - Encoded bytes (32 * d * K bytes)
/// * `d` - Number of bits per coefficient
///
/// # Returns
/// Polynomial vector with K polynomials
#[inline]
pub fn decode_polyvec_compressed<const K: usize>(bytes: &[u8], d: u32) -> PolyVec<K> {
    let chunk_size = (32 * d) as usize;
    debug_assert_eq!(bytes.len(), chunk_size * K);

    let mut vec = PolyVec::new();

    for i in 0..K {
        let chunk = &bytes[i * chunk_size..(i + 1) * chunk_size];
        vec.polys[i] = decode_poly_compressed(chunk, d);
    }

    vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_poly_12_roundtrip() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = ((i * 13) % Q as usize) as i16;
        }

        let encoded = encode_poly_12(&poly);
        let decoded = decode_poly_12(&encoded);

        assert_eq!(poly.coeffs, decoded.coeffs);
    }

    #[test]
    fn test_encode_decode_poly_12_zeros() {
        let poly = Poly::new();

        let encoded = encode_poly_12(&poly);
        let decoded = decode_poly_12(&encoded);

        assert_eq!(poly.coeffs, decoded.coeffs);
    }

    #[test]
    fn test_encode_decode_poly_12_max_values() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = Q - 1;
        }

        let encoded = encode_poly_12(&poly);
        let decoded = decode_poly_12(&encoded);

        assert_eq!(poly.coeffs, decoded.coeffs);
    }

    #[test]
    fn test_encode_poly_12_size() {
        let poly = Poly::new();
        let encoded = encode_poly_12(&poly);
        assert_eq!(encoded.len(), 384);
    }

    #[test]
    fn test_encode_decode_poly_compressed_d4() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = ((i * 13) % Q as usize) as i16;
        }

        let encoded = encode_poly_compressed(&poly, 4);
        let decoded = decode_poly_compressed(&encoded, 4);

        // Check approximate equality (lossy compression, accounting for wraparound)
        for i in 0..N {
            let diff = (poly.coeffs[i] - decoded.coeffs[i]).abs();
            let diff_wrapped = ((poly.coeffs[i] - decoded.coeffs[i] + Q) % Q).min((decoded.coeffs[i] - poly.coeffs[i] + Q) % Q);
            let max_error = Q / (1 << 4) + 1;
            assert!(diff <= max_error || diff_wrapped <= max_error,
                "i={}, orig={}, decoded={}, diff={}, diff_wrapped={}",
                i, poly.coeffs[i], decoded.coeffs[i], diff, diff_wrapped);
        }
    }

    #[test]
    fn test_encode_decode_poly_compressed_d10() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = ((i * 13) % Q as usize) as i16;
        }

        let encoded = encode_poly_compressed(&poly, 10);
        let decoded = decode_poly_compressed(&encoded, 10);

        // Check approximate equality (lossy compression)
        for i in 0..N {
            let diff = (poly.coeffs[i] - decoded.coeffs[i]).abs();
            let max_error = Q / (1 << 10) + 1;
            assert!(diff <= max_error);
        }
    }

    #[test]
    fn test_encode_poly_compressed_size() {
        let poly = Poly::new();

        let encoded_d4 = encode_poly_compressed(&poly, 4);
        assert_eq!(encoded_d4.len(), 32 * 4);

        let encoded_d10 = encode_poly_compressed(&poly, 10);
        assert_eq!(encoded_d10.len(), 32 * 10);
    }

    #[test]
    fn test_encode_decode_polyvec_12_roundtrip() {
        let mut vec = PolyVec::<3>::new();
        for i in 0..3 {
            for j in 0..N {
                vec.polys[i].coeffs[j] = (((i + 1) * (j + 1) * 17) % Q as usize) as i16;
            }
        }

        let encoded = encode_polyvec_12(&vec);
        let decoded = decode_polyvec_12::<3>(&encoded);

        for i in 0..3 {
            assert_eq!(vec.polys[i].coeffs, decoded.polys[i].coeffs);
        }
    }

    #[test]
    fn test_encode_polyvec_12_size() {
        let vec = PolyVec::<3>::new();
        let encoded = encode_polyvec_12(&vec);
        assert_eq!(encoded.len(), 384 * 3);
    }

    #[test]
    fn test_encode_decode_polyvec_compressed_roundtrip() {
        let mut vec = PolyVec::<2>::new();
        for i in 0..2 {
            for j in 0..N {
                vec.polys[i].coeffs[j] = (((i + 1) * (j + 1) * 17) % Q as usize) as i16;
            }
        }

        let encoded = encode_polyvec_compressed(&vec, 10);
        let decoded = decode_polyvec_compressed::<2>(&encoded, 10);

        for i in 0..2 {
            for j in 0..N {
                let diff = (vec.polys[i].coeffs[j] - decoded.polys[i].coeffs[j]).abs();
                let max_error = Q / (1 << 10) + 1;
                assert!(diff <= max_error);
            }
        }
    }

    #[test]
    fn test_encode_polyvec_compressed_size() {
        let vec = PolyVec::<3>::new();

        let encoded_d10 = encode_polyvec_compressed(&vec, 10);
        assert_eq!(encoded_d10.len(), 32 * 10 * 3);

        let encoded_d11 = encode_polyvec_compressed(&vec, 11);
        assert_eq!(encoded_d11.len(), 32 * 11 * 3);
    }
}
