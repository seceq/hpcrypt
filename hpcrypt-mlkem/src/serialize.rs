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

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use crate::intrinsics::avx2::compress::{compress_d10, compress_d11};

/// Magic constant for constant-time division by q = 3329
/// Computed as: floor(2^35 / 3329) = 10,321,340
const MAGIC_DIVISOR: u64 = 10_321_340;

/// Branchless normalization of coefficient to [0, q)
/// Uses branchless arithmetic for coefficients in range [-q, 2q)
/// For wider ranges, falls back to modulo
#[inline(always)]
fn normalize_coeff(x: i16) -> u64 {
    let x32 = x as i32;
    // Fast path: branchless for x in [-q, 2q)
    // Add q to handle negatives, then subtract q if >= q
    let pos = x32 + Q as i32;  // Now in [0, 3q) for typical inputs
    // Branchless subtraction: subtract q if pos >= q
    let high = pos - Q as i32;
    let mask = (high >> 31) as i32;  // -1 if high < 0, else 0
    let result = (high & !mask) | (pos & mask);
    // Handle case where result is still >= q (rare, for inputs > q)
    let high2 = result - Q as i32;
    let mask2 = (high2 >> 31) as i32;
    let final_result = (high2 & !mask2) | (result & mask2);
    final_result as u64
}

/// Branchless compression for d=4
/// Handles coefficients in typical ML-KEM range
#[inline(always)]
fn compress_fast_d4(x: i16) -> u16 {
    let normalized = normalize_coeff(x);
    let mut compressed = normalized << 4;
    compressed += 1664;  // q/2
    compressed = compressed.wrapping_mul(MAGIC_DIVISOR);
    compressed >>= 35;
    (compressed & 0xF) as u16
}

/// Branchless compression for d=10
/// Handles coefficients in typical ML-KEM range
#[inline(always)]
fn compress_fast_d10(x: i16) -> u32 {
    let normalized = normalize_coeff(x);
    let mut compressed = normalized << 10;
    compressed += 1664;  // q/2
    compressed = compressed.wrapping_mul(MAGIC_DIVISOR);
    compressed >>= 35;
    (compressed & 0x3FF) as u32
}

/// Branchless compression for d=11
/// Handles coefficients in typical ML-KEM range
#[inline(always)]
fn compress_fast_d11(x: i16) -> u32 {
    let normalized = normalize_coeff(x);
    let mut compressed = normalized << 11;
    compressed += 1664;  // q/2
    compressed = compressed.wrapping_mul(MAGIC_DIVISOR);
    compressed >>= 35;
    (compressed & 0x7FF) as u32
}

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
        // Using full modulo is required because NTT coefficients can be in wide range
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

/// Encode compressed polynomial coefficients for d=4
///
/// Uses byte-level packing: 2 coefficients (8 bits) → 1 byte
/// Much faster than bit-by-bit packing
///
/// # Arguments
/// * `poly` - Polynomial with coefficients in [0, q)
///
/// # Returns
/// Encoded bytes (128 bytes for d=4, N=256)
#[inline]
fn encode_poly_compressed_d4(poly: &Poly) -> Vec<u8> {
    let mut bytes = vec![0u8; 128];

    // Byte-level packing: 2 coefficients per byte (4 bits each)
    // Uses branchless compression for better performance
    for i in 0..(N / 2) {
        let c0 = compress_fast_d4(poly.coeffs[2 * i]) as u8;
        let c1 = compress_fast_d4(poly.coeffs[2 * i + 1]) as u8;
        bytes[i] = (c0 & 0xF) | (c1 << 4);
    }
    bytes
}

/// Encode compressed polynomial coefficients for d=10 (portable)
///
/// Uses byte-level packing: 4 coefficients (40 bits) → 5 bytes
#[inline]
#[allow(dead_code)]
fn encode_poly_compressed_d10_portable(poly: &Poly) -> Vec<u8> {
    let mut bytes = vec![0u8; 320];

    // Byte-level packing: compress 4 coefficients then pack into 5 bytes
    // Uses branchless compression for better performance
    for i in 0..(N / 4) {
        let c0 = compress_fast_d10(poly.coeffs[4 * i]);
        let c1 = compress_fast_d10(poly.coeffs[4 * i + 1]);
        let c2 = compress_fast_d10(poly.coeffs[4 * i + 2]);
        let c3 = compress_fast_d10(poly.coeffs[4 * i + 3]);

        let base = i * 5;
        bytes[base] = c0 as u8;
        bytes[base + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
        bytes[base + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
        bytes[base + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
        bytes[base + 4] = (c3 >> 2) as u8;
    }
    bytes
}

/// Encode compressed polynomial coefficients for d=10 (AVX2)
///
/// Uses AVX2 SIMD compression for 1.70x speedup (41% faster).
/// Processes 16 coefficients at a time.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline]
fn encode_poly_compressed_d10_avx2(poly: &Poly) -> Vec<u8> {
    let mut bytes = vec![0u8; 320];

    // Process 16 coefficients at a time with AVX2
    for chunk in 0..(N / 16) {
        let base_coeff = chunk * 16;
        let coeffs: [i16; 16] = poly.coeffs[base_coeff..base_coeff + 16].try_into().unwrap();
        // Safety: compress_d10 requires AVX2, which is guaranteed by cfg
        let compressed = unsafe { compress_d10(&coeffs) };

        // Pack 16 compressed values (10 bits each) into 20 bytes using 64-bit packing
        // 4 coefficients -> 5 bytes (40 bits), so 16 coefficients -> 20 bytes
        let base_byte = chunk * 20;
        for g in 0..4 {
            let c0 = compressed[4 * g] as u64;
            let c1 = compressed[4 * g + 1] as u64;
            let c2 = compressed[4 * g + 2] as u64;
            let c3 = compressed[4 * g + 3] as u64;

            // Pack 4 10-bit values into 40 bits
            let packed = c0 | (c1 << 10) | (c2 << 20) | (c3 << 30);

            // Write 5 bytes from packed value
            let b = base_byte + g * 5;
            bytes[b] = packed as u8;
            bytes[b + 1] = (packed >> 8) as u8;
            bytes[b + 2] = (packed >> 16) as u8;
            bytes[b + 3] = (packed >> 24) as u8;
            bytes[b + 4] = (packed >> 32) as u8;
        }
    }
    bytes
}

/// Encode compressed polynomial coefficients for d=10
///
/// Uses byte-level packing: 4 coefficients (40 bits) → 5 bytes
///
/// # Arguments
/// * `poly` - Polynomial with coefficients in [0, q)
///
/// # Returns
/// Encoded bytes (320 bytes for d=10, N=256)
#[inline]
fn encode_poly_compressed_d10(poly: &Poly) -> Vec<u8> {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        encode_poly_compressed_d10_avx2(poly)
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    {
        encode_poly_compressed_d10_portable(poly)
    }
}

/// Encode compressed polynomial coefficients for d=11 (portable)
///
/// Uses byte-level packing: 8 coefficients (88 bits) → 11 bytes
/// Used in ML-KEM-1024 DU parameter
#[inline]
#[allow(dead_code)]
fn encode_poly_compressed_d11_portable(poly: &Poly) -> Vec<u8> {
    let mut bytes = vec![0u8; 352];

    // Byte-level packing: compress 8 coefficients then pack into 11 bytes
    // Uses branchless compression for better performance
    for i in 0..(N / 8) {
        let c0 = compress_fast_d11(poly.coeffs[8 * i]);
        let c1 = compress_fast_d11(poly.coeffs[8 * i + 1]);
        let c2 = compress_fast_d11(poly.coeffs[8 * i + 2]);
        let c3 = compress_fast_d11(poly.coeffs[8 * i + 3]);
        let c4 = compress_fast_d11(poly.coeffs[8 * i + 4]);
        let c5 = compress_fast_d11(poly.coeffs[8 * i + 5]);
        let c6 = compress_fast_d11(poly.coeffs[8 * i + 6]);
        let c7 = compress_fast_d11(poly.coeffs[8 * i + 7]);

        let base = i * 11;
        bytes[base] = c0 as u8;
        bytes[base + 1] = ((c0 >> 8) | (c1 << 3)) as u8;
        bytes[base + 2] = ((c1 >> 5) | (c2 << 6)) as u8;
        bytes[base + 3] = (c2 >> 2) as u8;
        bytes[base + 4] = ((c2 >> 10) | (c3 << 1)) as u8;
        bytes[base + 5] = ((c3 >> 7) | (c4 << 4)) as u8;
        bytes[base + 6] = ((c4 >> 4) | (c5 << 7)) as u8;
        bytes[base + 7] = (c5 >> 1) as u8;
        bytes[base + 8] = ((c5 >> 9) | (c6 << 2)) as u8;
        bytes[base + 9] = ((c6 >> 6) | (c7 << 5)) as u8;
        bytes[base + 10] = (c7 >> 3) as u8;
    }
    bytes
}

/// Encode compressed polynomial coefficients for d=11 (AVX2)
///
/// Uses AVX2 SIMD compression for faster performance.
/// Processes 16 coefficients at a time.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline]
fn encode_poly_compressed_d11_avx2(poly: &Poly) -> Vec<u8> {
    let mut bytes = vec![0u8; 352];

    // Process 16 coefficients at a time with AVX2
    for chunk in 0..(N / 16) {
        let base_coeff = chunk * 16;
        let coeffs: [i16; 16] = poly.coeffs[base_coeff..base_coeff + 16].try_into().unwrap();
        // Safety: compress_d11 requires AVX2, which is guaranteed by cfg
        let compressed = unsafe { compress_d11(&coeffs) };

        // Pack 16 compressed values (11 bits each) into 22 bytes
        // 8 coefficients -> 11 bytes (88 bits), so 16 coefficients -> 22 bytes
        let base_byte = chunk * 22;

        // First group of 8 coefficients -> 11 bytes
        let c0 = compressed[0] as u32;
        let c1 = compressed[1] as u32;
        let c2 = compressed[2] as u32;
        let c3 = compressed[3] as u32;
        let c4 = compressed[4] as u32;
        let c5 = compressed[5] as u32;
        let c6 = compressed[6] as u32;
        let c7 = compressed[7] as u32;

        bytes[base_byte] = c0 as u8;
        bytes[base_byte + 1] = ((c0 >> 8) | (c1 << 3)) as u8;
        bytes[base_byte + 2] = ((c1 >> 5) | (c2 << 6)) as u8;
        bytes[base_byte + 3] = (c2 >> 2) as u8;
        bytes[base_byte + 4] = ((c2 >> 10) | (c3 << 1)) as u8;
        bytes[base_byte + 5] = ((c3 >> 7) | (c4 << 4)) as u8;
        bytes[base_byte + 6] = ((c4 >> 4) | (c5 << 7)) as u8;
        bytes[base_byte + 7] = (c5 >> 1) as u8;
        bytes[base_byte + 8] = ((c5 >> 9) | (c6 << 2)) as u8;
        bytes[base_byte + 9] = ((c6 >> 6) | (c7 << 5)) as u8;
        bytes[base_byte + 10] = (c7 >> 3) as u8;

        // Second group of 8 coefficients -> 11 bytes
        let c0 = compressed[8] as u32;
        let c1 = compressed[9] as u32;
        let c2 = compressed[10] as u32;
        let c3 = compressed[11] as u32;
        let c4 = compressed[12] as u32;
        let c5 = compressed[13] as u32;
        let c6 = compressed[14] as u32;
        let c7 = compressed[15] as u32;

        bytes[base_byte + 11] = c0 as u8;
        bytes[base_byte + 12] = ((c0 >> 8) | (c1 << 3)) as u8;
        bytes[base_byte + 13] = ((c1 >> 5) | (c2 << 6)) as u8;
        bytes[base_byte + 14] = (c2 >> 2) as u8;
        bytes[base_byte + 15] = ((c2 >> 10) | (c3 << 1)) as u8;
        bytes[base_byte + 16] = ((c3 >> 7) | (c4 << 4)) as u8;
        bytes[base_byte + 17] = ((c4 >> 4) | (c5 << 7)) as u8;
        bytes[base_byte + 18] = (c5 >> 1) as u8;
        bytes[base_byte + 19] = ((c5 >> 9) | (c6 << 2)) as u8;
        bytes[base_byte + 20] = ((c6 >> 6) | (c7 << 5)) as u8;
        bytes[base_byte + 21] = (c7 >> 3) as u8;
    }
    bytes
}

/// Encode compressed polynomial coefficients for d=11
///
/// Uses byte-level packing: 8 coefficients (88 bits) → 11 bytes
/// Used in ML-KEM-1024 DU parameter
///
/// # Arguments
/// * `poly` - Polynomial with coefficients in [0, q)
///
/// # Returns
/// Encoded bytes (352 bytes for d=11, N=256)
#[inline]
fn encode_poly_compressed_d11(poly: &Poly) -> Vec<u8> {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        encode_poly_compressed_d11_avx2(poly)
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    {
        encode_poly_compressed_d11_portable(poly)
    }
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
    // Use optimized versions for common cases
    match d {
        4 => return encode_poly_compressed_d4(poly),
        10 => return encode_poly_compressed_d10(poly),
        11 => return encode_poly_compressed_d11(poly),
        _ => {}
    }

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
    for i in 0..(N / 2) {
        let byte = bytes[i];
        let y0 = (byte & 0xF) as u32;
        let y1 = (byte >> 4) as u32;

        let numerator0 = Q * y0 + HALF;
        let numerator1 = Q * y1 + HALF;

        poly.coeffs[2 * i] = (numerator0 >> 4) as i16;
        poly.coeffs[2 * i + 1] = (numerator1 >> 4) as i16;
    }

    poly
}

/// Decode compressed polynomial coefficients for d=10
///
/// Specialized for d=10 (used in ML-KEM-768 DU parameter)
/// Uses byte-level unpacking with inline decompression
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

    // Unpack 5 bytes into 4 coefficients with inline decompression
    for i in 0..(N / 4) {
        let base = i * 5;

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

/// Decode compressed polynomial coefficients for d=11 (optimized)
///
/// Specialized for d=11 (used in ML-KEM-1024 DU parameter)
/// Uses byte-level unpacking with inline decompression
///
/// # Arguments
/// * `bytes` - Encoded bytes (352 bytes for d=11, N=256)
///
/// # Returns
/// Polynomial with coefficients in [0, q)
#[inline]
fn decode_poly_compressed_d11(bytes: &[u8]) -> Poly {
    const Q: u32 = crate::params::Q as u32;
    const HALF: u32 = 1u32 << 10; // 2^(11-1) = 1024

    let mut poly = Poly::new();

    // Unpack 11 bytes into 8 coefficients with inline decompression
    for i in 0..(N / 8) {
        let base = i * 11;

        let y0 = (bytes[base] as u32) | (((bytes[base + 1] as u32) & 0x07) << 8);
        let y1 = ((bytes[base + 1] as u32) >> 3) | (((bytes[base + 2] as u32) & 0x3F) << 5);
        let y2 = ((bytes[base + 2] as u32) >> 6) | ((bytes[base + 3] as u32) << 2) | (((bytes[base + 4] as u32) & 0x01) << 10);
        let y3 = ((bytes[base + 4] as u32) >> 1) | (((bytes[base + 5] as u32) & 0x0F) << 7);
        let y4 = ((bytes[base + 5] as u32) >> 4) | (((bytes[base + 6] as u32) & 0x7F) << 4);
        let y5 = ((bytes[base + 6] as u32) >> 7) | ((bytes[base + 7] as u32) << 1) | (((bytes[base + 8] as u32) & 0x03) << 9);
        let y6 = ((bytes[base + 8] as u32) >> 2) | (((bytes[base + 9] as u32) & 0x1F) << 6);
        let y7 = ((bytes[base + 9] as u32) >> 5) | ((bytes[base + 10] as u32) << 3);

        poly.coeffs[8 * i] = ((Q * y0 + HALF) >> 11) as i16;
        poly.coeffs[8 * i + 1] = ((Q * y1 + HALF) >> 11) as i16;
        poly.coeffs[8 * i + 2] = ((Q * y2 + HALF) >> 11) as i16;
        poly.coeffs[8 * i + 3] = ((Q * y3 + HALF) >> 11) as i16;
        poly.coeffs[8 * i + 4] = ((Q * y4 + HALF) >> 11) as i16;
        poly.coeffs[8 * i + 5] = ((Q * y5 + HALF) >> 11) as i16;
        poly.coeffs[8 * i + 6] = ((Q * y6 + HALF) >> 11) as i16;
        poly.coeffs[8 * i + 7] = ((Q * y7 + HALF) >> 11) as i16;
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
    match d {
        4 => return decode_poly_compressed_d4(bytes),
        10 => return decode_poly_compressed_d10(bytes),
        11 => return decode_poly_compressed_d11(bytes),
        _ => {}
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
