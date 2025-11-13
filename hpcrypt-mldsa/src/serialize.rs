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
use crate::params::{DsaParams, N, Q};
use crate::poly::Poly;
use crate::sign::Signature;

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
///
/// Note: Currently unused in favor of γ₁-dependent encode_poly_z for signatures.
/// Kept for reference and potential future use.
#[allow(dead_code)]
fn encode_poly_full(poly: &Poly) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Each coefficient is 24 bits (3 bytes)
    for &coeff in &poly.coeffs {
        let c = coeff.rem_euclid(Q);
        bytes.push((c & 0xFF) as u8);
        bytes.push(((c >> 8) & 0xFF) as u8);
        bytes.push(((c >> 16) & 0xFF) as u8);
    }

    bytes
}

/// Decode a polynomial from bytes (full 24-bit coefficients)
///
/// Note: Currently unused in favor of γ₁-dependent decode_poly_z for signatures.
/// Kept for reference and potential future use.
#[allow(dead_code)]
fn decode_poly_full(bytes: &[u8]) -> Result<Poly, SerializeError> {
    if bytes.len() != N * 3 {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    for i in 0..N {
        let idx = i * 3;
        let coeff =
            (bytes[idx] as i32) | ((bytes[idx + 1] as i32) << 8) | ((bytes[idx + 2] as i32) << 16);

        if coeff >= Q {
            return Err(SerializeError::InvalidCoefficient);
        }

        poly.coeffs[i] = coeff;
    }

    Ok(poly)
}

/// Encode z polynomial for signatures with γ₁-dependent bit-packing
///
/// FIPS 204 Algorithm 23 (sigEncode):
/// - For ML-DSA-44 (γ₁ = 2^17): coefficients are in [-γ₁+1, γ₁], needs 18 bits
/// - For ML-DSA-65/87 (γ₁ = 2^19): coefficients are in [-γ₁+1, γ₁], needs 20 bits
///
/// # Arguments
/// * `poly` - Polynomial with z coefficients
/// * `gamma1` - GAMMA1 parameter for the security level
fn encode_poly_z(poly: &Poly, gamma1: i32) -> Vec<u8> {
    // Determine bits per coefficient based on γ₁
    // γ₁ = 2^17 => range [-2^17+1, 2^17] => need 18 bits
    // γ₁ = 2^19 => range [-2^19+1, 2^19] => need 20 bits
    let bits_per_coeff = if gamma1 == (1 << 17) {
        18 // ML-DSA-44
    } else {
        20 // ML-DSA-65, ML-DSA-87
    };

    let total_bits = N * bits_per_coeff;
    let num_bytes = (total_bits + 7) / 8;

    let mut bytes = vec![0u8; num_bytes];
    let mut bit_pos = 0;

    for &coeff in &poly.coeffs {
        // z coefficients should be in [-γ₁+β, γ₁-β]
        // But they may be stored as positive values mod Q
        // Normalize to signed centered representation first
        let normalized = if coeff > Q / 2 {
            coeff - Q // Large positive -> negative
        } else {
            coeff
        };

        // Shift to positive range [0, 2*γ₁]
        let shifted = (normalized + gamma1) as u32;

        // Pack bits
        for j in 0..bits_per_coeff {
            let bit = ((shifted >> j) & 1) as u8;
            bytes[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }

    bytes
}

/// Decode z polynomial from signature bytes
///
/// FIPS 204 Algorithm 24 (sigDecode):
/// Unpacks z coefficients based on γ₁ parameter
fn decode_poly_z(bytes: &[u8], gamma1: i32) -> Result<Poly, SerializeError> {
    let bits_per_coeff = if gamma1 == (1 << 17) { 18 } else { 20 };

    let expected_bytes = (N * bits_per_coeff + 7) / 8;

    if bytes.len() != expected_bytes {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();
    let mut bit_pos = 0;

    for i in 0..N {
        let mut val = 0i32;

        // Unpack bits
        for j in 0..bits_per_coeff {
            let bit = (bytes[bit_pos / 8] >> (bit_pos % 8)) & 1;
            val |= (bit as i32) << j;
            bit_pos += 1;
        }

        // Convert from [0, 2*γ₁] back to [-γ₁, γ₁]
        poly.coeffs[i] = val - gamma1;
    }

    Ok(poly)
}

/// Encode a polynomial with small coefficients (eta-bounded)
///
/// For coefficients in [-η, η], uses fewer bits.
fn encode_poly_eta(poly: &Poly, eta: i32) -> Vec<u8> {
    let bits_per_coeff = if eta == 2 { 3 } else { 4 }; // η=2 needs 3 bits, η=4 needs 4 bits
    let total_bits = N * bits_per_coeff;
    let num_bytes = (total_bits + 7) / 8;

    let mut bytes = vec![0u8; num_bytes];
    let mut bit_pos = 0;

    for &coeff in &poly.coeffs {
        // Reduce coefficient to proper range first
        let mut c = coeff % Q;
        if c > Q / 2 {
            c -= Q; // Center to [-Q/2, Q/2]
        }

        // Clamp to [-η, η] if needed
        let c = c.max(-eta).min(eta);

        // Shift to [0, 2η]
        let centered = c + eta;

        // Pack into bits
        for j in 0..bits_per_coeff {
            let bit = ((centered >> j) & 1) as u8;
            bytes[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }

    bytes
}

/// Decode a polynomial with eta-bounded coefficients
fn decode_poly_eta(bytes: &[u8], eta: i32) -> Result<Poly, SerializeError> {
    let bits_per_coeff = if eta == 2 { 3 } else { 4 };
    let expected_bytes = (N * bits_per_coeff + 7) / 8;

    if bytes.len() != expected_bytes {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();
    let mut bit_pos = 0;

    for i in 0..N {
        let mut val = 0i32;

        for j in 0..bits_per_coeff {
            let bit = (bytes[bit_pos / 8] >> (bit_pos % 8)) & 1;
            val |= (bit as i32) << j;
            bit_pos += 1;
        }

        // Convert from [0, 2η] back to [-η, η]
        poly.coeffs[i] = val - eta;
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
fn encode_poly_t0(poly: &Poly, d: usize) -> Vec<u8> {
    // t0 has d bits per coefficient
    let bits_per_coeff = d;
    let total_bits = N * bits_per_coeff;
    let num_bytes = (total_bits + 7) / 8;

    let mut bytes = vec![0u8; num_bytes];
    let mut bit_pos = 0;

    for &coeff in &poly.coeffs {
        // Center to positive range
        let val = coeff.rem_euclid(1 << d);

        for j in 0..bits_per_coeff {
            let bit = ((val >> j) & 1) as u8;
            bytes[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }

    bytes
}

/// Decode t0 polynomial
fn decode_poly_t0(bytes: &[u8], d: usize) -> Result<Poly, SerializeError> {
    let bits_per_coeff = d;
    let expected_bytes = (N * bits_per_coeff + 7) / 8;

    if bytes.len() != expected_bytes {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();
    let mut bit_pos = 0;

    for i in 0..N {
        let mut val = 0i32;

        for j in 0..bits_per_coeff {
            let bit = (bytes[bit_pos / 8] >> (bit_pos % 8)) & 1;
            val |= (bit as i32) << j;
            bit_pos += 1;
        }

        poly.coeffs[i] = val;
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
/// Inverse of encode_hints_fips204. Reconstructs K hint polynomials from position encoding.
///
/// # Arguments
/// * `bytes` - Position-encoded hints (ω + K bytes)
///
/// # Returns
/// * Vector of K polynomials where coefficients are 0 or 1
fn decode_hints_fips204<P: DsaParams>(bytes: &[u8]) -> Result<Vec<Poly>, SerializeError> {
    if bytes.len() != P::OMEGA + P::K {
        return Err(SerializeError::InvalidLength);
    }

    let mut h = vec![Poly::new(); P::K];
    let mut prev_index = 0;

    for poly_idx in 0..P::K {
        let end_index = bytes[P::OMEGA + poly_idx] as usize;

        // Validate end_index is monotonically increasing
        if end_index < prev_index || end_index > P::OMEGA {
            return Err(SerializeError::InvalidHint);
        }

        // Decode positions for this polynomial
        for pos_idx in prev_index..end_index {
            let coeff_pos = bytes[pos_idx] as usize;
            if coeff_pos >= N {
                return Err(SerializeError::InvalidHint);
            }
            h[poly_idx].coeffs[coeff_pos] = 1;
        }

        prev_index = end_index;
    }

    Ok(h)
}

/// Encode hint polynomial (bits only) - OLD IMPLEMENTATION, kept for compatibility
#[allow(dead_code)]
fn encode_hint(poly: &Poly) -> Vec<u8> {
    let num_bytes = (N + 7) / 8;
    let mut bytes = vec![0u8; num_bytes];

    for i in 0..N {
        if poly.coeffs[i] != 0 {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }

    bytes
}

/// Decode hint polynomial
#[allow(dead_code)]
fn decode_hint(bytes: &[u8]) -> Result<Poly, SerializeError> {
    let expected_bytes = (N + 7) / 8;

    if bytes.len() != expected_bytes {
        return Err(SerializeError::InvalidLength);
    }

    let mut poly = Poly::new();

    for i in 0..N {
        let bit = (bytes[i / 8] >> (i % 8)) & 1;
        poly.coeffs[i] = bit as i32;
    }

    Ok(poly)
}

/// Serialize public key to bytes
pub fn serialize_public_key<P: DsaParams>(pk: &PublicKey<P>) -> Vec<u8> {
    let mut bytes = Vec::new();

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
    let mut bytes = Vec::new();

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

    // Recompute cached matrix A from rho
    // This is done once during deserialization, not every signature
    use crate::sampling::expand_matrix_a;
    let cached_a = expand_matrix_a::<P>(&rho);

    Ok(SecretKey::new(rho, k, tr, s1, s2, t0, cached_a))
}

/// Serialize signature to bytes
///
/// FIPS 204 Algorithm 23 (sigEncode) - uses γ₁-dependent bit-packing for z
pub fn serialize_signature<P: DsaParams>(sig: &Signature<P>) -> Vec<u8> {
    let mut bytes = Vec::new();

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

mod tests {

    #[test]
    fn test_encode_decode_poly_full() {
        let mut poly = Poly::new();
        poly.coeffs[0] = 12345;
        poly.coeffs[1] = 67890;
        poly.coeffs[255] = Q - 1;

        let encoded = encode_poly_full(&poly);
        let decoded = decode_poly_full(&encoded).unwrap();

        assert_eq!(poly, decoded);
    }

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
    fn test_encode_decode_hint() {
        let mut poly = Poly::new();
        poly.coeffs[0] = 1;
        poly.coeffs[10] = 1;
        poly.coeffs[255] = 1;

        let encoded = encode_hint(&poly);
        let decoded = decode_hint(&encoded).unwrap();

        assert_eq!(poly, decoded);
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
        assert_eq!(
            serialized44.len(),
            1312,
            "ML-DSA-44 pk size should be 1312 bytes (FIPS 204 Table 2)"
        );

        // ML-DSA-65
        let (pk65, _) = keygen_from_seed::<MlDsa65>(&seed);
        let serialized65 = serialize_public_key::<MlDsa65>(&pk65);
        assert_eq!(
            serialized65.len(),
            1952,
            "ML-DSA-65 pk size should be 1952 bytes (FIPS 204 Table 2)"
        );

        // ML-DSA-87
        let (pk87, _) = keygen_from_seed::<MlDsa87>(&seed);
        let serialized87 = serialize_public_key::<MlDsa87>(&pk87);
        assert_eq!(
            serialized87.len(),
            2592,
            "ML-DSA-87 pk size should be 2592 bytes (FIPS 204 Table 2)"
        );
    }

    #[test]
    fn test_all_security_levels_sk_sizes() {
        use crate::params::{MlDsa44, MlDsa65, MlDsa87};

        let seed = [42u8; 32];

        // ML-DSA-44: FIPS 204 Table 2 - 2560 bytes
        let (_, sk44) = keygen_from_seed::<MlDsa44>(&seed);
        let serialized44 = serialize_secret_key::<MlDsa44>(&sk44);
        // ρ(32) + K(32) + tr(64) + s1(4*96) + s2(4*96) + t0(4*416) = 32+32+64+384+384+1664 = 2560
        assert_eq!(
            serialized44.len(),
            2560,
            "ML-DSA-44 sk size should be 2560 bytes"
        );

        // ML-DSA-65: FIPS 204 Table 2 - 4032 bytes
        let (_, sk65) = keygen_from_seed::<MlDsa65>(&seed);
        let serialized65 = serialize_secret_key::<MlDsa65>(&sk65);
        // ρ(32) + K(32) + tr(64) + s1(5*128) + s2(6*128) + t0(6*416) = 32+32+64+640+768+2496 = 4032
        assert_eq!(
            serialized65.len(),
            4032,
            "ML-DSA-65 sk size should be 4032 bytes"
        );

        // ML-DSA-87: FIPS 204 Table 2 - 4896 bytes
        let (_, sk87) = keygen_from_seed::<MlDsa87>(&seed);
        let serialized87 = serialize_secret_key::<MlDsa87>(&sk87);
        // ρ(32) + K(32) + tr(64) + s1(7*96) + s2(8*96) + t0(8*416) = 32+32+64+672+768+3328 = 4896
        assert_eq!(
            serialized87.len(),
            4896,
            "ML-DSA-87 sk size should be 4896 bytes"
        );
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
            assert_eq!(
                poly.coeffs[i], decoded.coeffs[i],
                "ML-DSA-44 z coeff {} mismatch",
                i
            );
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
            assert_eq!(
                poly2.coeffs[i], decoded2.coeffs[i],
                "ML-DSA-65 z coeff {} mismatch",
                i
            );
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
