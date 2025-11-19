//! DER (Distinguished Encoding Rules) serialization for RSA keys
//!
//! This module provides ASN.1 DER encoding and decoding for RSA public and private keys,
//! conforming to PKCS#1 and PKCS#8 standards.
//!
//! # Standards
//!
//! - **PKCS#1 v2.2** (RFC 8017): RSAPublicKey and RSAPrivateKey formats
//! - **PKCS#8** (RFC 5958): PrivateKeyInfo wrapper for private keys
//! - **X.509** (RFC 5280): SubjectPublicKeyInfo wrapper for public keys
//!
//! # Format Specifications
//!
//! ## RSAPublicKey (PKCS#1)
//!
//! ```text
//! RSAPublicKey ::= SEQUENCE {
//!     modulus           INTEGER,  -- n
//!     publicExponent    INTEGER   -- e
//! }
//! ```
//!
//! ## RSAPrivateKey (PKCS#1)
//!
//! ```text
//! RSAPrivateKey ::= SEQUENCE {
//!     version           Version (0),
//!     modulus           INTEGER,  -- n
//!     publicExponent    INTEGER,  -- e
//!     privateExponent   INTEGER,  -- d
//!     prime1            INTEGER,  -- p
//!     prime2            INTEGER,  -- q
//!     exponent1         INTEGER,  -- d mod (p-1)
//!     exponent2         INTEGER,  -- d mod (q-1)
//!     coefficient       INTEGER   -- (inverse of q) mod p
//! }
//! ```

use crate::error::{Result, RsaError};
use crate::private_key::RsaPrivateKey;
use crate::public_key::RsaPublicKey;
use alloc::vec;
use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::Zero;

/// ASN.1 DER tag for SEQUENCE
const DER_SEQUENCE: u8 = 0x30;

/// ASN.1 DER tag for INTEGER
const DER_INTEGER: u8 = 0x02;

/// Encode a BigUint as ASN.1 DER INTEGER
///
/// # ASN.1 INTEGER Encoding Rules
///
/// - Must be in shortest form (no leading zero bytes except for sign bit)
/// - If MSB is set, prepend 0x00 to distinguish from negative numbers
/// - Zero is encoded as single byte 0x00
fn encode_integer(value: &BigUint) -> Vec<u8> {
    let mut bytes = value.to_bytes_be();

    // Handle zero case
    if bytes.is_empty() {
        return vec![DER_INTEGER, 0x01, 0x00];
    }

    // Add leading zero if MSB is set (to prevent interpretation as negative)
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }

    // Encode: tag + length + value
    let mut result = Vec::new();
    result.push(DER_INTEGER);
    result.extend_from_slice(&encode_length(bytes.len()));
    result.extend_from_slice(&bytes);
    result
}

/// Decode an ASN.1 DER INTEGER
///
/// Returns (BigUint, bytes_consumed)
fn decode_integer(data: &[u8]) -> Result<(BigUint, usize)> {
    if data.is_empty() {
        return Err(RsaError::InvalidDerEncoding);
    }

    // Check tag
    if data[0] != DER_INTEGER {
        return Err(RsaError::InvalidDerEncoding);
    }

    // Decode length
    let (length, length_bytes) = decode_length(&data[1..])?;
    let value_start = 1 + length_bytes;
    let value_end = value_start + length;

    if value_end > data.len() {
        return Err(RsaError::InvalidDerEncoding);
    }

    let value_bytes = &data[value_start..value_end];

    // Skip leading zero byte if present (used for positive sign)
    let value_bytes = if value_bytes.len() > 1 && value_bytes[0] == 0x00 {
        &value_bytes[1..]
    } else {
        value_bytes
    };

    let value = BigUint::from_bytes_be(value_bytes);
    Ok((value, value_end))
}

/// Encode length in ASN.1 DER format
///
/// # Length Encoding Rules
///
/// - Short form (0-127): single byte
/// - Long form (>127): first byte = 0x80 | num_length_bytes, followed by length bytes
fn encode_length(length: usize) -> Vec<u8> {
    if length < 128 {
        // Short form
        vec![length as u8]
    } else {
        // Long form
        let mut length_bytes = Vec::new();
        let mut len = length;
        while len > 0 {
            length_bytes.insert(0, (len & 0xFF) as u8);
            len >>= 8;
        }

        let mut result = Vec::new();
        result.push(0x80 | (length_bytes.len() as u8));
        result.extend_from_slice(&length_bytes);
        result
    }
}

/// Decode length from ASN.1 DER format
///
/// Returns (length_value, bytes_consumed)
fn decode_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(RsaError::InvalidDerEncoding);
    }

    let first_byte = data[0];

    if first_byte & 0x80 == 0 {
        // Short form
        Ok((first_byte as usize, 1))
    } else {
        // Long form
        let num_length_bytes = (first_byte & 0x7F) as usize;

        if num_length_bytes == 0 || num_length_bytes > 4 {
            return Err(RsaError::InvalidDerEncoding);
        }

        if data.len() < 1 + num_length_bytes {
            return Err(RsaError::InvalidDerEncoding);
        }

        let mut length = 0usize;
        for i in 0..num_length_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Ok((length, 1 + num_length_bytes))
    }
}

/// Encode RSA public key in PKCS#1 DER format
///
/// Format: RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
pub fn encode_public_key_pkcs1(public_key: &RsaPublicKey) -> Vec<u8> {
    // Encode integers
    let n_encoded = encode_integer(public_key.n());
    let e_encoded = encode_integer(public_key.e());

    // Calculate total length
    let content_length = n_encoded.len() + e_encoded.len();

    // Build SEQUENCE
    let mut result = Vec::new();
    result.push(DER_SEQUENCE);
    result.extend_from_slice(&encode_length(content_length));
    result.extend_from_slice(&n_encoded);
    result.extend_from_slice(&e_encoded);

    result
}

/// Decode RSA public key from PKCS#1 DER format
pub fn decode_public_key_pkcs1(data: &[u8]) -> Result<RsaPublicKey> {
    if data.is_empty() {
        return Err(RsaError::InvalidDerEncoding);
    }

    // Check SEQUENCE tag
    if data[0] != DER_SEQUENCE {
        return Err(RsaError::InvalidDerEncoding);
    }

    // Decode sequence length
    let (seq_length, length_bytes) = decode_length(&data[1..])?;
    let content_start = 1 + length_bytes;
    let content_end = content_start + seq_length;

    if content_end != data.len() {
        return Err(RsaError::InvalidDerEncoding);
    }

    let content = &data[content_start..content_end];

    // Decode modulus
    let (n, n_bytes) = decode_integer(content)?;

    // Decode public exponent
    let (e, _) = decode_integer(&content[n_bytes..])?;

    RsaPublicKey::new(n, e)
}

/// Encode RSA private key in PKCS#1 DER format
///
/// Format: RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
pub fn encode_private_key_pkcs1(private_key: &RsaPrivateKey) -> Vec<u8> {
    // Version 0 (two-prime RSA)
    let version = encode_integer(&BigUint::zero());

    // Encode all components
    let n_encoded = encode_integer(private_key.public_key().n());
    let e_encoded = encode_integer(private_key.public_key().e());
    let d_encoded = encode_integer(&private_key.d);
    let p_encoded = encode_integer(&private_key.p);
    let q_encoded = encode_integer(&private_key.q);
    let dp_encoded = encode_integer(&private_key.dp);
    let dq_encoded = encode_integer(&private_key.dq);
    let qinv_encoded = encode_integer(&private_key.qinv);

    // Calculate total length
    let content_length = version.len()
        + n_encoded.len()
        + e_encoded.len()
        + d_encoded.len()
        + p_encoded.len()
        + q_encoded.len()
        + dp_encoded.len()
        + dq_encoded.len()
        + qinv_encoded.len();

    // Build SEQUENCE
    let mut result = Vec::new();
    result.push(DER_SEQUENCE);
    result.extend_from_slice(&encode_length(content_length));
    result.extend_from_slice(&version);
    result.extend_from_slice(&n_encoded);
    result.extend_from_slice(&e_encoded);
    result.extend_from_slice(&d_encoded);
    result.extend_from_slice(&p_encoded);
    result.extend_from_slice(&q_encoded);
    result.extend_from_slice(&dp_encoded);
    result.extend_from_slice(&dq_encoded);
    result.extend_from_slice(&qinv_encoded);

    result
}

/// Decode RSA private key from PKCS#1 DER format
pub fn decode_private_key_pkcs1(data: &[u8]) -> Result<RsaPrivateKey> {
    if data.is_empty() {
        return Err(RsaError::InvalidDerEncoding);
    }

    // Check SEQUENCE tag
    if data[0] != DER_SEQUENCE {
        return Err(RsaError::InvalidDerEncoding);
    }

    // Decode sequence length
    let (seq_length, length_bytes) = decode_length(&data[1..])?;
    let content_start = 1 + length_bytes;
    let content_end = content_start + seq_length;

    if content_end != data.len() {
        return Err(RsaError::InvalidDerEncoding);
    }

    let mut content = &data[content_start..content_end];

    // Decode version (should be 0)
    let (version, bytes_read) = decode_integer(content)?;
    if version != BigUint::zero() {
        return Err(RsaError::InvalidDerEncoding);
    }
    content = &content[bytes_read..];

    // Decode modulus n
    let (n, bytes_read) = decode_integer(content)?;
    content = &content[bytes_read..];

    // Decode public exponent e
    let (e, bytes_read) = decode_integer(content)?;
    content = &content[bytes_read..];

    // Decode private exponent d
    let (d, bytes_read) = decode_integer(content)?;
    content = &content[bytes_read..];

    // Decode prime1 p
    let (p, bytes_read) = decode_integer(content)?;
    content = &content[bytes_read..];

    // Decode prime2 q
    let (q, bytes_read) = decode_integer(content)?;
    content = &content[bytes_read..];

    // Decode exponent1 dp
    let (dp, bytes_read) = decode_integer(content)?;
    content = &content[bytes_read..];

    // Decode exponent2 dq
    let (dq, bytes_read) = decode_integer(content)?;
    content = &content[bytes_read..];

    // Decode coefficient qinv
    let (qinv, _) = decode_integer(content)?;

    RsaPrivateKey::from_components(n, e, d, p, q, dp, dq, qinv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_keypair_default;

    #[test]
    fn test_encode_decode_integer() {
        let test_cases = vec![
            BigUint::zero(),
            BigUint::from(1u32),
            BigUint::from(127u32),
            BigUint::from(128u32),
            BigUint::from(255u32),
            BigUint::from(256u32),
            BigUint::from(65535u32),
            BigUint::from(0xFFFFFFFFu32),
        ];

        for value in test_cases {
            let encoded = encode_integer(&value);
            let (decoded, _) = decode_integer(&encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_encode_decode_length() {
        let test_cases = vec![0, 1, 127, 128, 255, 256, 1000, 10000, 65535];

        for length in test_cases {
            let encoded = encode_length(length);
            let (decoded, _) = decode_length(&encoded).unwrap();
            assert_eq!(length, decoded);
        }
    }

    #[test]
    fn test_integer_with_msb_set() {
        // Test that integers with MSB set get leading zero
        let value = BigUint::from(0x80u32); // MSB set in first byte
        let encoded = encode_integer(&value);

        // Should have leading 0x00
        assert_eq!(encoded[0], DER_INTEGER);
        assert_eq!(encoded[1], 0x02); // Length = 2
        assert_eq!(encoded[2], 0x00); // Leading zero
        assert_eq!(encoded[3], 0x80); // Actual value

        let (decoded, _) = decode_integer(&encoded).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_encode_decode_public_key() {
        // Generate a test key pair
        let (n, e, _d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(2048).unwrap();
        let public_key = RsaPublicKey::new(n, e).unwrap();

        // Encode to DER
        let der_bytes = encode_public_key_pkcs1(&public_key);

        // DER should start with SEQUENCE tag
        assert_eq!(der_bytes[0], DER_SEQUENCE);

        // Decode from DER
        let decoded_key = decode_public_key_pkcs1(&der_bytes).unwrap();

        // Verify they match
        assert_eq!(public_key, decoded_key);
    }

    #[test]
    fn test_encode_decode_private_key() {
        // Generate a test key pair
        let (n, e, d, p, q, dp, dq, qinv) = generate_keypair_default(2048).unwrap();
        let private_key = RsaPrivateKey::from_components(n, e, d, p, q, dp, dq, qinv).unwrap();

        // Encode to DER
        let der_bytes = encode_private_key_pkcs1(&private_key);

        // DER should start with SEQUENCE tag
        assert_eq!(der_bytes[0], DER_SEQUENCE);

        // Decode from DER
        let decoded_key = decode_private_key_pkcs1(&der_bytes).unwrap();

        // Verify they match by comparing components
        assert_eq!(private_key.public_key(), decoded_key.public_key());
        assert_eq!(&private_key.d, &decoded_key.d);
        assert_eq!(&private_key.p, &decoded_key.p);
        assert_eq!(&private_key.q, &decoded_key.q);
    }

    #[test]
    fn test_public_key_roundtrip() {
        // Test multiple key sizes
        for bits in [2048, 3072] {
            let (n, e, _d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(bits).unwrap();
            let original = RsaPublicKey::new(n, e).unwrap();

            let der = encode_public_key_pkcs1(&original);
            let decoded = decode_public_key_pkcs1(&der).unwrap();

            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_private_key_roundtrip() {
        // Generate a small key for faster testing
        let (n, e, d, p, q, dp, dq, qinv) = generate_keypair_default(2048).unwrap();
        let original = RsaPrivateKey::from_components(n, e, d, p, q, dp, dq, qinv).unwrap();

        let der = encode_private_key_pkcs1(&original);
        let decoded = decode_private_key_pkcs1(&der).unwrap();

        // Verify all components match
        assert_eq!(original.public_key(), decoded.public_key());
        assert_eq!(&original.d, &decoded.d);
        assert_eq!(&original.p, &decoded.p);
        assert_eq!(&original.q, &decoded.q);
        assert_eq!(&original.dp, &decoded.dp);
        assert_eq!(&original.dq, &decoded.dq);
        assert_eq!(&original.qinv, &decoded.qinv);
    }

    #[test]
    fn test_invalid_der_public_key() {
        // Test with invalid data
        let invalid_data = vec![0x30, 0x05, 0x02, 0x01, 0xFF]; // Truncated
        assert!(decode_public_key_pkcs1(&invalid_data).is_err());

        // Test with wrong tag
        let wrong_tag = vec![0x31, 0x00]; // Not a SEQUENCE
        assert!(decode_public_key_pkcs1(&wrong_tag).is_err());

        // Test with empty data
        assert!(decode_public_key_pkcs1(&[]).is_err());
    }

    #[test]
    fn test_invalid_der_private_key() {
        // Test with invalid data
        let invalid_data = vec![0x30, 0x05, 0x02, 0x01, 0x00]; // Truncated
        assert!(decode_private_key_pkcs1(&invalid_data).is_err());

        // Test with wrong version
        let wrong_version = vec![
            0x30, 0x06, // SEQUENCE
            0x02, 0x01, 0x01, // version = 1 (should be 0)
            0x02, 0x01, 0x00, // modulus = 0
        ];
        assert!(decode_private_key_pkcs1(&wrong_version).is_err());
    }
}
