//! PEM and DER encoding/decoding for ML-DSA keys
//!
//! This module provides support for encoding and decoding ML-DSA public and secret keys
//! in standard PEM and DER formats, allowing interoperability with other cryptographic tools.
//!
//! # Format Specification
//!
//! ML-DSA keys use the following format:
//! - **Public keys**: Raw concatenation of (rho || t1) encoded as bytes
//! - **Secret keys**: Raw concatenation of (rho || K || tr || s1 || s2 || t0) encoded as bytes
//!
//! PEM format uses Base64 encoding with header/footer markers:
//! ```text
//! -----BEGIN ML-DSA PUBLIC KEY-----
//! <Base64 encoded DER data>
//! -----END ML-DSA PUBLIC KEY-----
//! ```
//!
//! # Example
//!
//! ```no_run
//! use mldsa::keygen::keygen;
//! use mldsa::params::MlDsa65;
//! use mldsa::pem_encoding::{public_key_to_pem, public_key_from_pem};
//!
//! let (pk, sk) = keygen::<MlDsa65>();
//!
//! // Encode to PEM
//! let pem_str = public_key_to_pem(&pk).unwrap();
//!
//! // Decode from PEM
//! let pk_recovered = public_key_from_pem::<MlDsa65>(&pem_str).unwrap();
//! ```

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "pem")]
use pem;

use crate::keygen::{PublicKey, SecretKey};
use crate::params::DsaParams;
use crate::serialize::{
    deserialize_public_key, deserialize_secret_key, serialize_public_key, serialize_secret_key,
};

/// Error type for PEM/DER encoding operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemError {
    /// Invalid PEM format
    InvalidPemFormat,
    /// Invalid DER encoding
    InvalidDer,
    /// Decoding failed
    DecodeFailed,
    /// Feature not enabled
    FeatureNotEnabled,
}

impl core::fmt::Display for PemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PemError::InvalidPemFormat => write!(f, "Invalid PEM format"),
            PemError::InvalidDer => write!(f, "Invalid DER encoding"),
            PemError::DecodeFailed => write!(f, "Decoding failed"),
            PemError::FeatureNotEnabled => write!(f, "PEM feature not enabled"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PemError {}

/// PEM tag for ML-DSA public keys
const PEM_TAG_PUBLIC_KEY: &str = "ML-DSA PUBLIC KEY";

/// PEM tag for ML-DSA secret keys
const PEM_TAG_SECRET_KEY: &str = "ML-DSA PRIVATE KEY";

/// Encode a public key to PEM format
///
/// # Arguments
///
/// * `pk` - The public key to encode
///
/// # Returns
///
/// * `Ok(String)` - PEM-encoded public key
/// * `Err(PemError)` - If encoding fails
///
/// # Example
///
/// ```no_run
/// use mldsa::keygen::keygen;
/// use mldsa::params::MlDsa65;
/// use mldsa::pem_encoding::public_key_to_pem;
///
/// let (pk, _sk) = keygen::<MlDsa65>();
/// let pem_str = public_key_to_pem(&pk).unwrap();
/// println!("{}", pem_str);
/// ```
#[cfg(feature = "pem")]
pub fn public_key_to_pem<P: DsaParams>(pk: &PublicKey<P>) -> Result<String, PemError> {
    let der_bytes = serialize_public_key(pk);
    Ok(pem::encode_config(
        &pem::Pem::new(PEM_TAG_PUBLIC_KEY, der_bytes),
        pem::EncodeConfig::default(),
    ))
}

/// Encode a secret key to PEM format
///
/// # Arguments
///
/// * `sk` - The secret key to encode
///
/// # Returns
///
/// * `Ok(String)` - PEM-encoded secret key
/// * `Err(PemError)` - If encoding fails
///
/// # Security Warning
///
/// Secret keys contain sensitive cryptographic material. Ensure PEM-encoded
/// secret keys are stored securely and transmitted over encrypted channels only.
///
/// # Example
///
/// ```no_run
/// use mldsa::keygen::keygen;
/// use mldsa::params::MlDsa65;
/// use mldsa::pem_encoding::secret_key_to_pem;
///
/// let (_pk, sk) = keygen::<MlDsa65>();
/// let pem_str = secret_key_to_pem(&sk).unwrap();
/// // Store securely!
/// ```
#[cfg(feature = "pem")]
pub fn secret_key_to_pem<P: DsaParams>(sk: &SecretKey<P>) -> Result<String, PemError> {
    let der_bytes = serialize_secret_key(sk);
    Ok(pem::encode_config(
        &pem::Pem::new(PEM_TAG_SECRET_KEY, der_bytes),
        pem::EncodeConfig::default(),
    ))
}

/// Decode a public key from PEM format
///
/// # Arguments
///
/// * `pem_str` - PEM-encoded public key string
///
/// # Returns
///
/// * `Ok(PublicKey)` - Decoded public key
/// * `Err(PemError)` - If decoding fails
///
/// # Example
///
/// ```no_run
/// use mldsa::params::MlDsa65;
/// use mldsa::pem_encoding::public_key_from_pem;
///
/// let pem_str = "-----BEGIN ML-DSA PUBLIC KEY-----\n...\n-----END ML-DSA PUBLIC KEY-----";
/// let pk = public_key_from_pem::<MlDsa65>(pem_str).unwrap();
/// ```
#[cfg(feature = "pem")]
pub fn public_key_from_pem<P: DsaParams>(pem_str: &str) -> Result<PublicKey<P>, PemError> {
    let pem_contents = pem::parse(pem_str).map_err(|_| PemError::InvalidPemFormat)?;

    if pem_contents.tag() != PEM_TAG_PUBLIC_KEY {
        return Err(PemError::InvalidPemFormat);
    }

    deserialize_public_key(pem_contents.contents()).map_err(|_| PemError::DecodeFailed)
}

/// Decode a secret key from PEM format
///
/// # Arguments
///
/// * `pem_str` - PEM-encoded secret key string
///
/// # Returns
///
/// * `Ok(SecretKey)` - Decoded secret key
/// * `Err(PemError)` - If decoding fails
///
/// # Example
///
/// ```no_run
/// use mldsa::params::MlDsa65;
/// use mldsa::pem_encoding::secret_key_from_pem;
///
/// let pem_str = "-----BEGIN ML-DSA PRIVATE KEY-----\n...\n-----END ML-DSA PRIVATE KEY-----";
/// let sk = secret_key_from_pem::<MlDsa65>(pem_str).unwrap();
/// ```
#[cfg(feature = "pem")]
pub fn secret_key_from_pem<P: DsaParams>(pem_str: &str) -> Result<SecretKey<P>, PemError> {
    let pem_contents = pem::parse(pem_str).map_err(|_| PemError::InvalidPemFormat)?;

    if pem_contents.tag() != PEM_TAG_SECRET_KEY {
        return Err(PemError::InvalidPemFormat);
    }

    deserialize_secret_key(pem_contents.contents()).map_err(|_| PemError::DecodeFailed)
}

/// Encode a public key to DER format
///
/// This is simply the raw byte serialization, as ML-DSA uses a simple format.
///
/// # Arguments
///
/// * `pk` - The public key to encode
///
/// # Returns
///
/// DER-encoded public key bytes
#[cfg(feature = "pem")]
pub fn public_key_to_der<P: DsaParams>(pk: &PublicKey<P>) -> Vec<u8> {
    serialize_public_key(pk)
}

/// Encode a secret key to DER format
///
/// This is simply the raw byte serialization, as ML-DSA uses a simple format.
///
/// # Arguments
///
/// * `sk` - The secret key to encode
///
/// # Returns
///
/// DER-encoded secret key bytes
#[cfg(feature = "pem")]
pub fn secret_key_to_der<P: DsaParams>(sk: &SecretKey<P>) -> Vec<u8> {
    serialize_secret_key(sk)
}

/// Decode a public key from DER format
///
/// # Arguments
///
/// * `der_bytes` - DER-encoded public key bytes
///
/// # Returns
///
/// * `Ok(PublicKey)` - Decoded public key
/// * `Err(PemError)` - If decoding fails
#[cfg(feature = "pem")]
pub fn public_key_from_der<P: DsaParams>(der_bytes: &[u8]) -> Result<PublicKey<P>, PemError> {
    deserialize_public_key(der_bytes).map_err(|_| PemError::DecodeFailed)
}

/// Decode a secret key from DER format
///
/// # Arguments
///
/// * `der_bytes` - DER-encoded secret key bytes
///
/// # Returns
///
/// * `Ok(SecretKey)` - Decoded secret key
/// * `Err(PemError)` - If decoding fails
#[cfg(feature = "pem")]
pub fn secret_key_from_der<P: DsaParams>(der_bytes: &[u8]) -> Result<SecretKey<P>, PemError> {
    deserialize_secret_key(der_bytes).map_err(|_| PemError::DecodeFailed)
}

#[cfg(all(test, feature = "pem"))]
mod tests {
    use super::*;
    use crate::{MlDsa44, MlDsa65, MlDsa87};
    extern crate alloc;
    use crate::keygen::keygen_from_seed;
    use crate::params::MlDsa65;
    use alloc::vec;

    #[test]
    fn test_public_key_pem_roundtrip() {
        let seed = [0x42u8; 32];
        let (pk, _sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Encode to PEM
        let pem_str = public_key_to_pem(&pk).expect("Failed to encode to PEM");

        // Verify PEM format
        assert!(pem_str.contains("-----BEGIN ML-DSA PUBLIC KEY-----"));
        assert!(pem_str.contains("-----END ML-DSA PUBLIC KEY-----"));

        // Decode from PEM
        let pk_recovered =
            public_key_from_pem::<MlDsa65>(&pem_str).expect("Failed to decode from PEM");

        // Verify all fields match
        assert_eq!(pk.rho, pk_recovered.rho);
        assert_eq!(pk.tr, pk_recovered.tr);
        assert_eq!(pk.t1.len(), pk_recovered.t1.len());
        for (a, b) in pk.t1.iter().zip(pk_recovered.t1.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_secret_key_pem_roundtrip() {
        let seed = [0x42u8; 32];
        let (_pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Encode to PEM
        let pem_str = secret_key_to_pem(&sk).expect("Failed to encode to PEM");

        // Verify PEM format
        assert!(pem_str.contains("-----BEGIN ML-DSA PRIVATE KEY-----"));
        assert!(pem_str.contains("-----END ML-DSA PRIVATE KEY-----"));

        // Decode from PEM
        let sk_recovered =
            secret_key_from_pem::<MlDsa65>(&pem_str).expect("Failed to decode from PEM");

        // Verify all critical fields match
        assert_eq!(sk.rho, sk_recovered.rho);
        assert_eq!(sk.k, sk_recovered.k);
        assert_eq!(sk.tr, sk_recovered.tr);

        // Verify vectors have correct length
        assert_eq!(sk.s1.len(), sk_recovered.s1.len());
        assert_eq!(sk.s2.len(), sk_recovered.s2.len());
        assert_eq!(sk.t0.len(), sk_recovered.t0.len());

        // Verify that encoding again produces the same PEM
        let pem_str2 = secret_key_to_pem(&sk_recovered).expect("Failed to re-encode to PEM");
        assert_eq!(pem_str, pem_str2, "PEM encoding not stable");
    }

    #[test]
    fn test_public_key_der_roundtrip() {
        let seed = [0x42u8; 32];
        let (pk, _sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Encode to DER
        let der_bytes = public_key_to_der(&pk);

        // Decode from DER
        let pk_recovered =
            public_key_from_der::<MlDsa65>(&der_bytes).expect("Failed to decode from DER");

        // Verify all fields match
        assert_eq!(pk.rho, pk_recovered.rho);
        assert_eq!(pk.tr, pk_recovered.tr);
        assert_eq!(pk.t1.len(), pk_recovered.t1.len());
        for (a, b) in pk.t1.iter().zip(pk_recovered.t1.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_secret_key_der_roundtrip() {
        let seed = [0x42u8; 32];
        let (_pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Encode to DER
        let der_bytes = secret_key_to_der(&sk);

        // Decode from DER
        let sk_recovered =
            secret_key_from_der::<MlDsa65>(&der_bytes).expect("Failed to decode from DER");

        // Verify all fields match
        assert_eq!(sk.rho, sk_recovered.rho);
        assert_eq!(sk.k, sk_recovered.k);
        assert_eq!(sk.tr, sk_recovered.tr);
    }

    #[test]
    fn test_invalid_pem_format() {
        let invalid_pem = "-----BEGIN INVALID KEY-----\nZm9vYmFy\n-----END INVALID KEY-----";
        let result = public_key_from_pem::<MlDsa65>(invalid_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_der_data() {
        let invalid_der = vec![0u8; 100]; // Too short
        let result = public_key_from_der::<MlDsa65>(&invalid_der);
        assert!(result.is_err());
    }
}
