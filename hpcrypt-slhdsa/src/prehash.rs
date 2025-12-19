//! Prehash mode support for SLH-DSA (FIPS 205 Section 5.3)
//!
//! This module implements the prehash variant of SLH-DSA, which allows signing
//! a hash digest instead of the full message. The prehash mode uses domain
//! separator 0x01 and includes the hash function OID.

use hpcrypt_hash::{HashFunction, XofFunction};
use hpcrypt_hash::{Sha256, Sha384, Sha512, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

/// Hash algorithm OIDs per NIST SP 800-208 and FIPS 205 Appendix C
///
/// Note: SHA2-224, SHA2-512/224, and SHA2-512/256 are not currently supported
/// by hpcrypt-hash and are commented out. These are rarely used in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashOid {
    // Sha2_224,  // Not available in hpcrypt-hash
    Sha2_256,
    Sha2_384,
    Sha2_512,
    // Sha2_512_224,  // Not available in hpcrypt-hash
    // Sha2_512_256,  // Not available in hpcrypt-hash
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
}

impl HashOid {
    /// Parse hash algorithm name to OID
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            // "SHA2-224" => Some(HashOid::Sha2_224),  // Not available
            "SHA2-256" => Some(HashOid::Sha2_256),
            "SHA2-384" => Some(HashOid::Sha2_384),
            "SHA2-512" => Some(HashOid::Sha2_512),
            // "SHA2-512/224" => Some(HashOid::Sha2_512_224),  // Not available
            // "SHA2-512/256" => Some(HashOid::Sha2_512_256),  // Not available
            "SHA3-224" => Some(HashOid::Sha3_224),
            "SHA3-256" => Some(HashOid::Sha3_256),
            "SHA3-384" => Some(HashOid::Sha3_384),
            "SHA3-512" => Some(HashOid::Sha3_512),
            "SHAKE-128" => Some(HashOid::Shake128),
            "SHAKE-256" => Some(HashOid::Shake256),
            _ => None,
        }
    }

    /// Get the DER-encoded OID bytes for this hash algorithm
    /// Per NIST SP 800-208 Table 1 and FIPS 205 Appendix C
    pub fn der_encoding(&self) -> &'static [u8] {
        match self {
            // SHA-2 family (NIST FIPS 180-4)
            HashOid::Sha2_256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            HashOid::Sha2_384 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            HashOid::Sha2_512 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],

            // SHA-3 family (NIST FIPS 202)
            HashOid::Sha3_224 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
            HashOid::Sha3_256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            HashOid::Sha3_384 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            HashOid::Sha3_512 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],

            // SHAKE family (NIST FIPS 202) - using 256-bit output
            HashOid::Shake128 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b],
            HashOid::Shake256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c],
        }
    }

    /// Get the output length in bytes for this hash algorithm
    /// For XOFs (SHAKE), returns 256 bits (32 bytes) as specified in FIPS 205
    pub fn output_len(&self) -> usize {
        match self {
            HashOid::Sha3_224 => 28,
            HashOid::Sha2_256 | HashOid::Sha3_256 | HashOid::Shake128 | HashOid::Shake256 => 32,
            HashOid::Sha2_384 | HashOid::Sha3_384 => 48,
            HashOid::Sha2_512 | HashOid::Sha3_512 => 64,
        }
    }
}

/// Compute prehash of a message using the specified hash algorithm
///
/// # Parameters
/// - `hash_alg`: Name of the hash algorithm (e.g., "SHA2-256", "SHAKE-128")
/// - `message`: The message to hash
///
/// # Returns
/// The hash digest as a byte vector
pub fn compute_prehash(hash_alg: &str, message: &[u8]) -> Result<Vec<u8>, &'static str> {
    let oid = HashOid::from_name(hash_alg).ok_or("Unknown hash algorithm")?;

    let digest = match oid {
        HashOid::Sha2_256 => {
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashOid::Sha2_384 => {
            let mut hasher = Sha384::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashOid::Sha2_512 => {
            let mut hasher = Sha512::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashOid::Sha3_224 => {
            let mut hasher = Sha3_224::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashOid::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashOid::Sha3_384 => {
            let mut hasher = Sha3_384::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashOid::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashOid::Shake128 => {
            let mut hasher = Shake128::new();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            let mut output = vec![0u8; 32]; // 256 bits per FIPS 205
            reader.read(&mut output);
            output
        }
        HashOid::Shake256 => {
            let mut hasher = Shake256::new();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            let mut output = vec![0u8; 32]; // 256 bits per FIPS 205
            reader.read(&mut output);
            output
        }
    };

    Ok(digest)
}

/// Build the prehash message: OID || PH(M)
///
/// # Parameters
/// - `hash_alg`: Name of the hash algorithm
/// - `message`: The message to prehash
///
/// # Returns
/// OID || PH(M) where OID is the DER-encoded hash function identifier
/// and PH(M) is the hash digest of the message
pub fn build_prehash_message(hash_alg: &str, message: &[u8]) -> Result<Vec<u8>, &'static str> {
    let oid = HashOid::from_name(hash_alg).ok_or("Unknown hash algorithm")?;
    let digest = compute_prehash(hash_alg, message)?;

    // Build OID || PH(M)
    let mut prehash_msg = Vec::with_capacity(oid.der_encoding().len() + digest.len());
    prehash_msg.extend_from_slice(oid.der_encoding());
    prehash_msg.extend_from_slice(&digest);

    Ok(prehash_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_oid_parsing() {
        assert_eq!(HashOid::from_name("SHA2-256"), Some(HashOid::Sha2_256));
        assert_eq!(HashOid::from_name("SHAKE-128"), Some(HashOid::Shake128));
        assert_eq!(HashOid::from_name("invalid"), None);
    }

    #[test]
    fn test_oid_encoding() {
        // SHA2-256 OID: 2.16.840.1.101.3.4.2.1
        let oid = HashOid::Sha2_256.der_encoding();
        assert_eq!(oid[0], 0x06); // OID tag
        assert_eq!(oid[1], 0x09); // Length = 9 bytes
        assert_eq!(&oid[2..], &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    }

    #[test]
    fn test_compute_prehash_sha256() {
        let message = b"test message";
        let digest = compute_prehash("SHA2-256", message).unwrap();
        assert_eq!(digest.len(), 32);

        // Verify against known SHA-256 hash
        use hpcrypt_hash::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(message);
        let expected = hasher.finalize();
        assert_eq!(digest, &expected[..]);
    }

    #[test]
    fn test_build_prehash_message() {
        let message = b"test";
        let prehash_msg = build_prehash_message("SHA2-256", message).unwrap();

        // Should be OID (11 bytes) + digest (32 bytes) = 43 bytes
        assert_eq!(prehash_msg.len(), 11 + 32);

        // First byte should be OID tag
        assert_eq!(prehash_msg[0], 0x06);
    }
}
