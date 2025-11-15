//! HKDF - HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)

#![allow(clippy::manual_div_ceil)] // MSRV 1.70 compatibility - div_ceil stabilized in 1.73

extern crate alloc;
use alloc::vec::Vec;

use hpcrypt_mac::{HmacBlake2b, HmacSha256, HmacSha384, HmacSha512};

/// HKDF using SHA-256
pub struct HkdfSha256 {
    prk: Vec<u8>,
}

impl HkdfSha256 {
    /// Perform the HKDF-Extract step and return a pseudorandom key.
    ///
    /// This is the first step of the HKDF process as defined in RFC 5869.
    /// It extracts a fixed-length pseudorandom key from the input keying material.
    /// If salt is empty, a string of zeros equal to the hash output length is used.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let zero_salt = [0u8; 32];
        let salt_key = if salt.is_empty() { &zero_salt } else { salt };

        let prk = HmacSha256::new(salt_key).compute(ikm);
        let mut result = [0u8; 32];
        result.copy_from_slice(&prk);
        result
    }

    /// Create an HKDF instance from a pre-computed pseudorandom key.
    ///
    /// This allows reusing the same PRK for multiple expand operations,
    /// which is useful in protocols like TLS 1.3 where the same PRK
    /// needs to derive multiple keys.
    pub fn from_prk(prk: &[u8]) -> Self {
        Self {
            prk: prk.to_vec(),
        }
    }

    /// Create a new HKDF instance from input keying material
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let prk = Self::extract(salt, ikm);
        Self::from_prk(&prk)
    }

    /// Expand the PRK to derive output keying material
    pub fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
        let hash_len = 32;
        let n = (output.len() + hash_len - 1) / hash_len;

        if n > 255 {
            return Err("HKDF output too long");
        }

        let mut t = Vec::new();
        let mut offset = 0;

        for i in 1..=n {
            let mut data = Vec::new();
            data.extend_from_slice(&t);
            data.extend_from_slice(info);
            data.push(i as u8);

            let hmac = HmacSha256::new(&self.prk);
            t = hmac.compute(&data).to_vec();

            let to_copy = core::cmp::min(hash_len, output.len() - offset);
            output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
        }

        Ok(())
    }
}

/// HKDF using SHA-384
pub struct HkdfSha384 {
    prk: Vec<u8>,
}

impl HkdfSha384 {
    /// Perform the HKDF-Extract step and return a pseudorandom key.
    ///
    /// This is the first step of the HKDF process as defined in RFC 5869.
    /// It extracts a fixed-length pseudorandom key from the input keying material.
    /// If salt is empty, a string of zeros equal to the hash output length is used.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
        let zero_salt = [0u8; 48];
        let salt_key = if salt.is_empty() { &zero_salt } else { salt };

        let prk = HmacSha384::new(salt_key).compute(ikm);
        let mut result = [0u8; 48];
        result.copy_from_slice(&prk);
        result
    }

    /// Create an HKDF instance from a pre-computed pseudorandom key.
    ///
    /// This allows reusing the same PRK for multiple expand operations,
    /// which is useful in protocols like TLS 1.3 where the same PRK
    /// needs to derive multiple keys.
    pub fn from_prk(prk: &[u8]) -> Self {
        Self {
            prk: prk.to_vec(),
        }
    }

    /// Create a new HKDF instance from input keying material
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let prk = Self::extract(salt, ikm);
        Self::from_prk(&prk)
    }

    /// Expand the PRK to derive output keying material
    pub fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
        let hash_len = 48; // SHA-384 produces 48 bytes
        let n = (output.len() + hash_len - 1) / hash_len;

        if n > 255 {
            return Err("HKDF output too long");
        }

        let mut t = Vec::new();
        let mut offset = 0;

        for i in 1..=n {
            let mut data = Vec::new();
            data.extend_from_slice(&t);
            data.extend_from_slice(info);
            data.push(i as u8);

            let hmac = HmacSha384::new(&self.prk);
            t = hmac.compute(&data).to_vec();

            let to_copy = core::cmp::min(hash_len, output.len() - offset);
            output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
        }

        Ok(())
    }
}

/// HKDF using SHA-512
pub struct HkdfSha512 {
    prk: Vec<u8>,
}

impl HkdfSha512 {
    /// Perform the HKDF-Extract step and return a pseudorandom key.
    ///
    /// This is the first step of the HKDF process as defined in RFC 5869.
    /// It extracts a fixed-length pseudorandom key from the input keying material.
    /// If salt is empty, a string of zeros equal to the hash output length is used.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
        let zero_salt = [0u8; 64];
        let salt_key = if salt.is_empty() { &zero_salt } else { salt };

        let prk = HmacSha512::new(salt_key).compute(ikm);
        let mut result = [0u8; 64];
        result.copy_from_slice(&prk);
        result
    }

    /// Create an HKDF instance from a pre-computed pseudorandom key.
    ///
    /// This allows reusing the same PRK for multiple expand operations,
    /// which is useful in protocols like TLS 1.3 where the same PRK
    /// needs to derive multiple keys.
    pub fn from_prk(prk: &[u8]) -> Self {
        Self {
            prk: prk.to_vec(),
        }
    }

    /// Create a new HKDF instance from input keying material
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let prk = Self::extract(salt, ikm);
        Self::from_prk(&prk)
    }

    /// Expand the PRK to derive output keying material
    pub fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
        let hash_len = 64;
        let n = (output.len() + hash_len - 1) / hash_len;

        if n > 255 {
            return Err("HKDF output too long");
        }

        let mut t = Vec::new();
        let mut offset = 0;

        for i in 1..=n {
            let mut data = Vec::new();
            data.extend_from_slice(&t);
            data.extend_from_slice(info);
            data.push(i as u8);

            let hmac = HmacSha512::new(&self.prk);
            t = hmac.compute(&data).to_vec();

            let to_copy = core::cmp::min(hash_len, output.len() - offset);
            output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
        }

        Ok(())
    }
}

/// HKDF using BLAKE2b
pub struct HkdfBlake2b {
    prk: Vec<u8>,
}

impl HkdfBlake2b {
    /// Perform the HKDF-Extract step and return a pseudorandom key.
    ///
    /// This is the first step of the HKDF process as defined in RFC 5869.
    /// It extracts a fixed-length pseudorandom key from the input keying material.
    /// If salt is empty, a string of zeros equal to the hash output length is used.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
        let zero_salt = [0u8; 64];
        let salt_key = if salt.is_empty() { &zero_salt } else { salt };

        let prk = HmacBlake2b::new(salt_key).compute(ikm);
        let mut result = [0u8; 64];
        result.copy_from_slice(&prk);
        result
    }

    /// Create an HKDF instance from a pre-computed pseudorandom key.
    ///
    /// This allows reusing the same PRK for multiple expand operations,
    /// which is useful in protocols like TLS 1.3 where the same PRK
    /// needs to derive multiple keys.
    pub fn from_prk(prk: &[u8]) -> Self {
        Self {
            prk: prk.to_vec(),
        }
    }

    /// Create a new HKDF instance from input keying material
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let prk = Self::extract(salt, ikm);
        Self::from_prk(&prk)
    }

    /// Expand the PRK to derive output keying material
    pub fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
        let hash_len = 64;
        let n = (output.len() + hash_len - 1) / hash_len;

        if n > 255 {
            return Err("HKDF output too long");
        }

        let mut t = Vec::new();
        let mut offset = 0;

        for i in 1..=n {
            let mut data = Vec::new();
            data.extend_from_slice(&t);
            data.extend_from_slice(info);
            data.push(i as u8);

            let hmac = HmacBlake2b::new(&self.prk);
            t = hmac.compute(&data).to_vec();

            let to_copy = core::cmp::min(hash_len, output.len() - offset);
            output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
        }

        Ok(())
    }
}

/// HKDF with SHA-256 (convenience function)
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) {
    // Extract - PRK = HMAC-Hash(salt, IKM)
    // If salt is not provided, it is set to a string of HashLen zeros
    let zero_salt = [0u8; 32];
    let salt_key = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let prk = HmacSha256::new(salt_key).compute(ikm);

    // Expand
    let hash_len = 32;
    let n = (output.len() + hash_len - 1) / hash_len;

    if n > 255 {
        panic!("HKDF output too long");
    }

    let mut t = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i as u8);

        let hmac = HmacSha256::new(&prk);
        t = hmac.compute(&data).to_vec();

        let to_copy = core::cmp::min(hash_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;
    }
}

/// HKDF with SHA-384 (convenience function)
pub fn hkdf_sha384(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) {
    // Extract - PRK = HMAC-Hash(salt, IKM)
    let zero_salt = [0u8; 48];
    let salt_key = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let prk = HmacSha384::new(salt_key).compute(ikm);

    // Expand
    let hash_len = 48;
    let n = (output.len() + hash_len - 1) / hash_len;

    if n > 255 {
        panic!("HKDF output too long");
    }

    let mut t = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i as u8);

        let hmac = HmacSha384::new(&prk);
        t = hmac.compute(&data).to_vec();

        let to_copy = core::cmp::min(hash_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;
    }
}

/// HKDF with SHA-512 (convenience function)
pub fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) {
    // Extract - PRK = HMAC-Hash(salt, IKM)
    let zero_salt = [0u8; 64];
    let salt_key = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let prk = HmacSha512::new(salt_key).compute(ikm);

    // Expand
    let hash_len = 64;
    let n = (output.len() + hash_len - 1) / hash_len;

    if n > 255 {
        panic!("HKDF output too long");
    }

    let mut t = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i as u8);

        let hmac = HmacSha512::new(&prk);
        t = hmac.compute(&data).to_vec();

        let to_copy = core::cmp::min(hash_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;
    }
}

/// HKDF with BLAKE2b (convenience function)
pub fn hkdf_blake2b(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) {
    // Extract - PRK = HMAC-Hash(salt, IKM)
    let zero_salt = [0u8; 64];
    let salt_key = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let prk = HmacBlake2b::new(salt_key).compute(ikm);

    // Expand
    let hash_len = 64;
    let n = (output.len() + hash_len - 1) / hash_len;

    if n > 255 {
        panic!("HKDF output too long");
    }

    let mut t = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i as u8);

        let hmac = HmacBlake2b::new(&prk);
        t = hmac.compute(&data).to_vec();

        let to_copy = core::cmp::min(hash_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_rfc5869() {
        // RFC 5869 Test Case 1
        let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_literal::hex!("000102030405060708090a0b0c");
        let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

        let mut okm = [0u8; 42];
        hkdf_sha256(&salt, &ikm, &info, &mut okm);

        let expected = hex_literal::hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        assert_eq!(okm, expected);
    }

    #[test]
    fn test_hkdf_sha256_long_inputs() {
        // RFC 5869 Test Case 2 - SHA-256 with longer inputs
        let ikm = hex_literal::hex!(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f"
        );
        let salt = hex_literal::hex!(
            "606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        );
        let info = hex_literal::hex!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );

        let mut okm = [0u8; 82];
        hkdf_sha256(&salt, &ikm, &info, &mut okm);

        let expected = hex_literal::hex!(
            "b11e398dc80327a1c8e7f78c596a4934\
             4f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09\
             da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f\
             1d87"
        );

        assert_eq!(okm, expected);
    }

    #[test]
    fn test_hkdf_sha384_basic() {
        let ikm = b"input keying material";
        let salt = b"salt";
        let info = b"info";

        let mut okm = [0u8; 48];
        hkdf_sha384(salt, ikm, info, &mut okm);

        // Just verify it produces output without panicking
        assert_ne!(okm, [0u8; 48]);
    }

    #[test]
    fn test_hkdf_sha512_basic() {
        let ikm = b"input keying material";
        let salt = b"salt";
        let info = b"info";

        let mut okm = [0u8; 64];
        hkdf_sha512(salt, ikm, info, &mut okm);

        // Just verify it produces output without panicking
        assert_ne!(okm, [0u8; 64]);
    }

    #[test]
    fn test_extract_sha256() {
        let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_literal::hex!("000102030405060708090a0b0c");

        let prk = HkdfSha256::extract(&salt, &ikm);

        let expected_prk = hex_literal::hex!(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        assert_eq!(prk, expected_prk);
    }

    #[test]
    fn test_from_prk_sha256() {
        let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_literal::hex!("000102030405060708090a0b0c");
        let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

        let prk = HkdfSha256::extract(&salt, &ikm);
        let hkdf = HkdfSha256::from_prk(&prk);

        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();

        let expected = hex_literal::hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        assert_eq!(okm, expected);
    }

    #[test]
    fn test_new_equals_extract_from_prk() {
        let ikm = b"test input keying material";
        let salt = b"test salt";
        let info = b"test info";

        let hkdf1 = HkdfSha256::new(salt, ikm);
        let prk = HkdfSha256::extract(salt, ikm);
        let hkdf2 = HkdfSha256::from_prk(&prk);

        let mut okm1 = [0u8; 42];
        let mut okm2 = [0u8; 42];

        hkdf1.expand(info, &mut okm1).unwrap();
        hkdf2.expand(info, &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_prk_reuse() {
        let ikm = b"input keying material";
        let salt = b"salt";
        let info1 = b"context 1";
        let info2 = b"context 2";

        let prk = HkdfSha256::extract(salt, ikm);
        let hkdf = HkdfSha256::from_prk(&prk);

        let mut okm1 = [0u8; 32];
        let mut okm2 = [0u8; 32];

        hkdf.expand(info1, &mut okm1).unwrap();
        hkdf.expand(info2, &mut okm2).unwrap();

        assert_ne!(okm1, okm2);
        assert_ne!(okm1, [0u8; 32]);
        assert_ne!(okm2, [0u8; 32]);
    }

    #[test]
    fn test_extract_empty_salt() {
        let ikm = b"test input";
        let empty_salt: &[u8] = &[];

        let prk = HkdfSha256::extract(empty_salt, ikm);

        assert_eq!(prk.len(), 32);
        assert_ne!(prk, [0u8; 32]);
    }

    #[test]
    fn test_prk_sizes() {
        let ikm = b"test";
        let salt = b"salt";

        let prk256 = HkdfSha256::extract(salt, ikm);
        let prk384 = HkdfSha384::extract(salt, ikm);
        let prk512 = HkdfSha512::extract(salt, ikm);
        let prk_blake2b = HkdfBlake2b::extract(salt, ikm);

        assert_eq!(prk256.len(), 32);
        assert_eq!(prk384.len(), 48);
        assert_eq!(prk512.len(), 64);
        assert_eq!(prk_blake2b.len(), 64);
    }
}
