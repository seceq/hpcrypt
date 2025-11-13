//! NIST Known Answer Test (KAT) validation for ML-DSA
//!
//! This module provides functionality to parse and validate against
//! NIST FIPS 204 Known Answer Test vectors.
//!
//! KAT files are in `.rsp` format with fields:
//! - count: Test number
//! - xi: Keygen seed
//! - seed: DRBG seed
//! - pk: Public key (hex)
//! - sk: Secret key (hex)
//! - msg: Message to sign (hex)
//! - mlen: Message length
//! - sm: Signature concatenated with message (hex)
//! - smlen: Signature + message length
//! - ctx: Context string (16 bytes, hex)

use alloc::vec::Vec;
use core::str::FromStr;

extern crate alloc;

/// KAT test vector entry
#[derive(Debug, Clone)]
pub struct KatVector {
    /// Test number
    pub count: usize,
    /// Keygen seed (xi)
    pub xi: Vec<u8>,
    /// DRBG seed (for reproducibility)
    pub seed: Vec<u8>,
    /// Public key
    pub pk: Vec<u8>,
    /// Secret key
    pub sk: Vec<u8>,
    /// Message to sign
    pub msg: Vec<u8>,
    /// Message length
    pub mlen: usize,
    /// Signature concatenated with message
    pub sm: Vec<u8>,
    /// Signature + message length
    pub smlen: usize,
    /// Context string (16 bytes)
    pub ctx: Vec<u8>,
}

impl KatVector {
    /// Create a new KAT vector
    pub fn new() -> Self {
        Self {
            count: 0,
            xi: Vec::new(),
            seed: Vec::new(),
            pk: Vec::new(),
            sk: Vec::new(),
            msg: Vec::new(),
            mlen: 0,
            sm: Vec::new(),
            smlen: 0,
            ctx: Vec::new(),
        }
    }

    /// Extract signature from sm (sm = signature || message)
    pub fn signature(&self) -> Vec<u8> {
        let sig_len = self.smlen - self.mlen;
        self.sm[..sig_len].to_vec()
    }

    /// Extract message from sm (for verification)
    pub fn message_from_sm(&self) -> Vec<u8> {
        let sig_len = self.smlen - self.mlen;
        self.sm[sig_len..].to_vec()
    }
}

impl Default for KatVector {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a hex string to bytes
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(Vec::new());
    }

    if hex.len() % 2 != 0 {
        return Err("Hex string has odd length");
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|_| "Invalid hex character")?;
        bytes.push(byte);
    }

    Ok(bytes)
}

/// Parse a KAT .rsp file into a vector of test cases
pub fn parse_kat_file(content: &str) -> Result<Vec<KatVector>, &'static str> {
    let mut vectors = Vec::new();
    let mut current = KatVector::new();
    let mut in_vector = false;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse key = value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();

            match key {
                "count" => {
                    // Start of new vector
                    if in_vector {
                        vectors.push(current.clone());
                    }
                    current = KatVector::new();
                    current.count = usize::from_str(value).map_err(|_| "Invalid count")?;
                    in_vector = true;
                }
                "xi" => {
                    current.xi = parse_hex(value)?;
                }
                "seed" => {
                    current.seed = parse_hex(value)?;
                }
                "pk" => {
                    current.pk = parse_hex(value)?;
                }
                "sk" => {
                    current.sk = parse_hex(value)?;
                }
                "msg" => {
                    current.msg = parse_hex(value)?;
                }
                "mlen" => {
                    current.mlen = usize::from_str(value).map_err(|_| "Invalid mlen")?;
                }
                "sm" => {
                    current.sm = parse_hex(value)?;
                }
                "smlen" => {
                    current.smlen = usize::from_str(value).map_err(|_| "Invalid smlen")?;
                }
                "ctx" => {
                    current.ctx = parse_hex(value)?;
                }
                _ => {
                    // Unknown field, skip
                }
            }
        }
    }

    // Add the last vector
    if in_vector {
        vectors.push(current);
    }

    Ok(vectors)
}

mod tests {

    #[test]
    fn test_parse_hex() {
        let result = parse_hex("deadbeef");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_hex_empty() {
        let result = parse_hex("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_parse_hex_odd_length() {
        let result = parse_hex("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_kat_sample() {
        let sample = r#"
count = 0
xi = f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68
msg = 6dbbc4375136df3b07f7c70e639e223e
mlen = 16
ctx = 480c658c0cb3e040bde084345cef0df7

count = 1
xi = 6de62e3465a55c9c78a07d265be8540b3e58b0801a124d07ff12b438d5202ea0
msg = abcd
mlen = 2
ctx = 480c658c0cb3e040bde084345cef0df7
"#;

        let result = parse_kat_file(sample);
        assert!(result.is_ok());
        let vectors = result.unwrap();
        assert_eq!(vectors.len(), 2);

        assert_eq!(vectors[0].count, 0);
        assert_eq!(vectors[0].mlen, 16);
        assert_eq!(vectors[0].msg.len(), 16);

        assert_eq!(vectors[1].count, 1);
        assert_eq!(vectors[1].mlen, 2);
        assert_eq!(vectors[1].msg, vec![0xab, 0xcd]);
    }

    // NOTE: Comprehensive KAT validation is now in tests/test_nist_kat_vectors.rs
    // which uses 100 official NIST test vectors. Old tests that looked for files
    // in /tmp/ml-dsa-kat/ have been removed as obsolete.
}
