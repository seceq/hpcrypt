//! Common utilities for RFC test vector parsing

use serde::Deserialize;
use std::path::PathBuf;

/// Base path to RFC test vectors
pub fn test_vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("rfc-vectors")
}

/// Load an RFC test file
pub fn load_test_file<T>(filename: &str) -> T
where
    T: for<'de> Deserialize<'de>,
{
    let path = test_vectors_path().join(filename);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
}

/// Helper to decode hex strings
pub fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("Invalid hex string '{}': {}", s, e))
}

/// Helper to encode bytes as hex
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Test statistics helper for tracking test results
#[derive(Debug, Default)]
pub struct TestStats {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl TestStats {
    /// Create new test statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Print test summary
    pub fn print_summary(&self) {
        println!("\n--- Test Results ---");
        println!("Passed:  {}", self.passed);
        println!("Failed:  {}", self.failed);
        println!("Skipped: {}", self.skipped);
        println!("Total:     {}", self.passed + self.failed + self.skipped);

        let total = self.passed + self.failed + self.skipped;
        if total > 0 {
            let pass_rate = (self.passed as f64 / total as f64) * 100.0;
            println!("Pass rate: {:.2}%", pass_rate);
        }
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectors_path_exists() {
        let path = test_vectors_path();
        assert!(
            path.exists(),
            "RFC test vectors not found at: {}",
            path.display()
        );
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex(""), Vec::<u8>::new());
        assert_eq!(decode_hex("00"), vec![0u8]);
        assert_eq!(decode_hex("deadbeef"), vec![0xdeu8, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_encode_hex() {
        assert_eq!(encode_hex(&[]), "");
        assert_eq!(encode_hex(&[0u8]), "00");
        assert_eq!(encode_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
