//! Common utilities for NIST CAVP/ACVP test vector parsing

use serde::Deserialize;
use std::path::PathBuf;

/// Base path to CAVP test vectors (ACVP-Server gen-val/json-files)
pub fn test_vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("cavp-vectors/gen-val/json-files")
}

/// Load a CAVP test file
pub fn load_test_file<T>(algorithm_dir: &str, filename: &str) -> T
where
    T: for<'de> Deserialize<'de>,
{
    let path = test_vectors_path().join(algorithm_dir).join(filename);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
}

/// Helper to decode hex strings
pub fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("Invalid hex string '{}': {}", s, e))
}

/// Test statistics helper for tracking test results
pub struct TestStats {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl TestStats {
    /// Create new test statistics
    pub fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
        }
    }

    /// Print test summary
    pub fn print_summary(&self) {
        println!("\n--- Test Results ---");
        println!("✓ Passed:  {}", self.passed);
        println!("✗ Failed:  {}", self.failed);
        println!("⊘ Skipped: {}", self.skipped);
        println!("Total:     {}", self.passed + self.failed + self.skipped);
    }
}

impl Default for TestStats {
    fn default() -> Self {
        Self::new()
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
            "CAVP test vectors not found at: {}",
            path.display()
        );
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex(""), Vec::<u8>::new());
        assert_eq!(decode_hex("00"), vec![0u8]);
        assert_eq!(decode_hex("DEADBEEF"), vec![0xdeu8, 0xad, 0xbe, 0xef]);
    }
}
