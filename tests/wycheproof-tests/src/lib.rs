//! Common utilities for Wycheproof test vector parsing

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Base path to Wycheproof test vectors
pub fn test_vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("wycheproof/testvectors_v1")
}

/// Load a Wycheproof test file
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

/// Common test group structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup<T> {
    #[serde(rename = "type")]
    pub test_type: Option<String>,
    pub key_size: Option<usize>,
    pub tag_size: Option<usize>,
    pub tests: Vec<T>,
}

/// Top-level test file structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestFile<T> {
    pub algorithm: String,
    pub generator_version: String,
    pub number_of_tests: usize,
    pub header: Option<Vec<String>>,
    pub notes: Option<serde_json::Value>,
    pub schema: Option<String>,
    pub test_groups: Vec<TestGroup<T>>,
}

/// Test result expectation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

impl TestResult {
    /// Should this test case pass verification?
    pub fn should_pass(self) -> bool {
        matches!(self, TestResult::Valid | TestResult::Acceptable)
    }

    /// Should this test case fail verification?
    pub fn should_fail(self) -> bool {
        matches!(self, TestResult::Invalid)
    }
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
            "Wycheproof test vectors not found at: {}",
            path.display()
        );
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex(""), Vec::<u8>::new());
        assert_eq!(decode_hex("00"), vec![0u8]);
        assert_eq!(decode_hex("deadbeef"), vec![0xdeu8, 0xad, 0xbe, 0xef]);
    }
}
