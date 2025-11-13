//! Wycheproof Test Vectors Integration
//!
//! This module integrates Google's Wycheproof test vectors to ensure
//! cryptographic implementations are correct and resistant to known attacks.
//!
//! Wycheproof is a collection of unit tests that use test vectors to check
//! cryptographic libraries against known attacks.

pub mod aes_gcm;
pub mod chacha20_poly1305;
pub mod ecdsa;
pub mod eddsa;
pub mod rsa_oaep;
pub mod x25519;

use serde::{Deserialize, Serialize};

/// Common test group structure for Wycheproof vectors
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup<T> {
    #[serde(rename = "type")]
    pub test_type: Option<String>,
    pub key_size: Option<usize>,
    pub iv_size: Option<usize>,
    pub tag_size: Option<usize>,
    pub tests: Vec<T>,
}

/// Common test case structure
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    pub tc_id: u32,
    pub comment: String,
    pub result: TestResult,
    pub flags: Option<Vec<String>>,
}

/// Test result expectation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

/// Root structure for Wycheproof test files
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WycheproofTestFile<G> {
    pub algorithm: String,
    pub generator_version: String,
    pub number_of_tests: u32,
    pub test_groups: Vec<G>,
}

/// Helper to load and parse Wycheproof JSON test vectors
pub fn load_test_vectors<T>(json_data: &str) -> Result<T, serde_json::Error>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(json_data)
}

/// Helper to decode hex strings
pub fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}
