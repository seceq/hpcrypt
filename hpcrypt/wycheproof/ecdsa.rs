//! Wycheproof test vectors for ECDSA (P-256, secp256k1, P-384, P-521)

use super::{decode_hex, load_test_vectors, TestResult, WycheproofTestFile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaTestGroup {
    pub key: EcdsaPublicKey,
    pub key_der: String,
    pub key_pem: String,
    pub sha: String,
    #[serde(rename = "type")]
    pub test_type: String,
    pub tests: Vec<EcdsaTest>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaPublicKey {
    pub curve: String,
    pub key_size: usize,
    #[serde(rename = "type")]
    pub key_type: String,
    pub uncompressed: String,
    pub wx: String,
    pub wy: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaTest {
    pub tc_id: u32,
    pub comment: String,
    pub msg: String,
    pub sig: String,
    pub result: TestResult,
    pub flags: Option<Vec<String>>,
}

pub type EcdsaTestFile = WycheproofTestFile<EcdsaTestGroup>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_secp256k1_wycheproof() {
        // Placeholder - will be implemented with actual vectors
        let test_data = r#"{
  "algorithm": "ECDSA",
  "generatorVersion": "0.9",
  "numberOfTests": 0,
  "testGroups": []
}"#;

        let _vectors: EcdsaTestFile = load_test_vectors(test_data).unwrap();
        // Tests will be added once we have actual test vectors
    }

    #[test]
    fn test_ecdsa_p256_wycheproof() {
        // P-256 ECDSA tests
        let test_data = r#"{
  "algorithm": "ECDSA",
  "generatorVersion": "0.9",
  "numberOfTests": 0,
  "testGroups": []
}"#;

        let _vectors: EcdsaTestFile = load_test_vectors(test_data).unwrap();
    }
}
