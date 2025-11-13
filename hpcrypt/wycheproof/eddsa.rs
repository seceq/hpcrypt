//! Wycheproof test vectors for EdDSA (Ed25519, Ed448)

use super::{decode_hex, load_test_vectors, TestResult, WycheproofTestFile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaTestGroup {
    pub key: EddsaPublicKey,
    #[serde(rename = "type")]
    pub test_type: String,
    pub tests: Vec<EddsaTest>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaPublicKey {
    pub curve: String,
    pub key_size: usize,
    pub pk: String,
    #[serde(rename = "type")]
    pub key_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaTest {
    pub tc_id: u32,
    pub comment: String,
    pub msg: String,
    pub sig: String,
    pub result: TestResult,
    pub flags: Option<Vec<String>>,
}

pub type EddsaTestFile = WycheproofTestFile<EddsaTestGroup>;

#[cfg(test)]
mod tests {
    use super::*;
    use hpcrypt::signatures::Ed25519;

    #[test]
    fn test_ed25519_wycheproof() {
        let test_data = r#"{
  "algorithm": "EDDSA",
  "generatorVersion": "0.9",
  "numberOfTests": 1,
  "testGroups": [
    {
      "key": {
        "curve": "edwards25519",
        "keySize": 255,
        "pk": "7d4d0e7f6153a69b62b62b0bcc5832d76aef6cb96c24d7ae01e1961ec68c7fff",
        "type": "EDDSAPublicKey"
      },
      "type": "EddsaVerify",
      "tests": [
        {
          "tcId": 1,
          "comment": "small order point",
          "msg": "",
          "sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "result": "invalid",
          "flags": ["SmallPublicKey"]
        }
      ]
    }
  ]
}"#;

        let vectors: EddsaTestFile = load_test_vectors(test_data).unwrap();

        for group in &vectors.test_groups {
            let public_key_bytes = decode_hex(&group.key.pk).unwrap();

            if public_key_bytes.len() != 32 {
                continue;
            }

            let mut pk_array = [0u8; 32];
            pk_array.copy_from_slice(&public_key_bytes);

            for test in &group.tests {
                let message = decode_hex(&test.msg).unwrap();
                let signature = decode_hex(&test.sig).unwrap();

                if signature.len() != 64 {
                    continue;
                }

                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&signature);

                let verify_result = Ed25519::verify(&pk_array, &message, &sig_array);

                match test.result {
                    TestResult::Valid => {
                        assert!(verify_result.is_ok(), "Test {} should pass: {}", test.tc_id, test.comment);
                    }
                    TestResult::Invalid => {
                        assert!(verify_result.is_err(), "Test {} should fail: {}", test.tc_id, test.comment);
                    }
                    TestResult::Acceptable => {
                        // Implementation dependent
                    }
                }
            }
        }
    }
}
