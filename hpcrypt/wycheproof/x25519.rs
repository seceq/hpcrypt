//! Wycheproof test vectors for X25519 (ECDH on Curve25519)

use super::{decode_hex, load_test_vectors, TestResult, WycheproofTestFile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X25519TestGroup {
    pub curve: String,
    #[serde(rename = "type")]
    pub test_type: String,
    pub tests: Vec<X25519Test>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X25519Test {
    pub tc_id: u32,
    pub comment: String,
    pub public: String,
    pub private: String,
    pub shared: String,
    pub result: TestResult,
    pub flags: Option<Vec<String>>,
}

pub type X25519TestFile = WycheproofTestFile<X25519TestGroup>;

#[cfg(test)]
mod tests {
    use super::*;
    use hpcrypt::kex::X25519;

    #[test]
    fn test_x25519_wycheproof() {
        let test_data = r#"{
  "algorithm": "XDH",
  "generatorVersion": "0.9",
  "numberOfTests": 1,
  "testGroups": [
    {
      "curve": "curve25519",
      "type": "XdhComp",
      "tests": [
        {
          "tcId": 1,
          "comment": "normal case",
          "public": "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
          "private": "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
          "shared": "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320",
          "result": "valid",
          "flags": []
        }
      ]
    }
  ]
}"#;

        let vectors: X25519TestFile = load_test_vectors(test_data).unwrap();

        for group in &vectors.test_groups {
            for test in &group.tests {
                let public_key = decode_hex(&test.public).unwrap();
                let private_key = decode_hex(&test.private).unwrap();
                let expected_shared = decode_hex(&test.shared).unwrap();

                if public_key.len() != 32 || private_key.len() != 32 {
                    continue;
                }

                let mut pk_array = [0u8; 32];
                let mut sk_array = [0u8; 32];
                pk_array.copy_from_slice(&public_key);
                sk_array.copy_from_slice(&private_key);

                let shared_secret = X25519::diffie_hellman(&sk_array, &pk_array);

                match test.result {
                    TestResult::Valid => {
                        assert_eq!(shared_secret, expected_shared, "Test {} failed: {}", test.tc_id, test.comment);
                    }
                    TestResult::Invalid => {
                        // For invalid tests, we expect different shared secret or all-zero
                        let is_all_zero = shared_secret.iter().all(|&b| b == 0);
                        assert!(shared_secret != expected_shared || is_all_zero,
                            "Test {} should produce invalid result: {}", test.tc_id, test.comment);
                    }
                    TestResult::Acceptable => {}
                }
            }
        }
    }
}
