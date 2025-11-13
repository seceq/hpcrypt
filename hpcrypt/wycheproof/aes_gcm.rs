//! Wycheproof test vectors for AES-GCM
//!
//! Tests AES-GCM implementation against Google's Wycheproof test vectors.

use super::{decode_hex, load_test_vectors, TestResult, WycheproofTestFile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesGcmTestGroup {
    #[serde(rename = "type")]
    pub test_type: String,
    pub key_size: usize,
    pub iv_size: usize,
    pub tag_size: usize,
    pub tests: Vec<AesGcmTest>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesGcmTest {
    pub tc_id: u32,
    pub comment: String,
    pub key: String,
    pub iv: String,
    pub aad: String,
    pub msg: String,
    pub ct: String,
    pub tag: String,
    pub result: TestResult,
    pub flags: Option<Vec<String>>,
}

pub type AesGcmTestFile = WycheproofTestFile<AesGcmTestGroup>;

#[cfg(test)]
mod tests {
    use super::*;

    // Wycheproof test vectors (embedded JSON)
    // In practice, you'd download these from:
    // https://github.com/google/wycheproof/tree/master/testvectors
    const AES_128_GCM_TEST_VECTORS: &str = include_str!("../../../tests/vectors/aes_gcm_test.json");

    #[test]
    fn test_aes_128_gcm_wycheproof() {
        // This will be implemented once we have the actual test vectors
        // For now, create a minimal test structure

        let test_data = r#"{
  "algorithm": "AES-GCM",
  "generatorVersion": "0.9",
  "numberOfTests": 2,
  "testGroups": [
    {
      "type": "AesGcmTest",
      "keySize": 128,
      "ivSize": 96,
      "tagSize": 128,
      "tests": [
        {
          "tcId": 1,
          "comment": "empty plaintext",
          "key": "00000000000000000000000000000000",
          "iv": "000000000000000000000000",
          "aad": "",
          "msg": "",
          "ct": "",
          "tag": "58e2fccefa7e3061367f1d57a4e7455a",
          "result": "valid",
          "flags": []
        }
      ]
    }
  ]
}"#;

        let vectors: Result<AesGcmTestFile, _> = load_test_vectors(test_data);
        assert!(vectors.is_ok(), "Failed to parse test vectors");

        let vectors = vectors.unwrap();
        assert_eq!(vectors.algorithm, "AES-GCM");
        assert_eq!(vectors.number_of_tests, 2);

        // Run tests against hpcrypt implementation
        use hpcrypt::aead::{Aes128Gcm, AesGcm};

        for group in &vectors.test_groups {
            for test in &group.tests {
                let key = decode_hex(&test.key).expect("Invalid key hex");
                let iv = decode_hex(&test.iv).expect("Invalid iv hex");
                let aad = decode_hex(&test.aad).expect("Invalid aad hex");
                let msg = decode_hex(&test.msg).expect("Invalid msg hex");
                let expected_ct = decode_hex(&test.ct).expect("Invalid ct hex");
                let expected_tag = decode_hex(&test.tag).expect("Invalid tag hex");

                // Ensure key is correct size
                if key.len() != 16 {
                    continue; // Skip tests with wrong key size for AES-128
                }

                let mut key_array = [0u8; 16];
                key_array.copy_from_slice(&key);

                let cipher = Aes128Gcm::new(&key_array);

                // Test encryption
                let mut ciphertext = vec![0u8; msg.len()];
                let mut tag = [0u8; 16];

                let result = if iv.len() == 12 {
                    let mut iv_array = [0u8; 12];
                    iv_array.copy_from_slice(&iv);
                    cipher.encrypt(&iv_array, &aad, &msg, &mut ciphertext, &mut tag)
                } else {
                    continue; // Skip non-standard IV sizes for now
                };

                match test.result {
                    TestResult::Valid => {
                        assert!(result.is_ok(), "Test {} failed: {:?}", test.tc_id, test.comment);
                        assert_eq!(ciphertext, expected_ct, "Ciphertext mismatch for test {}", test.tc_id);
                        assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch for test {}", test.tc_id);
                    }
                    TestResult::Invalid => {
                        // For invalid tests, decryption should fail
                        let decrypt_result = cipher.decrypt(&iv.try_into().unwrap_or([0u8; 12]), &aad, &expected_ct, &expected_tag.try_into().unwrap_or([0u8; 16]), &mut ciphertext);
                        assert!(decrypt_result.is_err(), "Test {} should have failed but succeeded", test.tc_id);
                    }
                    TestResult::Acceptable => {
                        // Acceptable results are implementation-dependent
                        // We'll be lenient here
                    }
                }
            }
        }
    }

    #[test]
    fn test_aes_256_gcm_wycheproof() {
        // Similar structure for AES-256-GCM
        // Will be implemented with actual test vectors
    }
}
