//! Wycheproof test vectors for ChaCha20-Poly1305

use super::{decode_hex, load_test_vectors, TestResult, WycheproofTestFile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChaCha20Poly1305TestGroup {
    #[serde(rename = "type")]
    pub test_type: String,
    pub tests: Vec<ChaCha20Poly1305Test>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChaCha20Poly1305Test {
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

pub type ChaCha20Poly1305TestFile = WycheproofTestFile<ChaCha20Poly1305TestGroup>;

#[cfg(test)]
mod tests {
    use super::*;
    use hpcrypt::aead::ChaCha20Poly1305;

    #[test]
    fn test_chacha20_poly1305_wycheproof() {
        let test_data = r#"{
  "algorithm": "CHACHA20-POLY1305",
  "generatorVersion": "0.9",
  "numberOfTests": 1,
  "testGroups": [
    {
      "type": "ChaCha20Poly1305Test",
      "tests": [
        {
          "tcId": 1,
          "comment": "RFC 7539 Example",
          "key": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
          "iv": "070000004041424344454647",
          "aad": "50515253c0c1c2c3c4c5c6c7",
          "msg": "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
          "ct": "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
          "tag": "1ae10b594f09e26a7e902ecbd0600691",
          "result": "valid",
          "flags": []
        }
      ]
    }
  ]
}"#;

        let vectors: ChaCha20Poly1305TestFile = load_test_vectors(test_data).unwrap();

        for group in &vectors.test_groups {
            for test in &group.tests {
                let key = decode_hex(&test.key).unwrap();
                let nonce = decode_hex(&test.iv).unwrap();
                let aad = decode_hex(&test.aad).unwrap();
                let plaintext = decode_hex(&test.msg).unwrap();
                let expected_ct = decode_hex(&test.ct).unwrap();
                let expected_tag = decode_hex(&test.tag).unwrap();

                if key.len() != 32 || nonce.len() != 12 {
                    continue;
                }

                let mut key_array = [0u8; 32];
                let mut nonce_array = [0u8; 12];
                key_array.copy_from_slice(&key);
                nonce_array.copy_from_slice(&nonce);

                let cipher = ChaCha20Poly1305::new(&key_array);
                let mut ciphertext = vec![0u8; plaintext.len()];
                let mut tag = [0u8; 16];

                let result = cipher.encrypt(&nonce_array, &aad, &plaintext, &mut ciphertext, &mut tag);

                match test.result {
                    TestResult::Valid => {
                        assert!(result.is_ok(), "Test {} failed", test.tc_id);
                        assert_eq!(ciphertext, expected_ct, "CT mismatch test {}", test.tc_id);
                        assert_eq!(&tag[..], &expected_tag[..], "Tag mismatch test {}", test.tc_id);
                    }
                    TestResult::Invalid => {
                        // Test decryption failure
                        let mut plaintext_out = vec![0u8; expected_ct.len()];
                        let tag_array: [u8; 16] = expected_tag.try_into().unwrap_or([0u8; 16]);
                        let decrypt_result = cipher.decrypt(&nonce_array, &aad, &expected_ct, &tag_array, &mut plaintext_out);
                        assert!(decrypt_result.is_err(), "Test {} should fail", test.tc_id);
                    }
                    TestResult::Acceptable => {}
                }
            }
        }
    }
}
