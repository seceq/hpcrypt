//! NIST CAVP/ACVP Test Vectors for AES-GCM-SIV
//!
//! Tests AES-GCM-SIV (nonce misuse-resistant AEAD) against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-GCM-SIV-1.0/

#![cfg(feature = "enable-aead-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_aead::aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PromptFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "testType")]
    test_type: String,
    direction: String,
    #[serde(rename = "keyLen")]
    key_len: u32,
    #[serde(rename = "payloadLen")]
    payload_len: u32,
    #[serde(rename = "aadLen")]
    aad_len: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    #[serde(rename = "pt")]
    plaintext: Option<String>,
    #[serde(rename = "ct")]
    ciphertext: Option<String>,
    aad: String,
    iv: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<ExpectedGroup>,
}

#[derive(Debug, Deserialize)]
struct ExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<ExpectedTest>,
}

#[derive(Debug, Deserialize)]
struct ExpectedTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "ct")]
    ciphertext: Option<String>,
    #[serde(rename = "pt")]
    plaintext: Option<String>,
}

fn test_aes_gcm_siv_internal(key_size: u32) {
    println!("\nTesting AES-{}-GCM-SIV", key_size);

    let prompt: PromptFile = load_test_file("ACVP-AES-GCM-SIV-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-GCM-SIV-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Only test the specified key length
        if test_group.key_len != key_size {
            stats.skipped += test_group.tests.len();
            continue;
        }

        // Skip tests with non-byte-aligned lengths
        if test_group.payload_len % 8 != 0 || test_group.aad_len % 8 != 0 {
            stats.skipped += test_group.tests.len();
            continue;
        }

        let expected_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == test_group.tg_id);

        if expected_group.is_none() {
            stats.skipped += test_group.tests.len();
            continue;
        }
        let expected_group = expected_group.unwrap();

        for test in &test_group.tests {
            let expected_test = expected_group
                .tests
                .iter()
                .find(|t| t.tc_id == test.tc_id);

            if expected_test.is_none() {
                stats.skipped += 1;
                continue;
            }
            let expected_test = expected_test.unwrap();

            let key_bytes = decode_hex(&test.key);

            let nonce_bytes = decode_hex(&test.iv);
            let nonce: [u8; 12] = match nonce_bytes.as_slice().try_into() {
                Ok(n) => n,
                Err(_) => {
                    println!("FAIL: Test {} - Invalid nonce length", test.tc_id);
                    stats.failed += 1;
                    continue;
                }
            };

            let aad = if test.aad.is_empty() {
                vec![]
            } else {
                decode_hex(&test.aad)
            };

            if test_group.direction == "encrypt" {
                if let (Some(pt_hex), Some(expected_ct_hex)) =
                    (&test.plaintext, &expected_test.ciphertext)
                {
                    let plaintext = if pt_hex.is_empty() {
                        vec![]
                    } else {
                        decode_hex(pt_hex)
                    };
                    let expected_ct = decode_hex(expected_ct_hex);

                    let ciphertext_and_tag = if key_size == 128 {
                        let key: [u8; 16] = key_bytes.as_slice().try_into().unwrap();
                        Aes128GcmSiv::encrypt(&key, &nonce, &plaintext, &aad)
                    } else {
                        let key: [u8; 32] = key_bytes.as_slice().try_into().unwrap();
                        Aes256GcmSiv::encrypt(&key, &nonce, &plaintext, &aad)
                    };

                    if ciphertext_and_tag == expected_ct {
                        stats.passed += 1;
                    } else {
                        println!(
                            "FAIL: Test {} encryption mismatch (group {})",
                            test.tc_id, test_group.tg_id
                        );
                        stats.failed += 1;
                    }
                }
            } else if test_group.direction == "decrypt" {
                if let Some(ct_hex) = &test.ciphertext {
                    let ciphertext_and_tag = if ct_hex.is_empty() {
                        vec![]
                    } else {
                        decode_hex(ct_hex)
                    };

                    let result = if key_size == 128 {
                        let key: [u8; 16] = key_bytes.as_slice().try_into().unwrap();
                        Aes128GcmSiv::decrypt(&key, &nonce, &ciphertext_and_tag, &aad)
                    } else {
                        let key: [u8; 32] = key_bytes.as_slice().try_into().unwrap();
                        Aes256GcmSiv::decrypt(&key, &nonce, &ciphertext_and_tag, &aad)
                    };

                    match (&expected_test.plaintext, result) {
                        // Expected auth failure, got auth failure
                        (None, None) => {
                            stats.passed += 1;
                        }
                        // Expected plaintext, got plaintext
                        (Some(expected_pt_hex), Some(plaintext)) => {
                            let expected_pt = if expected_pt_hex.is_empty() {
                                vec![]
                            } else {
                                decode_hex(expected_pt_hex)
                            };
                            if plaintext == expected_pt {
                                stats.passed += 1;
                            } else {
                                println!(
                                    "FAIL: Test {} decryption mismatch (group {})",
                                    test.tc_id, test_group.tg_id
                                );
                                stats.failed += 1;
                            }
                        }
                        // Expected plaintext but got auth failure
                        (Some(_), None) => {
                            println!("FAIL: Test {} decryption failed (expected success)", test.tc_id);
                            stats.failed += 1;
                        }
                        // Expected auth failure but got plaintext
                        (None, Some(_)) => {
                            println!("FAIL: Test {} decryption succeeded (expected auth failure)", test.tc_id);
                            stats.failed += 1;
                        }
                    }
                }
            }
        }
    }

    println!(
        "AES-{}-GCM-SIV Results: {} passed, {} failed, {} skipped",
        key_size, stats.passed, stats.failed, stats.skipped
    );

    assert_eq!(stats.failed, 0, "Some AES-GCM-SIV tests failed");
}

#[test]
fn test_aes_gcm_siv() {
    test_aes_gcm_siv_internal(128);
    test_aes_gcm_siv_internal(256);
}
