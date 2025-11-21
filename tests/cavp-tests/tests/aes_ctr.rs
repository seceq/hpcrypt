//! NIST CAVP/ACVP Test Vectors for AES-CTR
//!
//! Tests AES-CTR (Counter mode) encryption and decryption against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-CTR-1.0/

#![cfg(feature = "enable-cipher-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_cipher::{AesCtr128, AesCtr192, AesCtr256};
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
    #[serde(rename = "keyLen")]
    key_len: u32,
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
    #[serde(rename = "payloadLen")]
    payload_len: Option<u32>,
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
    iv: Option<String>,
    #[serde(rename = "ct")]
    ciphertext: Option<String>,
    #[serde(rename = "pt")]
    plaintext: Option<String>,
}

trait AesCtrCipher {
    fn process(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String>;
}

impl AesCtrCipher for AesCtr128 {
    fn process(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        let nonce_array: [u8; 16] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
        let cipher = AesCtr128::new(&key_array);
        Ok(cipher.process(&nonce_array, data))
    }
}

impl AesCtrCipher for AesCtr192 {
    fn process(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length")?;
        let nonce_array: [u8; 16] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
        let cipher = AesCtr192::new(&key_array);
        Ok(cipher.process(&nonce_array, data))
    }
}

impl AesCtrCipher for AesCtr256 {
    fn process(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let nonce_array: [u8; 16] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
        let cipher = AesCtr256::new(&key_array);
        Ok(cipher.process(&nonce_array, data))
    }
}

fn run_aes_ctr_tests<C: AesCtrCipher>(algorithm_name: &str) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-CTR-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-CTR-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    let expected_key_len = match algorithm_name {
        "AES-128-CTR" => 128,
        "AES-192-CTR" => 192,
        "AES-256-CTR" => 256,
        _ => panic!("Unknown algorithm"),
    };

    for test_group in &prompt.test_groups {
        if test_group.key_len != expected_key_len {
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

            // Skip tests with partial bytes (non-byte-aligned payloads)
            // Most cipher implementations only support byte-aligned data
            if let Some(payload_len) = test.payload_len {
                if payload_len % 8 != 0 {
                    stats.skipped += 1;
                    continue;
                }
            }

            let key = decode_hex(&test.key);

            // Skip if no IV provided
            let iv_hex = match &expected_test.iv {
                Some(iv) => iv,
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };
            let iv = decode_hex(iv_hex);

            // Test encryption
            if let Some(pt_hex) = &test.plaintext {
                let plaintext = decode_hex(pt_hex);
                let expected_ct = decode_hex(expected_test.ciphertext.as_ref().unwrap());

                match C::process(&key, &iv, &plaintext) {
                    Ok(ciphertext) => {
                        if ciphertext == expected_ct {
                            stats.passed += 1;
                        } else {
                            println!("FAIL: Test {} encryption mismatch", test.tc_id);
                            stats.failed += 1;
                        }
                    }
                    Err(e) => {
                        println!("FAIL: Test {} error: {}", test.tc_id, e);
                        stats.failed += 1;
                    }
                }
            }
            // Test decryption
            else if let Some(ct_hex) = &test.ciphertext {
                let ciphertext = decode_hex(ct_hex);
                let expected_pt = decode_hex(expected_test.plaintext.as_ref().unwrap());

                match C::process(&key, &iv, &ciphertext) {
                    Ok(plaintext) => {
                        if plaintext == expected_pt {
                            stats.passed += 1;
                        } else {
                            println!("FAIL: Test {} decryption mismatch", test.tc_id);
                            stats.failed += 1;
                        }
                    }
                    Err(e) => {
                        println!("FAIL: Test {} error: {}", test.tc_id, e);
                        stats.failed += 1;
                    }
                }
            }
        }
    }

    println!(
        "{} Results: {} passed, {} failed, {} skipped",
        algorithm_name, stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(
        stats.failed, 0,
        "{} tests failed for {}",
        stats.failed, algorithm_name
    );
}

#[test]
fn test_aes_128_ctr() {
    run_aes_ctr_tests::<AesCtr128>("AES-128-CTR");
}

#[test]
fn test_aes_192_ctr() {
    run_aes_ctr_tests::<AesCtr192>("AES-192-CTR");
}

#[test]
fn test_aes_256_ctr() {
    run_aes_ctr_tests::<AesCtr256>("AES-256-CTR");
}
