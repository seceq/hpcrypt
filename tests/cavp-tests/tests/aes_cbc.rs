//! NIST CAVP/ACVP Test Vectors for AES-CBC
//!
//! Tests AES-CBC (Cipher Block Chaining mode) encryption and decryption
//! against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-CBC-1.0/

#![cfg(feature = "enable-cipher-tests")]

use cavp_tests::{decode_hex, load_test_file, test_vectors_path, TestStats};
use hpcrypt_cipher::{AesCbc128, AesCbc192, AesCbc256};
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
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    iv: String,
    #[serde(rename = "pt")]
    plaintext: Option<String>,
    #[serde(rename = "ct")]
    ciphertext: Option<String>,
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

trait AesCbcCipher {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>;
}

impl AesCbcCipher for AesCbc128 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCbc128::new(&key_array);
        cipher
            .encrypt(&iv_array, plaintext)
            .map_err(|e| format!("Encryption failed: {:?}", e))
    }

    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCbc128::new(&key_array);
        cipher
            .decrypt(&iv_array, ciphertext)
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }
}

impl AesCbcCipher for AesCbc192 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCbc192::new(&key_array);
        cipher
            .encrypt(&iv_array, plaintext)
            .map_err(|e| format!("Encryption failed: {:?}", e))
    }

    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCbc192::new(&key_array);
        cipher
            .decrypt(&iv_array, ciphertext)
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }
}

impl AesCbcCipher for AesCbc256 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCbc256::new(&key_array);
        cipher
            .encrypt(&iv_array, plaintext)
            .map_err(|e| format!("Encryption failed: {:?}", e))
    }

    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCbc256::new(&key_array);
        cipher
            .decrypt(&iv_array, ciphertext)
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }
}

fn run_aes_cbc_tests<C: AesCbcCipher>(algorithm_name: &str) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-CBC-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-CBC-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Find corresponding expected group
        let expected_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == test_group.tg_id);

        if expected_group.is_none() {
            println!(
                "Warning: No expected results for test group {}",
                test_group.tg_id
            );
            stats.skipped += test_group.tests.len();
            continue;
        }
        let expected_group = expected_group.unwrap();

        for test in &test_group.tests {
            // Skip if key length doesn't match our cipher
            let expected_key_len = match algorithm_name {
                "AES-128-CBC" => 128,
                "AES-192-CBC" => 192,
                "AES-256-CBC" => 256,
                _ => panic!("Unknown algorithm"),
            };
            if test_group.key_len != expected_key_len {
                stats.skipped += 1;
                continue;
            }

            // Find expected result
            let expected_test = expected_group
                .tests
                .iter()
                .find(|t| t.tc_id == test.tc_id);
            if expected_test.is_none() {
                stats.skipped += 1;
                continue;
            }
            let expected_test = expected_test.unwrap();

            // Decode test data
            let key = decode_hex(&test.key);
            let iv = decode_hex(&test.iv);

            if test_group.direction == "encrypt" {
                if let (Some(pt_hex), Some(expected_ct_hex)) =
                    (&test.plaintext, &expected_test.ciphertext)
                {
                    let plaintext = decode_hex(pt_hex);
                    let expected_ct = decode_hex(expected_ct_hex);

                    match C::encrypt(&key, &iv, &plaintext) {
                        Ok(ciphertext) => {
                            if ciphertext == expected_ct {
                                stats.passed += 1;
                            } else {
                                println!(
                                    "FAIL: Test {} encryption mismatch (group {})",
                                    test.tc_id, test_group.tg_id
                                );
                                stats.failed += 1;
                            }
                        }
                        Err(e) => {
                            println!("FAIL: Test {} encryption error: {}", test.tc_id, e);
                            stats.failed += 1;
                        }
                    }
                }
            } else if test_group.direction == "decrypt" {
                if let (Some(ct_hex), Some(expected_pt_hex)) =
                    (&test.ciphertext, &expected_test.plaintext)
                {
                    let ciphertext = decode_hex(ct_hex);
                    let expected_pt = decode_hex(expected_pt_hex);

                    match C::decrypt(&key, &iv, &ciphertext) {
                        Ok(plaintext) => {
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
                        Err(e) => {
                            println!("FAIL: Test {} decryption error: {}", test.tc_id, e);
                            stats.failed += 1;
                        }
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
fn test_aes_128_cbc() {
    run_aes_cbc_tests::<AesCbc128>("AES-128-CBC");
}

#[test]
fn test_aes_192_cbc() {
    run_aes_cbc_tests::<AesCbc192>("AES-192-CBC");
}

#[test]
fn test_aes_256_cbc() {
    run_aes_cbc_tests::<AesCbc256>("AES-256-CBC");
}
