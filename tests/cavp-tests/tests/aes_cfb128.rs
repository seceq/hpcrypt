//! NIST CAVP/ACVP Test Vectors for AES-CFB128
//!
//! Tests AES-CFB128 (Cipher Feedback mode with 128-bit feedback) encryption and decryption
//! against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-CFB128-1.0/

#![cfg(feature = "enable-cipher-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_cipher::{AesCfb128, AesCfb192, AesCfb256};
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

trait AesCfbCipher {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>;
}

impl AesCfbCipher for AesCfb128 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCfb128::new(&key_array);
        Ok(cipher.encrypt(&iv_array, plaintext))
    }

    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCfb128::new(&key_array);
        Ok(cipher.decrypt(&iv_array, ciphertext))
    }
}

impl AesCfbCipher for AesCfb192 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCfb192::new(&key_array);
        Ok(cipher.encrypt(&iv_array, plaintext))
    }

    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCfb192::new(&key_array);
        Ok(cipher.decrypt(&iv_array, ciphertext))
    }
}

impl AesCfbCipher for AesCfb256 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCfb256::new(&key_array);
        Ok(cipher.encrypt(&iv_array, plaintext))
    }

    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "Invalid IV length")?;
        let cipher = AesCfb256::new(&key_array);
        Ok(cipher.decrypt(&iv_array, ciphertext))
    }
}

fn run_aes_cfb128_tests<C: AesCfbCipher>(algorithm_name: &str, expected_key_len: usize) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-CFB128-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-CFB128-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
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

            let key = decode_hex(&test.key);
            let iv = decode_hex(&test.iv);

            // Skip tests with wrong key length
            if key.len() != expected_key_len {
                stats.skipped += 1;
                continue;
            }

            // Determine if this is an encryption or decryption test
            if let (Some(pt_hex), Some(expected_ct_hex)) =
                (&test.plaintext, &expected_test.ciphertext)
            {
                // Encryption test
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
                        println!("FAIL: Test {} error: {}", test.tc_id, e);
                        stats.failed += 1;
                    }
                }
            } else if let (Some(ct_hex), Some(expected_pt_hex)) =
                (&test.ciphertext, &expected_test.plaintext)
            {
                // Decryption test
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
                        println!("FAIL: Test {} error: {}", test.tc_id, e);
                        stats.failed += 1;
                    }
                }
            } else {
                // Neither encryption nor decryption test
                stats.skipped += 1;
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
fn test_aes_128_cfb128() {
    run_aes_cfb128_tests::<AesCfb128>("AES-128-CFB128", 16);
}

#[test]
fn test_aes_192_cfb128() {
    run_aes_cfb128_tests::<AesCfb192>("AES-192-CFB128", 24);
}

#[test]
fn test_aes_256_cfb128() {
    run_aes_cfb128_tests::<AesCfb256>("AES-256-CFB128", 32);
}
