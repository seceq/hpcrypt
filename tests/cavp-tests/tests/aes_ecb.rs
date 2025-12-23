//! NIST CAVP/ACVP Test Vectors for AES-ECB (1-way block operations)
//!
//! Tests AES block cipher encrypt/decrypt operations against NIST test vectors.
//! This tests single block operations using `encrypt_block` and `decrypt_block`.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-ECB-1.0/

#![cfg(feature = "enable-cipher-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_cipher::Aes;
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

fn run_aes_ecb_tests(key_len: u32, algorithm_name: &str) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-ECB-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-ECB-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Skip if key length doesn't match
        if test_group.key_len != key_len {
            stats.skipped += test_group.tests.len();
            continue;
        }

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

            // Decode key
            let key = decode_hex(&test.key);

            // Create cipher based on key length
            let cipher = match key_len {
                128 => {
                    let key_array: [u8; 16] = key.as_slice().try_into().unwrap();
                    Aes::new_128(&key_array)
                }
                192 => {
                    let key_array: [u8; 24] = key.as_slice().try_into().unwrap();
                    Aes::new_192(&key_array)
                }
                256 => {
                    let key_array: [u8; 32] = key.as_slice().try_into().unwrap();
                    Aes::new_256(&key_array)
                }
                _ => {
                    stats.skipped += 1;
                    continue;
                }
            };

            if test_group.direction == "encrypt" {
                if let (Some(pt_hex), Some(expected_ct_hex)) =
                    (&test.plaintext, &expected_test.ciphertext)
                {
                    let plaintext = decode_hex(pt_hex);
                    let expected_ct = decode_hex(expected_ct_hex);

                    // Skip multi-block tests (this test is for single block operations)
                    if plaintext.len() != 16 {
                        stats.skipped += 1;
                        continue;
                    }

                    // ECB operates on single 16-byte blocks
                    let pt_block: [u8; 16] = plaintext.as_slice().try_into().unwrap();
                    let ciphertext = cipher.encrypt_block(&pt_block);

                    if ciphertext[..] == expected_ct[..] {
                        stats.passed += 1;
                    } else {
                        println!(
                            "FAIL: Test {} encryption mismatch (group {})",
                            test.tc_id, test_group.tg_id
                        );
                        println!("  Expected: {}", expected_ct_hex);
                        println!("  Got:      {}", hex::encode(&ciphertext));
                        stats.failed += 1;
                    }
                }
            } else if test_group.direction == "decrypt" {
                if let (Some(ct_hex), Some(expected_pt_hex)) =
                    (&test.ciphertext, &expected_test.plaintext)
                {
                    let ciphertext = decode_hex(ct_hex);
                    let expected_pt = decode_hex(expected_pt_hex);

                    // Skip multi-block tests (this test is for single block operations)
                    if ciphertext.len() != 16 {
                        stats.skipped += 1;
                        continue;
                    }

                    // ECB operates on single 16-byte blocks
                    let ct_block: [u8; 16] = ciphertext.as_slice().try_into().unwrap();
                    let plaintext = cipher.decrypt_block(&ct_block);

                    if plaintext[..] == expected_pt[..] {
                        stats.passed += 1;
                    } else {
                        println!(
                            "FAIL: Test {} decryption mismatch (group {})",
                            test.tc_id, test_group.tg_id
                        );
                        println!("  Expected: {}", expected_pt_hex);
                        println!("  Got:      {}", hex::encode(&plaintext));
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
fn test_aes_128_ecb() {
    run_aes_ecb_tests(128, "AES-128-ECB");
}

#[test]
fn test_aes_192_ecb() {
    run_aes_ecb_tests(192, "AES-192-ECB");
}

#[test]
fn test_aes_256_ecb() {
    run_aes_ecb_tests(256, "AES-256-ECB");
}
