//! NIST CAVP/ACVP Test Vectors for AES-ECB (8-way parallel block operations)
//!
//! Tests AES block cipher using 8-block parallel operations (`encrypt_blocks_8`
//! and `decrypt_blocks_8`) against NIST test vectors.
//!
//! This test batches 8 test vectors at a time to exercise the parallel
//! encryption/decryption paths, which are optimal for AES-NI on x86/x86_64.
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

/// Test data for a single block operation
struct BlockTest {
    tc_id: u32,
    tg_id: u32,
    block: [u8; 16],
    expected: [u8; 16],
}

fn run_aes_ecb_x8_tests(key_len: u32, algorithm_name: &str) {
    println!("\nTesting {} (8-way parallel)", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-ECB-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-ECB-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    // Collect all encrypt tests with the same key into batches
    // For simplicity, we'll process each test group separately
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

        // Collect tests that share the same key for batching
        // Group tests by key
        let mut tests_by_key: std::collections::HashMap<String, Vec<BlockTest>> =
            std::collections::HashMap::new();

        for test in &test_group.tests {
            let expected_test = expected_group.tests.iter().find(|t| t.tc_id == test.tc_id);
            if expected_test.is_none() {
                stats.skipped += 1;
                continue;
            }
            let expected_test = expected_test.unwrap();

            let (block_hex, expected_hex) = if test_group.direction == "encrypt" {
                match (&test.plaintext, &expected_test.ciphertext) {
                    (Some(pt), Some(ct)) => (pt.clone(), ct.clone()),
                    _ => {
                        stats.skipped += 1;
                        continue;
                    }
                }
            } else {
                match (&test.ciphertext, &expected_test.plaintext) {
                    (Some(ct), Some(pt)) => (ct.clone(), pt.clone()),
                    _ => {
                        stats.skipped += 1;
                        continue;
                    }
                }
            };

            let block_vec = decode_hex(&block_hex);
            let expected_vec = decode_hex(&expected_hex);

            // Skip multi-block tests (this test is for single block operations batched 8 at a time)
            if block_vec.len() != 16 {
                stats.skipped += 1;
                continue;
            }

            let block: [u8; 16] = block_vec.as_slice().try_into().unwrap();
            let expected_arr: [u8; 16] = expected_vec.as_slice().try_into().unwrap();

            tests_by_key
                .entry(test.key.clone())
                .or_default()
                .push(BlockTest {
                    tc_id: test.tc_id,
                    tg_id: test_group.tg_id,
                    block,
                    expected: expected_arr,
                });
        }

        // Process each key's tests in batches of 8
        for (key_hex, tests) in tests_by_key {
            let key = decode_hex(&key_hex);

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
                _ => continue,
            };

            // Process in batches of 8
            let chunks: Vec<_> = tests.chunks(8).collect();
            for chunk in chunks {
                if chunk.len() == 8 {
                    // Full 8-block batch
                    let mut blocks: [[u8; 16]; 8] = [
                        chunk[0].block,
                        chunk[1].block,
                        chunk[2].block,
                        chunk[3].block,
                        chunk[4].block,
                        chunk[5].block,
                        chunk[6].block,
                        chunk[7].block,
                    ];

                    if test_group.direction == "encrypt" {
                        cipher.encrypt_blocks_8(&mut blocks);
                    } else {
                        cipher.decrypt_blocks_8(&mut blocks);
                    }

                    // Verify results
                    for (i, test_data) in chunk.iter().enumerate() {
                        if blocks[i] == test_data.expected {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} {} mismatch (group {}, 8-way batch)",
                                test_data.tc_id, test_group.direction, test_data.tg_id
                            );
                            println!("  Expected: {}", hex::encode(test_data.expected));
                            println!("  Got:      {}", hex::encode(blocks[i]));
                            stats.failed += 1;
                        }
                    }
                } else {
                    // Partial batch - pad with dummy blocks
                    let mut blocks: [[u8; 16]; 8] = [[0u8; 16]; 8];
                    for (i, test_data) in chunk.iter().enumerate() {
                        blocks[i] = test_data.block;
                    }

                    if test_group.direction == "encrypt" {
                        cipher.encrypt_blocks_8(&mut blocks);
                    } else {
                        cipher.decrypt_blocks_8(&mut blocks);
                    }

                    // Verify only the real results
                    for (i, test_data) in chunk.iter().enumerate() {
                        if blocks[i] == test_data.expected {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} {} mismatch (group {}, partial 8-way batch)",
                                test_data.tc_id, test_group.direction, test_data.tg_id
                            );
                            println!("  Expected: {}", hex::encode(test_data.expected));
                            println!("  Got:      {}", hex::encode(blocks[i]));
                            stats.failed += 1;
                        }
                    }
                }
            }
        }
    }

    println!(
        "{} (8-way) Results: {} passed, {} failed, {} skipped",
        algorithm_name, stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(
        stats.failed, 0,
        "{} tests failed for {} (8-way)",
        stats.failed, algorithm_name
    );
}

#[test]
fn test_aes_128_ecb_x8() {
    run_aes_ecb_x8_tests(128, "AES-128-ECB");
}

#[test]
fn test_aes_192_ecb_x8() {
    run_aes_ecb_x8_tests(192, "AES-192-ECB");
}

#[test]
fn test_aes_256_ecb_x8() {
    run_aes_ecb_x8_tests(256, "AES-256-ECB");
}
