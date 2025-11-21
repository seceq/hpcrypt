//! NIST CAVP/ACVP Test Vectors for X9.63 KDF
//!
//! Tests ANSI X9.63 Key Derivation Function against NIST test vectors.
//! X9.63 KDF is commonly used in ECDH key agreement schemes.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/kdf-components-ansix9.63-1.0/

#![cfg(feature = "enable-kdf-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_kdf::{x963_kdf_sha256, x963_kdf_sha384, x963_kdf_sha512};
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
    #[serde(rename = "hashAlg")]
    hash_alg: String,
    #[serde(rename = "sharedInfoLength")]
    shared_info_length: u32,
    #[serde(rename = "keyDataLength")]
    key_data_length: u32,
    #[serde(rename = "fieldSize")]
    field_size: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    z: String,
    #[serde(rename = "sharedInfo")]
    shared_info: String,
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
    #[serde(rename = "keyData")]
    key_data: String,
}

fn run_x963_kdf_tests() {
    println!("\nTesting X9.63 KDF");

    let prompt: PromptFile =
        load_test_file("kdf-components-ansix9.63-1.0", "prompt.json");
    let expected: ExpectedFile =
        load_test_file("kdf-components-ansix9.63-1.0", "expectedResults.json");

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

            let z = decode_hex(&test.z);
            let shared_info = if test.shared_info.is_empty() {
                vec![]
            } else {
                decode_hex(&test.shared_info)
            };
            let expected_key_data = decode_hex(&expected_test.key_data);

            // Convert key_data_length from bits to bytes
            let key_len = (test_group.key_data_length / 8) as usize;

            // Select the appropriate hash function
            let result: Result<Vec<u8>, String> = match test_group.hash_alg.as_str() {
                "SHA2-256" => Ok(x963_kdf_sha256(&z, &shared_info, key_len)),
                "SHA2-384" => Ok(x963_kdf_sha384(&z, &shared_info, key_len)),
                "SHA2-512" => Ok(x963_kdf_sha512(&z, &shared_info, key_len)),
                _ => {
                    // Unsupported hash algorithm
                    stats.skipped += 1;
                    continue;
                }
            };

            match result {
                Ok(key_data) => {
                    if key_data == expected_key_data {
                        stats.passed += 1;
                    } else {
                        println!(
                            "FAIL: Test {} mismatch (group {}, hash {})",
                            test.tc_id, test_group.tg_id, test_group.hash_alg
                        );
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

    println!(
        "X9.63 KDF Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(stats.failed, 0, "{} tests failed for X9.63 KDF", stats.failed);
}

#[test]
fn test_x963_kdf() {
    run_x963_kdf_tests();
}
