//! NIST CAVP/ACVP Test Vectors for CMAC-AES
//!
//! Tests AES-CMAC (Cipher-based Message Authentication Code) generation
//! against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/CMAC-AES-1.0/

#![cfg(feature = "enable-mac-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_mac::{AesCmac128, AesCmac256};
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
    #[serde(rename = "msgLen")]
    msg_len: u32,
    #[serde(rename = "macLen")]
    mac_len: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    message: String,
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
    mac: Option<String>,
}

trait CmacCipher {
    fn generate(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String>;
}

impl CmacCipher for AesCmac128 {
    fn generate(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        let cmac = AesCmac128::new(&key_array);
        Ok(cmac.compute(message).to_vec())
    }
}

impl CmacCipher for AesCmac256 {
    fn generate(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let cmac = AesCmac256::new(&key_array);
        Ok(cmac.compute(message).to_vec())
    }
}

fn run_cmac_tests<C: CmacCipher>(algorithm_name: &str) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("CMAC-AES-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("CMAC-AES-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    let expected_key_len = match algorithm_name {
        "AES-128-CMAC" => 128,
        "AES-256-CMAC" => 256,
        _ => panic!("Unknown algorithm"),
    };

    for test_group in &prompt.test_groups {
        // Skip if key length doesn't match
        if test_group.key_len != expected_key_len {
            stats.skipped += test_group.tests.len();
            continue;
        }

        // Find corresponding expected group
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
            let message = if test.message.is_empty() {
                vec![]
            } else {
                decode_hex(&test.message)
            };

            // Skip if no expected MAC
            let mac_hex = match &expected_test.mac {
                Some(m) => m,
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };
            let expected_mac = decode_hex(mac_hex);

            // Calculate mac_len in bytes
            let mac_len_bytes = (test_group.mac_len + 7) / 8;

            match C::generate(&key, &message) {
                Ok(mac) => {
                    // Truncate MAC to expected length
                    let truncated_mac = &mac[..mac_len_bytes as usize];

                    if truncated_mac == expected_mac.as_slice() {
                        stats.passed += 1;
                    } else {
                        println!(
                            "FAIL: Test {} MAC mismatch (group {}, macLen={})",
                            test.tc_id, test_group.tg_id, test_group.mac_len
                        );
                        println!("  Expected: {}", hex::encode(&expected_mac));
                        println!("  Got:      {}", hex::encode(truncated_mac));
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
fn test_aes_128_cmac() {
    run_cmac_tests::<AesCmac128>("AES-128-CMAC");
}

#[test]
fn test_aes_256_cmac() {
    run_cmac_tests::<AesCmac256>("AES-256-CMAC");
}
