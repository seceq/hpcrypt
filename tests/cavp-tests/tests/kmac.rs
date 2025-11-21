//! NIST CAVP/ACVP Test Vectors for KMAC
//!
//! Tests KMAC-128 and KMAC-256 (Keccak Message Authentication Code) against NIST test vectors.
//! KMAC is a variable-length MAC based on cSHAKE with a key input.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/KMAC-{128,256}-1.0/

#![cfg(feature = "enable-mac-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_mac::{kmac128, kmac256};
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
    xof: bool,
    #[serde(rename = "hexCustomization")]
    hex_customization: bool,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    #[serde(rename = "keyLen")]
    key_len: u32,
    msg: String,
    #[serde(rename = "msgLen")]
    msg_len: u32,
    #[serde(rename = "macLen")]
    mac_len: u32,
    #[serde(default)]
    customization: Option<String>,
    #[serde(rename = "customizationHex", default)]
    customization_hex: Option<String>,
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
    #[serde(default)]
    mac: Option<String>,
    #[serde(rename = "testPassed", default)]
    test_passed: Option<bool>,
}

fn run_kmac128_tests() {
    println!("\nTesting KMAC-128");

    let prompt: PromptFile = load_test_file("KMAC-128-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("KMAC-128-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Skip MCT (Monte Carlo Test) tests for now
        if test_group.test_type == "MCT" {
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

            // Skip non-byte-aligned key lengths
            if test.key_len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Skip non-byte-aligned message lengths
            if test.msg_len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Skip non-byte-aligned MAC lengths
            if test.mac_len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Decode inputs
            let key = decode_hex(&test.key);
            let key_len_bytes = (test.key_len / 8) as usize;
            let key_data = if key_len_bytes <= key.len() {
                &key[..key_len_bytes]
            } else {
                &key[..]
            };

            let msg = decode_hex(&test.msg);
            let msg_len_bytes = (test.msg_len / 8) as usize;
            let msg_data = if msg_len_bytes <= msg.len() {
                &msg[..msg_len_bytes]
            } else {
                &msg[..]
            };

            // Handle both customization and customizationHex fields
            let customization = if let Some(ref custom_hex) = test.customization_hex {
                decode_hex(custom_hex)
            } else if let Some(ref custom) = test.customization {
                if test_group.hex_customization {
                    decode_hex(custom)
                } else {
                    custom.as_bytes().to_vec()
                }
            } else {
                Vec::new()
            };

            let mac_len_bytes = (test.mac_len / 8) as usize;

            // Skip validation tests (those with testPassed instead of mac)
            let expected_mac_str = match &expected_test.mac {
                Some(m) => m,
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };

            // Compute KMAC-128
            let mac = kmac128(key_data, msg_data, &customization, mac_len_bytes);

            // Compare with expected
            let expected_mac = decode_hex(expected_mac_str);

            if mac == expected_mac {
                stats.passed += 1;
            } else {
                println!(
                    "FAIL: Test {} mismatch (group {})",
                    test.tc_id, test_group.tg_id
                );
                stats.failed += 1;
            }
        }
    }

    println!(
        "KMAC-128 Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(stats.failed, 0, "{} tests failed for KMAC-128", stats.failed);
}

fn run_kmac256_tests() {
    println!("\nTesting KMAC-256");

    let prompt: PromptFile = load_test_file("KMAC-256-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("KMAC-256-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Skip MCT (Monte Carlo Test) tests for now
        if test_group.test_type == "MCT" {
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

            // Skip non-byte-aligned key lengths
            if test.key_len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Skip non-byte-aligned message lengths
            if test.msg_len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Skip non-byte-aligned MAC lengths
            if test.mac_len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Decode inputs
            let key = decode_hex(&test.key);
            let key_len_bytes = (test.key_len / 8) as usize;
            let key_data = if key_len_bytes <= key.len() {
                &key[..key_len_bytes]
            } else {
                &key[..]
            };

            let msg = decode_hex(&test.msg);
            let msg_len_bytes = (test.msg_len / 8) as usize;
            let msg_data = if msg_len_bytes <= msg.len() {
                &msg[..msg_len_bytes]
            } else {
                &msg[..]
            };

            // Handle both customization and customizationHex fields
            let customization = if let Some(ref custom_hex) = test.customization_hex {
                decode_hex(custom_hex)
            } else if let Some(ref custom) = test.customization {
                if test_group.hex_customization {
                    decode_hex(custom)
                } else {
                    custom.as_bytes().to_vec()
                }
            } else {
                Vec::new()
            };

            let mac_len_bytes = (test.mac_len / 8) as usize;

            // Skip validation tests (those with testPassed instead of mac)
            let expected_mac_str = match &expected_test.mac {
                Some(m) => m,
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };

            // Compute KMAC-256
            let mac = kmac256(key_data, msg_data, &customization, mac_len_bytes);

            // Compare with expected
            let expected_mac = decode_hex(expected_mac_str);

            if mac == expected_mac {
                stats.passed += 1;
            } else {
                println!(
                    "FAIL: Test {} mismatch (group {})",
                    test.tc_id, test_group.tg_id
                );
                stats.failed += 1;
            }
        }
    }

    println!(
        "KMAC-256 Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(stats.failed, 0, "{} tests failed for KMAC-256", stats.failed);
}

#[test]
fn test_kmac128() {
    run_kmac128_tests();
}

#[test]
fn test_kmac256() {
    run_kmac256_tests();
}
