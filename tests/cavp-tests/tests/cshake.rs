//! NIST CAVP/ACVP Test Vectors for cSHAKE
//!
//! Tests cSHAKE-128 and cSHAKE-256 (Customizable SHAKE) against NIST test vectors.
//! cSHAKE is an extensible output function (XOF) with customization support.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/cSHAKE-{128,256}-1.0/

#![cfg(feature = "enable-mac-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_mac::{CShake128, CShake256};
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
    #[serde(rename = "hexCustomization")]
    hex_customization: bool,
    #[serde(rename = "minOutLen")]
    min_out_len: Option<u32>,
    #[serde(rename = "maxOutLen")]
    max_out_len: Option<u32>,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    len: u32,
    #[serde(rename = "functionName")]
    function_name: String,
    customization: String,
    #[serde(rename = "outLen")]
    out_len: Option<u32>,
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
    md: Option<String>,
}

fn run_cshake128_tests() {
    println!("\nTesting cSHAKE-128");

    let prompt: PromptFile = load_test_file("cSHAKE-128-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("cSHAKE-128-1.0", "expectedResults.json");

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

            // Skip non-byte-aligned message lengths for now
            // (bit-level truncation would require special handling)
            if test.len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Decode message
            let msg = decode_hex(&test.msg);
            let msg_len_bytes = (test.len / 8) as usize;
            let msg_data = if msg_len_bytes <= msg.len() {
                &msg[..msg_len_bytes]
            } else {
                &msg[..]
            };

            // Parse function name and customization
            let function_name = if test_group.hex_customization {
                decode_hex(&test.function_name)
            } else {
                test.function_name.as_bytes().to_vec()
            };

            let customization = if test_group.hex_customization {
                decode_hex(&test.customization)
            } else {
                test.customization.as_bytes().to_vec()
            };

            let expected_md_str = match &expected_test.md {
                Some(md) => md,
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };
            let expected_md = decode_hex(expected_md_str);
            let out_len = match test.out_len {
                Some(len) => {
                    // Skip non-byte-aligned output lengths
                    if len % 8 != 0 {
                        stats.skipped += 1;
                        continue;
                    }
                    (len / 8) as usize
                }
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };

            // Compute cSHAKE-128
            let mut hasher = CShake128::new(&function_name, &customization);
            hasher.update(msg_data);
            let mut output = vec![0u8; out_len];
            hasher.finalize(&mut output);

            if output == expected_md {
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
        "cSHAKE-128 Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(
        stats.failed, 0,
        "{} tests failed for cSHAKE-128",
        stats.failed
    );
}

fn run_cshake256_tests() {
    println!("\nTesting cSHAKE-256");

    let prompt: PromptFile = load_test_file("cSHAKE-256-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("cSHAKE-256-1.0", "expectedResults.json");

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

            // Skip non-byte-aligned message lengths for now
            // (bit-level truncation would require special handling)
            if test.len % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            // Decode message
            let msg = decode_hex(&test.msg);
            let msg_len_bytes = (test.len / 8) as usize;
            let msg_data = if msg_len_bytes <= msg.len() {
                &msg[..msg_len_bytes]
            } else {
                &msg[..]
            };

            // Parse function name and customization
            let function_name = if test_group.hex_customization {
                decode_hex(&test.function_name)
            } else {
                test.function_name.as_bytes().to_vec()
            };

            let customization = if test_group.hex_customization {
                decode_hex(&test.customization)
            } else {
                test.customization.as_bytes().to_vec()
            };

            let expected_md_str = match &expected_test.md {
                Some(md) => md,
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };
            let expected_md = decode_hex(expected_md_str);
            let out_len = match test.out_len {
                Some(len) => {
                    // Skip non-byte-aligned output lengths
                    if len % 8 != 0 {
                        stats.skipped += 1;
                        continue;
                    }
                    (len / 8) as usize
                }
                None => {
                    stats.skipped += 1;
                    continue;
                }
            };

            // Compute cSHAKE-256
            let mut hasher = CShake256::new(&function_name, &customization);
            hasher.update(msg_data);
            let mut output = vec![0u8; out_len];
            hasher.finalize(&mut output);

            if output == expected_md {
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
        "cSHAKE-256 Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(
        stats.failed, 0,
        "{} tests failed for cSHAKE-256",
        stats.failed
    );
}

#[test]
fn test_cshake128() {
    run_cshake128_tests();
}

#[test]
fn test_cshake256() {
    run_cshake256_tests();
}
