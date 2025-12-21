//! NIST CAVP/ACVP Test Vectors for AES-GMAC
//!
//! Tests AES-GMAC (Galois Message Authentication Code) against NIST test vectors.
//! GMAC is the authentication-only mode of GCM.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-GMAC-1.0/

#![cfg(feature = "enable-mac-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_mac::gmac_variable;
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
    #[serde(rename = "ivLen")]
    iv_len: u32,
    #[serde(rename = "tagLen")]
    tag_len: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    iv: String,
    aad: String,
    /// Tag field for verification tests
    #[serde(default)]
    tag: Option<String>,
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
    tag: Option<String>,
    #[serde(rename = "testPassed")]
    test_passed: Option<bool>,
}

fn run_gmac_tests() {
    println!("\nTesting AES-GMAC with variable IV/tag lengths");

    let prompt: PromptFile = load_test_file("ACVP-AES-GMAC-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-GMAC-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Validate tag length is supported (NIST SP 800-38D: 32, 64, 96, 104, 112, 120, 128 bits)
        let tag_len_bytes = (test_group.tag_len / 8) as usize;
        if !matches!(tag_len_bytes, 4 | 8 | 12 | 13 | 14 | 15 | 16) {
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

            let key = decode_hex(&test.key);
            let iv = decode_hex(&test.iv);
            let aad = if test.aad.is_empty() {
                vec![]
            } else {
                decode_hex(&test.aad)
            };

            // Handle generation tests (AFT: expected has tag field)
            if let Some(ref expected_tag_hex) = expected_test.tag {
                let expected_tag = decode_hex(expected_tag_hex);

                match gmac_variable(&key, &iv, &aad, tag_len_bytes) {
                    Ok(tag) => {
                        if tag == expected_tag {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} tag mismatch (group {})",
                                test.tc_id, test_group.tg_id
                            );
                            println!("  Expected: {:02x?}", expected_tag);
                            println!("  Got:      {:02x?}", tag);
                            stats.failed += 1;
                        }
                    }
                    Err(e) => {
                        println!("FAIL: Test {} error: {:?}", test.tc_id, e);
                        stats.failed += 1;
                    }
                }
            } else if let Some(test_passed) = expected_test.test_passed {
                // Verification test (MVT): prompt has tag, expected has testPassed
                let provided_tag = match &test.tag {
                    Some(t) => decode_hex(t),
                    None => {
                        stats.skipped += 1;
                        continue;
                    }
                };

                match gmac_variable(&key, &iv, &aad, tag_len_bytes) {
                    Ok(computed_tag) => {
                        let tags_match = computed_tag == provided_tag;
                        if tags_match == test_passed {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: MVT Test {} - expected testPassed={}, got tags_match={} (group {})",
                                test.tc_id, test_passed, tags_match, test_group.tg_id
                            );
                            stats.failed += 1;
                        }
                    }
                    Err(e) => {
                        println!("FAIL: Test {} error: {:?}", test.tc_id, e);
                        stats.failed += 1;
                    }
                }
            } else {
                // Unknown test type
                stats.skipped += 1;
            }
        }
    }

    println!(
        "AES-GMAC Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(
        stats.failed, 0,
        "{} tests failed for AES-GMAC",
        stats.failed
    );
}

#[test]
fn test_aes_gmac() {
    run_gmac_tests();
}
