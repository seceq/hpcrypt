//! Wycheproof tests for KMAC128 and KMAC256
//!
//! Tests for:
//! - KMAC128 (no customization)
//! - KMAC256 (no customization)
//!
//! KMAC (Keccak Message Authentication Code) is defined in NIST SP 800-185
//! and provides a variable-length MAC based on cSHAKE (customizable SHAKE).

#[cfg(feature = "enable-mac-tests")]
use hpcrypt_mac::{kmac128, kmac256};
use serde::Deserialize;
use wycheproof_tests::{decode_hex, TestResult, TestStats};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmacTest {
    tc_id: usize,
    comment: String,
    key: String,
    msg: String,
    tag: String,
    result: TestResult,
    flags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmacGroup {
    #[serde(rename = "type")]
    test_type: String,
    key_size: usize,
    tag_size: usize,
    tests: Vec<KmacTest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmacTestFile {
    algorithm: String,
    number_of_tests: usize,
    test_groups: Vec<KmacGroup>,
}

// ============================================================================
// KMAC128 Tests
// ============================================================================

#[test]
fn test_kmac128_wycheproof() {
    test_kmac128_file("kmac128_no_customization_test.json", "KMAC128");
}

// ============================================================================
// KMAC256 Tests
// ============================================================================

#[test]
fn test_kmac256_wycheproof() {
    test_kmac256_file("kmac256_no_customization_test.json", "KMAC256");
}

// ============================================================================
// Test Execution Functions
// ============================================================================

#[cfg(feature = "enable-mac-tests")]
fn test_kmac128_file(filename: &str, algorithm_name: &str) {
    let test_file: KmacTestFile = wycheproof_tests::load_test_file(filename);

    println!("\n=== {} Wycheproof Tests ===", algorithm_name);
    println!("Total test cases: {}", test_file.number_of_tests);
    assert_eq!(test_file.algorithm, algorithm_name);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        println!("\n--- Group: {} ---", group.test_type);
        println!("  Key size: {} bits", group.key_size);
        println!("  Tag size: {} bits", group.tag_size);

        for test in &group.tests {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_tag = decode_hex(&test.tag);

            // Tag size in bytes
            let tag_len = group.tag_size / 8;

            // Compute KMAC128 (with empty customization string)
            let computed_tag = kmac128(&key, &msg, b"", tag_len);

            // Check result
            let matches = computed_tag == expected_tag;

            match (&test.result, matches) {
                (TestResult::Valid, true) => {
                    stats.passed += 1;
                }
                (TestResult::Valid, false) => {
                    println!("  FAIL: Test {} - Valid test case produced wrong tag", test.tc_id);
                    println!("    Comment: {}", test.comment);
                    println!("    Expected: {}", test.tag);
                    println!("    Got:      {}", hex::encode(&computed_tag));
                    stats.failed += 1;
                }
                (TestResult::Invalid, false) => {
                    // Invalid test case correctly rejected
                    stats.passed += 1;
                }
                (TestResult::Invalid, true) => {
                    println!(
                        "  FAIL: Test {} - Invalid test case accepted",
                        test.tc_id
                    );
                    println!("    Comment: {}", test.comment);
                    println!("    Flags: {:?}", test.flags);
                    stats.failed += 1;
                }
                (TestResult::Acceptable, _) => {
                    // Acceptable results are implementation-dependent
                    stats.passed += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "{} Wycheproof tests failed", stats.failed);
}

#[cfg(feature = "enable-mac-tests")]
fn test_kmac256_file(filename: &str, algorithm_name: &str) {
    let test_file: KmacTestFile = wycheproof_tests::load_test_file(filename);

    println!("\n=== {} Wycheproof Tests ===", algorithm_name);
    println!("Total test cases: {}", test_file.number_of_tests);
    assert_eq!(test_file.algorithm, algorithm_name);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        println!("\n--- Group: {} ---", group.test_type);
        println!("  Key size: {} bits", group.key_size);
        println!("  Tag size: {} bits", group.tag_size);

        for test in &group.tests {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_tag = decode_hex(&test.tag);

            // Tag size in bytes
            let tag_len = group.tag_size / 8;

            // Compute KMAC256 (with empty customization string)
            let computed_tag = kmac256(&key, &msg, b"", tag_len);

            // Check result
            let matches = computed_tag == expected_tag;

            match (&test.result, matches) {
                (TestResult::Valid, true) => {
                    stats.passed += 1;
                }
                (TestResult::Valid, false) => {
                    println!("  FAIL: Test {} - Valid test case produced wrong tag", test.tc_id);
                    println!("    Comment: {}", test.comment);
                    println!("    Expected: {}", test.tag);
                    println!("    Got:      {}", hex::encode(&computed_tag));
                    stats.failed += 1;
                }
                (TestResult::Invalid, false) => {
                    // Invalid test case correctly rejected
                    stats.passed += 1;
                }
                (TestResult::Invalid, true) => {
                    println!(
                        "  FAIL: Test {} - Invalid test case accepted",
                        test.tc_id
                    );
                    println!("    Comment: {}", test.comment);
                    println!("    Flags: {:?}", test.flags);
                    stats.failed += 1;
                }
                (TestResult::Acceptable, _) => {
                    // Acceptable results are implementation-dependent
                    stats.passed += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "{} Wycheproof tests failed", stats.failed);
}

// ============================================================================
// Stub tests for non-MAC builds
// ============================================================================

#[cfg(not(feature = "enable-mac-tests"))]
fn test_kmac128_file(_filename: &str, algorithm_name: &str) {
    println!(
        "{} tests skipped: enable-mac-tests feature not enabled",
        algorithm_name
    );
}

#[cfg(not(feature = "enable-mac-tests"))]
fn test_kmac256_file(_filename: &str, algorithm_name: &str) {
    println!(
        "{} tests skipped: enable-mac-tests feature not enabled",
        algorithm_name
    );
}
