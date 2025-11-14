//! Wycheproof test vectors for AES-CMAC
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! AES-CMAC implementations against known edge cases and potential vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - NIST SP 800-38B (CMAC)
//! - RFC 4493 (AES-CMAC)

use hpcrypt_mac::cmac::AesCmac128;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    key_size: usize,
    tag_size: usize,
    tests: Vec<TestCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    #[serde(with = "hex")]
    key: Vec<u8>,
    #[serde(with = "hex")]
    msg: Vec<u8>,
    #[serde(with = "hex")]
    tag: Vec<u8>,
    result: TestResult,
    flags: Vec<String>,
}

#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestFile {
    #[allow(dead_code)]
    algorithm: String,
    number_of_tests: usize,
    test_groups: Vec<TestGroup>,
}

mod hex {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

fn run_aes_cmac_test(test: &TestCase) -> bool {
    // Check for valid key size (we only support 128-bit keys)
    if test.key.len() != 16 {
        // This is expected to fail for non-128-bit keys
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "AES-CMAC Test {} FAILED: Valid test has invalid key size: {}",
                    test.tc_id,
                    test.key.len()
                );
                return false;
            }
            TestResult::Invalid | TestResult::Acceptable => {
                // Expected to be invalid for unsupported key sizes
                return true;
            }
        }
    }

    // Check for valid tag size (we produce 128-bit tags)
    if test.tag.len() != 16 {
        // Tests with non-standard tag sizes
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "AES-CMAC Test {} FAILED: Valid test has non-standard tag size: {}",
                    test.tc_id,
                    test.tag.len()
                );
                return false;
            }
            TestResult::Invalid | TestResult::Acceptable => {
                // Expected to be invalid for unsupported tag sizes
                return true;
            }
        }
    }

    // Create key array
    let mut key = [0u8; 16];
    key.copy_from_slice(&test.key);

    // Compute CMAC
    let cmac = AesCmac128::new(&key);
    let computed_tag = cmac.compute(&test.msg);

    let matches = constant_time_compare(&computed_tag, &test.tag);

    match test.result {
        TestResult::Valid => {
            if !matches {
                eprintln!(
                    "AES-CMAC Test {} FAILED: Valid test produced wrong tag: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Expected: {}", "[binary data]");
                eprintln!("  Got:      {}", "[binary data]");
                return false;
            }
        }
        TestResult::Invalid => {
            if matches {
                eprintln!(
                    "AES-CMAC Test {} FAILED: Invalid test produced expected tag: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // These might be edge cases with unusual parameters
        }
    }

    true
}

#[test]
fn wycheproof_aes_cmac() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/aes_cmac_test.json");
    let test_file: TestFile =
        serde_json::from_str(test_data).expect("Failed to parse Wycheproof AES-CMAC test vectors");

    println!(
        "Running {} Wycheproof AES-CMAC tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        // We only support 128-bit keys
        if group.key_size != 128 {
            eprintln!(
                "Skipping test group with key size: {} bits (unsupported)",
                group.key_size
            );
            skipped_tests += group.tests.len();
            continue;
        }

        // We only produce 128-bit tags
        if group.tag_size != 128 {
            eprintln!(
                "Skipping test group with tag size: {} bits (unsupported)",
                group.tag_size
            );
            skipped_tests += group.tests.len();
            continue;
        }

        for test in group.tests {
            total_tests += 1;

            if run_aes_cmac_test(&test) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "AES-CMAC Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests, total_tests,
        "Some AES-CMAC tests failed (note: {} tests were skipped for unsupported parameters)",
        skipped_tests
    );
}

// Test edge cases
#[test]
fn aes_cmac_edge_cases() {
    // Test with empty message
    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let cmac = AesCmac128::new(&key);
    let tag = cmac.compute(b"");
    assert_ne!(
        tag, [0u8; 16],
        "Tag for empty message should not be all zeros"
    );

    // Test with single block
    let tag_single = cmac.compute(&[0u8; 16]);
    assert_ne!(
        tag_single, tag,
        "Different messages should produce different tags"
    );

    // Test with multiple blocks
    let tag_multi = cmac.compute(&[0u8; 32]);
    assert_ne!(
        tag_multi, tag_single,
        "Different lengths should produce different tags"
    );

    // Test with incomplete block
    let tag_incomplete = cmac.compute(&[0u8; 10]);
    assert_ne!(
        tag_incomplete, tag_single,
        "Incomplete blocks should produce different tags"
    );

    // Test verification
    assert!(
        cmac.verify(b"", &tag),
        "Verification should succeed for matching tag"
    );
    assert!(
        !cmac.verify(b"", &tag_single),
        "Verification should fail for mismatched tag"
    );

    println!("AES-CMAC edge case tests: All passed");
}
