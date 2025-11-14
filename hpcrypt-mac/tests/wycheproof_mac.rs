//! Wycheproof test vectors for Message Authentication Codes (MACs)
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! MAC implementations (HMAC and CMAC) against known edge cases and vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - RFC 2104 (HMAC)
//! - NIST SP 800-38B (CMAC)

use hpcrypt_mac::{aes_cmac_128, aes_cmac_256};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    key_size: usize,
    #[allow(dead_code)]
    tag_size: usize,
    tests: Vec<TestCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    #[serde(with = "hex_serde")]
    key: Vec<u8>,
    #[serde(with = "hex_serde")]
    msg: Vec<u8>,
    #[serde(with = "hex_serde")]
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

mod hex_serde {
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

fn run_cmac_aes128_test(test: &TestCase) -> bool {
    // Only test with 128-bit keys
    if test.key.len() != 16 {
        return true; // Skip non-standard key sizes
    }

    let key: [u8; 16] = test.key.as_slice().try_into().unwrap();

    // Compute CMAC
    let computed_tag = aes_cmac_128(&key, &test.msg);

    // For CMAC, we need to compare only the first tag_size bytes
    let tag_to_compare = if test.tag.len() <= 16 {
        &computed_tag[..test.tag.len()]
    } else {
        &computed_tag[..]
    };

    let matches = constant_time_compare(tag_to_compare, &test.tag);

    match test.result {
        TestResult::Valid => {
            if !matches {
                eprintln!(
                    "CMAC-AES-128 Test {} FAILED: Valid test produced wrong tag: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Expected tag length: {}", test.tag.len());
                eprintln!("  Got tag length:      {}", tag_to_compare.len());
                return false;
            }
        }
        TestResult::Invalid => {
            if matches {
                eprintln!(
                    "CMAC-AES-128 Test {} FAILED: Invalid tag verified: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
        }
    }

    true
}

fn run_cmac_aes256_test(test: &TestCase) -> bool {
    // Only test with 256-bit keys
    if test.key.len() != 32 {
        return true; // Skip non-standard key sizes
    }

    let key: [u8; 32] = test.key.as_slice().try_into().unwrap();

    // Compute CMAC
    let computed_tag = aes_cmac_256(&key, &test.msg);

    // For CMAC, we need to compare only the first tag_size bytes
    let tag_to_compare = if test.tag.len() <= 16 {
        &computed_tag[..test.tag.len()]
    } else {
        &computed_tag[..]
    };

    let matches = constant_time_compare(tag_to_compare, &test.tag);

    match test.result {
        TestResult::Valid => {
            if !matches {
                eprintln!(
                    "CMAC-AES-256 Test {} FAILED: Valid test produced wrong tag: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Expected tag length: {}", test.tag.len());
                eprintln!("  Got tag length:      {}", tag_to_compare.len());
                return false;
            }
        }
        TestResult::Invalid => {
            if matches {
                eprintln!(
                    "CMAC-AES-256 Test {} FAILED: Invalid tag verified: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
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
        for test in group.tests {
            total_tests += 1;

            let result = match group.key_size {
                128 => run_cmac_aes128_test(&test),
                256 => run_cmac_aes256_test(&test),
                _ => {
                    skipped_tests += 1;
                    continue;
                }
            };

            if result {
                passed_tests += 1;
            }
        }
    }

    println!(
        "AES-CMAC Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some AES-CMAC tests failed"
    );
}

// Note: HMAC tests would require access to HMAC implementations
// These are typically in the hpcrypt-hash crate
// For now, we'll add basic HMAC test structure that can be expanded

#[test]
#[ignore] // Ignore for now - HMAC is in hpcrypt-hash, not hpcrypt-mac
fn wycheproof_hmac_sha256() {
    // Note: HMAC is implemented in hpcrypt-hash crate, not hpcrypt-mac
    // These tests should be added to hpcrypt-hash/tests/wycheproof_hmac.rs
    println!("HMAC-SHA256 Wycheproof tests: Placeholder");
    println!("TODO: Add HMAC tests to hpcrypt-hash crate");
    println!("Test vectors: ../../../wycheproof/testvectors_v1/hmac_sha256_test.json");
}

#[test]
#[ignore] // Ignore for now - HMAC is in hpcrypt-hash, not hpcrypt-mac
fn wycheproof_hmac_sha512() {
    // Note: HMAC is implemented in hpcrypt-hash crate, not hpcrypt-mac
    // These tests should be added to hpcrypt-hash/tests/wycheproof_hmac.rs
    println!("HMAC-SHA512 Wycheproof tests: Placeholder");
    println!("TODO: Add HMAC tests to hpcrypt-hash crate");
    println!("Test vectors: ../../../wycheproof/testvectors_v1/hmac_sha512_test.json");
}

// Test CMAC edge cases
#[test]
fn cmac_edge_cases() {
    // Test with empty message
    let key = [0x2b; 16];
    let empty_msg = b"";
    let tag = aes_cmac_128(&key, empty_msg);
    assert_eq!(tag.len(), 16, "CMAC tag should be 16 bytes");

    // Test with message shorter than block size
    let short_msg = b"short";
    let tag_short = aes_cmac_128(&key, short_msg);
    assert_eq!(tag_short.len(), 16, "CMAC tag should be 16 bytes");
    assert_ne!(
        tag, tag_short,
        "Different messages should produce different tags"
    );

    // Test with message equal to block size
    let block_msg = b"exactly 16 bytes";
    let tag_block = aes_cmac_128(&key, block_msg);
    assert_eq!(tag_block.len(), 16, "CMAC tag should be 16 bytes");

    // Test with message longer than block size
    let long_msg = b"This message is longer than one AES block";
    let tag_long = aes_cmac_128(&key, long_msg);
    assert_eq!(tag_long.len(), 16, "CMAC tag should be 16 bytes");

    // Test with AES-256
    let key256 = [0x42; 32];
    let tag256 = aes_cmac_256(&key256, long_msg);
    assert_eq!(tag256.len(), 16, "CMAC tag should be 16 bytes");
    assert_ne!(
        tag_long, tag256,
        "AES-128 and AES-256 CMAC should produce different tags"
    );

    println!("CMAC edge case tests: All passed");
}
