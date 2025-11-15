//! Wycheproof test vectors for HKDF
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! HKDF implementations against known edge cases and potential vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - RFC 5869 (HKDF)

use hpcrypt_kdf::{hkdf_sha256, hkdf_sha384, hkdf_sha512, HkdfSha256, HkdfSha384, HkdfSha512};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    #[allow(dead_code)]
    key_size: usize,
    tests: Vec<TestCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    #[serde(with = "hex")]
    ikm: Vec<u8>,
    #[serde(with = "hex")]
    salt: Vec<u8>,
    #[serde(with = "hex")]
    info: Vec<u8>,
    size: usize,
    #[serde(with = "hex")]
    okm: Vec<u8>,
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

fn run_hkdf_sha256_test(test: &TestCase) -> bool {
    // HKDF has a maximum output length of 255 * hash_len
    // For SHA-256, this is 255 * 32 = 8160 bytes
    const MAX_OUTPUT_LEN: usize = 255 * 32;

    // Check if output size exceeds maximum
    if test.size > MAX_OUTPUT_LEN {
        // This is expected to fail - HKDF cannot produce this much output
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "HKDF-SHA256 Test {} FAILED: Valid test requests impossible output length: {}",
                    test.tc_id, test.size
                );
                return false;
            }
            TestResult::Invalid | TestResult::Acceptable => {
                // Expected to be invalid - output size exceeds maximum
                return true;
            }
        }
    }

    // Allocate output buffer
    let mut output = vec![0u8; test.size];

    // Run HKDF
    hkdf_sha256(&test.salt, &test.ikm, &test.info, &mut output);

    let matches = constant_time_compare(&output, &test.okm);

    match test.result {
        TestResult::Valid => {
            if !matches {
                eprintln!(
                    "HKDF-SHA256 Test {} FAILED: Valid test produced wrong output: {}",
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
                    "HKDF-SHA256 Test {} FAILED: Invalid test produced expected output: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // For HKDF, these might be edge cases with unusual parameters
        }
    }

    true
}

fn run_hkdf_sha384_test(test: &TestCase) -> bool {
    // HKDF has a maximum output length of 255 * hash_len
    // For SHA-384, this is 255 * 48 = 12240 bytes
    const MAX_OUTPUT_LEN: usize = 255 * 48;

    // Check if output size exceeds maximum
    if test.size > MAX_OUTPUT_LEN {
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "HKDF-SHA384 Test {} FAILED: Valid test requests impossible output length: {}",
                    test.tc_id, test.size
                );
                return false;
            }
            TestResult::Invalid | TestResult::Acceptable => {
                return true;
            }
        }
    }

    let mut output = vec![0u8; test.size];
    hkdf_sha384(&test.salt, &test.ikm, &test.info, &mut output);

    let matches = constant_time_compare(&output, &test.okm);

    match test.result {
        TestResult::Valid => {
            if !matches {
                eprintln!(
                    "HKDF-SHA384 Test {} FAILED: Valid test produced wrong output: {}",
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
                    "HKDF-SHA384 Test {} FAILED: Invalid test produced expected output: {}",
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

fn run_hkdf_sha512_test(test: &TestCase) -> bool {
    // HKDF has a maximum output length of 255 * hash_len
    // For SHA-512, this is 255 * 64 = 16320 bytes
    const MAX_OUTPUT_LEN: usize = 255 * 64;

    // Check if output size exceeds maximum
    if test.size > MAX_OUTPUT_LEN {
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "HKDF-SHA512 Test {} FAILED: Valid test requests impossible output length: {}",
                    test.tc_id, test.size
                );
                return false;
            }
            TestResult::Invalid | TestResult::Acceptable => {
                return true;
            }
        }
    }

    let mut output = vec![0u8; test.size];
    hkdf_sha512(&test.salt, &test.ikm, &test.info, &mut output);

    let matches = constant_time_compare(&output, &test.okm);

    match test.result {
        TestResult::Valid => {
            if !matches {
                eprintln!(
                    "HKDF-SHA512 Test {} FAILED: Valid test produced wrong output: {}",
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
                    "HKDF-SHA512 Test {} FAILED: Invalid test produced expected output: {}",
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
#[cfg(wycheproof_test_vectors)]
fn wycheproof_hkdf_sha256() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/hkdf_sha256_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof HKDF-SHA256 test vectors");

    println!(
        "Running {} Wycheproof HKDF-SHA256 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;

    for group in test_file.test_groups {
        for test in group.tests {
            total_tests += 1;

            if run_hkdf_sha256_test(&test) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "HKDF-SHA256 Wycheproof: {}/{} tests passed",
        passed_tests, total_tests
    );

    assert_eq!(passed_tests, total_tests, "Some HKDF-SHA256 tests failed");
}

#[test]
#[cfg(wycheproof_test_vectors)]
fn wycheproof_hkdf_sha384() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/hkdf_sha384_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof HKDF-SHA384 test vectors");

    println!(
        "Running {} Wycheproof HKDF-SHA384 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;

    for group in test_file.test_groups {
        for test in group.tests {
            total_tests += 1;

            if run_hkdf_sha384_test(&test) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "HKDF-SHA384 Wycheproof: {}/{} tests passed",
        passed_tests, total_tests
    );

    assert_eq!(passed_tests, total_tests, "Some HKDF-SHA384 tests failed");
}

#[test]
#[cfg(wycheproof_test_vectors)]
fn wycheproof_hkdf_sha512() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/hkdf_sha512_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof HKDF-SHA512 test vectors");

    println!(
        "Running {} Wycheproof HKDF-SHA512 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;

    for group in test_file.test_groups {
        for test in group.tests {
            total_tests += 1;

            if run_hkdf_sha512_test(&test) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "HKDF-SHA512 Wycheproof: {}/{} tests passed",
        passed_tests, total_tests
    );

    assert_eq!(passed_tests, total_tests, "Some HKDF-SHA512 tests failed");
}

// Test HKDF edge cases
#[test]
fn hkdf_edge_cases() {
    // Test with empty salt
    let ikm = b"input key material";
    let info = b"info";
    let mut okm1 = [0u8; 32];
    hkdf_sha256(b"", ikm, info, &mut okm1);
    assert_ne!(okm1, [0u8; 32], "Output should not be all zeros");

    // Test with empty info
    let mut okm2 = [0u8; 32];
    hkdf_sha256(b"salt", ikm, b"", &mut okm2);
    assert_ne!(okm2, [0u8; 32], "Output should not be all zeros");
    assert_ne!(okm1, okm2, "Different info should produce different output");

    // Test with empty IKM (edge case)
    let mut okm3 = [0u8; 32];
    hkdf_sha256(b"salt", b"", info, &mut okm3);
    assert_ne!(okm3, [0u8; 32], "Output should not be all zeros");

    // Test with all empty
    let mut okm4 = [0u8; 32];
    hkdf_sha256(b"", b"", b"", &mut okm4);
    assert_ne!(okm4, [0u8; 32], "Output should not be all zeros");

    // Test with various output lengths
    for len in [16, 32, 48, 64, 96, 128] {
        let mut okm = vec![0u8; len];
        hkdf_sha256(b"salt", ikm, info, &mut okm);
        assert!(
            okm.iter().any(|&b| b != 0),
            "Output should not be all zeros for length {}",
            len
        );
    }

    // Test with different hash functions
    let mut okm_256 = [0u8; 64];
    let mut okm_384 = [0u8; 64];
    let mut okm_512 = [0u8; 64];

    hkdf_sha256(b"salt", ikm, info, &mut okm_256);
    hkdf_sha384(b"salt", ikm, info, &mut okm_384);
    hkdf_sha512(b"salt", ikm, info, &mut okm_512);

    // Different hash functions should produce different outputs
    assert_ne!(okm_256, okm_384, "SHA-256 and SHA-384 should differ");
    assert_ne!(okm_256, okm_512, "SHA-256 and SHA-512 should differ");
    assert_ne!(okm_384, okm_512, "SHA-384 and SHA-512 should differ");

    println!("HKDF edge case tests: All passed");
}

// Test using the struct API
#[test]
fn hkdf_struct_api() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"info";

    // Test SHA-256
    let hkdf = HkdfSha256::new(salt, ikm);
    let mut okm256 = [0u8; 42];
    hkdf.expand(info, &mut okm256)
        .expect("Expansion should succeed");
    assert_ne!(okm256, [0u8; 42], "Output should not be all zeros");

    // Test SHA-384
    let hkdf = HkdfSha384::new(salt, ikm);
    let mut okm384 = [0u8; 42];
    hkdf.expand(info, &mut okm384)
        .expect("Expansion should succeed");
    assert_ne!(okm384, [0u8; 42], "Output should not be all zeros");
    assert_ne!(
        okm256, okm384,
        "Different hash functions should produce different outputs"
    );

    // Test SHA-512
    let hkdf = HkdfSha512::new(salt, ikm);
    let mut okm512 = [0u8; 42];
    hkdf.expand(info, &mut okm512)
        .expect("Expansion should succeed");
    assert_ne!(okm512, [0u8; 42], "Output should not be all zeros");

    println!("HKDF struct API tests: All passed");
}
