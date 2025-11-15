//! Wycheproof test vectors for AES-GCM
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! AES-GCM implementations against known edge cases and potential vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - NIST SP 800-38D

use hpcrypt_aead::{Aes128Gcm, Aes192Gcm, Aes256Gcm};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    key_size: usize,
    #[allow(dead_code)]
    iv_size: usize,
    #[allow(dead_code)]
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
    iv: Vec<u8>,
    #[serde(with = "hex")]
    aad: Vec<u8>,
    #[serde(with = "hex")]
    msg: Vec<u8>,
    #[serde(with = "hex")]
    ct: Vec<u8>,
    #[serde(with = "hex")]
    tag: Vec<u8>,
    result: TestResult,
    #[allow(dead_code)]
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

fn run_aes128_gcm_test(test: &TestCase) -> bool {
    // Only test with 12-byte nonces (96-bit) as that's what our API supports
    if test.iv.len() != 12 {
        return true; // Skip tests with non-standard nonce sizes
    }

    if test.key.len() != 16 {
        return true; // Skip wrong key size
    }

    // Prepare key and nonce
    let key: [u8; 16] = test.key.as_slice().try_into().unwrap();
    let nonce: [u8; 12] = test.iv.as_slice().try_into().unwrap();

    // Prepare the test vector's ciphertext + tag for decryption testing
    let mut test_ciphertext_with_tag = test.ct.clone();
    test_ciphertext_with_tag.extend_from_slice(&test.tag);

    // For valid tests, also test encryption
    if test.result == TestResult::Valid {
        let ciphertext = Aes128Gcm::encrypt(&key, &nonce, &test.msg, &test.aad);

        if ciphertext != test_ciphertext_with_tag {
            eprintln!(
                "AES-128-GCM Test {} FAILED (encryption): {}",
                test.tc_id, test.comment
            );
            eprintln!("  Expected: {}", "[binary data]");
            eprintln!("  Got:      {}", "[binary data]");
            return false;
        }
    }

    // Test decryption with the test vector's ciphertext + tag
    let decrypted = Aes128Gcm::decrypt(&key, &nonce, &test_ciphertext_with_tag, &test.aad);

    match test.result {
        TestResult::Valid => match decrypted {
            Ok(plaintext) => {
                if plaintext != test.msg {
                    eprintln!(
                        "AES-128-GCM Test {} FAILED (decryption): {}",
                        test.tc_id, test.comment
                    );
                    eprintln!("  Expected: {}", "[binary data]");
                    eprintln!("  Got:      {}", "[binary data]");
                    return false;
                }
            }
            Err(_) => {
                eprintln!(
                    "AES-128-GCM Test {} FAILED: Valid test rejected: {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        },
        TestResult::Invalid => {
            if decrypted.is_ok() {
                eprintln!(
                    "AES-128-GCM Test {} FAILED: Invalid test accepted: {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail - we just document the behavior
            // No assertion needed
        }
    }

    true
}

fn run_aes192_gcm_test(test: &TestCase) -> bool {
    if test.iv.len() != 12 || test.key.len() != 24 {
        return true; // Skip non-standard sizes
    }

    let key: [u8; 24] = test.key.as_slice().try_into().unwrap();
    let nonce: [u8; 12] = test.iv.as_slice().try_into().unwrap();

    // Prepare the test vector's ciphertext + tag for decryption testing
    let mut test_ciphertext_with_tag = test.ct.clone();
    test_ciphertext_with_tag.extend_from_slice(&test.tag);

    // For valid tests, also test encryption
    if test.result == TestResult::Valid {
        let ciphertext = Aes192Gcm::encrypt(&key, &nonce, &test.msg, &test.aad);

        if ciphertext != test_ciphertext_with_tag {
            eprintln!(
                "AES-192-GCM Test {} FAILED (encryption): {}",
                test.tc_id, test.comment
            );
            return false;
        }
    }

    // Test decryption with the test vector's ciphertext + tag
    let decrypted = Aes192Gcm::decrypt(&key, &nonce, &test_ciphertext_with_tag, &test.aad);

    match test.result {
        TestResult::Valid => {
            if decrypted.is_err() || decrypted.as_ref().unwrap() != &test.msg {
                eprintln!(
                    "AES-192-GCM Test {} FAILED (decryption): {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        }
        TestResult::Invalid => {
            if decrypted.is_ok() {
                eprintln!(
                    "AES-192-GCM Test {} FAILED: Invalid test accepted: {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        }
        TestResult::Acceptable => {
            // No assertion for acceptable tests
        }
    }

    true
}

fn run_aes256_gcm_test(test: &TestCase) -> bool {
    if test.iv.len() != 12 || test.key.len() != 32 {
        return true; // Skip non-standard sizes
    }

    let key: [u8; 32] = test.key.as_slice().try_into().unwrap();
    let nonce: [u8; 12] = test.iv.as_slice().try_into().unwrap();

    // Prepare the test vector's ciphertext + tag for decryption testing
    let mut test_ciphertext_with_tag = test.ct.clone();
    test_ciphertext_with_tag.extend_from_slice(&test.tag);

    // For valid tests, also test encryption
    if test.result == TestResult::Valid {
        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &test.msg, &test.aad);

        if ciphertext != test_ciphertext_with_tag {
            eprintln!(
                "AES-256-GCM Test {} FAILED (encryption): {}",
                test.tc_id, test.comment
            );
            return false;
        }
    }

    // Test decryption with the test vector's ciphertext + tag
    let decrypted = Aes256Gcm::decrypt(&key, &nonce, &test_ciphertext_with_tag, &test.aad);

    match test.result {
        TestResult::Valid => {
            if decrypted.is_err() || decrypted.as_ref().unwrap() != &test.msg {
                eprintln!(
                    "AES-256-GCM Test {} FAILED (decryption): {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        }
        TestResult::Invalid => {
            if decrypted.is_ok() {
                eprintln!(
                    "AES-256-GCM Test {} FAILED: Invalid test accepted: {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        }
        TestResult::Acceptable => {
            // No assertion for acceptable tests
        }
    }

    true
}

#[test]
#[cfg(wycheproof_test_vectors)]
fn wycheproof_aes_gcm() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/aes_gcm_test.json");
    let test_file: TestFile =
        serde_json::from_str(test_data).expect("Failed to parse Wycheproof AES-GCM test vectors");

    println!(
        "Running {} Wycheproof AES-GCM tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        for test in group.tests {
            total_tests += 1;

            let result = match group.key_size {
                128 => run_aes128_gcm_test(&test),
                192 => run_aes192_gcm_test(&test),
                256 => run_aes256_gcm_test(&test),
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
        "AES-GCM Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some AES-GCM tests failed"
    );
}
