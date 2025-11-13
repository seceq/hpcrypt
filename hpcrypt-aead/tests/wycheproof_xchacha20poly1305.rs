//! Wycheproof test vectors for XChaCha20-Poly1305
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! XChaCha20-Poly1305 AEAD implementations against known edge cases and potential vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - draft-arciszewski-xchacha

use hpcrypt_aead::chacha20poly1305::XChaCha20Poly1305;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    test_type: String,
    key_size: usize,
    iv_size: usize,
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

fn run_xchacha20poly1305_test(test: &TestCase) -> bool {
    // Check for valid key size (256 bits = 32 bytes)
    if test.key.len() != 32 {
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "XChaCha20-Poly1305 Test {} FAILED: Valid test has invalid key size: {}",
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

    // Check for valid nonce size (192 bits = 24 bytes for XChaCha20)
    if test.iv.len() != 24 {
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "XChaCha20-Poly1305 Test {} FAILED: Valid test has invalid nonce size: {}",
                    test.tc_id,
                    test.iv.len()
                );
                return false;
            }
            TestResult::Invalid | TestResult::Acceptable => {
                // Expected to be invalid for unsupported nonce sizes
                return true;
            }
        }
    }

    // Check for valid tag size (128 bits = 16 bytes)
    if test.tag.len() != 16 {
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "XChaCha20-Poly1305 Test {} FAILED: Valid test has invalid tag size: {}",
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

    // Create key and nonce arrays
    let mut key = [0u8; 32];
    key.copy_from_slice(&test.key);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&test.iv);

    match test.result {
        TestResult::Valid => {
            // For valid tests, encrypt and verify we get expected ciphertext+tag
            let ciphertext_with_tag =
                XChaCha20Poly1305::encrypt(&key, &nonce, &test.msg, &test.aad);

            // Expected output is ct || tag
            let mut expected = test.ct.clone();
            expected.extend_from_slice(&test.tag);

            if !constant_time_compare(&ciphertext_with_tag, &expected) {
                eprintln!(
                    "XChaCha20-Poly1305 Test {} FAILED: Valid test encryption mismatch: {}",
                    test.tc_id, test.comment
                );
                eprintln!(
                    "  Expected length: {}, Got length: {}",
                    expected.len(),
                    ciphertext_with_tag.len()
                );
                return false;
            }

            // Also test decryption
            let decrypted =
                XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext_with_tag, &test.aad);

            match decrypted {
                Some(plaintext) => {
                    if !constant_time_compare(&plaintext, &test.msg) {
                        eprintln!(
                            "XChaCha20-Poly1305 Test {} FAILED: Valid test decryption mismatch: {}",
                            test.tc_id, test.comment
                        );
                        return false;
                    }
                }
                None => {
                    eprintln!(
                        "XChaCha20-Poly1305 Test {} FAILED: Valid ciphertext rejected: {}",
                        test.tc_id, test.comment
                    );
                    return false;
                }
            }
        }
        TestResult::Invalid => {
            // For invalid tests, decryption should fail
            let mut ciphertext_with_tag = test.ct.clone();
            ciphertext_with_tag.extend_from_slice(&test.tag);

            let decrypted =
                XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext_with_tag, &test.aad);

            if decrypted.is_some() {
                eprintln!(
                    "XChaCha20-Poly1305 Test {} FAILED: Invalid ciphertext accepted: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // These typically involve edge cases
        }
    }

    true
}

#[test]
fn wycheproof_xchacha20poly1305() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/xchacha20_poly1305_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof XChaCha20-Poly1305 test vectors");

    println!(
        "Running {} Wycheproof XChaCha20-Poly1305 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        // We only support 256-bit keys
        if group.key_size != 256 {
            eprintln!(
                "Skipping test group with key size: {} bits (unsupported)",
                group.key_size
            );
            skipped_tests += group.tests.len();
            continue;
        }

        // We only support 192-bit nonces (24 bytes for XChaCha20)
        if group.iv_size != 192 {
            eprintln!(
                "Skipping test group with nonce size: {} bits (unsupported)",
                group.iv_size
            );
            skipped_tests += group.tests.len();
            continue;
        }

        // We only support 128-bit tags
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

            if run_xchacha20poly1305_test(&test) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "XChaCha20-Poly1305 Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests,
        total_tests,
        "Some XChaCha20-Poly1305 tests failed (note: {} tests were skipped for unsupported parameters)",
        skipped_tests
    );
}

// Test edge cases
#[test]
fn xchacha20poly1305_edge_cases() {
    let key = [0u8; 32];
    let nonce = [0u8; 24]; // 24 bytes for XChaCha20

    // Test with empty message
    let ciphertext1 = XChaCha20Poly1305::encrypt(&key, &nonce, b"", b"");
    assert_eq!(
        ciphertext1.len(),
        16,
        "Empty message should produce 16-byte tag only"
    );

    let decrypted1 = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext1, b"");
    assert_eq!(
        decrypted1,
        Some(vec![]),
        "Decryption of empty message should succeed"
    );

    // Test with non-empty message
    let msg = b"Hello, XChaCha20-Poly1305!";
    let ciphertext2 = XChaCha20Poly1305::encrypt(&key, &nonce, msg, b"");
    assert_eq!(
        ciphertext2.len(),
        msg.len() + 16,
        "Ciphertext should be plaintext + 16-byte tag"
    );

    let decrypted2 = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext2, b"");
    assert_eq!(
        decrypted2,
        Some(msg.to_vec()),
        "Decryption should recover plaintext"
    );

    // Test with AAD
    let aad = b"additional authenticated data";
    let ciphertext3 = XChaCha20Poly1305::encrypt(&key, &nonce, msg, aad);

    let decrypted3 = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext3, aad);
    assert_eq!(
        decrypted3,
        Some(msg.to_vec()),
        "Decryption with AAD should succeed"
    );

    // Wrong AAD should fail
    let decrypted4 = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext3, b"wrong aad");
    assert_eq!(decrypted4, None, "Decryption with wrong AAD should fail");

    // Modified ciphertext should fail
    let mut modified = ciphertext2.clone();
    modified[0] ^= 1;
    let decrypted5 = XChaCha20Poly1305::decrypt(&key, &nonce, &modified, b"");
    assert_eq!(
        decrypted5, None,
        "Decryption of modified ciphertext should fail"
    );

    // Modified tag should fail
    let mut modified_tag = ciphertext2.clone();
    let len = modified_tag.len();
    modified_tag[len - 1] ^= 1;
    let decrypted6 = XChaCha20Poly1305::decrypt(&key, &nonce, &modified_tag, b"");
    assert_eq!(decrypted6, None, "Decryption with modified tag should fail");

    println!("XChaCha20-Poly1305 edge case tests: All passed");
}
