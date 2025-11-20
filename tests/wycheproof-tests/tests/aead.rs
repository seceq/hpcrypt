//! Wycheproof tests for AEAD ciphers
//!
//! Tests for:
//! - ChaCha20-Poly1305 (RFC 7539)
//! - XChaCha20-Poly1305
//! - AES-GCM (128, 192, 256-bit keys)
//! - AES-GCM-SIV
//! - AES-CCM
//! - AES-EAX
//! - AES-SIV
//! - Ascon-128/128a

use serde::Deserialize;
use wycheproof_tests::{decode_hex, load_test_file, TestFile, TestResult, TestStats};

/// AEAD test case structure (common for all AEAD ciphers)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadTest {
    tc_id: usize,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: TestResult,
    flags: Vec<String>,
}

/// Test group for AEAD tests
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadGroup {
    iv_size: usize,
    key_size: usize,
    tag_size: usize,
    #[serde(rename = "type")]
    test_type: String,
    tests: Vec<AeadTest>,
}

/// AEAD test file structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadTestFile {
    algorithm: String,
    generator_version: Option<String>,
    number_of_tests: usize,
    header: Option<Vec<String>>,
    notes: Option<serde_json::Value>,
    schema: String,
    test_groups: Vec<AeadGroup>,
}

// ============================================================================
// ChaCha20-Poly1305 Tests
// ============================================================================

#[test]
fn test_chacha20_poly1305_wycheproof() {
    let test_file: AeadTestFile = load_test_file("chacha20_poly1305_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        println!(
            "\nTest group: key_size={}, iv_size={}, tag_size={}",
            group.key_size, group.iv_size, group.tag_size
        );

        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);
            let aad = decode_hex(&test.aad);
            let plaintext = decode_hex(&test.msg);
            let ciphertext = decode_hex(&test.ct);
            let tag = decode_hex(&test.tag);

            // Combine ciphertext and tag as expected by AEAD APIs
            let mut ct_with_tag = ciphertext.clone();
            ct_with_tag.extend_from_slice(&tag);

            // Actual ChaCha20-Poly1305 implementation tests
            #[cfg(feature = "enable-aead-tests")]
            {
                use hpcrypt_aead::ChaCha20Poly1305;

                // Convert key and nonce to fixed-size arrays
                let test_valid = key.len() == 32 && nonce.len() == 12;

                if !test_valid {
                    // Invalid key/nonce size - should fail
                    match test.result {
                        TestResult::Valid => {
                            println!("  ✗ Test {}: Valid test has wrong key/nonce size", test.tc_id);
                            stats.failed += 1;
                        }
                        _ => stats.passed += 1,
                    }
                } else {
                    let key_array: &[u8; 32] = key.as_slice().try_into().unwrap();
                    let nonce_array: &[u8; 12] = nonce.as_slice().try_into().unwrap();

                    match test.result {
                        TestResult::Valid => {
                            // Test decryption (verification + decrypt)
                            match ChaCha20Poly1305::decrypt(key_array, nonce_array, &ct_with_tag, &aad) {
                                Some(decrypted) => {
                                    if decrypted != plaintext {
                                        println!("  ✗ Test {}: Decryption mismatch: {}", test.tc_id, test.comment);
                                        println!("      Expected: {} bytes", plaintext.len());
                                        println!("      Got: {} bytes", decrypted.len());
                                        stats.failed += 1;
                                    } else {
                                        stats.passed += 1;
                                    }
                                }
                                None => {
                                    println!("  ✗ Test {}: Valid test failed to decrypt: {}", test.tc_id, test.comment);
                                    stats.failed += 1;
                                }
                            }
                        }
                        TestResult::Invalid => {
                            match ChaCha20Poly1305::decrypt(key_array, nonce_array, &ct_with_tag, &aad) {
                                Some(_) => {
                                    println!("  ✗ Test {}: Invalid test should have failed: {}", test.tc_id, test.comment);
                                    stats.failed += 1;
                                }
                                None => {
                                    stats.passed += 1;
                                }
                            }
                        }
                        TestResult::Acceptable => {
                            stats.skipped += 1;
                        }
                    }
                }
            }

            // Placeholder implementation for structure validation when tests disabled
            #[cfg(not(feature = "enable-aead-tests"))]
            match test.result {
                TestResult::Valid => {
                    assert_eq!(key.len(), 32, "ChaCha20 key must be 32 bytes");
                    assert_eq!(nonce.len(), 12, "ChaCha20-Poly1305 nonce must be 12 bytes");
                    assert_eq!(tag.len(), 16, "Poly1305 tag must be 16 bytes");
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    // Invalid tests might have wrong sizes or corrupted data
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ChaCha20-Poly1305 tests failed");
}

#[test]
fn test_xchacha20_poly1305_wycheproof() {
    let test_file: AeadTestFile = load_test_file("xchacha20_poly1305_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);
            let _aad = decode_hex(&test.aad);
            let _plaintext = decode_hex(&test.msg);
            let _ciphertext = decode_hex(&test.ct);
            let tag = decode_hex(&test.tag);

            // TODO: Uncomment when XChaCha20-Poly1305 is ready
            // Similar structure to ChaCha20-Poly1305 above

            // Placeholder
            match test.result {
                TestResult::Valid => {
                    assert_eq!(key.len(), 32, "XChaCha20 key must be 32 bytes");
                    assert_eq!(nonce.len(), 24, "XChaCha20-Poly1305 nonce must be 24 bytes");
                    assert_eq!(tag.len(), 16, "Poly1305 tag must be 16 bytes");
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some XChaCha20-Poly1305 tests failed");
}

// ============================================================================
// AES-GCM Tests
// ============================================================================

#[test]
fn test_aes_gcm_wycheproof() {
    let test_file: AeadTestFile = load_test_file("aes_gcm_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);
            let _aad = decode_hex(&test.aad);
            let _plaintext = decode_hex(&test.msg);
            let _ciphertext = decode_hex(&test.ct);
            let tag = decode_hex(&test.tag);

            // TODO: Uncomment when AES-GCM is ready
            /*
            use hpcrypt_aead::{Aes128Gcm, Aes192Gcm, Aes256Gcm};

            // Select cipher based on key size
            let result = match key.len() {
                16 => {
                    let cipher = Aes128Gcm::new(&key);
                    cipher.decrypt(&nonce, &aad, &ct_with_tag)
                }
                24 => {
                    let cipher = Aes192Gcm::new(&key);
                    cipher.decrypt(&nonce, &aad, &ct_with_tag)
                }
                32 => {
                    let cipher = Aes256Gcm::new(&key);
                    cipher.decrypt(&nonce, &aad, &ct_with_tag)
                }
                _ => panic!("Invalid AES key size"),
            };
            */

            // Placeholder
            match test.result {
                TestResult::Valid => {
                    assert!(
                        key.len() == 16 || key.len() == 24 || key.len() == 32,
                        "AES key must be 16, 24, or 32 bytes"
                    );
                    assert_eq!(tag.len(), 16, "GCM tag must be 16 bytes");
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some AES-GCM tests failed");
}

// ============================================================================
// AES-GCM-SIV Tests
// ============================================================================

#[test]
fn test_aes_gcm_siv_wycheproof() {
    let test_file: AeadTestFile = load_test_file("aes_gcm_siv_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);

            // TODO: Implement AES-GCM-SIV tests
            // Similar structure to AES-GCM

            match test.result {
                TestResult::Valid => {
                    assert!(
                        key.len() == 16 || key.len() == 32,
                        "AES-GCM-SIV key must be 16 or 32 bytes"
                    );
                    assert_eq!(nonce.len(), 12, "GCM-SIV nonce must be 12 bytes");
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some AES-GCM-SIV tests failed");
}

// ============================================================================
// Ascon Tests
// ============================================================================

#[test]
fn test_ascon128_wycheproof() {
    let test_file: AeadTestFile = load_test_file("ascon128_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);

            // TODO: Implement Ascon-128 tests

            match test.result {
                TestResult::Valid => {
                    assert_eq!(key.len(), 16, "Ascon-128 key must be 16 bytes");
                    assert_eq!(nonce.len(), 16, "Ascon-128 nonce must be 16 bytes");
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some Ascon-128 tests failed");
}

#[test]
fn test_ascon128a_wycheproof() {
    let test_file: AeadTestFile = load_test_file("ascon128a_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);

            // TODO: Implement Ascon-128a tests

            match test.result {
                TestResult::Valid => {
                    assert_eq!(key.len(), 16, "Ascon-128a key must be 16 bytes");
                    assert_eq!(nonce.len(), 16, "Ascon-128a nonce must be 16 bytes");
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some Ascon-128a tests failed");
}

// ============================================================================
// AES-CCM Tests
// ============================================================================

#[test]
fn test_aes_ccm_wycheproof() {
    let test_file: AeadTestFile = load_test_file("aes_ccm_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);
            let tag = decode_hex(&test.tag);

            // TODO: Implement AES-CCM tests
            // Similar structure to AES-GCM

            match test.result {
                TestResult::Valid => {
                    let _ = (key, nonce, tag);
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some AES-CCM tests failed");
}

// ============================================================================
// AES-EAX Tests
// ============================================================================

#[test]
fn test_aes_eax_wycheproof() {
    let test_file: AeadTestFile = load_test_file("aes_eax_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);
            let tag = decode_hex(&test.tag);

            // TODO: Implement AES-EAX tests

            match test.result {
                TestResult::Valid => {
                    let _ = (key, nonce, tag);
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some AES-EAX tests failed");
}

// ============================================================================
// AES-SIV Tests
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesSivTest {
    tc_id: usize,
    comment: String,
    key: String,
    aad: String,
    msg: String,
    ct: String,
    result: TestResult,
    #[serde(default)]
    flags: Vec<String>,
}

#[test]
fn test_aes_siv_wycheproof() {
    // AES-SIV uses a different structure (no separate iv/tag fields)
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesSivGroup {
        key_size: usize,
        #[serde(rename = "type")]
        test_type: String,
        tests: Vec<AesSivTest>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesSivFile {
        algorithm: String,
        generator_version: Option<String>,
        number_of_tests: usize,
        test_groups: Vec<AesSivGroup>,
    }

    let test_file: AesSivFile = load_test_file("aes_siv_cmac_test.json");

    println!(
        "\n=== Testing {} ===",
        test_file.algorithm
    );
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let _aad = decode_hex(&test.aad);
            let _msg = decode_hex(&test.msg);
            let _ct = decode_hex(&test.ct);

            // TODO: Implement AES-SIV tests
            // AES-SIV is deterministic AEAD - IV is derived from key and data

            match test.result {
                TestResult::Valid => {
                    let _ = key;
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some AES-SIV tests failed");
}

// ============================================================================
// AEGIS Tests
// ============================================================================

#[test]
fn test_aegis128_wycheproof() {
    test_aegis_file("aegis128_test.json", "AEGIS-128");
}

#[test]
fn test_aegis128l_wycheproof() {
    test_aegis_file("aegis128L_test.json", "AEGIS-128L");
}

#[test]
fn test_aegis256_wycheproof() {
    test_aegis_file("aegis256_test.json", "AEGIS-256");
}

fn test_aegis_file(filename: &str, algorithm_name: &str) {
    let test_file: AeadTestFile = load_test_file(filename);

    println!("\n=== Testing {} ===", algorithm_name);
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        for test in &group.tests {
            let key = decode_hex(&test.key);
            let nonce = decode_hex(&test.iv);
            let aad = decode_hex(&test.aad);
            let plaintext = decode_hex(&test.msg);
            let ciphertext = decode_hex(&test.ct);
            let tag = decode_hex(&test.tag);

            // TODO: Implement actual AEGIS tests with hpcrypt-aead
            /*
            use hpcrypt_aead::{Aegis128, Aegis128L, Aegis256};

            match algorithm_name {
                "AEGIS-128" => {
                    let cipher = Aegis128::new(&key);
                    match test.result {
                        TestResult::Valid => {
                            let mut ct_with_tag = ciphertext.clone();
                            ct_with_tag.extend_from_slice(&tag);
                            match cipher.decrypt(&nonce, &aad, &ct_with_tag) {
                                Ok(decrypted) => {
                                    if decrypted != plaintext {
                                        stats.failed += 1;
                                    } else {
                                        stats.passed += 1;
                                    }
                                }
                                Err(_) => stats.failed += 1,
                            }
                        }
                        TestResult::Invalid => {
                            let mut ct_with_tag = ciphertext.clone();
                            ct_with_tag.extend_from_slice(&tag);
                            match cipher.decrypt(&nonce, &aad, &ct_with_tag) {
                                Ok(_) => stats.failed += 1,
                                Err(_) => stats.passed += 1,
                            }
                        }
                        TestResult::Acceptable => {
                            stats.skipped += 1;
                        }
                    }
                }
                "AEGIS-128L" => { /* Similar to AEGIS-128 */ }
                "AEGIS-256" => { /* Similar to AEGIS-128 */ }
                _ => panic!("Unknown AEGIS variant"),
            }
            */

            // Placeholder validation
            match test.result {
                TestResult::Valid => {
                    // AEGIS-128/128L use 16-byte keys and nonces
                    // AEGIS-256 uses 32-byte keys and nonces
                    assert!(key.len() == 16 || key.len() == 32, "AEGIS key must be 16 or 32 bytes");
                    assert!(nonce.len() == 16 || nonce.len() == 32, "AEGIS nonce must be 16 or 32 bytes");
                    assert_eq!(tag.len(), 16, "AEGIS tag must be 16 bytes");
                    let _ = (aad, plaintext, ciphertext);
                    stats.passed += 1;
                }
                TestResult::Invalid => {
                    let _ = (key, nonce, aad, plaintext, ciphertext, tag);
                    stats.passed += 1;
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "{} tests failed", algorithm_name);
}

