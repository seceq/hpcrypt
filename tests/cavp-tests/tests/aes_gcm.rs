//! NIST CAVP test vectors for AES-GCM
//!
//! Tests AES-GCM encryption and decryption using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-aead-tests")]
use hpcrypt_aead::{Aes128Gcm, Aes192Gcm, Aes256Gcm, gcm_encrypt_variable, gcm_decrypt_variable};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmPrompt {
    vs_id: u32,
    algorithm: String,
    test_groups: Vec<AesGcmTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmTestGroup {
    tg_id: u32,
    test_type: String,
    direction: String,
    key_len: usize,
    iv_len: usize,
    #[serde(default)]
    payload_len: Option<usize>,
    #[serde(default)]
    aad_len: Option<usize>,
    tag_len: usize,
    tests: Vec<AesGcmTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmTestCase {
    tc_id: u32,
    key: String,
    #[serde(default)]
    pt: Option<String>,
    #[serde(default)]
    ct: Option<String>,
    iv: String,
    #[serde(default)]
    aad: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmExpected {
    vs_id: u32,
    test_groups: Vec<AesGcmExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmExpectedGroup {
    tg_id: u32,
    tests: Vec<AesGcmExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesGcmExpectedCase {
    tc_id: u32,
    #[serde(default)]
    ct: Option<String>,
    #[serde(default)]
    pt: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    test_passed: Option<bool>,
}

// ============================================================================
// AES-GCM Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-aead-tests")]
fn test_aes_gcm_cavp() {
    let prompt: AesGcmPrompt = load_test_file("ACVP-AES-GCM-1.0", "prompt.json");
    let expected: AesGcmExpected = load_test_file("ACVP-AES-GCM-1.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Validate tag length is supported (NIST SP 800-38D: 32, 64, 96, 104, 112, 120, 128 bits)
        let tag_len_bytes = group.tag_len / 8;
        if !matches!(tag_len_bytes, 4 | 8 | 12 | 13 | 14 | 15 | 16) {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        // Use variable API for non-standard IV or tag lengths
        let use_variable_api = group.iv_len != 96 || group.tag_len != 128;

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let key = decode_hex(&test.key);
            let iv = decode_hex(&test.iv);
            let aad = test.aad.as_ref().map(|a| decode_hex(a)).unwrap_or_default();

            if use_variable_api {
                // Use variable IV/tag API
                if group.direction == "encrypt" {
                    test_encrypt_variable(&key, &iv, &aad, tag_len_bytes, test, expected_test, &mut stats);
                } else {
                    test_decrypt_variable(&key, &iv, &aad, tag_len_bytes, test, expected_test, &mut stats);
                }
            } else {
                // Use standard fixed-size API
                match group.key_len {
                    128 => {
                        if group.direction == "encrypt" {
                            test_encrypt::<Aes128Gcm>(&key, &iv, &aad, test, expected_test, &mut stats);
                        } else {
                            test_decrypt::<Aes128Gcm>(&key, &iv, &aad, test, expected_test, &mut stats);
                        }
                    }
                    192 => {
                        if group.direction == "encrypt" {
                            test_encrypt::<Aes192Gcm>(&key, &iv, &aad, test, expected_test, &mut stats);
                        } else {
                            test_decrypt::<Aes192Gcm>(&key, &iv, &aad, test, expected_test, &mut stats);
                        }
                    }
                    256 => {
                        if group.direction == "encrypt" {
                            test_encrypt::<Aes256Gcm>(&key, &iv, &aad, test, expected_test, &mut stats);
                        } else {
                            test_decrypt::<Aes256Gcm>(&key, &iv, &aad, test, expected_test, &mut stats);
                        }
                    }
                    _ => {
                        eprintln!("Unsupported key length: {}", group.key_len);
                        stats.skipped += 1;
                    }
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some AES-GCM tests failed");
}

trait AesGcmCipher {
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>;
}

impl AesGcmCipher for Aes128Gcm {
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length".to_string())?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length".to_string())?;
        // API: encrypt(key, nonce, plaintext, aad) returns Vec<u8>
        Ok(Aes128Gcm::encrypt(&key_array, &nonce_array, plaintext, aad))
    }

    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length".to_string())?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length".to_string())?;
        // API: decrypt(key, nonce, ciphertext, aad) returns Result<Vec<u8>, AeadError>
        Aes128Gcm::decrypt(&key_array, &nonce_array, ciphertext, aad)
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }
}

impl AesGcmCipher for Aes192Gcm {
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length".to_string())?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length".to_string())?;
        Ok(Aes192Gcm::encrypt(&key_array, &nonce_array, plaintext, aad))
    }

    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length".to_string())?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length".to_string())?;
        Aes192Gcm::decrypt(&key_array, &nonce_array, ciphertext, aad)
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }
}

impl AesGcmCipher for Aes256Gcm {
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length".to_string())?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length".to_string())?;
        Ok(Aes256Gcm::encrypt(&key_array, &nonce_array, plaintext, aad))
    }

    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length".to_string())?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length".to_string())?;
        Aes256Gcm::decrypt(&key_array, &nonce_array, ciphertext, aad)
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }
}

#[cfg(feature = "enable-aead-tests")]
fn test_encrypt<C: AesGcmCipher>(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    test: &AesGcmTestCase,
    expected: &AesGcmExpectedCase,
    stats: &mut TestStats,
) {
    let plaintext = test.pt.as_ref().map(|p| decode_hex(p)).unwrap_or_default();
    let expected_ct_and_tag = decode_hex(expected.ct.as_ref().unwrap());
    let expected_tag = decode_hex(expected.tag.as_ref().unwrap());

    // The expected ciphertext and tag might be concatenated or separate
    let (expected_ct, expected_tag_from_ct) = if expected_ct_and_tag.len() >= expected_tag.len() {
        let ct_len = expected_ct_and_tag.len() - expected_tag.len();
        (&expected_ct_and_tag[..ct_len], &expected_ct_and_tag[ct_len..])
    } else {
        (expected_ct_and_tag.as_slice(), expected_tag.as_slice())
    };

    match C::encrypt(key, iv, aad, &plaintext) {
        Ok(result) => {
            // Result should be ciphertext || tag
            let tag_len = expected_tag.len();
            if result.len() < tag_len {
                eprintln!("Test case {} FAILED: Result too short", test.tc_id);
                stats.failed += 1;
                return;
            }

            let ct_len = result.len() - tag_len;
            let result_ct = &result[..ct_len];
            let result_tag = &result[ct_len..];

            if result_ct == expected_ct && (result_tag == &expected_tag || result_tag == expected_tag_from_ct) {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Ciphertext or tag mismatch", test.tc_id);
                if result_ct != expected_ct {
                    eprintln!("  CT length: expected {}, got {}", expected_ct.len(), result_ct.len());
                }
                if result_tag != &expected_tag && result_tag != expected_tag_from_ct {
                    eprintln!("  Tag mismatch");
                }
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: Encryption error: {}", test.tc_id, e);
            stats.failed += 1;
        }
    }
}

#[cfg(feature = "enable-aead-tests")]
fn test_decrypt<C: AesGcmCipher>(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    test: &AesGcmTestCase,
    expected: &AesGcmExpectedCase,
    stats: &mut TestStats,
) {
    let ciphertext = test.ct.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
    let tag = test.tag.as_ref().map(|t| decode_hex(t)).unwrap_or_default();

    // Concatenate ciphertext and tag
    let mut ct_with_tag = ciphertext.clone();
    ct_with_tag.extend_from_slice(&tag);

    let should_pass = expected.test_passed.unwrap_or(true);

    match C::decrypt(key, iv, aad, &ct_with_tag) {
        Ok(result) => {
            if should_pass {
                let expected_pt = expected.pt.as_ref().map(|p| decode_hex(p)).unwrap_or_default();
                if result == expected_pt {
                    stats.passed += 1;
                } else {
                    eprintln!("Test case {} FAILED: Plaintext mismatch", test.tc_id);
                    stats.failed += 1;
                }
            } else {
                eprintln!("Test case {} FAILED: Should have failed decryption", test.tc_id);
                stats.failed += 1;
            }
        }
        Err(_) => {
            if !should_pass {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Decryption failed when it should pass", test.tc_id);
                stats.failed += 1;
            }
        }
    }
}

// ============================================================================
// Variable IV/Tag Length Test Functions
// ============================================================================

#[cfg(feature = "enable-aead-tests")]
fn test_encrypt_variable(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag_len: usize,
    test: &AesGcmTestCase,
    expected: &AesGcmExpectedCase,
    stats: &mut TestStats,
) {
    let plaintext = test.pt.as_ref().map(|p| decode_hex(p)).unwrap_or_default();
    let expected_ct = decode_hex(expected.ct.as_ref().unwrap());
    let expected_tag = decode_hex(expected.tag.as_ref().unwrap());

    match gcm_encrypt_variable(key, iv, &plaintext, aad, tag_len) {
        Ok(result) => {
            // Result should be ciphertext || tag
            if result.len() < tag_len {
                eprintln!("Test case {} FAILED: Result too short", test.tc_id);
                stats.failed += 1;
                return;
            }

            let ct_len = result.len() - tag_len;
            let result_ct = &result[..ct_len];
            let result_tag = &result[ct_len..];

            if result_ct == expected_ct.as_slice() && result_tag == expected_tag.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Ciphertext or tag mismatch", test.tc_id);
                if result_ct != expected_ct.as_slice() {
                    eprintln!("  CT: expected {} bytes, got {} bytes", expected_ct.len(), result_ct.len());
                }
                if result_tag != expected_tag.as_slice() {
                    eprintln!("  Tag mismatch: expected {:02x?}, got {:02x?}", expected_tag, result_tag);
                }
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: Encryption error: {:?}", test.tc_id, e);
            stats.failed += 1;
        }
    }
}

#[cfg(feature = "enable-aead-tests")]
fn test_decrypt_variable(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag_len: usize,
    test: &AesGcmTestCase,
    expected: &AesGcmExpectedCase,
    stats: &mut TestStats,
) {
    let ciphertext = test.ct.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
    let tag = test.tag.as_ref().map(|t| decode_hex(t)).unwrap_or_default();

    // Concatenate ciphertext and tag
    let mut ct_with_tag = ciphertext.clone();
    ct_with_tag.extend_from_slice(&tag);

    let should_pass = expected.test_passed.unwrap_or(true);

    match gcm_decrypt_variable(key, iv, &ct_with_tag, aad, tag_len) {
        Ok(result) => {
            if should_pass {
                let expected_pt = expected.pt.as_ref().map(|p| decode_hex(p)).unwrap_or_default();
                if result == expected_pt {
                    stats.passed += 1;
                } else {
                    eprintln!("Test case {} FAILED: Plaintext mismatch", test.tc_id);
                    stats.failed += 1;
                }
            } else {
                eprintln!("Test case {} FAILED: Should have failed decryption", test.tc_id);
                stats.failed += 1;
            }
        }
        Err(_) => {
            if !should_pass {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Decryption failed when it should pass", test.tc_id);
                stats.failed += 1;
            }
        }
    }
}

// ============================================================================
// Stub tests for non-AEAD builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-aead-tests"))]
fn test_aes_gcm_cavp() {
    println!("AES-GCM tests skipped: enable-aead-tests feature not enabled");
}
