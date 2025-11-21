//! NIST CAVP/ACVP Test Vectors for AES-CCM
//!
//! Tests AES-CCM (Counter with CBC-MAC) authenticated encryption against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-CCM-1.0/

#![cfg(feature = "enable-aead-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_aead::{Aes128Ccm, Aes256Ccm};
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
    #[serde(rename = "payloadLen")]
    payload_len: u32,
    #[serde(rename = "aadLen")]
    aad_len: u32,
    #[serde(rename = "tagLen")]
    tag_len: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    #[serde(rename = "pt")]
    plaintext: Option<String>,
    #[serde(rename = "ct")]
    ciphertext: Option<String>,
    aad: String,
    iv: String,
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
    #[serde(rename = "ct")]
    ciphertext: Option<String>,
    #[serde(rename = "pt")]
    plaintext: Option<String>,
}

trait CcmCipher {
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, String>;
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, String>;
}

impl CcmCipher for Aes128Ccm {
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        Aes128Ccm::encrypt(&key_array, nonce, plaintext, aad, tag_len)
            .map_err(|e| format!("{:?}", e))
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        Aes128Ccm::decrypt(&key_array, nonce, ciphertext_and_tag, aad, tag_len)
            .map_err(|e| format!("{:?}", e))
    }
}

impl CcmCipher for Aes256Ccm {
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        Aes256Ccm::encrypt(&key_array, nonce, plaintext, aad, tag_len)
            .map_err(|e| format!("{:?}", e))
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        Aes256Ccm::decrypt(&key_array, nonce, ciphertext_and_tag, aad, tag_len)
            .map_err(|e| format!("{:?}", e))
    }
}

fn run_aes_ccm_tests<C: CcmCipher>(algorithm_name: &str) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-CCM-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-CCM-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    let expected_key_len = match algorithm_name {
        "AES-128-CCM" => 128,
        "AES-256-CCM" => 256,
        _ => panic!("Unknown algorithm"),
    };

    for test_group in &prompt.test_groups {
        if test_group.key_len != expected_key_len {
            stats.skipped += test_group.tests.len();
            continue;
        }

        // Skip tests with non-byte-aligned lengths
        if test_group.iv_len % 8 != 0
            || test_group.payload_len % 8 != 0
            || test_group.aad_len % 8 != 0
            || test_group.tag_len % 8 != 0
        {
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
            let tag_len = (test_group.tag_len / 8) as usize;

            if test_group.direction == "encrypt" {
                if let (Some(pt_hex), Some(expected_ct_hex)) =
                    (&test.plaintext, &expected_test.ciphertext)
                {
                    let plaintext = if pt_hex.is_empty() {
                        vec![]
                    } else {
                        decode_hex(pt_hex)
                    };
                    let expected_ct = decode_hex(expected_ct_hex);

                    match C::encrypt(&key, &iv, &plaintext, &aad, tag_len) {
                        Ok(ciphertext_and_tag) => {
                            if ciphertext_and_tag == expected_ct {
                                stats.passed += 1;
                            } else {
                                println!(
                                    "FAIL: Test {} encryption mismatch (group {})",
                                    test.tc_id, test_group.tg_id
                                );
                                stats.failed += 1;
                            }
                        }
                        Err(e) => {
                            println!("FAIL: Test {} encryption error: {}", test.tc_id, e);
                            stats.failed += 1;
                        }
                    }
                }
            } else if test_group.direction == "decrypt" {
                if let (Some(ct_hex), Some(expected_pt_hex)) =
                    (&test.ciphertext, &expected_test.plaintext)
                {
                    let ciphertext_and_tag = if ct_hex.is_empty() {
                        vec![]
                    } else {
                        decode_hex(ct_hex)
                    };
                    let expected_pt = if expected_pt_hex.is_empty() {
                        vec![]
                    } else {
                        decode_hex(expected_pt_hex)
                    };

                    match C::decrypt(&key, &iv, &ciphertext_and_tag, &aad, tag_len) {
                        Ok(plaintext) => {
                            if plaintext == expected_pt {
                                stats.passed += 1;
                            } else {
                                println!(
                                    "FAIL: Test {} decryption mismatch (group {})",
                                    test.tc_id, test_group.tg_id
                                );
                                stats.failed += 1;
                            }
                        }
                        Err(e) => {
                            println!("FAIL: Test {} decryption error: {}", test.tc_id, e);
                            stats.failed += 1;
                        }
                    }
                }
            }
        }
    }

    println!(
        "{} Results: {} passed, {} failed, {} skipped",
        algorithm_name, stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(
        stats.failed, 0,
        "{} tests failed for {}",
        stats.failed, algorithm_name
    );
}

#[test]
fn test_aes_128_ccm() {
    run_aes_ccm_tests::<Aes128Ccm>("AES-128-CCM");
}

#[test]
fn test_aes_256_ccm() {
    run_aes_ccm_tests::<Aes256Ccm>("AES-256-CCM");
}
