//! NIST CAVP/ACVP Test Vectors for AES-XTS
//!
//! Tests AES-XTS (XEX-based tweaked-codebook mode with ciphertext stealing)
//! encryption and decryption against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-XTS-1.0/

#![cfg(feature = "enable-cipher-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_cipher::{AesXts128, AesXts256};
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
    #[serde(rename = "payloadLen")]
    payload_len: u32,
    #[serde(rename = "tweakMode")]
    tweak_mode: String,
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
    #[serde(rename = "tweakValue")]
    tweak_value: Option<String>,
    #[serde(rename = "sequenceNumber")]
    sequence_number: Option<u32>,
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

trait AesXtsCipher {
    fn encrypt(key: &[u8], tweak: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(
        key: &[u8],
        tweak: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String>;
}

impl AesXtsCipher for AesXts128 {
    fn encrypt(key: &[u8], tweak: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let cipher = AesXts128::new(&key_array);
        cipher
            .encrypt(tweak, plaintext)
            .map_err(|e| format!("{:?}", e))
    }

    fn decrypt(
        key: &[u8],
        tweak: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let cipher = AesXts128::new(&key_array);
        cipher
            .decrypt(tweak, ciphertext)
            .map_err(|e| format!("{:?}", e))
    }
}

impl AesXtsCipher for AesXts256 {
    fn encrypt(key: &[u8], tweak: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 64] = key.try_into().map_err(|_| "Invalid key length")?;
        let cipher = AesXts256::new(&key_array);
        cipher
            .encrypt(tweak, plaintext)
            .map_err(|e| format!("{:?}", e))
    }

    fn decrypt(
        key: &[u8],
        tweak: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key_array: [u8; 64] = key.try_into().map_err(|_| "Invalid key length")?;
        let cipher = AesXts256::new(&key_array);
        cipher
            .decrypt(tweak, ciphertext)
            .map_err(|e| format!("{:?}", e))
    }
}

fn run_aes_xts_tests<C: AesXtsCipher>(algorithm_name: &str) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-XTS-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-XTS-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    let expected_key_len = match algorithm_name {
        "AES-128-XTS" => 128,
        "AES-256-XTS" => 256,
        _ => panic!("Unknown algorithm"),
    };

    for test_group in &prompt.test_groups {
        if test_group.key_len != expected_key_len {
            stats.skipped += test_group.tests.len();
            continue;
        }

        // Skip tests with non-byte-aligned payloads
        if test_group.payload_len % 8 != 0 {
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

            // Handle both tweak modes: hex (tweakValue) and number (sequenceNumber)
            let tweak: [u8; 16] = if let Some(ref tweak_hex) = test.tweak_value {
                let tweak_bytes = decode_hex(tweak_hex);
                match tweak_bytes.as_slice().try_into() {
                    Ok(t) => t,
                    Err(_) => {
                        println!("FAIL: Test {} - Invalid tweak length", test.tc_id);
                        stats.failed += 1;
                        continue;
                    }
                }
            } else if let Some(seq_num) = test.sequence_number {
                // Convert sequence number to 128-bit little-endian tweak
                let mut tweak = [0u8; 16];
                tweak[..4].copy_from_slice(&seq_num.to_le_bytes());
                tweak
            } else {
                println!("FAIL: Test {} - No tweak value provided", test.tc_id);
                stats.failed += 1;
                continue;
            };

            if test_group.direction == "encrypt" {
                if let (Some(pt_hex), Some(expected_ct_hex)) =
                    (&test.plaintext, &expected_test.ciphertext)
                {
                    let plaintext = decode_hex(pt_hex);
                    let expected_ct = decode_hex(expected_ct_hex);

                    match C::encrypt(&key, &tweak, &plaintext) {
                        Ok(ciphertext) => {
                            if ciphertext == expected_ct {
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
                            println!("FAIL: Test {} error: {}", test.tc_id, e);
                            stats.failed += 1;
                        }
                    }
                }
            } else if test_group.direction == "decrypt" {
                if let (Some(ct_hex), Some(expected_pt_hex)) =
                    (&test.ciphertext, &expected_test.plaintext)
                {
                    let ciphertext = decode_hex(ct_hex);
                    let expected_pt = decode_hex(expected_pt_hex);

                    match C::decrypt(&key, &tweak, &ciphertext) {
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
                            println!("FAIL: Test {} error: {}", test.tc_id, e);
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
fn test_aes_128_xts() {
    run_aes_xts_tests::<AesXts128>("AES-128-XTS");
}

#[test]
fn test_aes_256_xts() {
    run_aes_xts_tests::<AesXts256>("AES-256-XTS");
}
