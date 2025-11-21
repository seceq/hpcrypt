//! NIST CAVP/ACVP Test Vectors for AES-GMAC
//!
//! Tests AES-GMAC (Galois Message Authentication Code) against NIST test vectors.
//! GMAC is the authentication-only mode of GCM.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/ACVP-AES-GMAC-1.0/

#![cfg(feature = "enable-mac-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_mac::{Gmac128, Gmac192, Gmac256};
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
    #[serde(rename = "tagLen")]
    tag_len: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    iv: String,
    aad: String,
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
    tag: Option<String>,
    #[serde(rename = "testPassed")]
    test_passed: Option<bool>,
}

trait GmacCipher {
    fn compute(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String>;
}

impl GmacCipher for Gmac128 {
    fn compute(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 16] = key.try_into().map_err(|_| "Invalid key length")?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
        let mut gmac = Gmac128::new(&key_array, &nonce_array);
        gmac.update(data);
        Ok(gmac.finalize().to_vec())
    }
}

impl GmacCipher for Gmac192 {
    fn compute(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 24] = key.try_into().map_err(|_| "Invalid key length")?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
        let mut gmac = Gmac192::new(&key_array, &nonce_array);
        gmac.update(data);
        Ok(gmac.finalize().to_vec())
    }
}

impl GmacCipher for Gmac256 {
    fn compute(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce length")?;
        let mut gmac = Gmac256::new(&key_array, &nonce_array);
        gmac.update(data);
        Ok(gmac.finalize().to_vec())
    }
}

fn run_gmac_tests<C: GmacCipher>(algorithm_name: &str, expected_key_len: usize) {
    println!("\nTesting {}", algorithm_name);

    let prompt: PromptFile = load_test_file("ACVP-AES-GMAC-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("ACVP-AES-GMAC-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Skip tests with non-96-bit IVs (implementation only supports 96-bit nonces)
        if test_group.iv_len != 96 {
            stats.skipped += test_group.tests.len();
            continue;
        }

        // Skip tests with non-128-bit tags (implementation produces 128-bit tags)
        if test_group.tag_len != 128 {
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
            let nonce = decode_hex(&test.iv);
            let aad = if test.aad.is_empty() {
                vec![]
            } else {
                decode_hex(&test.aad)
            };

            // Skip tests with wrong key length
            if key.len() != expected_key_len {
                stats.skipped += 1;
                continue;
            }

            // Handle both generation and validation tests
            if let Some(ref expected_tag_hex) = expected_test.tag {
                // Generation test - compare computed tag with expected tag
                let expected_tag = decode_hex(expected_tag_hex);

                match C::compute(&key, &nonce, &aad) {
                    Ok(tag) => {
                        if tag == expected_tag {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} tag mismatch (group {})",
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
            } else if let Some(_test_passed) = expected_test.test_passed {
                // Validation test - we don't have the tag to verify, skip these
                stats.skipped += 1;
            } else {
                // Unknown test type
                stats.skipped += 1;
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
fn test_aes_128_gmac() {
    run_gmac_tests::<Gmac128>("AES-128-GMAC", 16);
}

#[test]
fn test_aes_192_gmac() {
    run_gmac_tests::<Gmac192>("AES-192-GMAC", 24);
}

#[test]
fn test_aes_256_gmac() {
    run_gmac_tests::<Gmac256>("AES-256-GMAC", 32);
}
