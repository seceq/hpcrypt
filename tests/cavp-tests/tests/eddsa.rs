//! NIST CAVP/ACVP Test Vectors for EdDSA
//!
//! Tests EdDSA (Ed25519 and Ed448) signature verification against NIST test vectors.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/EDDSA-SigVer-1.0/
//!
//! Note: PreHash variants (Ed25519ph, Ed448ph) are currently skipped as they require
//! implementation of the prehash flag in the signing/verification functions.

#![cfg(feature = "hpcrypt-curves")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_curves::ed25519;
use hpcrypt_curves::ed448;
use hpcrypt_curves::Ed25519;
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
    curve: String,
    #[serde(rename = "preHash")]
    pre_hash: bool,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    message: String,
    q: String, // Public key
    signature: String,
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
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

fn test_ed25519_sigver() {
    println!("\nTesting Ed25519 Signature Verification");

    let prompt: PromptFile = load_test_file("EDDSA-SigVer-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("EDDSA-SigVer-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        // Skip preHash variants (Ed25519ph, Ed448ph) - not yet implemented
        if test_group.pre_hash {
            stats.skipped += test_group.tests.len();
            continue;
        }

        // Only test Ed25519 and Ed448 (non-preHash)
        if test_group.curve != "ED-25519" && test_group.curve != "ED-448" {
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

            // Decode test data
            let message = decode_hex(&test.message);
            let pub_key_bytes = decode_hex(&test.q);
            let sig_bytes = decode_hex(&test.signature);

            // Verify signature based on curve type
            let verified = if test_group.curve == "ED-25519" {
                // Ed25519: 32-byte public key, 64-byte signature
                let public_key: ed25519::PublicKey = match pub_key_bytes.as_slice().try_into() {
                    Ok(pk) => pk,
                    Err(_) => {
                        // Invalid public key length - should fail verification
                        if !expected_test.test_passed {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} - Invalid Ed25519 public key length but expected to pass",
                                test.tc_id
                            );
                            stats.failed += 1;
                        }
                        continue;
                    }
                };

                let signature: ed25519::Signature = match sig_bytes.as_slice().try_into() {
                    Ok(sig) => sig,
                    Err(_) => {
                        // Invalid signature length - should fail verification
                        if !expected_test.test_passed {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} - Invalid Ed25519 signature length but expected to pass",
                                test.tc_id
                            );
                            stats.failed += 1;
                        }
                        continue;
                    }
                };

                Ed25519::verify(&public_key, &message, &signature)
            } else {
                // Ed448: 57-byte public key, 114-byte signature
                let public_key: ed448::PublicKey = match pub_key_bytes.as_slice().try_into() {
                    Ok(pk) => pk,
                    Err(_) => {
                        // Invalid public key length - should fail verification
                        if !expected_test.test_passed {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} - Invalid Ed448 public key length but expected to pass",
                                test.tc_id
                            );
                            stats.failed += 1;
                        }
                        continue;
                    }
                };

                let signature: ed448::Signature = match sig_bytes.as_slice().try_into() {
                    Ok(sig) => sig,
                    Err(_) => {
                        // Invalid signature length - should fail verification
                        if !expected_test.test_passed {
                            stats.passed += 1;
                        } else {
                            println!(
                                "FAIL: Test {} - Invalid Ed448 signature length but expected to pass",
                                test.tc_id
                            );
                            stats.failed += 1;
                        }
                        continue;
                    }
                };

                ed448::verify(&public_key, &message, &signature)
            };

            if verified == expected_test.test_passed {
                stats.passed += 1;
            } else {
                println!(
                    "FAIL: Test {} - Expected {}, got {}",
                    test.tc_id, expected_test.test_passed, verified
                );
                stats.failed += 1;
            }
        }
    }

    println!(
        "EdDSA Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(stats.failed, 0, "{} tests failed", stats.failed);
}

#[test]
fn test_eddsa_signature_verification() {
    test_ed25519_sigver();
}
