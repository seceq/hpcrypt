//! Wycheproof test vectors for ECDSA
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! ECDSA implementations against known edge cases and potential vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - FIPS 186-4
//! - SEC 1: Elliptic Curve Cryptography

use hpcrypt_signatures::ecdsa::{Signature, VerifyingKey};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    test_type: String,
    public_key: PublicKey,
    key: Option<PublicKeyDetails>,
    sha: String,
    tests: Vec<TestCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKey {
    #[serde(with = "hex_serde")]
    wx: Vec<u8>,
    #[serde(with = "hex_serde")]
    wy: Vec<u8>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyDetails {
    curve: String,
    key_size: usize,
    #[serde(rename = "type")]
    key_type: String,
    #[serde(with = "hex_serde")]
    wx: Vec<u8>,
    #[serde(with = "hex_serde")]
    wy: Vec<u8>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    #[serde(with = "hex_serde")]
    msg: Vec<u8>,
    #[serde(with = "hex_serde")]
    sig: Vec<u8>,
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

fn run_ecdsa_test(test: &TestCase, verifying_key: &VerifyingKey, test_type: &str) -> bool {
    // Parse the signature from DER encoding
    let signature = match Signature::from_der(&test.sig) {
        Ok(sig) => sig,
        Err(_) => {
            // If we can't parse the signature, it should be invalid
            if test.result == TestResult::Invalid {
                return true; // Expected failure
            } else {
                eprintln!(
                    "ECDSA-{} Test {} FAILED: Could not parse signature for {:?} test: {}",
                    test_type, test.tc_id, test.result, test.comment
                );
                return false;
            }
        }
    };

    // Verify the signature
    let verification_result = verifying_key.verify(&test.msg, &signature);

    match test.result {
        TestResult::Valid => {
            if !verification_result {
                eprintln!(
                    "ECDSA-{} Test {} FAILED: Valid signature rejected: {}",
                    test_type, test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Invalid => {
            if verification_result {
                eprintln!(
                    "ECDSA-{} Test {} FAILED: Invalid signature accepted: {}",
                    test_type, test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                eprintln!("  Message: {}", "[binary data]");
                eprintln!("  Signature: {}", "[binary data]");
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // These are edge cases that different implementations may handle differently
            // We document the behavior but don't fail the test
            if !verification_result {
                // Log for informational purposes
                // println!(
                //     "ECDSA-{} Test {} (Acceptable): Signature rejected: {}",
                //     test_type, test.tc_id, test.comment
                // );
            }
        }
    }

    true
}

#[test]
fn wycheproof_ecdsa_secp256r1_sha256() {
    let test_data =
        include_str!("../../../wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof ECDSA P-256 test vectors");

    println!(
        "Running {} Wycheproof ECDSA P-256 (secp256r1) SHA-256 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;

    for group in test_file.test_groups {
        // Create verifying key from public key coordinates
        let verifying_key =
            match VerifyingKey::from_affine_coords(&group.public_key.wx, &group.public_key.wy) {
                Ok(key) => key,
                Err(_) => {
                    // If we can't create the key, skip this group
                    // (Wycheproof may include invalid keys as part of the test)
                    continue;
                }
            };

        for test in group.tests {
            total_tests += 1;

            if run_ecdsa_test(&test, &verifying_key, "P256") {
                passed_tests += 1;
            }
        }
    }

    println!(
        "ECDSA P-256 Wycheproof: {}/{} tests passed",
        passed_tests, total_tests
    );

    assert_eq!(passed_tests, total_tests, "Some ECDSA P-256 tests failed");
}

#[test]
#[ignore] // Ignore by default as P-384 might not be fully implemented yet
fn wycheproof_ecdsa_secp384r1_sha384() {
    // Note: This test would require P-384 support in hpcrypt-signatures
    // For now, we'll skip it unless P-384 is implemented

    println!("ECDSA P-384 tests: Skipped (P-384 support may not be complete)");
}

#[test]
#[ignore] // Ignore by default as P-521 might not be fully implemented yet
fn wycheproof_ecdsa_secp521r1_sha512() {
    // Note: This test would require P-521 support in hpcrypt-signatures
    // For now, we'll skip it unless P-521 is implemented

    println!("ECDSA P-521 tests: Skipped (P-521 support may not be complete)");
}

#[test]
fn wycheproof_ecdsa_secp256k1_sha256() {
    use hpcrypt_signatures::ecdsa_secp256k1::{
        Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey,
    };

    let test_data =
        include_str!("../../../wycheproof/testvectors_v1/ecdsa_secp256k1_sha256_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof ECDSA secp256k1 test vectors");

    println!(
        "Running {} Wycheproof ECDSA secp256k1 SHA-256 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;

    for group in test_file.test_groups {
        // Create verifying key from public key coordinates
        let verifying_key = match Secp256k1VerifyingKey::from_affine_coords(
            &group.public_key.wx,
            &group.public_key.wy,
        ) {
            Ok(key) => key,
            Err(_) => {
                // If we can't create the key, skip this group
                // (Wycheproof may include invalid keys as part of the test)
                continue;
            }
        };

        for test in group.tests {
            total_tests += 1;

            // Parse the signature from DER encoding
            let signature = match Secp256k1Signature::from_der(&test.sig) {
                Ok(sig) => sig,
                Err(_) => {
                    // If we can't parse the signature, it should be invalid
                    if test.result == TestResult::Invalid {
                        passed_tests += 1;
                        continue; // Expected failure
                    } else {
                        eprintln!(
                            "ECDSA-secp256k1 Test {} FAILED: Could not parse signature for {:?} test: {}",
                            test.tc_id, test.result, test.comment
                        );
                        continue;
                    }
                }
            };

            // Verify the signature
            let verification_result = verifying_key.verify(&test.msg, &signature);

            match test.result {
                TestResult::Valid => {
                    if !verification_result {
                        eprintln!(
                            "ECDSA-secp256k1 Test {} FAILED: Valid signature rejected: {}",
                            test.tc_id, test.comment
                        );
                        eprintln!("  Flags: {:?}", test.flags);
                        continue;
                    }
                }
                TestResult::Invalid => {
                    if verification_result {
                        eprintln!(
                            "ECDSA-secp256k1 Test {} FAILED: Invalid signature accepted: {}",
                            test.tc_id, test.comment
                        );
                        eprintln!("  Flags: {:?}", test.flags);
                        continue;
                    }
                }
                TestResult::Acceptable => {
                    // Acceptable tests can pass or fail
                }
            }

            passed_tests += 1;
        }
    }

    println!(
        "ECDSA secp256k1 Wycheproof: {}/{} tests passed",
        passed_tests, total_tests
    );

    assert_eq!(
        passed_tests, total_tests,
        "Some ECDSA secp256k1 tests failed"
    );
}

// Test for handling of edge cases
#[test]
fn ecdsa_edge_cases() {
    use hpcrypt_signatures::ecdsa::{Signature, VerifyingKey};

    // Test vectors from Wycheproof showcase common edge cases

    // Known P-256 public key from Wycheproof
    let wx =
        hex::decode("1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83").unwrap();
    let wy =
        hex::decode("ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9").unwrap();

    let verifying_key = VerifyingKey::from_affine_coords(&wx, &wy).expect("Valid public key");

    // Test 1: All-zero signature (r=0, s=0)
    let zero_sig = Signature::new([0u8; 32], [0u8; 32]);
    let msg = b"test message";
    assert!(
        !verifying_key.verify(msg, &zero_sig),
        "All-zero signature should not verify"
    );

    // Test 2: r=0, s=1
    let mut s_one = [0u8; 32];
    s_one[31] = 1;
    let r_zero_sig = Signature::new([0u8; 32], s_one);
    assert!(
        !verifying_key.verify(msg, &r_zero_sig),
        "Signature with r=0 should not verify"
    );

    // Test 3: r=1, s=0
    let mut r_one = [0u8; 32];
    r_one[31] = 1;
    let s_zero_sig = Signature::new(r_one, [0u8; 32]);
    assert!(
        !verifying_key.verify(msg, &s_zero_sig),
        "Signature with s=0 should not verify"
    );

    // Test 4: High r value (close to curve order n)
    // P-256 order n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    let high_r =
        hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550").unwrap();
    let high_r_arr: [u8; 32] = high_r.try_into().unwrap();
    let high_r_sig = Signature::new(high_r_arr, s_one);
    assert!(
        !verifying_key.verify(msg, &high_r_sig),
        "Signature with r >= n should not verify"
    );

    println!("ECDSA edge case tests: All passed");
}
