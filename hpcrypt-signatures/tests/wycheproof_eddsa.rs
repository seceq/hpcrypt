//! Wycheproof test vectors for EdDSA (Ed25519)
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! EdDSA (Ed25519) implementations against known edge cases and vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)

use hpcrypt_curves::Ed25519;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct TestGroup {
    #[serde(rename = "type")]
    test_type: String,
    public_key: PublicKeyInfo,
    tests: Vec<TestCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyInfo {
    #[serde(with = "hex")]
    pk: Vec<u8>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    #[serde(with = "hex")]
    msg: Vec<u8>,
    #[serde(with = "hex")]
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
#[allow(dead_code)]
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

fn run_ed25519_test(public_key: &[u8], test: &TestCase) -> bool {
    // Ed25519 requires 32-byte public keys and 64-byte signatures
    if public_key.len() != 32 || test.sig.len() != 64 {
        return true; // Skip malformed tests
    }

    let pk: [u8; 32] = public_key.try_into().unwrap();
    let signature: [u8; 64] = test.sig.as_slice().try_into().unwrap();

    let is_valid = Ed25519::verify(&pk, &test.msg, &signature);

    match test.result {
        TestResult::Valid => {
            if !is_valid {
                eprintln!(
                    "Ed25519 Test {} FAILED: Valid signature rejected: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Test flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Invalid => {
            if is_valid {
                eprintln!(
                    "Ed25519 Test {} FAILED: Invalid signature accepted: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Test flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // We document the behavior but don't fail the test
        }
    }

    true
}

#[test]
fn wycheproof_ed25519() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/ed25519_test.json");
    let test_file: TestFile =
        serde_json::from_str(test_data).expect("Failed to parse Wycheproof Ed25519 test vectors");

    println!(
        "Running {} Wycheproof Ed25519 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;

    for group in test_file.test_groups {
        for test in group.tests {
            total_tests += 1;

            if run_ed25519_test(&group.public_key.pk, &test) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "Ed25519 Wycheproof: {}/{} tests passed",
        passed_tests, total_tests
    );

    assert_eq!(passed_tests, total_tests, "Some Ed25519 tests failed");
}

#[test]
#[ignore] // Ignore until Ed448 is implemented
fn wycheproof_ed448() {
    println!("EdDSA Ed448 Wycheproof tests: Not yet implemented");
    println!("TODO: Implement Ed448 if available in hpcrypt");
}
