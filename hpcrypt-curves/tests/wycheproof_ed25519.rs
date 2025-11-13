//! Wycheproof test vectors for Ed25519
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! Ed25519 signature implementations against known edge cases and potential vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - RFC 8032 (EdDSA: Ed25519 and Ed448)

use hpcrypt_curves::ed25519::Ed25519;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    test_type: String,
    public_key: PublicKey,
    tests: Vec<TestCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKey {
    #[serde(rename = "type")]
    key_type: String,
    curve: String,
    key_size: usize,
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

fn run_ed25519_test(test: &TestCase, public_key: &[u8; 32]) -> bool {
    // Check signature length (must be exactly 64 bytes)
    if test.sig.len() != 64 {
        match test.result {
            TestResult::Valid => {
                eprintln!(
                    "Ed25519 Test {} FAILED: Valid test has invalid signature length: {}",
                    test.tc_id, test.sig.len()
                );
                return false;
            }
            TestResult::Invalid | TestResult::Acceptable => {
                // Expected to be invalid for incorrect signature lengths
                return true;
            }
        }
    }

    // Convert signature to array
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&test.sig);

    // Verify the signature
    let verification_result = Ed25519::verify(public_key, &test.msg, &signature);

    match test.result {
        TestResult::Valid => {
            if !verification_result {
                eprintln!(
                    "Ed25519 Test {} FAILED: Valid signature rejected: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Invalid => {
            if verification_result {
                eprintln!(
                    "Ed25519 Test {} FAILED: Invalid signature accepted: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // These are edge cases that different implementations may handle differently
            // For Ed25519, we should reject non-canonical S values (signature malleability)
            if test.flags.contains(&"SignatureMalleability".to_string()) {
                if verification_result {
                    // Log for informational purposes - we accept malleable signatures
                    // This is actually a weakness, but some implementations allow it
                    // println!(
                    //     "Ed25519 Test {} (Acceptable/Malleability): Signature accepted: {}",
                    //     test.tc_id, test.comment
                    // );
                }
            }
        }
    }

    true
}

#[test]
fn wycheproof_ed25519() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/ed25519_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof Ed25519 test vectors");

    println!(
        "Running {} Wycheproof Ed25519 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        // Check public key length
        if group.public_key.pk.len() != 32 {
            eprintln!(
                "Skipping test group with invalid public key length: {}",
                group.public_key.pk.len()
            );
            skipped_tests += group.tests.len();
            continue;
        }

        // Convert public key to array
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&group.public_key.pk);

        for test in group.tests {
            total_tests += 1;

            if run_ed25519_test(&test, &public_key) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "Ed25519 Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests,
        total_tests,
        "Some Ed25519 tests failed (note: {} tests were skipped for unsupported parameters)",
        skipped_tests
    );
}

// Test edge cases
#[test]
fn ed25519_edge_cases() {
    // Create a test keypair (use fixed bytes for determinism in tests)
    let private_key = [42u8; 32];
    let public_key = Ed25519::public_key(&private_key);

    // Test with empty message
    let msg1 = b"";
    let sig1 = Ed25519::sign(&private_key, msg1);
    assert!(
        Ed25519::verify(&public_key, msg1, &sig1),
        "Empty message signature should verify"
    );

    // Test with non-empty message
    let msg2 = b"Hello, Ed25519!";
    let sig2 = Ed25519::sign(&private_key, msg2);
    assert!(
        Ed25519::verify(&public_key, msg2, &sig2),
        "Regular message signature should verify"
    );

    // Signatures should be different
    assert_ne!(sig1, sig2, "Different messages should produce different signatures");

    // Wrong message should fail
    assert!(
        !Ed25519::verify(&public_key, b"wrong message", &sig2),
        "Signature should not verify for wrong message"
    );

    // Modified signature should fail
    let mut modified_sig = sig2;
    modified_sig[0] ^= 1;
    assert!(
        !Ed25519::verify(&public_key, msg2, &modified_sig),
        "Modified signature should not verify"
    );

    // Wrong public key should fail
    let wrong_private = [99u8; 32];
    let wrong_public = Ed25519::public_key(&wrong_private);
    assert!(
        !Ed25519::verify(&wrong_public, msg2, &sig2),
        "Signature should not verify with wrong public key"
    );

    // Test signature is deterministic (RFC 8032 requirement)
    let sig2_again = Ed25519::sign(&private_key, msg2);
    assert_eq!(
        sig2, sig2_again,
        "Ed25519 signatures should be deterministic"
    );

    println!("Ed25519 edge case tests: All passed");
}
