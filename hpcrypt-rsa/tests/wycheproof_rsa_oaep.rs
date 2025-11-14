//! Wycheproof test vectors for RSA-OAEP
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! RSA-OAEP implementations against known edge cases and potential vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - RFC 8017 (PKCS#1 v2.2)
//! - Manger's attack on RSA-OAEP

use hpcrypt_rsa::oaep::{decrypt_oaep, Sha256};
use hpcrypt_rsa::RsaPrivateKey;
use num_bigint::BigUint;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    #[allow(dead_code)]
    key_size: usize,
    #[allow(dead_code)]
    sha: String,
    #[allow(dead_code)]
    mgf: String,
    #[allow(dead_code)]
    mgf_sha: String,
    private_key: PrivateKey,
    tests: Vec<TestCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrivateKey {
    #[serde(with = "hex")]
    modulus: Vec<u8>,
    #[serde(with = "hex")]
    private_exponent: Vec<u8>,
    #[serde(with = "hex")]
    public_exponent: Vec<u8>,
    #[serde(with = "hex")]
    prime1: Vec<u8>,
    #[serde(with = "hex")]
    prime2: Vec<u8>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    #[serde(with = "hex")]
    msg: Vec<u8>,
    #[serde(with = "hex")]
    ct: Vec<u8>,
    #[serde(with = "hex")]
    label: Vec<u8>,
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
    #[allow(dead_code)]
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

fn parse_private_key(private_key: &PrivateKey) -> Option<RsaPrivateKey> {
    use num_traits::One;

    let n = BigUint::from_bytes_be(&private_key.modulus);
    let d = BigUint::from_bytes_be(&private_key.private_exponent);
    let e = BigUint::from_bytes_be(&private_key.public_exponent);
    let p = BigUint::from_bytes_be(&private_key.prime1);
    let q = BigUint::from_bytes_be(&private_key.prime2);

    // Compute CRT parameters
    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();
    let dp = &d % &p_minus_1;
    let dq = &d % &q_minus_1;

    // Compute qinv = q^(-1) mod p using extended GCD
    let qinv = mod_inverse(&q, &p)?;

    RsaPrivateKey::from_components(n, e, d, p, q, dp, dq, qinv).ok()
}

// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::Sign;

    let a_signed = num_bigint::BigInt::from_biguint(Sign::Plus, a.clone());
    let m_signed = num_bigint::BigInt::from_biguint(Sign::Plus, m.clone());

    let (gcd, x, _) = extended_gcd(&a_signed, &m_signed);

    if gcd != num_bigint::BigInt::from(1) {
        return None;
    }

    let result = if x.sign() == Sign::Minus {
        &m_signed + x
    } else {
        x
    };

    result.to_biguint()
}

// Extended Euclidean algorithm
fn extended_gcd(
    a: &num_bigint::BigInt,
    b: &num_bigint::BigInt,
) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
    use num_traits::Zero;

    if b.is_zero() {
        return (
            a.clone(),
            num_bigint::BigInt::from(1),
            num_bigint::BigInt::from(0),
        );
    }

    let (gcd, x1, y1) = extended_gcd(b, &(a % b));
    let x = y1.clone();
    let y = x1 - (a / b) * y1;

    (gcd, x, y)
}

fn run_test(test: &TestCase, private_key: &RsaPrivateKey) -> bool {
    // Attempt to decrypt
    let result = decrypt_oaep::<Sha256>(private_key, &test.ct, &test.label);

    match test.result {
        TestResult::Valid => match result {
            Ok(plaintext) => {
                if plaintext != test.msg {
                    eprintln!(
                        "RSA-OAEP Test {} FAILED: Decrypted plaintext mismatch: {}",
                        test.tc_id, test.comment
                    );
                    return false;
                }
            }
            Err(_) => {
                eprintln!(
                    "RSA-OAEP Test {} FAILED: Valid ciphertext rejected: {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        },
        TestResult::Invalid => {
            if result.is_ok() {
                eprintln!(
                    "RSA-OAEP Test {} FAILED: Invalid ciphertext accepted: {}",
                    test.tc_id, test.comment
                );
                eprintln!("  Flags: {:?}", test.flags);
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // These typically involve edge cases or deprecated parameters
        }
    }

    true
}

#[test]
#[ignore = "Wycheproof test vectors not included in dist release"]
fn wycheproof_rsa_oaep_2048_sha256_mgf1sha256() {
    let test_data = include_str!(
        "../../../wycheproof/testvectors_v1/rsa_oaep_2048_sha256_mgf1sha256_test.json"
    );
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof RSA-OAEP 2048 SHA256 test vectors");

    println!(
        "Running {} Wycheproof RSA-OAEP 2048-bit SHA-256/MGF1-SHA256 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        let private_key = match parse_private_key(&group.private_key) {
            Some(key) => key,
            None => {
                eprintln!("Failed to parse private key for test group");
                skipped_tests += group.tests.len();
                continue;
            }
        };

        for test in group.tests {
            total_tests += 1;

            if run_test(&test, &private_key) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "RSA-OAEP 2048-bit SHA-256/MGF1-SHA256 Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some RSA-OAEP tests failed"
    );
}

#[test]
#[ignore = "Wycheproof test vectors not included in dist release"]
fn wycheproof_rsa_oaep_3072_sha256_mgf1sha256() {
    let test_data = include_str!(
        "../../../wycheproof/testvectors_v1/rsa_oaep_3072_sha256_mgf1sha256_test.json"
    );
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof RSA-OAEP 3072 SHA256 test vectors");

    println!(
        "Running {} Wycheproof RSA-OAEP 3072-bit SHA-256/MGF1-SHA256 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        let private_key = match parse_private_key(&group.private_key) {
            Some(key) => key,
            None => {
                skipped_tests += group.tests.len();
                continue;
            }
        };

        for test in group.tests {
            total_tests += 1;

            if run_test(&test, &private_key) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "RSA-OAEP 3072-bit SHA-256/MGF1-SHA256 Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some RSA-OAEP tests failed"
    );
}

#[test]
#[ignore = "Wycheproof test vectors not included in dist release"]
fn wycheproof_rsa_oaep_4096_sha256_mgf1sha256() {
    let test_data = include_str!(
        "../../../wycheproof/testvectors_v1/rsa_oaep_4096_sha256_mgf1sha256_test.json"
    );
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof RSA-OAEP 4096 SHA256 test vectors");

    println!(
        "Running {} Wycheproof RSA-OAEP 4096-bit SHA-256/MGF1-SHA256 tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        let private_key = match parse_private_key(&group.private_key) {
            Some(key) => key,
            None => {
                skipped_tests += group.tests.len();
                continue;
            }
        };

        for test in group.tests {
            total_tests += 1;

            if run_test(&test, &private_key) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "RSA-OAEP 4096-bit SHA-256/MGF1-SHA256 Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some RSA-OAEP tests failed"
    );
}
