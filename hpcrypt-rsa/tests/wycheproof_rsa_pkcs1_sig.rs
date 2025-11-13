//! Wycheproof test vectors for RSA PKCS#1 v1.5 signatures
//!
//! This test suite uses Google's Wycheproof project test vectors to validate
//! RSA PKCS#1 v1.5 signature implementations against known edge cases and vulnerabilities.
//!
//! References:
//! - https://github.com/google/wycheproof
//! - RFC 8017 (PKCS#1 v2.2)
//! - FIPS 186-4

use hpcrypt_rsa::pkcs1v15::{verify_pkcs1v15, HashAlgorithm};
use hpcrypt_rsa::RsaPublicKey;
use num_bigint::BigUint;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    test_type: String,
    #[serde(rename = "sha")]
    sha_algorithm: Option<String>,
    key_size: usize,
    #[serde(with = "hex")]
    key_der: Vec<u8>,
    tests: Vec<TestCase>,
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

fn parse_public_key_from_der(der: &[u8]) -> Option<RsaPublicKey> {
    // Very simple DER parser for RSA public keys (SubjectPublicKeyInfo format)
    // This is a minimal parser - production code should use a proper ASN.1 library

    // Skip SEQUENCE header and algorithm identifier
    let mut offset = 0;

    // Find the BIT STRING containing the public key
    while offset < der.len() {
        if der[offset] == 0x03 {
            // BIT STRING tag
            offset += 1;

            // Read length
            let len_byte = der[offset];
            offset += 1;

            let _content_len = if len_byte & 0x80 == 0 {
                len_byte as usize
            } else {
                let num_bytes = (len_byte & 0x7F) as usize;
                let mut length = 0;
                for _ in 0..num_bytes {
                    length = (length << 8) | der[offset] as usize;
                    offset += 1;
                }
                length
            };

            // Skip unused bits byte
            offset += 1;

            // Now we have the actual RSA public key SEQUENCE
            break;
        }
        offset += 1;
    }

    if offset >= der.len() || der[offset] != 0x30 {
        return None;
    }

    offset += 1;

    // Read SEQUENCE length
    let len_byte = der[offset];
    offset += 1;

    if len_byte & 0x80 != 0 {
        let num_bytes = (len_byte & 0x7F) as usize;
        for _ in 0..num_bytes {
            offset += 1;
        }
    }

    // Read modulus (n)
    if offset >= der.len() || der[offset] != 0x02 {
        return None;
    }
    offset += 1;

    let n_len = parse_length(&der[offset..], &mut offset)?;
    let n_bytes = &der[offset..offset + n_len];
    let n = BigUint::from_bytes_be(n_bytes);
    offset += n_len;

    // Read exponent (e)
    if offset >= der.len() || der[offset] != 0x02 {
        return None;
    }
    offset += 1;

    let e_len = parse_length(&der[offset..], &mut offset)?;
    let e_bytes = &der[offset..offset + e_len];
    let e = BigUint::from_bytes_be(e_bytes);

    RsaPublicKey::new(n, e).ok()
}

fn parse_length(data: &[u8], offset: &mut usize) -> Option<usize> {
    if data.is_empty() {
        return None;
    }

    let len_byte = data[0];
    *offset += 1;

    if len_byte & 0x80 == 0 {
        Some(len_byte as usize)
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        let mut length = 0;
        for i in 0..num_bytes {
            if *offset >= data.len() {
                return None;
            }
            length = (length << 8) | data[1 + i] as usize;
            *offset += 1;
        }
        Some(length)
    }
}

fn hash_message(algorithm: &str, message: &[u8]) -> Option<(Vec<u8>, HashAlgorithm)> {
    match algorithm {
        "SHA-256" => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(message);
            let digest = hasher.finalize().to_vec();
            Some((digest, HashAlgorithm::Sha256))
        }
        "SHA-384" => {
            use sha2::{Sha384, Digest};
            let mut hasher = Sha384::new();
            hasher.update(message);
            let digest = hasher.finalize().to_vec();
            Some((digest, HashAlgorithm::Sha384))
        }
        "SHA-512" => {
            use sha2::{Sha512, Digest};
            let mut hasher = Sha512::new();
            hasher.update(message);
            let digest = hasher.finalize().to_vec();
            Some((digest, HashAlgorithm::Sha512))
        }
        _ => None,
    }
}

fn run_test(test: &TestCase, public_key: &RsaPublicKey, sha_algorithm: &str) -> bool {
    // Hash the message
    let (digest, hash_alg) = match hash_message(sha_algorithm, &test.msg) {
        Some(d) => d,
        None => {
            // Skip tests with unsupported hash algorithms (like SHA-1)
            return true;
        }
    };

    // Create DigestInfo
    let mut digest_info = hash_alg.oid().to_vec();
    digest_info.extend_from_slice(&digest);

    // Verify signature
    let result = verify_pkcs1v15(public_key, &digest_info, &test.sig);

    match test.result {
        TestResult::Valid => {
            if result.is_err() {
                eprintln!(
                    "RSA PKCS#1 v1.5 Test {} FAILED: Valid signature rejected: {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        }
        TestResult::Invalid => {
            if result.is_ok() {
                eprintln!(
                    "RSA PKCS#1 v1.5 Test {} FAILED: Invalid signature accepted: {}",
                    test.tc_id, test.comment
                );
                return false;
            }
        }
        TestResult::Acceptable => {
            // Acceptable tests can pass or fail
            // These typically involve weak parameters (small keys, SHA-1)
        }
    }

    true
}

#[test]
fn wycheproof_rsa_pkcs1_2048_sig_gen() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/rsa_pkcs1_2048_sig_gen_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof RSA PKCS#1 2048 test vectors");

    println!(
        "Running {} Wycheproof RSA PKCS#1 v1.5 2048-bit signature tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        let public_key = match parse_public_key_from_der(&group.key_der) {
            Some(key) => key,
            None => {
                eprintln!("Failed to parse public key for test group");
                skipped_tests += group.tests.len();
                continue;
            }
        };

        let sha_algorithm = group.sha_algorithm.as_deref().unwrap_or("SHA-256");

        for test in group.tests {
            total_tests += 1;

            if run_test(&test, &public_key, sha_algorithm) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "RSA PKCS#1 v1.5 2048-bit Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some RSA PKCS#1 v1.5 tests failed"
    );
}

#[test]
fn wycheproof_rsa_pkcs1_3072_sig_gen() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/rsa_pkcs1_3072_sig_gen_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof RSA PKCS#1 3072 test vectors");

    println!(
        "Running {} Wycheproof RSA PKCS#1 v1.5 3072-bit signature tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        let public_key = match parse_public_key_from_der(&group.key_der) {
            Some(key) => key,
            None => {
                skipped_tests += group.tests.len();
                continue;
            }
        };

        let sha_algorithm = group.sha_algorithm.as_deref().unwrap_or("SHA-256");

        for test in group.tests {
            total_tests += 1;

            if run_test(&test, &public_key, sha_algorithm) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "RSA PKCS#1 v1.5 3072-bit Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some RSA PKCS#1 v1.5 tests failed"
    );
}

#[test]
fn wycheproof_rsa_pkcs1_4096_sig_gen() {
    let test_data = include_str!("../../../wycheproof/testvectors_v1/rsa_pkcs1_4096_sig_gen_test.json");
    let test_file: TestFile = serde_json::from_str(test_data)
        .expect("Failed to parse Wycheproof RSA PKCS#1 4096 test vectors");

    println!(
        "Running {} Wycheproof RSA PKCS#1 v1.5 4096-bit signature tests...",
        test_file.number_of_tests
    );

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for group in test_file.test_groups {
        let public_key = match parse_public_key_from_der(&group.key_der) {
            Some(key) => key,
            None => {
                skipped_tests += group.tests.len();
                continue;
            }
        };

        let sha_algorithm = group.sha_algorithm.as_deref().unwrap_or("SHA-256");

        for test in group.tests {
            total_tests += 1;

            if run_test(&test, &public_key, sha_algorithm) {
                passed_tests += 1;
            }
        }
    }

    println!(
        "RSA PKCS#1 v1.5 4096-bit Wycheproof: {}/{} tests passed, {} skipped",
        passed_tests, total_tests, skipped_tests
    );

    assert_eq!(
        passed_tests + skipped_tests,
        total_tests,
        "Some RSA PKCS#1 v1.5 tests failed"
    );
}
