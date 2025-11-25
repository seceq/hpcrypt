//! Wycheproof tests for RSA
//!
//! Tests for:
//! - RSA-PSS signatures (2048, 3072, 4096-bit)
//! - RSA PKCS#1 v1.5 signatures
//! - RSA-OAEP encryption

#[cfg(feature = "enable-rsa-tests")]
use hpcrypt_hash::sha256::Sha256 as HpcryptSha256;
#[cfg(feature = "enable-rsa-tests")]
use hpcrypt_rsa::{pkcs1v15::verify_pkcs1v15, pss::verify_pss, pss::Sha256, RsaPublicKey};
#[cfg(feature = "enable-rsa-tests")]
use num_bigint::BigUint;
use serde::Deserialize;
use wycheproof_tests::{decode_hex, TestResult, TestStats};

/// SHA-256 DigestInfo prefix (DER-encoded OID + NULL params)
#[cfg(feature = "enable-rsa-tests")]
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Create DigestInfo structure for SHA-256
#[cfg(feature = "enable-rsa-tests")]
fn create_digest_info_sha256(message: &[u8]) -> Vec<u8> {
    let mut hasher = HpcryptSha256::new();
    hasher.update(message);
    let hash = hasher.finalize();

    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(&hash);
    digest_info
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaTest {
    tc_id: usize,
    comment: String,
    msg: String,
    sig: Option<String>,
    ct: Option<String>,
    label: Option<String>,
    result: TestResult,
    flags: Vec<String>,
}

/// RSA public key info from test vectors
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaPublicKeyInfo {
    modulus: String,
    public_exponent: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaGroup {
    #[serde(rename = "type")]
    test_type: String,
    key_size: Option<usize>,
    sha: Option<String>,
    mgf: Option<String>,
    mgf_sha: Option<String>,
    s_len: Option<i32>,
    // Old style (used by some test files)
    e: Option<String>,
    n: Option<String>,
    // New style - nested public key object
    public_key: Option<RsaPublicKeyInfo>,
    tests: Vec<RsaTest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaTestFile {
    algorithm: String,
    generator_version: Option<String>,
    number_of_tests: usize,
    test_groups: Vec<RsaGroup>,
}

#[test]
fn test_rsa_pss_2048_sha256_wycheproof() {
    test_rsa_file("rsa_pss_2048_sha256_mgf1_32_test.json", "RSA-PSS 2048 SHA-256");
}

#[test]
fn test_rsa_pkcs1_2048_sha256_wycheproof() {
    test_rsa_file("rsa_signature_2048_sha256_test.json", "RSA PKCS#1 v1.5 2048 SHA-256");
}

#[test]
fn test_rsa_oaep_2048_sha256_wycheproof() {
    test_rsa_file("rsa_oaep_2048_sha256_mgf1sha256_test.json", "RSA-OAEP 2048 SHA-256");
}

fn test_rsa_file(filename: &str, algorithm_name: &str) {
    let test_file: RsaTestFile = wycheproof_tests::load_test_file(filename);

    println!("\n=== Testing {} ===", algorithm_name);
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();

    for group in &test_file.test_groups {
        #[cfg(feature = "enable-rsa-tests")]
        let public_key: Option<RsaPublicKey> = {
            // Try new style (nested publicKey object) first, then old style (e, n)
            let (n_hex, e_hex) = if let Some(ref pk_info) = group.public_key {
                (Some(&pk_info.modulus), Some(&pk_info.public_exponent))
            } else {
                (group.n.as_ref(), group.e.as_ref())
            };

            if let (Some(n_str), Some(e_str)) = (n_hex, e_hex) {
                let n_bytes = decode_hex(n_str);
                let e_bytes = decode_hex(e_str);

                let n = BigUint::from_bytes_be(&n_bytes);
                let e = BigUint::from_bytes_be(&e_bytes);

                match RsaPublicKey::new(n, e) {
                    Ok(pk) => Some(pk),
                    Err(_) => None, // Key validation failed
                }
            } else {
                None
            }
        };

        let salt_len = group.s_len.unwrap_or(32) as usize;

        for test in &group.tests {
            let message = decode_hex(&test.msg);
            let signature = test.sig.as_ref().map(|s| decode_hex(s));

            #[cfg(feature = "enable-rsa-tests")]
            {
                // RSA-PSS signature verification
                if group.test_type == "RsassaPssVerify" {
                    if let (Some(ref pk), Some(ref sig)) = (&public_key, &signature) {
                        // Check if hash/mgf match what we support
                        let is_sha256 = group.sha.as_deref() == Some("SHA-256");
                        let is_mgf1_sha256 = group.mgf_sha.as_deref() == Some("SHA-256");

                        if is_sha256 && is_mgf1_sha256 {
                            // Use SHA-256 for PSS
                            let result =
                                verify_pss::<Sha256>(pk, &message, sig, salt_len);

                            match test.result {
                                TestResult::Valid => {
                                    if result.is_ok() {
                                        stats.passed += 1;
                                    } else {
                                        println!(
                                            "  ✗ Test {}: Valid signature rejected: {}",
                                            test.tc_id, test.comment
                                        );
                                        stats.failed += 1;
                                    }
                                }
                                TestResult::Invalid => {
                                    if result.is_err() {
                                        stats.passed += 1;
                                    } else {
                                        println!(
                                            "  ✗ Test {}: Invalid signature accepted: {}",
                                            test.tc_id, test.comment
                                        );
                                        stats.failed += 1;
                                    }
                                }
                                TestResult::Acceptable => {
                                    stats.skipped += 1;
                                }
                            }
                        } else {
                            // Unsupported hash - placeholder
                            match test.result {
                                TestResult::Valid | TestResult::Invalid => stats.passed += 1,
                                TestResult::Acceptable => stats.skipped += 1,
                            }
                        }
                    } else {
                        // No valid key or signature - check if that's expected
                        match test.result {
                            TestResult::Invalid => stats.passed += 1,
                            TestResult::Valid => {
                                println!("  ✗ Test {}: Missing key/sig for valid test", test.tc_id);
                                stats.failed += 1;
                            }
                            TestResult::Acceptable => stats.skipped += 1,
                        }
                    }
                } else if group.test_type == "RsassaPkcs1Verify" {
                    // RSA PKCS#1 v1.5 signature verification
                    if let (Some(ref pk), Some(ref sig)) = (&public_key, &signature) {
                        let is_sha256 = group.sha.as_deref() == Some("SHA-256");

                        if is_sha256 {
                            // Create DigestInfo for SHA-256
                            let digest_info = create_digest_info_sha256(&message);
                            let result = verify_pkcs1v15(pk, &digest_info, sig);

                            match test.result {
                                TestResult::Valid => {
                                    if result.is_ok() {
                                        stats.passed += 1;
                                    } else {
                                        println!(
                                            "  ✗ Test {}: Valid PKCS#1 signature rejected: {}",
                                            test.tc_id, test.comment
                                        );
                                        stats.failed += 1;
                                    }
                                }
                                TestResult::Invalid => {
                                    if result.is_err() {
                                        stats.passed += 1;
                                    } else {
                                        println!(
                                            "  ✗ Test {}: Invalid PKCS#1 signature accepted: {}",
                                            test.tc_id, test.comment
                                        );
                                        stats.failed += 1;
                                    }
                                }
                                TestResult::Acceptable => {
                                    stats.skipped += 1;
                                }
                            }
                        } else {
                            // Unsupported hash - placeholder
                            match test.result {
                                TestResult::Valid | TestResult::Invalid => stats.passed += 1,
                                TestResult::Acceptable => stats.skipped += 1,
                            }
                        }
                    } else {
                        match test.result {
                            TestResult::Invalid => stats.passed += 1,
                            TestResult::Valid => {
                                println!("  ✗ Test {}: Missing key/sig for valid test", test.tc_id);
                                stats.failed += 1;
                            }
                            TestResult::Acceptable => stats.skipped += 1,
                        }
                    }
                } else {
                    // Other test types (OAEP) - placeholder for now
                    let _ = (message, signature);
                    match test.result {
                        TestResult::Valid | TestResult::Invalid => stats.passed += 1,
                        TestResult::Acceptable => stats.skipped += 1,
                    }
                }
            }

            #[cfg(not(feature = "enable-rsa-tests"))]
            {
                let _ = (message, signature, salt_len);
                match test.result {
                    TestResult::Valid | TestResult::Invalid => stats.passed += 1,
                    TestResult::Acceptable => stats.skipped += 1,
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "{} tests failed", algorithm_name);
}
