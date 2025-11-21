//! NIST CAVP test vectors for RSA
//!
//! Tests RSA signature verification using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-rsa-tests")]
use hpcrypt_rsa::{PublicKey, RsaError};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaPrompt {
    vs_id: u32,
    algorithm: String,
    mode: String,
    test_groups: Vec<RsaTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaTestGroup {
    tg_id: u32,
    sig_type: String,
    modulo: usize,
    hash_alg: String,
    n: String,
    e: String,
    test_type: String,
    tests: Vec<RsaTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaTestCase {
    tc_id: u32,
    message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaExpected {
    vs_id: u32,
    test_groups: Vec<RsaExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaExpectedGroup {
    tg_id: u32,
    tests: Vec<RsaExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaExpectedCase {
    tc_id: u32,
    test_passed: bool,
}

// ============================================================================
// RSA PKCS#1 v1.5 SigVer Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-rsa-tests")]
fn test_rsa_pkcs1v15_sigver_cavp() {
    let prompt: RsaPrompt = load_test_file("RSA-SigVer-FIPS186-5", "prompt.json");
    let expected: RsaExpected = load_test_file("RSA-SigVer-FIPS186-5", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Only test PKCS#1 v1.5 for now
        if group.sig_type != "pkcs1v1.5" {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        // Only test 2048-bit modulus
        if group.modulo != 2048 {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        // Only test SHA-256
        if group.hash_alg != "SHA2-256" {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        let n = decode_hex(&group.n);
        let e = decode_hex(&group.e);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let message = decode_hex(&test.message);
            let signature = decode_hex(&test.signature);

            test_rsa_verify_pkcs1v15(&n, &e, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some RSA PKCS#1 v1.5 SigVer tests failed");
}

#[cfg(feature = "enable-rsa-tests")]
fn test_rsa_verify_pkcs1v15(
    n: &[u8],
    e: &[u8],
    message: &[u8],
    signature: &[u8],
    should_pass: bool,
    stats: &mut TestStats,
    tc_id: u32,
) {
    // Try to construct public key
    let public_key_result = PublicKey::from_components(n, e);

    match public_key_result {
        Ok(public_key) => {
            // Verify signature using PKCS#1 v1.5 with SHA-256
            let result = public_key.verify_pkcs1v15_sha256(message, signature);

            let verification_passed = result.is_ok();

            if verification_passed == should_pass {
                stats.passed += 1;
            } else {
                eprintln!(
                    "Test case {} FAILED: Verification mismatch (expected {}, got {})",
                    tc_id, should_pass, verification_passed
                );
                stats.failed += 1;
            }
        }
        Err(_) => {
            // If we can't construct the key, verification should fail
            if !should_pass {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Could not construct public key", tc_id);
                stats.failed += 1;
            }
        }
    }
}

// ============================================================================
// Stub tests for non-RSA builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-rsa-tests"))]
fn test_rsa_pkcs1v15_sigver_cavp() {
    println!("RSA tests skipped: enable-rsa-tests feature not enabled");
}
