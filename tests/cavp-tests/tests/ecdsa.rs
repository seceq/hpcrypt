//! NIST CAVP test vectors for ECDSA
//!
//! Tests ECDSA signature verification using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-signature-tests")]
use hpcrypt_signatures::{
    ecdsa_p256::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey, Signature as P256Signature},
    ecdsa_p384::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey, Signature as P384Signature},
    ecdsa_p521::{SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey, Signature as P521Signature},
};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaPrompt {
    vs_id: u32,
    algorithm: String,
    mode: String,
    test_groups: Vec<EcdsaTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaTestGroup {
    tg_id: u32,
    test_type: String,
    curve: String,
    hash_alg: String,
    tests: Vec<EcdsaTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaTestCase {
    tc_id: u32,
    message: String,
    qx: String,
    qy: String,
    r: String,
    s: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaExpected {
    vs_id: u32,
    test_groups: Vec<EcdsaExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaExpectedGroup {
    tg_id: u32,
    tests: Vec<EcdsaExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaExpectedCase {
    tc_id: u32,
    test_passed: bool,
}

// ============================================================================
// ECDSA P-256 SigVer Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-signature-tests")]
fn test_ecdsa_p256_sigver_cavp() {
    let prompt: EcdsaPrompt = load_test_file("ECDSA-SigVer-FIPS186-5", "prompt.json");
    let expected: EcdsaExpected = load_test_file("ECDSA-SigVer-FIPS186-5", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Only test P-256 curve
        if group.curve != "P-256" {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        // Only test SHA-256 for now (most common)
        if group.hash_alg != "SHA2-256" {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let message = decode_hex(&test.message);
            let qx = decode_hex(&test.qx);
            let qy = decode_hex(&test.qy);
            let r = decode_hex(&test.r);
            let s = decode_hex(&test.s);

            test_p256_verify(&qx, &qy, &r, &s, &message, expected_test.test_passed, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ECDSA P-256 SigVer tests failed");
}

#[cfg(feature = "enable-signature-tests")]
fn test_p256_verify(
    qx: &[u8],
    qy: &[u8],
    r: &[u8],
    s: &[u8],
    message: &[u8],
    should_pass: bool,
    stats: &mut TestStats,
    tc_id: u32,
) {
    // Try to construct public key from coordinates
    let verifying_key_result = P256VerifyingKey::from_affine_coords(qx, qy);

    // Try to construct signature from r and s
    let mut sig_bytes = [0u8; 64];
    if r.len() > 32 || s.len() > 32 {
        // Invalid signature format
        if !should_pass {
            stats.passed += 1;
        } else {
            eprintln!("Test case {} FAILED: Invalid signature size but should pass", tc_id);
            stats.failed += 1;
        }
        return;
    }

    // Pad r and s to 32 bytes
    sig_bytes[32 - r.len()..32].copy_from_slice(r);
    sig_bytes[64 - s.len()..64].copy_from_slice(s);

    let signature = P256Signature::from_bytes(&sig_bytes);

    match verifying_key_result {
        Ok(verifying_key) => {
            let result = verifying_key.verify(message, &signature);

            if result == should_pass {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Verification mismatch (expected {}, got {})",
                    tc_id, should_pass, result);
                stats.failed += 1;
            }
        }
        Err(_) => {
            // If we can't construct the key, it should fail verification
            if !should_pass {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Could not construct verifying key", tc_id);
                stats.failed += 1;
            }
        }
    }
}

// ============================================================================
// ECDSA P-384 SigVer Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-signature-tests")]
fn test_ecdsa_p384_sigver_cavp() {
    let prompt: EcdsaPrompt = load_test_file("ECDSA-SigVer-FIPS186-5", "prompt.json");
    let expected: EcdsaExpected = load_test_file("ECDSA-SigVer-FIPS186-5", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        if group.curve != "P-384" || group.hash_alg != "SHA2-384" {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let message = decode_hex(&test.message);
            let qx = decode_hex(&test.qx);
            let qy = decode_hex(&test.qy);
            let r = decode_hex(&test.r);
            let s = decode_hex(&test.s);

            test_p384_verify(&qx, &qy, &r, &s, &message, expected_test.test_passed, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ECDSA P-384 SigVer tests failed");
}

#[cfg(feature = "enable-signature-tests")]
fn test_p384_verify(
    qx: &[u8],
    qy: &[u8],
    r: &[u8],
    s: &[u8],
    message: &[u8],
    should_pass: bool,
    stats: &mut TestStats,
    tc_id: u32,
) {
    let verifying_key_result = P384VerifyingKey::from_affine_coords(qx, qy);

    let mut sig_bytes = [0u8; 96];
    if r.len() > 48 || s.len() > 48 {
        if !should_pass {
            stats.passed += 1;
        } else {
            stats.failed += 1;
        }
        return;
    }

    sig_bytes[48 - r.len()..48].copy_from_slice(r);
    sig_bytes[96 - s.len()..96].copy_from_slice(s);

    let signature = P384Signature::from_bytes(&sig_bytes);

    match verifying_key_result {
        Ok(verifying_key) => {
            let result = verifying_key.verify(message, &signature);
            if result == should_pass {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Verification mismatch", tc_id);
                stats.failed += 1;
            }
        }
        Err(_) => {
            if !should_pass {
                stats.passed += 1;
            } else {
                stats.failed += 1;
            }
        }
    }
}

// ============================================================================
// ECDSA P-521 SigVer Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-signature-tests")]
fn test_ecdsa_p521_sigver_cavp() {
    let prompt: EcdsaPrompt = load_test_file("ECDSA-SigVer-FIPS186-5", "prompt.json");
    let expected: EcdsaExpected = load_test_file("ECDSA-SigVer-FIPS186-5", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        if group.curve != "P-521" || group.hash_alg != "SHA2-512" {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let message = decode_hex(&test.message);
            let qx = decode_hex(&test.qx);
            let qy = decode_hex(&test.qy);
            let r = decode_hex(&test.r);
            let s = decode_hex(&test.s);

            test_p521_verify(&qx, &qy, &r, &s, &message, expected_test.test_passed, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ECDSA P-521 SigVer tests failed");
}

#[cfg(feature = "enable-signature-tests")]
fn test_p521_verify(
    qx: &[u8],
    qy: &[u8],
    r: &[u8],
    s: &[u8],
    message: &[u8],
    should_pass: bool,
    stats: &mut TestStats,
    tc_id: u32,
) {
    let verifying_key_result = P521VerifyingKey::from_affine_coords(qx, qy);

    let mut sig_bytes = [0u8; 132];
    if r.len() > 66 || s.len() > 66 {
        if !should_pass {
            stats.passed += 1;
        } else {
            stats.failed += 1;
        }
        return;
    }

    sig_bytes[66 - r.len()..66].copy_from_slice(r);
    sig_bytes[132 - s.len()..132].copy_from_slice(s);

    let signature = P521Signature::from_bytes(&sig_bytes);

    match verifying_key_result {
        Ok(verifying_key) => {
            let result = verifying_key.verify(message, &signature);
            if result == should_pass {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Verification mismatch", tc_id);
                stats.failed += 1;
            }
        }
        Err(_) => {
            if !should_pass {
                stats.passed += 1;
            } else {
                stats.failed += 1;
            }
        }
    }
}

// ============================================================================
// Stub tests for non-signature builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-signature-tests"))]
fn test_ecdsa_p256_sigver_cavp() {
    println!("ECDSA tests skipped: enable-signature-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-signature-tests"))]
fn test_ecdsa_p384_sigver_cavp() {
    println!("ECDSA tests skipped: enable-signature-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-signature-tests"))]
fn test_ecdsa_p521_sigver_cavp() {
    println!("ECDSA tests skipped: enable-signature-tests feature not enabled");
}
