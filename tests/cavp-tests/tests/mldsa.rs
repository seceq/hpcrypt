//! NIST CAVP test vectors for ML-DSA (FIPS-204)
//!
//! Tests ML-DSA key generation, signature generation, and signature verification
//! using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::{MlDsa44, MlDsa65, MlDsa87};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::test_api::SignatureScheme;

// ============================================================================
// Test Data Structures - KeyGen
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPrompt {
    vs_id: u32,
    algorithm: String,
    test_groups: Vec<KeyGenTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenTestGroup {
    tg_id: u32,
    test_type: String,
    parameter_set: String,
    tests: Vec<KeyGenTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenTestCase {
    tc_id: u32,
    seed: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenExpected {
    vs_id: u32,
    test_groups: Vec<KeyGenExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenExpectedGroup {
    tg_id: u32,
    tests: Vec<KeyGenExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenExpectedCase {
    tc_id: u32,
    pk: String,
    sk: String,
}

// ============================================================================
// Test Data Structures - SigGen
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenPrompt {
    vs_id: u32,
    algorithm: String,
    test_groups: Vec<SigGenTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenTestGroup {
    tg_id: u32,
    test_type: String,
    parameter_set: String,
    deterministic: bool,
    tests: Vec<SigGenTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenTestCase {
    tc_id: u32,
    sk: String,
    message: String,
    #[serde(default)]
    rnd: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpected {
    vs_id: u32,
    test_groups: Vec<SigGenExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpectedGroup {
    tg_id: u32,
    tests: Vec<SigGenExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpectedCase {
    tc_id: u32,
    signature: String,
}

// ============================================================================
// Test Data Structures - SigVer
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerPrompt {
    vs_id: u32,
    algorithm: String,
    test_groups: Vec<SigVerTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerTestGroup {
    tg_id: u32,
    test_type: String,
    parameter_set: String,
    tests: Vec<SigVerTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerTestCase {
    tc_id: u32,
    pk: String,
    message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerExpected {
    vs_id: u32,
    test_groups: Vec<SigVerExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerExpectedGroup {
    tg_id: u32,
    tests: Vec<SigVerExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerExpectedCase {
    tc_id: u32,
    test_passed: bool,
}

// ============================================================================
// ML-DSA KeyGen Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_keygen_cavp() {
    let prompt: KeyGenPrompt = load_test_file("ML-DSA-keyGen-FIPS204", "prompt.json");
    let expected: KeyGenExpected = load_test_file("ML-DSA-keyGen-FIPS204", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let seed = decode_hex(&test.seed);
            let expected_pk = decode_hex(&expected_test.pk);
            let expected_sk = decode_hex(&expected_test.sk);

            match group.parameter_set.as_str() {
                "ML-DSA-44" => {
                    test_keygen::<MlDsa44>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id);
                }
                "ML-DSA-65" => {
                    test_keygen::<MlDsa65>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id);
                }
                "ML-DSA-87" => {
                    test_keygen::<MlDsa87>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id);
                }
                _ => {
                    eprintln!("Unknown parameter set: {}", group.parameter_set);
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ML-DSA KeyGen tests failed");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_keygen<S: SignatureScheme>(
    seed: &[u8],
    expected_pk: &[u8],
    expected_sk: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    match S::generate_deterministic(seed) {
        Ok((pk, sk)) => {
            if pk.as_ref() == expected_pk && sk.as_ref() == expected_sk {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Key mismatch", tc_id);
                if pk.as_ref() != expected_pk {
                    eprintln!("  Public key mismatch (expected {}, got {})",
                        expected_pk.len(), pk.as_ref().len());
                }
                if sk.as_ref() != expected_sk {
                    eprintln!("  Secret key mismatch (expected {}, got {})",
                        expected_sk.len(), sk.as_ref().len());
                }
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: KeyGen error: {:?}", tc_id, e);
            stats.failed += 1;
        }
    }
}

// ============================================================================
// ML-DSA SigGen Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_siggen_cavp() {
    let prompt: SigGenPrompt = load_test_file("ML-DSA-sigGen-FIPS204", "prompt.json");
    let expected: SigGenExpected = load_test_file("ML-DSA-sigGen-FIPS204", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let sk = decode_hex(&test.sk);
            let message = decode_hex(&test.message);
            let expected_sig = decode_hex(&expected_test.signature);

            match group.parameter_set.as_str() {
                "ML-DSA-44" => {
                    if group.deterministic {
                        test_siggen_deterministic::<MlDsa44>(
                            &sk, &message, &expected_sig, &mut stats, test.tc_id
                        );
                    } else {
                        let rnd = test.rnd.as_ref().map(|r| decode_hex(r));
                        test_siggen_hedged::<MlDsa44>(
                            &sk, &message, rnd.as_deref(), &expected_sig, &mut stats, test.tc_id
                        );
                    }
                }
                "ML-DSA-65" => {
                    if group.deterministic {
                        test_siggen_deterministic::<MlDsa65>(
                            &sk, &message, &expected_sig, &mut stats, test.tc_id
                        );
                    } else {
                        let rnd = test.rnd.as_ref().map(|r| decode_hex(r));
                        test_siggen_hedged::<MlDsa65>(
                            &sk, &message, rnd.as_deref(), &expected_sig, &mut stats, test.tc_id
                        );
                    }
                }
                "ML-DSA-87" => {
                    if group.deterministic {
                        test_siggen_deterministic::<MlDsa87>(
                            &sk, &message, &expected_sig, &mut stats, test.tc_id
                        );
                    } else {
                        let rnd = test.rnd.as_ref().map(|r| decode_hex(r));
                        test_siggen_hedged::<MlDsa87>(
                            &sk, &message, rnd.as_deref(), &expected_sig, &mut stats, test.tc_id
                        );
                    }
                }
                _ => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ML-DSA SigGen tests failed");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_siggen_deterministic<S: SignatureScheme>(
    sk: &[u8],
    message: &[u8],
    expected_sig: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    match S::sign_deterministic(sk, message) {
        Ok(signature) => {
            if signature.as_ref() == expected_sig {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Signature mismatch", tc_id);
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: Sign error: {:?}", tc_id, e);
            stats.failed += 1;
        }
    }
}

#[cfg(feature = "enable-pqc-tests")]
fn test_siggen_hedged<S: SignatureScheme>(
    sk: &[u8],
    message: &[u8],
    rnd: Option<&[u8]>,
    expected_sig: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    let result = if let Some(rnd_bytes) = rnd {
        S::sign_with_rng(sk, message, rnd_bytes)
    } else {
        S::sign(sk, message)
    };

    match result {
        Ok(signature) => {
            if signature.as_ref() == expected_sig {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Signature mismatch", tc_id);
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: Sign error: {:?}", tc_id, e);
            stats.failed += 1;
        }
    }
}

// ============================================================================
// ML-DSA SigVer Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_sigver_cavp() {
    let prompt: SigVerPrompt = load_test_file("ML-DSA-sigVer-FIPS204", "prompt.json");
    let expected: SigVerExpected = load_test_file("ML-DSA-sigVer-FIPS204", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let pk = decode_hex(&test.pk);
            let message = decode_hex(&test.message);
            let signature = decode_hex(&test.signature);

            match group.parameter_set.as_str() {
                "ML-DSA-44" => {
                    test_sigver::<MlDsa44>(
                        &pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id
                    );
                }
                "ML-DSA-65" => {
                    test_sigver::<MlDsa65>(
                        &pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id
                    );
                }
                "ML-DSA-87" => {
                    test_sigver::<MlDsa87>(
                        &pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id
                    );
                }
                _ => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ML-DSA SigVer tests failed");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_sigver<S: SignatureScheme>(
    pk: &[u8],
    message: &[u8],
    signature: &[u8],
    should_pass: bool,
    stats: &mut TestStats,
    tc_id: u32,
) {
    let result = S::verify(pk, message, signature);

    match (result, should_pass) {
        (Ok(true), true) | (Ok(false), false) | (Err(_), false) => {
            stats.passed += 1;
        }
        _ => {
            eprintln!("Test case {} FAILED: Verification result mismatch", tc_id);
            eprintln!("  Expected: {}", should_pass);
            eprintln!("  Got: {:?}", result);
            stats.failed += 1;
        }
    }
}

// ============================================================================
// Stub tests for non-PQC builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_mldsa_keygen_cavp() {
    println!("ML-DSA tests skipped: enable-pqc-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_mldsa_siggen_cavp() {
    println!("ML-DSA tests skipped: enable-pqc-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_mldsa_sigver_cavp() {
    println!("ML-DSA tests skipped: enable-pqc-tests feature not enabled");
}
