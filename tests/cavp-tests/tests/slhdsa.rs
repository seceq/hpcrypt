//! NIST CAVP test vectors for SLH-DSA (FIPS-205)
//!
//! Tests SLH-DSA key generation, signature generation, and signature verification
//! using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_slhdsa::{Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_slhdsa::test_api::SignatureScheme;

// ============================================================================
// Test Data Structures
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
    #[serde(rename = "skSeed")]
    sk_seed: String,
    #[serde(rename = "skPrf")]
    sk_prf: String,
    #[serde(rename = "pkSeed")]
    pk_seed: String,
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
    additional_randomness: Option<String>,
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
// Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_keygen_cavp() {
    let prompt: KeyGenPrompt = load_test_file("SLH-DSA-keyGen-FIPS205", "prompt.json");
    let expected: KeyGenExpected = load_test_file("SLH-DSA-keyGen-FIPS205", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let sk_seed = decode_hex(&test.sk_seed);
            let sk_prf = decode_hex(&test.sk_prf);
            let pk_seed = decode_hex(&test.pk_seed);
            let expected_pk = decode_hex(&expected_test.pk);
            let expected_sk = decode_hex(&expected_test.sk);

            // Combine seeds for key generation
            let mut seed = Vec::new();
            seed.extend_from_slice(&sk_seed);
            seed.extend_from_slice(&sk_prf);
            seed.extend_from_slice(&pk_seed);

            match group.parameter_set.as_str() {
                "SLH-DSA-SHA2-128s" => test_keygen::<Sha2_128s>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-128f" => test_keygen::<Sha2_128f>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-192s" => test_keygen::<Sha2_192s>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-192f" => test_keygen::<Sha2_192f>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-256s" => test_keygen::<Sha2_256s>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-256f" => test_keygen::<Sha2_256f>(&seed, &expected_pk, &expected_sk, &mut stats, test.tc_id),
                _ => stats.skipped += 1,
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SLH-DSA KeyGen tests failed");
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
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: KeyGen error: {:?}", tc_id, e);
            stats.failed += 1;
        }
    }
}

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_siggen_cavp() {
    let prompt: SigGenPrompt = load_test_file("SLH-DSA-sigGen-FIPS205", "prompt.json");
    let expected: SigGenExpected = load_test_file("SLH-DSA-sigGen-FIPS205", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let sk = decode_hex(&test.sk);
            let message = decode_hex(&test.message);
            let expected_sig = decode_hex(&expected_test.signature);
            let additional_randomness = test.additional_randomness.as_ref().map(|r| decode_hex(r));

            match group.parameter_set.as_str() {
                "SLH-DSA-SHA2-128s" => test_siggen::<Sha2_128s>(&sk, &message, additional_randomness.as_deref(), &expected_sig, group.deterministic, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-128f" => test_siggen::<Sha2_128f>(&sk, &message, additional_randomness.as_deref(), &expected_sig, group.deterministic, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-192s" => test_siggen::<Sha2_192s>(&sk, &message, additional_randomness.as_deref(), &expected_sig, group.deterministic, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-192f" => test_siggen::<Sha2_192f>(&sk, &message, additional_randomness.as_deref(), &expected_sig, group.deterministic, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-256s" => test_siggen::<Sha2_256s>(&sk, &message, additional_randomness.as_deref(), &expected_sig, group.deterministic, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-256f" => test_siggen::<Sha2_256f>(&sk, &message, additional_randomness.as_deref(), &expected_sig, group.deterministic, &mut stats, test.tc_id),
                _ => stats.skipped += 1,
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SLH-DSA SigGen tests failed");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_siggen<S: SignatureScheme>(
    sk: &[u8],
    message: &[u8],
    additional_randomness: Option<&[u8]>,
    expected_sig: &[u8],
    deterministic: bool,
    stats: &mut TestStats,
    tc_id: u32,
) {
    let result = if deterministic {
        S::sign_deterministic(sk, message)
    } else if let Some(rnd) = additional_randomness {
        S::sign_with_rng(sk, message, rnd)
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

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_sigver_cavp() {
    let prompt: SigVerPrompt = load_test_file("SLH-DSA-sigVer-FIPS205", "prompt.json");
    let expected: SigVerExpected = load_test_file("SLH-DSA-sigVer-FIPS205", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let pk = decode_hex(&test.pk);
            let message = decode_hex(&test.message);
            let signature = decode_hex(&test.signature);

            match group.parameter_set.as_str() {
                "SLH-DSA-SHA2-128s" => test_sigver::<Sha2_128s>(&pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-128f" => test_sigver::<Sha2_128f>(&pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-192s" => test_sigver::<Sha2_192s>(&pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-192f" => test_sigver::<Sha2_192f>(&pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-256s" => test_sigver::<Sha2_256s>(&pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id),
                "SLH-DSA-SHA2-256f" => test_sigver::<Sha2_256f>(&pk, &message, &signature, expected_test.test_passed, &mut stats, test.tc_id),
                _ => stats.skipped += 1,
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SLH-DSA SigVer tests failed");
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
            eprintln!("Test case {} FAILED: Verification result mismatch (expected {})", tc_id, should_pass);
            stats.failed += 1;
        }
    }
}

// Stub tests
#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_slhdsa_keygen_cavp() {
    println!("SLH-DSA tests skipped: enable-pqc-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_slhdsa_siggen_cavp() {
    println!("SLH-DSA tests skipped: enable-pqc-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_slhdsa_sigver_cavp() {
    println!("SLH-DSA tests skipped: enable-pqc-tests feature not enabled");
}
