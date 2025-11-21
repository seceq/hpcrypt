//! NIST CAVP test vectors for ML-KEM (FIPS-203)
//!
//! Tests ML-KEM key generation and encapsulation/decapsulation using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mlkem::{MlKem512, MlKem768, MlKem1024};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mlkem::test_api::KemCore;

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
    z: String,
    d: String,
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
    ek: String,
    dk: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapDecapPrompt {
    vs_id: u32,
    algorithm: String,
    test_groups: Vec<EncapDecapTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapDecapTestGroup {
    tg_id: u32,
    test_type: String,
    parameter_set: String,
    function: String,
    tests: Vec<EncapDecapTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapDecapTestCase {
    tc_id: u32,
    #[serde(default)]
    m: Option<String>,
    #[serde(default)]
    ek: Option<String>,
    #[serde(default)]
    dk: Option<String>,
    #[serde(default)]
    c: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapDecapExpected {
    vs_id: u32,
    test_groups: Vec<EncapDecapExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapDecapExpectedGroup {
    tg_id: u32,
    tests: Vec<EncapDecapExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapDecapExpectedCase {
    tc_id: u32,
    #[serde(default)]
    c: Option<String>,
    #[serde(default)]
    k: Option<String>,
}

// ============================================================================
// ML-KEM KeyGen Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_keygen_cavp() {
    let prompt: KeyGenPrompt = load_test_file("ML-KEM-keyGen-FIPS203", "prompt.json");
    let expected: KeyGenExpected = load_test_file("ML-KEM-keyGen-FIPS203", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let z = decode_hex(&test.z);
            let d = decode_hex(&test.d);
            let expected_ek = decode_hex(&expected_test.ek);
            let expected_dk = decode_hex(&expected_test.dk);

            match group.parameter_set.as_str() {
                "ML-KEM-512" => {
                    test_keygen::<MlKem512>(&z, &d, &expected_ek, &expected_dk, &mut stats, test.tc_id);
                }
                "ML-KEM-768" => {
                    test_keygen::<MlKem768>(&z, &d, &expected_ek, &expected_dk, &mut stats, test.tc_id);
                }
                "ML-KEM-1024" => {
                    test_keygen::<MlKem1024>(&z, &d, &expected_ek, &expected_dk, &mut stats, test.tc_id);
                }
                _ => {
                    eprintln!("Unknown parameter set: {}", group.parameter_set);
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ML-KEM KeyGen tests failed");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_keygen<K: KemCore>(
    z: &[u8],
    d: &[u8],
    expected_ek: &[u8],
    expected_dk: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    // Combine z and d to form the seed (z || d)
    let mut seed = Vec::with_capacity(z.len() + d.len());
    seed.extend_from_slice(d);
    seed.extend_from_slice(z);

    // Generate keypair from seed
    match K::generate_deterministic(&seed) {
        Ok((ek, dk)) => {
            // Compare encapsulation key
            if ek.as_ref() == expected_ek {
                // Compare decapsulation key
                if dk.as_ref() == expected_dk {
                    stats.passed += 1;
                } else {
                    eprintln!("Test case {} FAILED: Decapsulation key mismatch", tc_id);
                    eprintln!("  Expected dk length: {}", expected_dk.len());
                    eprintln!("  Got dk length: {}", dk.as_ref().len());
                    stats.failed += 1;
                }
            } else {
                eprintln!("Test case {} FAILED: Encapsulation key mismatch", tc_id);
                eprintln!("  Expected ek length: {}", expected_ek.len());
                eprintln!("  Got ek length: {}", ek.as_ref().len());
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
// ML-KEM Encap/Decap Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_encap_decap_cavp() {
    let prompt: EncapDecapPrompt = load_test_file("ML-KEM-encapDecap-FIPS203", "prompt.json");
    let expected: EncapDecapExpected =
        load_test_file("ML-KEM-encapDecap-FIPS203", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            match group.parameter_set.as_str() {
                "ML-KEM-512" => {
                    if group.function == "encapsulation" {
                        test_encap::<MlKem512>(test, expected_test, &mut stats);
                    } else if group.function == "decapsulation" {
                        test_decap::<MlKem512>(test, expected_test, &mut stats);
                    }
                }
                "ML-KEM-768" => {
                    if group.function == "encapsulation" {
                        test_encap::<MlKem768>(test, expected_test, &mut stats);
                    } else if group.function == "decapsulation" {
                        test_decap::<MlKem768>(test, expected_test, &mut stats);
                    }
                }
                "ML-KEM-1024" => {
                    if group.function == "encapsulation" {
                        test_encap::<MlKem1024>(test, expected_test, &mut stats);
                    } else if group.function == "decapsulation" {
                        test_decap::<MlKem1024>(test, expected_test, &mut stats);
                    }
                }
                _ => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some ML-KEM Encap/Decap tests failed");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_encap<K: KemCore>(
    test: &EncapDecapTestCase,
    expected: &EncapDecapExpectedCase,
    stats: &mut TestStats,
) {
    let m = decode_hex(test.m.as_ref().unwrap());
    let ek = decode_hex(test.ek.as_ref().unwrap());
    let expected_c = decode_hex(expected.c.as_ref().unwrap());
    let expected_k = decode_hex(expected.k.as_ref().unwrap());

    match K::encapsulate_deterministic(&ek, &m) {
        Ok((ciphertext, shared_secret)) => {
            if ciphertext.as_ref() == expected_c.as_slice()
                && shared_secret.as_ref() == expected_k.as_slice()
            {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Encapsulation mismatch", test.tc_id);
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: Encap error: {:?}", test.tc_id, e);
            stats.failed += 1;
        }
    }
}

#[cfg(feature = "enable-pqc-tests")]
fn test_decap<K: KemCore>(
    test: &EncapDecapTestCase,
    expected: &EncapDecapExpectedCase,
    stats: &mut TestStats,
) {
    let dk = decode_hex(test.dk.as_ref().unwrap());
    let c = decode_hex(test.c.as_ref().unwrap());
    let expected_k = decode_hex(expected.k.as_ref().unwrap());

    match K::decapsulate(&dk, &c) {
        Ok(shared_secret) => {
            if shared_secret.as_ref() == expected_k.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: Shared secret mismatch", test.tc_id);
                stats.failed += 1;
            }
        }
        Err(e) => {
            eprintln!("Test case {} FAILED: Decap error: {:?}", test.tc_id, e);
            stats.failed += 1;
        }
    }
}

// ============================================================================
// Stub tests for non-PQC builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_mlkem_keygen_cavp() {
    println!("ML-KEM tests skipped: enable-pqc-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-pqc-tests"))]
fn test_mlkem_encap_decap_cavp() {
    println!("ML-KEM tests skipped: enable-pqc-tests feature not enabled");
}
