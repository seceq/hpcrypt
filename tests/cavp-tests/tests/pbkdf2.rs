//! NIST CAVP test vectors for PBKDF2
//!
//! Tests PBKDF2 key derivation using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-kdf-tests")]
use hpcrypt_kdf::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfPrompt {
    vs_id: u32,
    algorithm: String,
    revision: String,
    test_groups: Vec<PbkdfTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfTestGroup {
    tg_id: u32,
    test_type: String,
    hmac_alg: String,
    tests: Vec<PbkdfTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfTestCase {
    tc_id: u32,
    key_len: usize,
    salt: String,
    password: String,
    iteration_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfExpected {
    vs_id: u32,
    test_groups: Vec<PbkdfExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfExpectedGroup {
    tg_id: u32,
    tests: Vec<PbkdfExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfExpectedCase {
    tc_id: u32,
    derived_key: String,
}

// ============================================================================
// PBKDF2 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-kdf-tests")]
fn test_pbkdf2_cavp() {
    let prompt: PbkdfPrompt = load_test_file("PBKDF-1.0", "prompt.json");
    let expected: PbkdfExpected = load_test_file("PBKDF-1.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Only test SHA2-256 and SHA2-512
        if group.hmac_alg != "SHA2-256" && group.hmac_alg != "SHA2-512" {
            for _ in &group.tests {
                stats.skipped += 1;
            }
            continue;
        }

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let salt = decode_hex(&test.salt);
            let password = test.password.as_bytes();
            let expected_key = decode_hex(&expected_test.derived_key);

            // Key length is in bits, convert to bytes
            let key_len_bytes = (test.key_len + 7) / 8;

            match group.hmac_alg.as_str() {
                "SHA2-256" => {
                    test_pbkdf2_sha256(
                        password,
                        &salt,
                        test.iteration_count,
                        key_len_bytes,
                        &expected_key,
                        &mut stats,
                        test.tc_id,
                    );
                }
                "SHA2-512" => {
                    test_pbkdf2_sha512(
                        password,
                        &salt,
                        test.iteration_count,
                        key_len_bytes,
                        &expected_key,
                        &mut stats,
                        test.tc_id,
                    );
                }
                _ => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some PBKDF2 tests failed");
}

#[cfg(feature = "enable-kdf-tests")]
fn test_pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
    expected: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    let mut derived_key = vec![0u8; key_len];
    pbkdf2_hmac_sha256(password, salt, iterations, &mut derived_key);

    if derived_key == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Derived key mismatch", tc_id);
        eprintln!("  Password: {}", String::from_utf8_lossy(password));
        eprintln!("  Salt length: {}", salt.len());
        eprintln!("  Iterations: {}", iterations);
        eprintln!("  Key length: {}", key_len);
        eprintln!("  Expected length: {}", expected.len());
        eprintln!("  Got length: {}", derived_key.len());
        stats.failed += 1;
    }
}

#[cfg(feature = "enable-kdf-tests")]
fn test_pbkdf2_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
    expected: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    let mut derived_key = vec![0u8; key_len];
    pbkdf2_hmac_sha512(password, salt, iterations, &mut derived_key);

    if derived_key == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Derived key mismatch", tc_id);
        eprintln!("  Password: {}", String::from_utf8_lossy(password));
        eprintln!("  Salt length: {}", salt.len());
        eprintln!("  Iterations: {}", iterations);
        eprintln!("  Key length: {}", key_len);
        stats.failed += 1;
    }
}

// ============================================================================
// Stub tests for non-KDF builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-kdf-tests"))]
fn test_pbkdf2_cavp() {
    println!("PBKDF2 tests skipped: enable-kdf-tests feature not enabled");
}
