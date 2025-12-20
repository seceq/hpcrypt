//! NIST CAVP test vectors for SHA-2 family
//!
//! Tests SHA-1, SHA-256, SHA-384, and SHA-512 using official NIST CAVP test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-hash-tests")]
use hpcrypt_hash::{HashFunction, Sha1, Sha256, Sha384, Sha512};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShaPrompt {
    vs_id: u32,
    algorithm: String,
    revision: String,
    test_groups: Vec<ShaTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShaTestGroup {
    tg_id: u32,
    test_type: String,
    tests: Vec<ShaTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShaTestCase {
    tc_id: u32,
    len: usize,
    msg: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShaExpected {
    vs_id: u32,
    test_groups: Vec<ShaExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShaExpectedGroup {
    tg_id: u32,
    tests: Vec<ShaExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShaExpectedCase {
    tc_id: u32,
    md: String,
}

// ============================================================================
// SHA-1 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha1_cavp() {
    let prompt: ShaPrompt = load_test_file("SHA1-1.0", "prompt.json");
    let expected: ShaExpected = load_test_file("SHA1-1.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(&test.msg);
            let msg_len_bytes = test.len / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(&expected_test.md);

            test_sha1(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA-1 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha1(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha1::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest.as_slice() == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        eprintln!("  Expected: {}", hex::encode(expected));
        eprintln!("  Got:      {}", hex::encode(&digest));
        stats.failed += 1;
    }
}

// ============================================================================
// SHA-256 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha256_cavp() {
    let prompt: ShaPrompt = load_test_file("SHA2-256-1.0", "prompt.json");
    let expected: ShaExpected = load_test_file("SHA2-256-1.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(&test.msg);
            let msg_len_bytes = test.len / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(&expected_test.md);

            test_sha256(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA-256 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha256(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest.as_slice() == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        eprintln!("  Expected: {}", hex::encode(expected));
        eprintln!("  Got:      {}", hex::encode(&digest));
        stats.failed += 1;
    }
}

// ============================================================================
// SHA-384 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha384_cavp() {
    let prompt: ShaPrompt = load_test_file("SHA2-384-1.0", "prompt.json");
    let expected: ShaExpected = load_test_file("SHA2-384-1.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(&test.msg);
            let msg_len_bytes = test.len / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(&expected_test.md);

            test_sha384(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA-384 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha384(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha384::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest.as_slice() == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        eprintln!("  Expected: {}", hex::encode(expected));
        eprintln!("  Got:      {}", hex::encode(&digest));
        stats.failed += 1;
    }
}

// ============================================================================
// SHA-512 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha512_cavp() {
    let prompt: ShaPrompt = load_test_file("SHA2-512-1.0", "prompt.json");
    let expected: ShaExpected = load_test_file("SHA2-512-1.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(&test.msg);
            let msg_len_bytes = test.len / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(&expected_test.md);

            test_sha512(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA-512 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha512(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha512::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest.as_slice() == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        eprintln!("  Expected: {}", hex::encode(expected));
        eprintln!("  Got:      {}", hex::encode(&digest));
        stats.failed += 1;
    }
}

// ============================================================================
// Stub tests for non-hash builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha1_cavp() {
    println!("SHA-1 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha256_cavp() {
    println!("SHA-256 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha384_cavp() {
    println!("SHA-384 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha512_cavp() {
    println!("SHA-512 tests skipped: enable-hash-tests feature not enabled");
}
