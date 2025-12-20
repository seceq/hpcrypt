//! NIST CAVP test vectors for HMAC
//!
//! Tests HMAC-SHA2 using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-mac-tests")]
use hpcrypt_mac::{HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacSha512_224, HmacSha512_256, Mac};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacPrompt {
    #[allow(dead_code)]
    vs_id: u32,
    #[allow(dead_code)]
    algorithm: String,
    test_groups: Vec<HmacTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacTestGroup {
    tg_id: u32,
    #[allow(dead_code)]
    test_type: String,
    tests: Vec<HmacTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacTestCase {
    tc_id: u32,
    key: String,
    #[allow(dead_code)]
    key_len: usize,
    msg: String,
    #[allow(dead_code)]
    msg_len: usize,
    mac_len: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacExpected {
    #[allow(dead_code)]
    vs_id: u32,
    test_groups: Vec<HmacExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacExpectedGroup {
    tg_id: u32,
    tests: Vec<HmacExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacExpectedCase {
    #[allow(dead_code)]
    tc_id: u32,
    mac: String,
}

// ============================================================================
// HMAC-SHA224 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-mac-tests")]
fn test_hmac_sha224_cavp() {
    let prompt: HmacPrompt = load_test_file("HMAC-SHA2-224-2.0", "prompt.json");
    let expected: HmacExpected = load_test_file("HMAC-SHA2-224-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            let mac = HmacSha224::compute(&key, &msg);

            // Truncate to requested MAC length (in bits)
            let mac_len_bytes = (test.mac_len + 7) / 8;
            let truncated_mac = &mac[..mac_len_bytes];

            if truncated_mac == expected_mac.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: MAC mismatch", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&expected_mac));
                eprintln!("  Got: {}", hex::encode(truncated_mac));
                stats.failed += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some HMAC-SHA224 tests failed");
}

// ============================================================================
// HMAC-SHA256 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-mac-tests")]
fn test_hmac_sha256_cavp() {
    let prompt: HmacPrompt = load_test_file("HMAC-SHA2-256-2.0", "prompt.json");
    let expected: HmacExpected = load_test_file("HMAC-SHA2-256-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            let mac = HmacSha256::compute(&key, &msg);

            // Truncate to requested MAC length (in bits)
            let mac_len_bytes = (test.mac_len + 7) / 8;
            let truncated_mac = &mac[..mac_len_bytes];

            if truncated_mac == expected_mac.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: MAC mismatch", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&expected_mac));
                eprintln!("  Got: {}", hex::encode(truncated_mac));
                stats.failed += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some HMAC-SHA256 tests failed");
}

// ============================================================================
// HMAC-SHA384 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-mac-tests")]
fn test_hmac_sha384_cavp() {
    let prompt: HmacPrompt = load_test_file("HMAC-SHA2-384-2.0", "prompt.json");
    let expected: HmacExpected = load_test_file("HMAC-SHA2-384-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            let mac = HmacSha384::compute(&key, &msg);

            // Truncate to requested MAC length (in bits)
            let mac_len_bytes = (test.mac_len + 7) / 8;
            let truncated_mac = &mac[..mac_len_bytes];

            if truncated_mac == expected_mac.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: MAC mismatch", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&expected_mac));
                eprintln!("  Got: {}", hex::encode(truncated_mac));
                stats.failed += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some HMAC-SHA384 tests failed");
}

// ============================================================================
// HMAC-SHA512 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-mac-tests")]
fn test_hmac_sha512_cavp() {
    let prompt: HmacPrompt = load_test_file("HMAC-SHA2-512-2.0", "prompt.json");
    let expected: HmacExpected = load_test_file("HMAC-SHA2-512-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            let mac = HmacSha512::compute(&key, &msg);

            // Truncate to requested MAC length (in bits)
            let mac_len_bytes = (test.mac_len + 7) / 8;
            let truncated_mac = &mac[..mac_len_bytes];

            if truncated_mac == expected_mac.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: MAC mismatch", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&expected_mac));
                eprintln!("  Got: {}", hex::encode(truncated_mac));
                stats.failed += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some HMAC-SHA512 tests failed");
}

// ============================================================================
// HMAC-SHA512/224 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-mac-tests")]
fn test_hmac_sha512_224_cavp() {
    let prompt: HmacPrompt = load_test_file("HMAC-SHA2-512-224-2.0", "prompt.json");
    let expected: HmacExpected = load_test_file("HMAC-SHA2-512-224-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            let mac = HmacSha512_224::compute(&key, &msg);

            // Truncate to requested MAC length (in bits)
            let mac_len_bytes = (test.mac_len + 7) / 8;
            let truncated_mac = &mac[..mac_len_bytes];

            if truncated_mac == expected_mac.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: MAC mismatch", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&expected_mac));
                eprintln!("  Got: {}", hex::encode(truncated_mac));
                stats.failed += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some HMAC-SHA512/224 tests failed");
}

// ============================================================================
// HMAC-SHA512/256 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-mac-tests")]
fn test_hmac_sha512_256_cavp() {
    let prompt: HmacPrompt = load_test_file("HMAC-SHA2-512-256-2.0", "prompt.json");
    let expected: HmacExpected = load_test_file("HMAC-SHA2-512-256-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            let mac = HmacSha512_256::compute(&key, &msg);

            // Truncate to requested MAC length (in bits)
            let mac_len_bytes = (test.mac_len + 7) / 8;
            let truncated_mac = &mac[..mac_len_bytes];

            if truncated_mac == expected_mac.as_slice() {
                stats.passed += 1;
            } else {
                eprintln!("Test case {} FAILED: MAC mismatch", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&expected_mac));
                eprintln!("  Got: {}", hex::encode(truncated_mac));
                stats.failed += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some HMAC-SHA512/256 tests failed");
}

// ============================================================================
// Stub tests for non-MAC builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-mac-tests"))]
fn test_hmac_sha224_cavp() {
    println!("HMAC tests skipped: enable-mac-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-mac-tests"))]
fn test_hmac_sha256_cavp() {
    println!("HMAC tests skipped: enable-mac-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-mac-tests"))]
fn test_hmac_sha384_cavp() {
    println!("HMAC tests skipped: enable-mac-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-mac-tests"))]
fn test_hmac_sha512_cavp() {
    println!("HMAC tests skipped: enable-mac-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-mac-tests"))]
fn test_hmac_sha512_224_cavp() {
    println!("HMAC tests skipped: enable-mac-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-mac-tests"))]
fn test_hmac_sha512_256_cavp() {
    println!("HMAC tests skipped: enable-mac-tests feature not enabled");
}
