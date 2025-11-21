//! NIST CAVP test vectors for HMAC
//!
//! Tests HMAC-SHA2 using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-mac-tests")]
use hpcrypt_mac::{Hmac, HmacSha256, HmacSha384, HmacSha512};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacPrompt {
    vs_id: u32,
    algorithm: String,
    test_groups: Vec<HmacTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacTestGroup {
    tg_id: u32,
    test_type: String,
    tests: Vec<HmacTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacTestCase {
    tc_id: u32,
    key: String,
    key_len: usize,
    msg: String,
    msg_len: usize,
    mac_len: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacExpected {
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
    tc_id: u32,
    mac: String,
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
            assert_eq!(test.tc_id, expected_test.tc_id);

            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            test_hmac::<HmacSha256>(&key, &msg, &expected_mac, test.mac_len, &mut stats, test.tc_id);
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
            assert_eq!(test.tc_id, expected_test.tc_id);

            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            test_hmac::<HmacSha384>(&key, &msg, &expected_mac, test.mac_len, &mut stats, test.tc_id);
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
            assert_eq!(test.tc_id, expected_test.tc_id);

            let key = decode_hex(&test.key);
            let msg = decode_hex(&test.msg);
            let expected_mac = decode_hex(&expected_test.mac);

            test_hmac::<HmacSha512>(&key, &msg, &expected_mac, test.mac_len, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some HMAC-SHA512 tests failed");
}

// ============================================================================
// Test Helper
// ============================================================================

#[cfg(feature = "enable-mac-tests")]
fn test_hmac<H: Hmac>(
    key: &[u8],
    msg: &[u8],
    expected_mac: &[u8],
    mac_len_bits: usize,
    stats: &mut TestStats,
    tc_id: u32,
) {
    let mac = H::mac(key, msg);

    // Truncate to requested MAC length (in bits)
    let mac_len_bytes = (mac_len_bits + 7) / 8;
    let truncated_mac = &mac[..mac_len_bytes];

    if truncated_mac == expected_mac {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: MAC mismatch", tc_id);
        eprintln!("  Expected length: {}", expected_mac.len());
        eprintln!("  Got length: {}", truncated_mac.len());
        eprintln!("  Expected: {}", hex::encode(expected_mac));
        eprintln!("  Got: {}", hex::encode(truncated_mac));
        stats.failed += 1;
    }
}

// ============================================================================
// Stub tests for non-MAC builds
// ============================================================================

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
