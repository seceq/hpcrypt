//! NIST CAVP test vectors for SHA-3 and SHAKE
//!
//! Tests SHA-3 hash functions and SHAKE XOFs using official NIST test vectors.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-hash-tests")]
use hpcrypt_hash::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

// ============================================================================
// Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sha3Prompt {
    vs_id: u32,
    algorithm: String,
    revision: String,
    test_groups: Vec<Sha3TestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sha3TestGroup {
    tg_id: u32,
    test_type: String,
    tests: Vec<Sha3TestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sha3TestCase {
    tc_id: u32,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    large_msg: Option<serde_json::Value>,
    #[serde(default)]
    len: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sha3Expected {
    vs_id: u32,
    test_groups: Vec<Sha3ExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sha3ExpectedGroup {
    tg_id: u32,
    tests: Vec<Sha3ExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sha3ExpectedCase {
    tc_id: u32,
    #[serde(default)]
    md: Option<String>,
    #[serde(default)]
    results_array: Option<serde_json::Value>,
}

// ============================================================================
// SHAKE Test Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakePrompt {
    vs_id: u32,
    algorithm: String,
    revision: String,
    test_groups: Vec<ShakeTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeTestGroup {
    tg_id: u32,
    test_type: String,
    #[serde(default)]
    min_out_len: Option<usize>,
    #[serde(default)]
    max_out_len: Option<usize>,
    #[serde(default)]
    out_len: Option<usize>,
    tests: Vec<ShakeTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeTestCase {
    tc_id: u32,
    msg: String,
    #[serde(default)]
    out_len: Option<usize>,
    len: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeExpected {
    vs_id: u32,
    test_groups: Vec<ShakeExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeExpectedGroup {
    tg_id: u32,
    tests: Vec<ShakeExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeExpectedCase {
    tc_id: u32,
    md: String,
}

// ============================================================================
// SHA3-224 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha3_224_cavp() {
    let prompt: Sha3Prompt = load_test_file("SHA3-224-2.0", "prompt.json");
    let expected: Sha3Expected = load_test_file("SHA3-224-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Filter byte-aligned tests with regular msg (skip largeMsg and MCT tests)
        let byte_aligned_tests: Vec<_> = group.tests.iter()
            .filter(|t| t.len.is_some() && t.len.unwrap() % 8 == 0 && t.msg.is_some())
            .collect();
        let byte_aligned_expected: Vec<_> = expected_group.tests.iter().filter(|t| {
            t.md.is_some() && group.tests.iter().any(|gt| {
                gt.tc_id == t.tc_id && gt.len.is_some() && gt.len.unwrap() % 8 == 0 && gt.msg.is_some()
            })
        }).collect();

        stats.skipped += group.tests.len() - byte_aligned_tests.len();

        for (test, expected_test) in byte_aligned_tests.iter().zip(&byte_aligned_expected) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(test.msg.as_ref().unwrap());
            let msg_len_bytes = test.len.unwrap() / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(expected_test.md.as_ref().unwrap());

            test_sha3_224(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA3-224 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha3_224(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha3_224::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        eprintln!("  Expected: {}", hex::encode(expected));
        eprintln!("  Got:      {}", hex::encode(&digest));
        stats.failed += 1;
    }
}

// ============================================================================
// SHA3-256 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha3_256_cavp() {
    let prompt: Sha3Prompt = load_test_file("SHA3-256-2.0", "prompt.json");
    let expected: Sha3Expected = load_test_file("SHA3-256-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Filter byte-aligned tests with regular msg (skip largeMsg and MCT tests)
        let byte_aligned_tests: Vec<_> = group.tests.iter()
            .filter(|t| t.len.is_some() && t.len.unwrap() % 8 == 0 && t.msg.is_some())
            .collect();
        let byte_aligned_expected: Vec<_> = expected_group.tests.iter().filter(|t| {
            t.md.is_some() && group.tests.iter().any(|gt| {
                gt.tc_id == t.tc_id && gt.len.is_some() && gt.len.unwrap() % 8 == 0 && gt.msg.is_some()
            })
        }).collect();

        stats.skipped += group.tests.len() - byte_aligned_tests.len();

        for (test, expected_test) in byte_aligned_tests.iter().zip(&byte_aligned_expected) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(test.msg.as_ref().unwrap());
            let msg_len_bytes = test.len.unwrap() / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(expected_test.md.as_ref().unwrap());

            test_sha3_256(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA3-256 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha3_256(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha3_256::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        stats.failed += 1;
    }
}

// ============================================================================
// SHA3-384 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha3_384_cavp() {
    let prompt: Sha3Prompt = load_test_file("SHA3-384-2.0", "prompt.json");
    let expected: Sha3Expected = load_test_file("SHA3-384-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Filter byte-aligned tests with regular msg (skip largeMsg and MCT tests)
        let byte_aligned_tests: Vec<_> = group.tests.iter()
            .filter(|t| t.len.is_some() && t.len.unwrap() % 8 == 0 && t.msg.is_some())
            .collect();
        let byte_aligned_expected: Vec<_> = expected_group.tests.iter().filter(|t| {
            t.md.is_some() && group.tests.iter().any(|gt| {
                gt.tc_id == t.tc_id && gt.len.is_some() && gt.len.unwrap() % 8 == 0 && gt.msg.is_some()
            })
        }).collect();

        stats.skipped += group.tests.len() - byte_aligned_tests.len();

        for (test, expected_test) in byte_aligned_tests.iter().zip(&byte_aligned_expected) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(test.msg.as_ref().unwrap());
            let msg_len_bytes = test.len.unwrap() / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(expected_test.md.as_ref().unwrap());

            test_sha3_384(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA3-384 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha3_384(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha3_384::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        stats.failed += 1;
    }
}

// ============================================================================
// SHA3-512 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_sha3_512_cavp() {
    let prompt: Sha3Prompt = load_test_file("SHA3-512-2.0", "prompt.json");
    let expected: Sha3Expected = load_test_file("SHA3-512-2.0", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        // Filter byte-aligned tests with regular msg (skip largeMsg and MCT tests)
        let byte_aligned_tests: Vec<_> = group.tests.iter()
            .filter(|t| t.len.is_some() && t.len.unwrap() % 8 == 0 && t.msg.is_some())
            .collect();
        let byte_aligned_expected: Vec<_> = expected_group.tests.iter().filter(|t| {
            t.md.is_some() && group.tests.iter().any(|gt| {
                gt.tc_id == t.tc_id && gt.len.is_some() && gt.len.unwrap() % 8 == 0 && gt.msg.is_some()
            })
        }).collect();

        stats.skipped += group.tests.len() - byte_aligned_tests.len();

        for (test, expected_test) in byte_aligned_tests.iter().zip(&byte_aligned_expected) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(test.msg.as_ref().unwrap());
            let msg_len_bytes = test.len.unwrap() / 8;
            let msg_data = &msg[..msg_len_bytes];
            let expected_digest = decode_hex(expected_test.md.as_ref().unwrap());

            test_sha3_512(msg_data, &expected_digest, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHA3-512 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_sha3_512(msg: &[u8], expected: &[u8], stats: &mut TestStats, tc_id: u32) {
    let mut hasher = Sha3_512::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    if digest == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Digest mismatch", tc_id);
        stats.failed += 1;
    }
}

// ============================================================================
// SHAKE-128 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_shake128_cavp() {
    let prompt: ShakePrompt = load_test_file("SHAKE-128-FIPS202", "prompt.json");
    let expected: ShakeExpected = load_test_file("SHAKE-128-FIPS202", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let msg = decode_hex(&test.msg);
            let expected_output = decode_hex(&expected_test.md);

            // Output length is in bits, convert to bytes
            let out_len_bits = test.out_len.or(group.out_len).expect("Missing output length");
            let out_len_bytes = (out_len_bits + 7) / 8;

            test_shake128(&msg, &expected_output, out_len_bytes, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHAKE-128 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_shake128(msg: &[u8], expected: &[u8], out_len: usize, stats: &mut TestStats, tc_id: u32) {
    let mut xof = Shake128::new();
    xof.update(msg);
    let mut output = vec![0u8; out_len];
    xof.finalize(&mut output);

    if output == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Output mismatch", tc_id);
        eprintln!("  Expected length: {}", expected.len());
        eprintln!("  Got length: {}", output.len());
        stats.failed += 1;
    }
}

// ============================================================================
// SHAKE-256 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_shake256_cavp() {
    let prompt: ShakePrompt = load_test_file("SHAKE-256-FIPS202", "prompt.json");
    let expected: ShakeExpected = load_test_file("SHAKE-256-FIPS202", "expectedResults.json");

    let mut stats = TestStats::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            // Output length is in bits, convert to bytes
            let out_len_bits = test.out_len.or(group.out_len).expect("Missing output length");

            // Skip non-byte-aligned output lengths
            // (bit-level output would require special handling)
            if out_len_bits % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            let out_len_bytes = out_len_bits / 8;

            let msg = decode_hex(&test.msg);
            let expected_output = decode_hex(&expected_test.md);

            test_shake256(&msg, &expected_output, out_len_bytes, &mut stats, test.tc_id);
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHAKE-256 tests failed");
}

#[cfg(feature = "enable-hash-tests")]
fn test_shake256(msg: &[u8], expected: &[u8], out_len: usize, stats: &mut TestStats, tc_id: u32) {
    let mut xof = Shake256::new();
    xof.update(msg);
    let mut output = vec![0u8; out_len];
    xof.finalize(&mut output);

    if output == expected {
        stats.passed += 1;
    } else {
        eprintln!("Test case {} FAILED: Output mismatch", tc_id);
        stats.failed += 1;
    }
}

// ============================================================================
// Stub tests for non-hash builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha3_224_cavp() {
    println!("SHA-3 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha3_256_cavp() {
    println!("SHA-3 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha3_384_cavp() {
    println!("SHA-3 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_sha3_512_cavp() {
    println!("SHA-3 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_shake128_cavp() {
    println!("SHAKE tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_shake256_cavp() {
    println!("SHAKE tests skipped: enable-hash-tests feature not enabled");
}
