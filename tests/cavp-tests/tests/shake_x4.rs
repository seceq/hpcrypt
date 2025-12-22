//! NIST CAVP test vectors for 4-way parallel SHAKE (SHAKE x4)
//!
//! Tests Shake128x4 and Shake256x4 using official NIST FIPS 202 test vectors.
//! Processes test vectors in batches of 4 to exercise the parallel Keccak implementation.

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-hash-tests")]
use hpcrypt_hash::shake_x4::{Shake128x4, Shake256x4};

// ============================================================================
// SHAKE Test Data Structures (same as sha3.rs)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakePrompt {
    #[allow(dead_code)]
    vs_id: u32,
    #[allow(dead_code)]
    algorithm: String,
    #[allow(dead_code)]
    revision: String,
    test_groups: Vec<ShakeTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeTestGroup {
    tg_id: u32,
    #[allow(dead_code)]
    test_type: String,
    #[serde(default)]
    #[allow(dead_code)]
    min_out_len: Option<usize>,
    #[serde(default)]
    #[allow(dead_code)]
    max_out_len: Option<usize>,
    #[serde(default)]
    out_len: Option<usize>,
    tests: Vec<ShakeTestCase>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ShakeTestCase {
    tc_id: u32,
    msg: String,
    #[serde(default)]
    out_len: Option<usize>,
    #[allow(dead_code)]
    len: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeExpected {
    #[allow(dead_code)]
    vs_id: u32,
    test_groups: Vec<ShakeExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShakeExpectedGroup {
    tg_id: u32,
    tests: Vec<ShakeExpectedCase>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ShakeExpectedCase {
    tc_id: u32,
    md: String,
}

// ============================================================================
// Test case with input and expected output combined
// ============================================================================

struct ProcessedTestCase {
    tc_id: u32,
    msg: Vec<u8>,
    expected: Vec<u8>,
    out_len: usize,
}

// ============================================================================
// SHAKE-128 x4 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_shake128_x4_cavp() {
    let prompt: ShakePrompt = load_test_file("SHAKE-128-FIPS202", "prompt.json");
    let expected: ShakeExpected = load_test_file("SHAKE-128-FIPS202", "expectedResults.json");

    let mut stats = TestStats::new();

    // Collect all test cases with their expected outputs
    let mut all_tests: Vec<ProcessedTestCase> = Vec::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let out_len_bits = test.out_len.or(group.out_len).expect("Missing output length");

            // Skip non-byte-aligned output lengths
            if out_len_bits % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            let out_len_bytes = out_len_bits / 8;

            // Skip tests with output > 1024 bytes (our buffer limit)
            if out_len_bytes > 1024 {
                stats.skipped += 1;
                continue;
            }

            let msg = decode_hex(&test.msg);
            let expected_output = decode_hex(&expected_test.md);

            all_tests.push(ProcessedTestCase {
                tc_id: test.tc_id,
                msg,
                expected: expected_output,
                out_len: out_len_bytes,
            });
        }
    }

    // Process tests in batches of 4
    let mut i = 0;
    while i + 4 <= all_tests.len() {
        let batch = &all_tests[i..i + 4];

        // Find max output length in this batch
        let max_out_len = batch.iter().map(|t| t.out_len).max().unwrap();

        // Prepare inputs
        let inputs: [&[u8]; 4] = [
            &batch[0].msg,
            &batch[1].msg,
            &batch[2].msg,
            &batch[3].msg,
        ];

        // Run Shake128x4 with fixed-size output buffer
        let mut hasher = Shake128x4::new();
        hasher.absorb_x4(&inputs);

        // Use fixed-size array for outputs, then compare the relevant portion
        let mut outputs: [[u8; 1024]; 4] = [[0u8; 1024]; 4];
        hasher.squeeze_x4(&mut outputs);

        // Verify each output (only up to max_out_len)
        for (j, test) in batch.iter().enumerate() {
            let actual = &outputs[j][..test.out_len];
            if actual == &test.expected[..] {
                stats.passed += 1;
            } else {
                eprintln!(
                    "SHAKE-128 x4 batch test case {} FAILED (batch starting at {})",
                    test.tc_id,
                    batch[0].tc_id
                );
                eprintln!("  Expected: {}", hex::encode(&test.expected));
                eprintln!("  Got:      {}", hex::encode(actual));
                stats.failed += 1;
            }
        }
        let _ = max_out_len; // silence unused warning

        i += 4;
    }

    // Handle remaining tests (less than 4) with padding
    if i < all_tests.len() {
        let remaining = &all_tests[i..];

        // Pad with empty inputs
        let empty: Vec<u8> = vec![];
        let mut inputs_vec: Vec<&[u8]> = remaining.iter().map(|t| t.msg.as_slice()).collect();
        while inputs_vec.len() < 4 {
            inputs_vec.push(&empty);
        }
        let inputs: [&[u8]; 4] = [inputs_vec[0], inputs_vec[1], inputs_vec[2], inputs_vec[3]];

        let mut hasher = Shake128x4::new();
        hasher.absorb_x4(&inputs);

        let mut outputs: [[u8; 1024]; 4] = [[0u8; 1024]; 4];
        hasher.squeeze_x4(&mut outputs);

        for (j, test) in remaining.iter().enumerate() {
            let actual = &outputs[j][..test.out_len];
            if actual == &test.expected[..] {
                stats.passed += 1;
            } else {
                eprintln!("SHAKE-128 x4 remaining test case {} FAILED", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&test.expected));
                eprintln!("  Got:      {}", hex::encode(actual));
                stats.failed += 1;
            }
        }
    }

    println!("\n=== SHAKE-128 x4 CAVP Test Results ===");
    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHAKE-128 x4 tests failed");
}

// ============================================================================
// SHAKE-256 x4 Tests
// ============================================================================

#[test]
#[cfg(feature = "enable-hash-tests")]
fn test_shake256_x4_cavp() {
    let prompt: ShakePrompt = load_test_file("SHAKE-256-FIPS202", "prompt.json");
    let expected: ShakeExpected = load_test_file("SHAKE-256-FIPS202", "expectedResults.json");

    let mut stats = TestStats::new();

    // Collect all test cases with their expected outputs
    let mut all_tests: Vec<ProcessedTestCase> = Vec::new();

    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        assert_eq!(group.tg_id, expected_group.tg_id);

        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(test.tc_id, expected_test.tc_id);

            let out_len_bits = test.out_len.or(group.out_len).expect("Missing output length");

            // Skip non-byte-aligned output lengths
            if out_len_bits % 8 != 0 {
                stats.skipped += 1;
                continue;
            }

            let out_len_bytes = out_len_bits / 8;

            // Skip tests with output > 1024 bytes (our buffer limit)
            if out_len_bytes > 1024 {
                stats.skipped += 1;
                continue;
            }

            let msg = decode_hex(&test.msg);
            let expected_output = decode_hex(&expected_test.md);

            all_tests.push(ProcessedTestCase {
                tc_id: test.tc_id,
                msg,
                expected: expected_output,
                out_len: out_len_bytes,
            });
        }
    }

    // Process tests in batches of 4
    let mut i = 0;
    while i + 4 <= all_tests.len() {
        let batch = &all_tests[i..i + 4];

        // Find max output length in this batch
        let max_out_len = batch.iter().map(|t| t.out_len).max().unwrap();

        // Prepare inputs
        let inputs: [&[u8]; 4] = [
            &batch[0].msg,
            &batch[1].msg,
            &batch[2].msg,
            &batch[3].msg,
        ];

        // Run Shake256x4 with fixed-size output buffer
        let mut hasher = Shake256x4::new();
        hasher.absorb_x4(&inputs);

        // Use fixed-size array for outputs, then compare the relevant portion
        let mut outputs: [[u8; 1024]; 4] = [[0u8; 1024]; 4];
        hasher.squeeze_x4(&mut outputs);

        // Verify each output (only up to max_out_len)
        for (j, test) in batch.iter().enumerate() {
            let actual = &outputs[j][..test.out_len];
            if actual == &test.expected[..] {
                stats.passed += 1;
            } else {
                eprintln!(
                    "SHAKE-256 x4 batch test case {} FAILED (batch starting at {})",
                    test.tc_id,
                    batch[0].tc_id
                );
                eprintln!("  Expected: {}", hex::encode(&test.expected));
                eprintln!("  Got:      {}", hex::encode(actual));
                stats.failed += 1;
            }
        }
        let _ = max_out_len; // silence unused warning

        i += 4;
    }

    // Handle remaining tests (less than 4) with padding
    if i < all_tests.len() {
        let remaining = &all_tests[i..];

        // Pad with empty inputs
        let empty: Vec<u8> = vec![];
        let mut inputs_vec: Vec<&[u8]> = remaining.iter().map(|t| t.msg.as_slice()).collect();
        while inputs_vec.len() < 4 {
            inputs_vec.push(&empty);
        }
        let inputs: [&[u8]; 4] = [inputs_vec[0], inputs_vec[1], inputs_vec[2], inputs_vec[3]];

        let mut hasher = Shake256x4::new();
        hasher.absorb_x4(&inputs);

        let mut outputs: [[u8; 1024]; 4] = [[0u8; 1024]; 4];
        hasher.squeeze_x4(&mut outputs);

        for (j, test) in remaining.iter().enumerate() {
            let actual = &outputs[j][..test.out_len];
            if actual == &test.expected[..] {
                stats.passed += 1;
            } else {
                eprintln!("SHAKE-256 x4 remaining test case {} FAILED", test.tc_id);
                eprintln!("  Expected: {}", hex::encode(&test.expected));
                eprintln!("  Got:      {}", hex::encode(actual));
                stats.failed += 1;
            }
        }
    }

    println!("\n=== SHAKE-256 x4 CAVP Test Results ===");
    stats.print_summary();
    assert_eq!(stats.failed, 0, "Some SHAKE-256 x4 tests failed");
}

// ============================================================================
// Stub tests for non-hash builds
// ============================================================================

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_shake128_x4_cavp() {
    println!("SHAKE x4 tests skipped: enable-hash-tests feature not enabled");
}

#[test]
#[cfg(not(feature = "enable-hash-tests"))]
fn test_shake256_x4_cavp() {
    println!("SHAKE x4 tests skipped: enable-hash-tests feature not enabled");
}
