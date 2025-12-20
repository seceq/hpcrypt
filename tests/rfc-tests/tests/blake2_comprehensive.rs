//! BLAKE2 Comprehensive Test Suite
//!
//! This test suite uses the official BLAKE2 Known Answer Test (KAT) vectors
//! from the BLAKE2 reference implementation. It provides extensive coverage
//! with 1024 test vectors (512 for BLAKE2b, 512 for BLAKE2s).
//!
//! Source: https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json
//!
//! This provides coverage equivalent to CAVP or Wycheproof test suites for
//! other algorithms, ensuring implementation correctness across a wide range
//! of input sizes, key sizes, and edge cases.

use hpcrypt_hash::HashFunction;
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Blake2KatTestVector {
    test_id: u32,
    algorithm: String,
    variant: String,
    input: String,
    key: String,
    hash: String,
    input_length: usize,
    hash_length: usize,
    note: String,
}

#[test]
fn test_blake2_comprehensive_kat() {
    let test_vectors: Vec<Blake2KatTestVector> =
        load_test_file("blake2-kat-comprehensive.json");

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  BLAKE2 COMPREHENSIVE TEST SUITE - Official KAT Vectors    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\nTotal test vectors: {}", test_vectors.len());
    println!("Source: BLAKE2/BLAKE2 official repository");
    println!("Coverage: Full Known Answer Test suite\n");

    let mut stats = TestStats::new();
    let mut blake2b_count = 0;
    let mut blake2s_count = 0;

    for test in &test_vectors {
        // Print progress every 100 tests
        if test.test_id % 100 == 0 {
            println!("Progress: {}/{} tests completed", test.test_id, test_vectors.len());
        }

        let input = if test.input.is_empty() {
            vec![]
        } else {
            decode_hex(&test.input)
        };

        let key = if test.key.is_empty() {
            vec![]
        } else {
            decode_hex(&test.key)
        };

        let expected_hash = decode_hex(&test.hash);

        // Validate input and hash lengths
        assert_eq!(
            input.len(),
            test.input_length,
            "Input length mismatch for test {}",
            test.test_id
        );
        assert_eq!(
            expected_hash.len(),
            test.hash_length,
            "Hash length mismatch for test {}",
            test.test_id
        );

        match test.algorithm.as_str() {
            "BLAKE2b" => {
                use hpcrypt_hash::Blake2b;
                blake2b_count += 1;

                let output = if key.is_empty() {
                    // Unkeyed hash mode
                    let mut hasher = Blake2b::new_with_output_len(test.hash_length);
                    hasher.update(&input);
                    hasher.finalize()
                } else {
                    // Keyed hash mode (MAC)
                    let mut hasher = Blake2b::new_keyed(&key, test.hash_length);
                    hasher.update(&input);
                    hasher.finalize()
                };

                if output.as_slice() == expected_hash.as_slice() {
                    stats.passed += 1;
                } else {
                    println!("\n✗ BLAKE2b test {} FAILED", test.test_id);
                    println!("  Input length: {} bytes", test.input_length);
                    println!("  Key length: {} bytes", key.len());
                    println!("  Expected: {}", hex::encode(&expected_hash));
                    println!("  Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "BLAKE2s" => {
                use hpcrypt_hash::Blake2s;
                blake2s_count += 1;

                let output = if key.is_empty() {
                    // Unkeyed hash mode
                    let mut hasher = Blake2s::new_with_output_len(test.hash_length);
                    hasher.update(&input);
                    hasher.finalize()
                } else {
                    // Keyed hash mode (MAC)
                    let mut hasher = Blake2s::new_keyed(&key, test.hash_length);
                    hasher.update(&input);
                    hasher.finalize()
                };

                if output.as_slice() == expected_hash.as_slice() {
                    stats.passed += 1;
                } else {
                    println!("\n✗ BLAKE2s test {} FAILED", test.test_id);
                    println!("  Input length: {} bytes", test.input_length);
                    println!("  Key length: {} bytes", key.len());
                    println!("  Expected: {}", hex::encode(&expected_hash));
                    println!("  Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            _ => {
                println!("Unknown algorithm: {}", test.algorithm);
                stats.skipped += 1;
            }
        }
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    TEST RESULTS SUMMARY                      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  BLAKE2b test vectors: {}", blake2b_count);
    println!("  BLAKE2s test vectors: {}", blake2s_count);
    println!();

    stats.print_summary();

    assert_eq!(stats.failed, 0, "All BLAKE2 KAT tests should pass");
    assert_eq!(
        stats.passed,
        test_vectors.len(),
        "All test vectors should be tested"
    );
}

#[test]
fn test_blake2b_kat_coverage() {
    let test_vectors: Vec<Blake2KatTestVector> =
        load_test_file("blake2-kat-comprehensive.json");

    let blake2b_vectors: Vec<_> = test_vectors
        .iter()
        .filter(|t| t.algorithm == "BLAKE2b")
        .collect();

    println!("\n=== BLAKE2b KAT Coverage Analysis ===");
    println!("Total BLAKE2b test vectors: {}", blake2b_vectors.len());

    // Analyze input sizes
    let mut input_sizes: Vec<usize> = blake2b_vectors.iter().map(|t| t.input_length).collect();
    input_sizes.sort();
    input_sizes.dedup();

    println!("Unique input sizes tested: {}", input_sizes.len());
    println!(
        "  Min input size: {} bytes",
        input_sizes.first().unwrap_or(&0)
    );
    println!(
        "  Max input size: {} bytes",
        input_sizes.last().unwrap_or(&0)
    );

    // Count keyed vs unkeyed
    let keyed = blake2b_vectors.iter().filter(|t| !t.key.is_empty()).count();
    let unkeyed = blake2b_vectors.len() - keyed;
    println!("  Unkeyed hash tests: {}", unkeyed);
    println!("  Keyed hash (MAC) tests: {}", keyed);

    assert!(
        blake2b_vectors.len() >= 500,
        "Should have extensive BLAKE2b coverage"
    );
}

#[test]
fn test_blake2s_kat_coverage() {
    let test_vectors: Vec<Blake2KatTestVector> =
        load_test_file("blake2-kat-comprehensive.json");

    let blake2s_vectors: Vec<_> = test_vectors
        .iter()
        .filter(|t| t.algorithm == "BLAKE2s")
        .collect();

    println!("\n=== BLAKE2s KAT Coverage Analysis ===");
    println!("Total BLAKE2s test vectors: {}", blake2s_vectors.len());

    // Analyze input sizes
    let mut input_sizes: Vec<usize> = blake2s_vectors.iter().map(|t| t.input_length).collect();
    input_sizes.sort();
    input_sizes.dedup();

    println!("Unique input sizes tested: {}", input_sizes.len());
    println!(
        "  Min input size: {} bytes",
        input_sizes.first().unwrap_or(&0)
    );
    println!(
        "  Max input size: {} bytes",
        input_sizes.last().unwrap_or(&0)
    );

    // Count keyed vs unkeyed
    let keyed = blake2s_vectors.iter().filter(|t| !t.key.is_empty()).count();
    let unkeyed = blake2s_vectors.len() - keyed;
    println!("  Unkeyed hash tests: {}", unkeyed);
    println!("  Keyed hash (MAC) tests: {}", keyed);

    assert!(
        blake2s_vectors.len() >= 500,
        "Should have extensive BLAKE2s coverage"
    );
}

/// Test that ensures comprehensive coverage exists
#[test]
fn test_blake2_coverage_completeness() {
    let test_vectors: Vec<Blake2KatTestVector> =
        load_test_file("blake2-kat-comprehensive.json");

    println!("\n=== BLAKE2 Comprehensive Coverage Report ===");
    println!("Total test vectors: {}", test_vectors.len());

    // Should have complete KAT coverage
    assert!(
        test_vectors.len() >= 1000,
        "Comprehensive test suite should have 1000+ vectors"
    );

    // Both algorithms should be well represented
    let blake2b_count = test_vectors.iter().filter(|t| t.algorithm == "BLAKE2b").count();
    let blake2s_count = test_vectors.iter().filter(|t| t.algorithm == "BLAKE2s").count();

    println!("  BLAKE2b vectors: {}", blake2b_count);
    println!("  BLAKE2s vectors: {}", blake2s_count);

    assert!(blake2b_count >= 500, "Should have 500+ BLAKE2b vectors");
    assert!(blake2s_count >= 500, "Should have 500+ BLAKE2s vectors");

    println!("\n* Comprehensive coverage confirmed");
    println!("  This test suite provides CAVP/Wycheproof-equivalent coverage");
    println!("  for BLAKE2b and BLAKE2s implementations.");
}
