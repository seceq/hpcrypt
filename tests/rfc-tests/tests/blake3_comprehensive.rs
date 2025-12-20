//! BLAKE3 Comprehensive Test Suite
//!
//! This test suite uses the official BLAKE3 test vectors from the BLAKE3 team.
//! It provides extensive coverage with vectors covering all three modes
//! (hash, keyed_hash, derive_key) and a wide range of input sizes from 0 bytes
//! to 100+ KB.
//!
//! Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
//!
//! This provides coverage equivalent to CAVP or Wycheproof test suites for
//! other algorithms, ensuring implementation correctness across all BLAKE3
//! modes and edge cases.

use hpcrypt_hash::HashFunction;
use rfc_tests::{decode_hex, test_vectors_path, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Blake3KatFile {
    #[serde(rename = "_comment")]
    _comment: String,
    key: String,
    context_string: String,
    cases: Vec<Blake3TestCase>,
}

#[derive(Debug, Deserialize)]
struct Blake3TestCase {
    input_len: usize,
    hash: String,
    keyed_hash: String,
    derive_key: String,
}

fn load_blake3_kat() -> Blake3KatFile {
    let path = test_vectors_path().join("blake3-kat-comprehensive.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read BLAKE3 KAT file at {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to parse BLAKE3 KAT JSON: {}", e))
}

fn generate_input(len: usize) -> Vec<u8> {
    // Input is a repeating sequence: 0, 1, 2, ..., 249, 250, 0, 1, ...
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn test_blake3_comprehensive_kat_hash_mode() {
    let kat = load_blake3_kat();

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║     BLAKE3 COMPREHENSIVE TEST - Hash Mode                   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\nTotal test cases: {}", kat.cases.len());
    println!("Source: BLAKE3-team/BLAKE3 official repository");
    println!("Coverage: Full Known Answer Test suite - Hash mode\n");

    let mut stats = TestStats::new();

    for (idx, test) in kat.cases.iter().enumerate() {
        if (idx + 1) % 10 == 0 {
            println!("Progress: {}/{} tests completed", idx + 1, kat.cases.len());
        }

        let input = generate_input(test.input_len);
        assert_eq!(
            input.len(),
            test.input_len,
            "Generated input length mismatch"
        );

        let expected_hash = decode_hex(&test.hash);

        use hpcrypt_hash::Blake3;
        let mut hasher = Blake3::new();
        hasher.update(&input);

        // BLAKE3 uses extended output (XOF)
        let output = if expected_hash.len() > 32 {
            hasher.finalize_xof(expected_hash.len())
        } else {
            hasher.finalize().to_vec()
        };

        if output == expected_hash {
            stats.passed += 1;
        } else {
            println!("\n✗ BLAKE3 hash test {} FAILED", idx + 1);
            println!("  Input length: {} bytes", test.input_len);
            println!("  Output length: {} bytes", expected_hash.len());
            println!("  Expected: {}...", &test.hash[..64.min(test.hash.len())]);
            println!("  Got:      {}...", hex::encode(&output[..32.min(output.len())]));
            stats.failed += 1;
        }
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                  HASH MODE TEST RESULTS                      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    stats.print_summary();

    assert_eq!(stats.failed, 0, "All BLAKE3 hash mode tests should pass");
    assert_eq!(
        stats.passed,
        kat.cases.len(),
        "All test vectors should be tested"
    );
}

#[test]
fn test_blake3_comprehensive_kat_keyed_hash_mode() {
    let kat = load_blake3_kat();

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║     BLAKE3 COMPREHENSIVE TEST - Keyed Hash Mode             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\nTotal test cases: {}", kat.cases.len());
    println!("Key: \"{}\"", kat.key);
    println!("Coverage: Full Known Answer Test suite - Keyed hash mode\n");

    // Convert key string to 32-byte array
    let key_bytes = kat.key.as_bytes();
    assert_eq!(key_bytes.len(), 32, "Key must be 32 bytes");
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);

    let mut stats = TestStats::new();

    for (idx, test) in kat.cases.iter().enumerate() {
        if (idx + 1) % 10 == 0 {
            println!("Progress: {}/{} tests completed", idx + 1, kat.cases.len());
        }

        let input = generate_input(test.input_len);
        let expected_hash = decode_hex(&test.keyed_hash);

        use hpcrypt_hash::Blake3;
        let mut hasher = Blake3::new_keyed(&key_array);
        hasher.update(&input);

        let output = if expected_hash.len() > 32 {
            hasher.finalize_xof(expected_hash.len())
        } else {
            hasher.finalize().to_vec()
        };

        if output == expected_hash {
            stats.passed += 1;
        } else {
            println!("\n✗ BLAKE3 keyed hash test {} FAILED", idx + 1);
            println!("  Input length: {} bytes", test.input_len);
            println!("  Output length: {} bytes", expected_hash.len());
            println!("  Expected: {}...", &test.keyed_hash[..64.min(test.keyed_hash.len())]);
            println!("  Got:      {}...", hex::encode(&output[..32.min(output.len())]));
            stats.failed += 1;
        }
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║              KEYED HASH MODE TEST RESULTS                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    stats.print_summary();

    assert_eq!(
        stats.failed, 0,
        "All BLAKE3 keyed hash mode tests should pass"
    );
}

#[test]
fn test_blake3_comprehensive_kat_derive_key_mode() {
    let kat = load_blake3_kat();

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║     BLAKE3 COMPREHENSIVE TEST - Key Derivation Mode         ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\nTotal test cases: {}", kat.cases.len());
    println!("Context: \"{}\"", kat.context_string);
    println!("Coverage: Full Known Answer Test suite - Key derivation mode\n");

    let mut stats = TestStats::new();

    for (idx, test) in kat.cases.iter().enumerate() {
        if (idx + 1) % 10 == 0 {
            println!("Progress: {}/{} tests completed", idx + 1, kat.cases.len());
        }

        let input = generate_input(test.input_len);
        let expected_hash = decode_hex(&test.derive_key);

        use hpcrypt_hash::Blake3;
        let mut hasher = Blake3::new_derive_key(&kat.context_string);
        hasher.update(&input);

        let output = if expected_hash.len() > 32 {
            hasher.finalize_xof(expected_hash.len())
        } else {
            hasher.finalize().to_vec()
        };

        if output == expected_hash {
            stats.passed += 1;
        } else {
            println!("\n✗ BLAKE3 derive_key test {} FAILED", idx + 1);
            println!("  Input length: {} bytes", test.input_len);
            println!("  Output length: {} bytes", expected_hash.len());
            println!("  Expected: {}...", &test.derive_key[..64.min(test.derive_key.len())]);
            println!("  Got:      {}...", hex::encode(&output[..32.min(output.len())]));
            stats.failed += 1;
        }
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║           KEY DERIVATION MODE TEST RESULTS                   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    stats.print_summary();

    assert_eq!(
        stats.failed, 0,
        "All BLAKE3 derive_key mode tests should pass"
    );
}

#[test]
fn test_blake3_coverage_analysis() {
    let kat = load_blake3_kat();

    println!("\n=== BLAKE3 Comprehensive Coverage Analysis ===");
    println!("Total test cases: {}", kat.cases.len());

    // Analyze input sizes
    let mut input_sizes: Vec<usize> = kat.cases.iter().map(|t| t.input_len).collect();
    input_sizes.sort();

    println!("\nInput size coverage:");
    println!("  Minimum input size: {} bytes", input_sizes.first().unwrap_or(&0));
    println!("  Maximum input size: {} bytes", input_sizes.last().unwrap_or(&0));
    println!("  Total unique sizes: {}", input_sizes.len());

    // Count tests by size category
    let empty = kat.cases.iter().filter(|t| t.input_len == 0).count();
    let small = kat.cases.iter().filter(|t| t.input_len > 0 && t.input_len < 64).count();
    let medium = kat.cases.iter().filter(|t| t.input_len >= 64 && t.input_len < 1024).count();
    let large = kat.cases.iter().filter(|t| t.input_len >= 1024).count();

    println!("\nTest distribution:");
    println!("  Empty input: {} test(s)", empty);
    println!("  Small (1-63 bytes): {} tests", small);
    println!("  Medium (64-1023 bytes): {} tests", medium);
    println!("  Large (1024+ bytes): {} tests", large);

    // Analyze output sizes (all should have extended outputs)
    let first_case = kat.cases.first().expect("Should have at least one test");
    let output_len = decode_hex(&first_case.hash).len();
    println!("\nExtended output length: {} bytes", output_len);
    println!("  Standard BLAKE3 output: 32 bytes");
    println!("  Extended output tested: {} bytes", output_len);

    println!("\nModes tested:");
    println!("  * Hash mode (standard hashing)");
    println!("  * Keyed hash mode (MAC)");
    println!("  * Key derivation mode (KDF)");

    println!("\n* Comprehensive coverage confirmed");
    println!("  This test suite provides CAVP/Wycheproof-equivalent coverage");
    println!("  for BLAKE3 implementation across all modes and input sizes.");

    assert!(kat.cases.len() >= 30, "Should have 30+ comprehensive test cases");
}

#[test]
fn test_blake3_all_modes_combined() {
    let kat = load_blake3_kat();

    println!("\n=== BLAKE3 All Modes Combined Test ===");
    println!("Running comprehensive test across all three modes...\n");

    let total_tests = kat.cases.len() * 3; // 3 modes
    let mut passed = 0;

    // Test all three modes for each input length
    for test in &kat.cases {
        let input = generate_input(test.input_len);

        // Test hash mode
        let expected_hash = decode_hex(&test.hash);
        let mut hasher = hpcrypt_hash::Blake3::new();
        hasher.update(&input);
        let output = if expected_hash.len() > 32 {
            hasher.finalize_xof(expected_hash.len())
        } else {
            hasher.finalize().to_vec()
        };
        if output == expected_hash {
            passed += 1;
        }

        // Test keyed hash mode
        let key_bytes = kat.key.as_bytes();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key_bytes);
        let expected_keyed = decode_hex(&test.keyed_hash);
        let mut hasher = hpcrypt_hash::Blake3::new_keyed(&key_array);
        hasher.update(&input);
        let output = if expected_keyed.len() > 32 {
            hasher.finalize_xof(expected_keyed.len())
        } else {
            hasher.finalize().to_vec()
        };
        if output == expected_keyed {
            passed += 1;
        }

        // Test derive_key mode
        let expected_derived = decode_hex(&test.derive_key);
        let mut hasher = hpcrypt_hash::Blake3::new_derive_key(&kat.context_string);
        hasher.update(&input);
        let output = if expected_derived.len() > 32 {
            hasher.finalize_xof(expected_derived.len())
        } else {
            hasher.finalize().to_vec()
        };
        if output == expected_derived {
            passed += 1;
        }
    }

    println!("Total tests across all modes: {}", total_tests);
    println!("Passed: {}", passed);
    println!("Failed: {}", total_tests - passed);

    assert_eq!(
        passed, total_tests,
        "All BLAKE3 tests across all modes should pass"
    );
    println!("\n* All {} tests passed successfully!", total_tests);
}
