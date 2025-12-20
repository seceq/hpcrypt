//! RFC 7693 - BLAKE2 Cryptographic Hash and Message Authentication Code
//!
//! Tests for BLAKE2b and BLAKE2s using official RFC 7693 test vectors.
//!
//! BLAKE2 is a cryptographic hash function faster than MD5, SHA-1, SHA-2, and SHA-3,
//! while being at least as secure as SHA-3.

use hpcrypt_hash::HashFunction;
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Blake2TestVector {
    test_id: u32,
    algorithm: String,
    variant: String,
    hash_length: usize,
    input_length: usize,
    input: String,
    key: String,
    hash: String,
    note: String,
}

#[test]
fn test_blake2_rfc7693() {
    let test_vectors: Vec<Blake2TestVector> = load_test_file("rfc7693-blake2.json");

    println!("\n=== RFC 7693: BLAKE2 Cryptographic Hash and MAC ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Variant: {}", test.variant);
        println!("  Input length: {} bytes", test.input_length);
        println!("  Key length: {} bytes", test.key.len() / 2);
        if !test.note.is_empty() {
            println!("  Note: {}", test.note);
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

        // Validate input length matches
        assert_eq!(
            input.len(),
            test.input_length,
            "Input length mismatch for test {}",
            test.test_id
        );

        // Validate expected hash length
        assert_eq!(
            expected_hash.len(),
            test.hash_length,
            "Hash length mismatch for test {}",
            test.test_id
        );

        match test.algorithm.as_str() {
            "BLAKE2b" => {
                use hpcrypt_hash::Blake2b;

                let output = if key.is_empty() {
                    // Unkeyed hash mode
                    match test.hash_length {
                        32 => {
                            let mut hasher = Blake2b::new_with_output_len(32);
                            hasher.update(&input);
                            hasher.finalize()
                        }
                        64 => {
                            let mut hasher = Blake2b::new();
                            hasher.update(&input);
                            hasher.finalize()
                        }
                        _ => {
                            println!("  Skipping unsupported hash length: {}", test.hash_length);
                            stats.skipped += 1;
                            continue;
                        }
                    }
                } else {
                    // Keyed hash mode (MAC)
                    let mut hasher = Blake2b::new_keyed(&key, test.hash_length);
                    hasher.update(&input);
                    hasher.finalize()
                };

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  BLAKE2b hash matches");
                    stats.passed += 1;
                } else {
                    println!("  BLAKE2b hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "BLAKE2s" => {
                use hpcrypt_hash::Blake2s;

                let output = if key.is_empty() {
                    // Unkeyed hash mode
                    match test.hash_length {
                        16 => {
                            let mut hasher = Blake2s::new_with_output_len(16);
                            hasher.update(&input);
                            hasher.finalize()
                        }
                        32 => {
                            let mut hasher = Blake2s::new();
                            hasher.update(&input);
                            hasher.finalize()
                        }
                        _ => {
                            println!("  Skipping unsupported hash length: {}", test.hash_length);
                            stats.skipped += 1;
                            continue;
                        }
                    }
                } else {
                    // Keyed hash mode (MAC)
                    let mut hasher = Blake2s::new_keyed(&key, test.hash_length);
                    hasher.update(&input);
                    hasher.finalize()
                };

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  BLAKE2s hash matches");
                    stats.passed += 1;
                } else {
                    println!("  BLAKE2s hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            _ => {
                println!("  Unknown algorithm: {}", test.algorithm);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();

    assert_eq!(stats.failed, 0, "All BLAKE2 tests should pass");
}

#[test]
fn test_blake2_vector_count() {
    let test_vectors: Vec<Blake2TestVector> = load_test_file("rfc7693-blake2.json");
    assert!(test_vectors.len() > 0, "RFC 7693 should have test vectors");
    println!("BLAKE2 test vectors loaded: {}", test_vectors.len());
}
