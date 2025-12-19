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

                if output == expected_hash {
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

                if output == expected_hash {
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

/// Test BLAKE2b with various input sizes
#[test]
fn test_blake2b_various_inputs() {
    use hpcrypt_hash::Blake2b;

    println!("\n=== BLAKE2b Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 64], "One block (64 bytes)"),
        (vec![0u8; 128], "Two blocks (128 bytes)"),
        (vec![0u8; 1000], "Large input (1000 bytes)"),
    ];

    for (input, description) in test_cases {
        println!("  Testing: {}", description);
        let mut hasher = Blake2b::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 64, "BLAKE2b-512 should produce 64 bytes");
        println!("    Hash length correct: {} bytes", hash.len());
    }

    println!("\nAll BLAKE2b input size tests passed");
}

/// Test BLAKE2s with various input sizes
#[test]
fn test_blake2s_various_inputs() {
    use hpcrypt_hash::Blake2s;

    println!("\n=== BLAKE2s Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 64], "One block (64 bytes)"),
        (vec![0u8; 128], "Two blocks (128 bytes)"),
        (vec![0u8; 1000], "Large input (1000 bytes)"),
    ];

    for (input, description) in test_cases {
        println!("  Testing: {}", description);
        let mut hasher = Blake2s::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "BLAKE2s-256 should produce 32 bytes");
        println!("    Hash length correct: {} bytes", hash.len());
    }

    println!("\nAll BLAKE2s input size tests passed");
}

/// Test BLAKE2 MAC (keyed hash) functionality
#[test]
fn test_blake2_mac_functionality() {
    use hpcrypt_hash::{Blake2b, Blake2s};

    println!("\n=== BLAKE2 MAC (Keyed Hash) Functionality ===");

    // BLAKE2b MAC
    println!("  Testing BLAKE2b MAC...");
    let key = b"secret_key_for_testing_blake2b_mac";
    let message = b"The quick brown fox jumps over the lazy dog";

    let mut hasher = Blake2b::new_keyed(key, 64);
    hasher.update(message);
    let mac1 = hasher.finalize();

    // Same key and message should produce same MAC
    let mut hasher2 = Blake2b::new_keyed(key, 64);
    hasher2.update(message);
    let mac2 = hasher2.finalize();

    assert_eq!(mac1, mac2, "Same key/message should produce same MAC");
    println!("    BLAKE2b MAC deterministic");

    // Different key should produce different MAC
    let different_key = b"different_secret_key_for_blake2b";
    let mut hasher3 = Blake2b::new_keyed(different_key, 64);
    hasher3.update(message);
    let mac3 = hasher3.finalize();

    assert_ne!(mac1.as_slice(), mac3.as_slice(), "Different keys should produce different MACs");
    println!("    BLAKE2b MAC key-dependent");

    // BLAKE2s MAC
    println!("  Testing BLAKE2s MAC...");
    let key_s = b"secret_key_for_blake2s";
    let mut hasher_s = Blake2s::new_keyed(key_s, 32);
    hasher_s.update(message);
    let mac_s = hasher_s.finalize();
    assert_eq!(mac_s.len(), 32, "BLAKE2s MAC should be 32 bytes");
    println!("    BLAKE2s MAC works correctly");

    println!("\nAll BLAKE2 MAC tests passed");
}

/// Test BLAKE2 with variable output lengths
#[test]
fn test_blake2_variable_output() {
    use hpcrypt_hash::{Blake2b, Blake2s};

    println!("\n=== BLAKE2 Variable Output Lengths ===");

    // BLAKE2b supports 1-64 byte outputs
    println!("  Testing BLAKE2b variable outputs...");
    for len in [16, 32, 48, 64] {
        let mut hasher = Blake2b::new_with_output_len(len);
        hasher.update(b"test");
        let hash = hasher.finalize();
        assert_eq!(hash.len(), len, "BLAKE2b output length mismatch");
        println!("    BLAKE2b-{} ({} bytes) works", len * 8, len);
    }

    // BLAKE2s supports 1-32 byte outputs
    println!("  Testing BLAKE2s variable outputs...");
    for len in [16, 24, 32] {
        let mut hasher = Blake2s::new_with_output_len(len);
        hasher.update(b"test");
        let hash = hasher.finalize();
        assert_eq!(hash.len(), len, "BLAKE2s output length mismatch");
        println!("    BLAKE2s-{} ({} bytes) works", len * 8, len);
    }

    println!("\nAll variable output length tests passed");
}
