//! BLAKE3 - Official Test Vectors
//!
//! Tests for BLAKE3 cryptographic hash function using official test vectors
//! from the BLAKE3 team.
//!
//! BLAKE3 is a cryptographic hash function based on Bao and BLAKE2, designed
//! for high performance with SIMD instructions.

use hpcrypt_hash::HashFunction;
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Blake3TestVector {
    test_id: u32,
    algorithm: String,
    mode: String,
    input_len: usize,
    input: String,
    key: String,
    context: String,
    hash: String,
    note: String,
}

#[test]
fn test_blake3_official_vectors() {
    let test_vectors: Vec<Blake3TestVector> = load_test_file("blake3-official.json");

    println!("\n=== BLAKE3 Official Test Vectors ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Mode: {}", test.mode);
        println!("  Input length: {} bytes", test.input_len);
        if !test.note.is_empty() {
            println!("  Note: {}", test.note);
        }

        let input = if test.input.is_empty() {
            vec![]
        } else {
            decode_hex(&test.input)
        };

        let expected_hash = decode_hex(&test.hash);

        // Validate input length
        assert_eq!(
            input.len(),
            test.input_len,
            "Input length mismatch for test {}",
            test.test_id
        );

        match test.mode.as_str() {
            "hash" => {
                use hpcrypt_hash::Blake3;

                let mut hasher = Blake3::new();
                hasher.update(&input);

                // Use XOF for outputs > 32 bytes
                let output = if expected_hash.len() > 32 {
                    hasher.finalize_xof(expected_hash.len())
                } else {
                    hasher.finalize().to_vec()
                };

                if &output[..] == &expected_hash[..] {
                    println!("  BLAKE3 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  BLAKE3 hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "keyed_hash" => {
                use hpcrypt_hash::Blake3;

                // Decode key - removing hyphens if present
                let key_hex = test.key.replace("-", "");
                let key_bytes = decode_hex(&key_hex);

                // BLAKE3 key must be exactly 32 bytes
                if key_bytes.len() != 32 {
                    println!("  Skipping: key must be 32 bytes, got {}", key_bytes.len());
                    stats.skipped += 1;
                    continue;
                }

                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key_bytes);

                let mut hasher = Blake3::new_keyed(&key_array);
                hasher.update(&input);

                // Use XOF for outputs > 32 bytes
                let output = if expected_hash.len() > 32 {
                    hasher.finalize_xof(expected_hash.len())
                } else {
                    hasher.finalize().to_vec()
                };

                if &output[..] == &expected_hash[..] {
                    println!("  BLAKE3 keyed hash matches");
                    stats.passed += 1;
                } else {
                    println!("  BLAKE3 keyed hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "derive_key" => {
                use hpcrypt_hash::Blake3;

                let context = &test.context;

                let mut hasher = Blake3::new_derive_key(context);
                hasher.update(&input);

                // Use XOF for outputs > 32 bytes
                let output = if expected_hash.len() > 32 {
                    hasher.finalize_xof(expected_hash.len())
                } else {
                    hasher.finalize().to_vec()
                };

                if &output[..] == &expected_hash[..] {
                    println!("  BLAKE3 derive_key matches");
                    stats.passed += 1;
                } else {
                    println!("  BLAKE3 derive_key mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            _ => {
                println!("  Unknown mode: {}", test.mode);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();

    assert_eq!(stats.failed, 0, "All BLAKE3 tests should pass");
}

#[test]
fn test_blake3_vector_count() {
    let test_vectors: Vec<Blake3TestVector> = load_test_file("blake3-official.json");
    assert!(test_vectors.len() > 0, "BLAKE3 should have test vectors");
    println!("BLAKE3 test vectors loaded: {}", test_vectors.len());
}

/// Test BLAKE3 basic hash functionality
#[test]
fn test_blake3_basic_hash() {
    use hpcrypt_hash::Blake3;

    println!("\n=== BLAKE3 Basic Hash Test ===");

    // Test empty input
    println!("  Testing empty input...");
    let mut hasher = Blake3::new();
    let hash = hasher.finalize();
    assert_eq!(hash.len(), 32, "Default output should be 32 bytes");
    println!("    Empty input hash: {} bytes", hash.len());

    // Test simple message
    println!("  Testing 'hello world'...");
    let mut hasher = Blake3::new();
    hasher.update(b"hello world");
    let hash = hasher.finalize();
    assert_eq!(hash.len(), 32);
    println!("    Message hash produced");

    // Test incremental updates
    println!("  Testing incremental updates...");
    let mut hasher1 = Blake3::new();
    hasher1.update(b"hello ");
    hasher1.update(b"world");
    let hash1 = hasher1.finalize();

    let mut hasher2 = Blake3::new();
    hasher2.update(b"hello world");
    let hash2 = hasher2.finalize();

    assert_eq!(&hash1[..], &hash2[..], "Incremental hashing should match");
    println!("    Incremental updates work correctly");

    println!("\nAll BLAKE3 basic hash tests passed");
}

/// Test BLAKE3 keyed hash mode
#[test]
fn test_blake3_keyed_hash() {
    use hpcrypt_hash::Blake3;

    println!("\n=== BLAKE3 Keyed Hash Mode ===");

    let key = [42u8; 32]; // 32-byte key
    let message = b"secret message for authentication";

    // Test keyed hash
    println!("  Testing keyed hash...");
    let mut hasher = Blake3::new_keyed(&key);
    hasher.update(message);
    let mac1 = hasher.finalize();
    println!("    Keyed hash produced");

    // Same key and message should produce same output
    println!("  Testing determinism...");
    let mut hasher2 = Blake3::new_keyed(&key);
    hasher2.update(message);
    let mac2 = hasher2.finalize();
    assert_eq!(&mac1[..], &mac2[..], "Keyed hash should be deterministic");
    println!("    Keyed hash is deterministic");

    // Different key should produce different output
    println!("  Testing key sensitivity...");
    let different_key = [99u8; 32];
    let mut hasher3 = Blake3::new_keyed(&different_key);
    hasher3.update(message);
    let mac3 = hasher3.finalize();
    assert_ne!(&mac1[..], &mac3[..], "Different keys should produce different outputs");
    println!("    Keyed hash is key-dependent");

    println!("\nAll BLAKE3 keyed hash tests passed");
}

/// Test BLAKE3 key derivation mode
#[test]
fn test_blake3_derive_key() {
    use hpcrypt_hash::Blake3;

    println!("\n=== BLAKE3 Key Derivation Mode ===");

    let context = "my application key derivation context 2024";
    let key_material = b"source key material for derivation";

    // Test key derivation
    println!("  Testing key derivation...");
    let mut hasher = Blake3::new_derive_key(context);
    hasher.update(key_material);
    let derived1 = hasher.finalize();
    println!("    Derived key produced");

    // Same context and material should produce same key
    println!("  Testing determinism...");
    let mut hasher2 = Blake3::new_derive_key(context);
    hasher2.update(key_material);
    let derived2 = hasher2.finalize();
    assert_eq!(&derived1[..], &derived2[..], "Key derivation should be deterministic");
    println!("    Key derivation is deterministic");

    // Different context should produce different key
    println!("  Testing context sensitivity...");
    let different_context = "different application context";
    let mut hasher3 = Blake3::new_derive_key(different_context);
    hasher3.update(key_material);
    let derived3 = hasher3.finalize();
    assert_ne!(&derived1[..], &derived3[..], "Different contexts should produce different keys");
    println!("    Key derivation is context-dependent");

    println!("\nAll BLAKE3 key derivation tests passed");
}

/// Test BLAKE3 with various input sizes
#[test]
fn test_blake3_various_inputs() {
    use hpcrypt_hash::Blake3;

    println!("\n=== BLAKE3 Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 64], "64 bytes"),
        (vec![0u8; 1024], "1 KB"),
        (vec![0u8; 1024 * 1024], "1 MB"),
    ];

    for (input, description) in test_cases {
        println!("  Testing: {}", description);
        let mut hasher = Blake3::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "Output should be 32 bytes");
        println!("    Hash length correct: {} bytes", hash.len());
    }

    println!("\nAll BLAKE3 input size tests passed");
}

/// Test BLAKE3 extended output (XOF mode)
#[test]
fn test_blake3_extended_output() {
    use hpcrypt_hash::Blake3;

    println!("\n=== BLAKE3 Extended Output (XOF) ===");

    let message = b"test message for extended output";

    // Test various output lengths
    for len in [32, 64, 128, 256] {
        println!("  Testing {}-byte output...", len);
        let mut hasher = Blake3::new();
        hasher.update(message);
        let output = hasher.finalize_xof(len);
        assert_eq!(output.len(), len, "Output length should match requested");
        println!("    {}-byte extended output produced", len);
    }

    // Verify that XOF outputs are consistent prefixes
    println!("  Testing XOF consistency...");
    let mut hasher1 = Blake3::new();
    hasher1.update(message);
    let output_64 = hasher1.finalize_xof(64);

    let mut hasher2 = Blake3::new();
    hasher2.update(message);
    let output_32 = hasher2.finalize_xof(32);

    assert_eq!(&output_64[..32], &output_32[..], "XOF outputs should be consistent prefixes");
    println!("    XOF outputs are consistent prefixes");

    println!("\nAll BLAKE3 extended output tests passed");
}
