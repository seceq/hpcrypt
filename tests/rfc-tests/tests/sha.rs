//! FIPS 180-4 - Secure Hash Standard (SHS)
//!
//! Tests for SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256
//! using official FIPS 180-4 test vectors.

use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;
use hpcrypt_hash::HashFunction;

#[derive(Debug, Deserialize)]
struct ShaTestVector {
    test_id: u32,
    algorithm: String,
    source: String,
    input: String,
    hash: String,
    note: String,
}

#[test]
fn test_sha_fips180_4() {
    let test_vectors: Vec<ShaTestVector> = load_test_file("fips180-4-sha.json");

    println!("\n=== FIPS 180-4: Secure Hash Standard (SHS) ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Source: {}", test.source);
        if !test.note.is_empty() {
            println!("  Note: {}", test.note);
        }

        let input = if test.input.is_empty() {
            vec![]
        } else {
            decode_hex(&test.input)
        };

        let expected_hash = decode_hex(&test.hash);

        match test.algorithm.as_str() {
            "SHA-1" => {
                use hpcrypt_hash::Sha1;

                let mut hasher = Sha1::new();
                hasher.update(&input);
                let output = hasher.finalize();

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  SHA-1 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  SHA-1 hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "SHA-224" => {
                use hpcrypt_hash::Sha224;

                let mut hasher = Sha224::new();
                hasher.update(&input);
                let output = hasher.finalize();

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  SHA-224 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  SHA-224 hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "SHA-256" => {
                use hpcrypt_hash::Sha256;

                let mut hasher = Sha256::new();
                hasher.update(&input);
                let output = hasher.finalize();

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  SHA-256 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  SHA-256 hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "SHA-384" => {
                use hpcrypt_hash::Sha384;

                let mut hasher = Sha384::new();
                hasher.update(&input);
                let output = hasher.finalize();

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  SHA-384 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  SHA-384 hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "SHA-512" => {
                use hpcrypt_hash::Sha512;

                let mut hasher = Sha512::new();
                hasher.update(&input);
                let output = hasher.finalize();

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  SHA-512 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  SHA-512 hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "SHA-512/224" => {
                use hpcrypt_hash::Sha512_224;

                let mut hasher = Sha512_224::new();
                hasher.update(&input);
                let output = hasher.finalize();

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  SHA-512/224 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  SHA-512/224 hash mismatch");
                    println!("    Expected: {}", hex::encode(&expected_hash));
                    println!("    Got:      {}", hex::encode(&output));
                    stats.failed += 1;
                }
            }
            "SHA-512/256" => {
                use hpcrypt_hash::Sha512_256;

                let mut hasher = Sha512_256::new();
                hasher.update(&input);
                let output = hasher.finalize();

                if output.as_slice() == expected_hash.as_slice() {
                    println!("  SHA-512/256 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  SHA-512/256 hash mismatch");
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

    assert_eq!(stats.failed, 0, "All SHA tests should pass");
}

#[test]
fn test_sha_vector_count() {
    let test_vectors: Vec<ShaTestVector> = load_test_file("fips180-4-sha.json");
    assert!(test_vectors.len() > 0, "FIPS 180-4 should have test vectors");
    println!("SHA test vectors loaded: {}", test_vectors.len());
}

/// Test SHA-1 with various input sizes
#[test]
fn test_sha1_various_inputs() {
    use hpcrypt_hash::Sha1;

    println!("\n=== SHA-1 Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 55], "55 bytes (one block boundary)"),
        (vec![0u8; 56], "56 bytes (padding boundary)"),
        (vec![0u8; 64], "64 bytes (one block)"),
        (vec![0u8; 128], "128 bytes (two blocks)"),
        (vec![0u8; 1000], "1000 bytes"),
    ];

    for (input, description) in test_cases {
        println!("  Testing: {}", description);
        let mut hasher = Sha1::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 20, "SHA-1 should produce 20 bytes");
        println!("    Hash length correct: {} bytes", hash.len());
    }

    println!("\nAll SHA-1 input size tests passed");
}

/// Test SHA-256 with various input sizes
#[test]
fn test_sha256_various_inputs() {
    use hpcrypt_hash::Sha256;

    println!("\n=== SHA-256 Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 55], "55 bytes (one block boundary)"),
        (vec![0u8; 56], "56 bytes (padding boundary)"),
        (vec![0u8; 64], "64 bytes (one block)"),
        (vec![0u8; 128], "128 bytes (two blocks)"),
        (vec![0u8; 1000], "1000 bytes"),
    ];

    for (input, description) in test_cases {
        println!("  Testing: {}", description);
        let mut hasher = Sha256::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 32, "SHA-256 should produce 32 bytes");
        println!("    Hash length correct: {} bytes", hash.len());
    }

    println!("\nAll SHA-256 input size tests passed");
}

/// Test SHA-512 with various input sizes
#[test]
fn test_sha512_various_inputs() {
    use hpcrypt_hash::Sha512;

    println!("\n=== SHA-512 Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 111], "111 bytes (one block boundary)"),
        (vec![0u8; 112], "112 bytes (padding boundary)"),
        (vec![0u8; 128], "128 bytes (one block)"),
        (vec![0u8; 256], "256 bytes (two blocks)"),
        (vec![0u8; 1000], "1000 bytes"),
    ];

    for (input, description) in test_cases {
        println!("  Testing: {}", description);
        let mut hasher = Sha512::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 64, "SHA-512 should produce 64 bytes");
        println!("    Hash length correct: {} bytes", hash.len());
    }

    println!("\nAll SHA-512 input size tests passed");
}

/// Test SHA-384 with various input sizes
#[test]
fn test_sha384_various_inputs() {
    use hpcrypt_hash::Sha384;

    println!("\n=== SHA-384 Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 111], "111 bytes (one block boundary)"),
        (vec![0u8; 112], "112 bytes (padding boundary)"),
        (vec![0u8; 128], "128 bytes (one block)"),
        (vec![0u8; 256], "256 bytes (two blocks)"),
        (vec![0u8; 1000], "1000 bytes"),
    ];

    for (input, description) in test_cases {
        println!("  Testing: {}", description);
        let mut hasher = Sha384::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 48, "SHA-384 should produce 48 bytes");
        println!("    Hash length correct: {} bytes", hash.len());
    }

    println!("\nAll SHA-384 input size tests passed");
}

/// Test incremental hashing matches single-shot
#[test]
fn test_sha_incremental() {
    use hpcrypt_hash::{Sha256, Sha512};

    println!("\n=== SHA Incremental Hashing ===");

    let message = b"The quick brown fox jumps over the lazy dog";

    // SHA-256 incremental
    println!("  Testing SHA-256 incremental...");
    let mut hasher1 = Sha256::new();
    hasher1.update(&message[..10]);
    hasher1.update(&message[10..20]);
    hasher1.update(&message[20..]);
    let hash1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(message);
    let hash2 = hasher2.finalize();

    assert_eq!(hash1, hash2, "Incremental should match single-shot");
    println!("    SHA-256 incremental matches single-shot");

    // SHA-512 incremental
    println!("  Testing SHA-512 incremental...");
    let mut hasher3 = Sha512::new();
    hasher3.update(&message[..10]);
    hasher3.update(&message[10..20]);
    hasher3.update(&message[20..]);
    let hash3 = hasher3.finalize();

    let mut hasher4 = Sha512::new();
    hasher4.update(message);
    let hash4 = hasher4.finalize();

    assert_eq!(hash3, hash4, "Incremental should match single-shot");
    println!("    SHA-512 incremental matches single-shot");

    println!("\nAll incremental hashing tests passed");
}
