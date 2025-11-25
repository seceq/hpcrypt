//! RFC 9861 - TurboSHAKE Extendable-Output Functions
//!
//! Tests for TurboSHAKE128 and TurboSHAKE256 using official RFC 9861 test vectors.
//!
//! TurboSHAKE is a family of fast extendable-output functions (XOFs) based on the
//! 12-round Keccak-p[1600,12] permutation, providing approximately 2x speedup
//! compared to SHAKE128/256 while maintaining the same security levels.

use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TurboShakeTestVector {
    test_id: u32,
    algorithm: String,
    input_length: usize,
    input: String,
    domain_sep: String,
    output_length: usize,
    hash: String,
    note: String,
}

#[test]
fn test_turboshake_rfc9861() {
    let test_vectors: Vec<TurboShakeTestVector> = load_test_file("rfc9861-turboshake.json");

    println!("\n=== RFC 9861: TurboSHAKE Extendable-Output Functions ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Input length: {} bytes", test.input_length);
        println!("  Domain separation: 0x{}", test.domain_sep);
        println!("  Output length: {} bytes", test.output_length);
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
            test.input_length,
            "Input length mismatch for test {}",
            test.test_id
        );

        // Validate expected hash length
        assert_eq!(
            expected_hash.len(),
            test.output_length,
            "Hash length mismatch for test {}",
            test.test_id
        );

        // Parse domain separation byte
        let domain_sep = u8::from_str_radix(&test.domain_sep, 16)
            .expect("Invalid domain separation byte");

        match test.algorithm.as_str() {
            "TurboSHAKE128" => {
                use hpcrypt_hash::TurboShake128;

                let mut hasher = if domain_sep == 0x1F {
                    // Default domain separation
                    TurboShake128::new()
                } else {
                    // Custom domain separation
                    TurboShake128::with_domain_sep(domain_sep)
                };

                hasher.update(&input);

                let mut output = vec![0u8; test.output_length];
                hasher.finalize(&mut output);

                if &output[..] == &expected_hash[..] {
                    println!("  TurboSHAKE128 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  TurboSHAKE128 hash mismatch");
                    println!(
                        "    Expected: {}",
                        hex::encode(&expected_hash[..expected_hash.len().min(32)])
                    );
                    println!(
                        "    Got:      {}",
                        hex::encode(&output[..output.len().min(32)])
                    );
                    stats.failed += 1;
                }
            }
            "TurboSHAKE256" => {
                use hpcrypt_hash::TurboShake256;

                let mut hasher = if domain_sep == 0x1F {
                    // Default domain separation
                    TurboShake256::new()
                } else {
                    // Custom domain separation
                    TurboShake256::with_domain_sep(domain_sep)
                };

                hasher.update(&input);

                let mut output = vec![0u8; test.output_length];
                hasher.finalize(&mut output);

                if &output[..] == &expected_hash[..] {
                    println!("  TurboSHAKE256 hash matches");
                    stats.passed += 1;
                } else {
                    println!("  TurboSHAKE256 hash mismatch");
                    println!(
                        "    Expected: {}",
                        hex::encode(&expected_hash[..expected_hash.len().min(32)])
                    );
                    println!(
                        "    Got:      {}",
                        hex::encode(&output[..output.len().min(32)])
                    );
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

    assert_eq!(stats.failed, 0, "All TurboSHAKE tests should pass");
}

#[test]
fn test_turboshake_vector_count() {
    let test_vectors: Vec<TurboShakeTestVector> = load_test_file("rfc9861-turboshake.json");
    assert!(
        test_vectors.len() > 0,
        "RFC 9861 should have test vectors"
    );
    println!("TurboSHAKE test vectors loaded: {}", test_vectors.len());
}

/// Test TurboSHAKE128 basic functionality
#[test]
fn test_turboshake128_basic() {
    use hpcrypt_hash::TurboShake128;

    println!("\n=== TurboSHAKE128 Basic Functionality ===");

    // Test empty input
    println!("  Testing empty input...");
    let mut hasher = TurboShake128::new();
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    println!("    Empty input hash: {} bytes", output.len());

    // Test simple message
    println!("  Testing 'hello world'...");
    let mut hasher = TurboShake128::new();
    hasher.update(b"hello world");
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    println!("    Message hash produced");

    // Test incremental updates
    println!("  Testing incremental updates...");
    let mut hasher1 = TurboShake128::new();
    hasher1.update(b"hello ");
    hasher1.update(b"world");
    let mut hash1 = [0u8; 32];
    hasher1.finalize(&mut hash1);

    let mut hasher2 = TurboShake128::new();
    hasher2.update(b"hello world");
    let mut hash2 = [0u8; 32];
    hasher2.finalize(&mut hash2);

    assert_eq!(&hash1[..], &hash2[..], "Incremental hashing should match");
    println!("    Incremental updates work correctly");

    println!("\nAll TurboSHAKE128 basic tests passed");
}

/// Test TurboSHAKE256 basic functionality
#[test]
fn test_turboshake256_basic() {
    use hpcrypt_hash::TurboShake256;

    println!("\n=== TurboSHAKE256 Basic Functionality ===");

    // Test empty input
    println!("  Testing empty input...");
    let mut hasher = TurboShake256::new();
    let mut output = [0u8; 64];
    hasher.finalize(&mut output);
    println!("    Empty input hash: {} bytes", output.len());

    // Test simple message
    println!("  Testing 'hello world'...");
    let mut hasher = TurboShake256::new();
    hasher.update(b"hello world");
    let mut output = [0u8; 64];
    hasher.finalize(&mut output);
    println!("    Message hash produced");

    // Test incremental updates
    println!("  Testing incremental updates...");
    let mut hasher1 = TurboShake256::new();
    hasher1.update(b"hello ");
    hasher1.update(b"world");
    let mut hash1 = [0u8; 64];
    hasher1.finalize(&mut hash1);

    let mut hasher2 = TurboShake256::new();
    hasher2.update(b"hello world");
    let mut hash2 = [0u8; 64];
    hasher2.finalize(&mut hash2);

    assert_eq!(&hash1[..], &hash2[..], "Incremental hashing should match");
    println!("    Incremental updates work correctly");

    println!("\nAll TurboSHAKE256 basic tests passed");
}

/// Test TurboSHAKE with various output lengths
#[test]
fn test_turboshake_variable_output() {
    use hpcrypt_hash::{TurboShake128, TurboShake256};

    println!("\n=== TurboSHAKE Variable Output Lengths ===");

    let message = b"test message for variable output";

    // Test TurboSHAKE128 with various output lengths
    println!("  Testing TurboSHAKE128 variable outputs...");
    for len in [16, 32, 64, 128, 256] {
        let mut hasher = TurboShake128::new();
        hasher.update(message);
        let mut output = vec![0u8; len];
        hasher.finalize(&mut output);
        assert_eq!(output.len(), len, "Output length should match requested");
        println!("    {}-byte output produced", len);
    }

    // Test TurboSHAKE256 with various output lengths
    println!("  Testing TurboSHAKE256 variable outputs...");
    for len in [32, 64, 128, 256, 512] {
        let mut hasher = TurboShake256::new();
        hasher.update(message);
        let mut output = vec![0u8; len];
        hasher.finalize(&mut output);
        assert_eq!(output.len(), len, "Output length should match requested");
        println!("    {}-byte output produced", len);
    }

    // Verify that outputs are consistent prefixes
    println!("  Testing output consistency...");
    let mut hasher1 = TurboShake128::new();
    hasher1.update(message);
    let mut output_64 = vec![0u8; 64];
    hasher1.finalize(&mut output_64);

    let mut hasher2 = TurboShake128::new();
    hasher2.update(message);
    let mut output_32 = vec![0u8; 32];
    hasher2.finalize(&mut output_32);

    assert_eq!(
        &output_64[..32],
        &output_32[..],
        "Outputs should be consistent prefixes"
    );
    println!("    Outputs are consistent prefixes");

    println!("\nAll TurboSHAKE variable output tests passed");
}

/// Test TurboSHAKE with custom domain separation
#[test]
fn test_turboshake_domain_separation() {
    use hpcrypt_hash::{TurboShake128, TurboShake256};

    println!("\n=== TurboSHAKE Domain Separation ===");

    let message = b"test message";

    // Test TurboSHAKE128 with different domain separations
    println!("  Testing TurboSHAKE128 domain separation...");
    let mut hasher1 = TurboShake128::new(); // Default 0x1F
    hasher1.update(message);
    let mut hash1 = [0u8; 32];
    hasher1.finalize(&mut hash1);

    let mut hasher2 = TurboShake128::with_domain_sep(0x01);
    hasher2.update(message);
    let mut hash2 = [0u8; 32];
    hasher2.finalize(&mut hash2);

    assert_ne!(
        &hash1[..],
        &hash2[..],
        "Different domain separations should produce different outputs"
    );
    println!("    Domain separation affects output");

    // Test TurboSHAKE256 with different domain separations
    println!("  Testing TurboSHAKE256 domain separation...");
    let mut hasher3 = TurboShake256::new(); // Default 0x1F
    hasher3.update(message);
    let mut hash3 = [0u8; 64];
    hasher3.finalize(&mut hash3);

    let mut hasher4 = TurboShake256::with_domain_sep(0x06);
    hasher4.update(message);
    let mut hash4 = [0u8; 64];
    hasher4.finalize(&mut hash4);

    assert_ne!(
        &hash3[..],
        &hash4[..],
        "Different domain separations should produce different outputs"
    );
    println!("    Domain separation affects output");

    println!("\nAll TurboSHAKE domain separation tests passed");
}

/// Test TurboSHAKE with various input sizes
#[test]
fn test_turboshake_various_inputs() {
    use hpcrypt_hash::{TurboShake128, TurboShake256};

    println!("\n=== TurboSHAKE Various Input Sizes ===");

    let test_cases = vec![
        (vec![], "Empty"),
        (vec![0u8], "Single byte"),
        (vec![0u8; 168], "One TurboSHAKE128 block (168 bytes)"),
        (vec![0u8; 336], "Two TurboSHAKE128 blocks (336 bytes)"),
        (vec![0u8; 1024], "1 KB"),
        (vec![0u8; 1024 * 1024], "1 MB"),
    ];

    // Test TurboSHAKE128
    println!("  Testing TurboSHAKE128 with various inputs...");
    for (input, description) in &test_cases {
        let mut hasher = TurboShake128::new();
        hasher.update(input);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        println!("    {}: hash produced", description);
    }

    // Test TurboSHAKE256
    println!("  Testing TurboSHAKE256 with various inputs...");
    for (input, description) in &test_cases {
        let mut hasher = TurboShake256::new();
        hasher.update(input);
        let mut output = [0u8; 64];
        hasher.finalize(&mut output);
        println!("    {}: hash produced", description);
    }

    println!("\nAll TurboSHAKE input size tests passed");
}

/// Performance comparison note between TurboSHAKE and SHAKE
#[test]
fn test_turboshake_vs_shake_note() {
    println!("\n=== TurboSHAKE vs SHAKE Performance Note ===");
    println!("  TurboSHAKE uses 12-round Keccak-p[1600,12] vs 24-round Keccak-f[1600]");
    println!("  Expected performance: ~2x faster than SHAKE");
    println!("  Security level: Same as SHAKE (128-bit for TurboSHAKE128, 256-bit for TurboSHAKE256)");
    println!("  TurboSHAKE128 rate: 168 bytes (1344 bits)");
    println!("  TurboSHAKE256 rate: 136 bytes (1088 bits)");
    println!("\nNote: This is an informational test");
}
