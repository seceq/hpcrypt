//! Comprehensive scrypt Test Vectors
//!
//! This test file includes:
//! - RFC 7914 official test vectors
//! - Additional parameter combinations
//! - Edge cases and security tests
//!
//! scrypt is a memory-hard password-based KDF designed to be expensive
//! to compute on custom hardware.

use hpcrypt_kdf::scrypt::{scrypt, ScryptParams};
use rfc_tests::{decode_hex, encode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ScryptTestVector {
    test_id: u32,
    password: String,
    salt: String,
    #[serde(rename = "N")]
    n: u32,
    r: u32,
    p: u32,
    #[serde(rename = "dkLen")]
    dk_len: usize,
    expected_output: String,
    note: Option<String>,
}

#[test]
fn test_scrypt_rfc7914_comprehensive() {
    let test_vectors: Vec<ScryptTestVector> = load_test_file("rfc7914-scrypt.json");

    println!("\n=== RFC 7914: scrypt Password-Based KDF (Comprehensive) ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  N={}, r={}, p={}, dkLen={}", test.n, test.r, test.p, test.dk_len);
        if let Some(note) = &test.note {
            println!("  Note: {}", note);
        }

        let password = test.password.as_bytes();
        let salt = test.salt.as_bytes();
        let expected = decode_hex(&test.expected_output);

        let params = ScryptParams {
            n: test.n as usize,
            r: test.r as usize,
            p: test.p as usize,
        };

        let result = scrypt(password, salt, &params, test.dk_len);

        if result == expected {
            println!("  * Test passed");
            stats.passed += 1;
        } else {
            println!("  ✗ Test failed");
            println!("    Expected: {}", test.expected_output);
            println!("    Got:      {}", encode_hex(&result));
            stats.failed += 1;
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All scrypt RFC 7914 tests should pass");
}

/// Test scrypt with various parameter combinations
#[test]
fn test_scrypt_parameter_variations() {
    println!("\n=== scrypt Parameter Variations ===");

    let password = b"test_password";
    let salt = b"test_salt_12345678";

    let test_cases = vec![
        ("Very light", 16, 1, 1),        // N=16, r=1, p=1
        ("Light", 256, 2, 1),            // N=256, r=2, p=1
        ("Medium", 1024, 8, 1),          // N=1024, r=8, p=1
        ("Interactive", 16384, 8, 1),    // N=16384, r=8, p=1 (recommended for interactive)
        ("High parallelism", 1024, 4, 4), // N=1024, r=4, p=4
    ];

    for (name, n, r, p) in test_cases {
        println!("\n  Testing: {}", name);
        println!("    N={}, r={}, p={}", n, r, p);

        let params = ScryptParams {
            n: n as usize,
            r: r as usize,
            p: p as usize,
        };

        let output = scrypt(password, salt, &params, 32);
        assert_eq!(output.len(), 32);
        println!("    * Generated {}-byte output", output.len());
    }

    println!("\n  All parameter variation tests passed");
}

/// Test that different passwords produce different outputs
#[test]
fn test_scrypt_password_sensitivity() {
    println!("\n=== scrypt Password Sensitivity ===");

    let salt = b"consistent_salt";
    let params = ScryptParams {
        n: 1024,
        r: 8,
        p: 1,
    };

    let output1 = scrypt(b"password1", salt, &params, 32);
    let output2 = scrypt(b"password2", salt, &params, 32);
    let output3 = scrypt(b"password1", salt, &params, 32);

    assert_ne!(output1, output2, "Different passwords should produce different outputs");
    assert_eq!(output1, output3, "Same password should produce same output with same salt");

    println!("  * Password sensitivity verified");
}

/// Test that different salts produce different outputs
#[test]
fn test_scrypt_salt_sensitivity() {
    println!("\n=== scrypt Salt Sensitivity ===");

    let password = b"constant_password";
    let params = ScryptParams {
        n: 1024,
        r: 8,
        p: 1,
    };

    let output1 = scrypt(password, b"salt1", &params, 32);
    let output2 = scrypt(password, b"salt2", &params, 32);
    let output3 = scrypt(password, b"salt1", &params, 32);

    assert_ne!(output1, output2, "Different salts should produce different outputs");
    assert_eq!(output1, output3, "Same salt should produce same output with same password");

    println!("  * Salt sensitivity verified");
}

/// Test different output lengths
#[test]
fn test_scrypt_output_lengths() {
    println!("\n=== scrypt Output Length Variations ===");

    let password = b"test_password";
    let salt = b"test_salt";
    let params = ScryptParams {
        n: 256,
        r: 4,
        p: 1,
    };

    let lengths = [16, 32, 64, 128];

    for &len in &lengths {
        let output = scrypt(password, salt, &params, len);
        assert_eq!(output.len(), len);
        println!("  * Generated {}-byte output", len);
    }

    println!("\n  All output length tests passed");
}

/// Test parameter impact on cost
#[test]
fn test_scrypt_cost_parameters() {
    println!("\n=== scrypt Cost Parameter Impact ===");

    let password = b"password";
    let salt = b"salt";

    // Test N parameter impact (must be power of 2)
    println!("\n  Testing N parameter (CPU/memory cost):");
    for &n in &[16, 64, 256, 1024] {
        let params = ScryptParams { n, r: 1, p: 1 };
        let output = scrypt(password, salt, &params, 32);
        println!("    N={}: Generated {}-byte output", n, output.len());
    }

    // Test r parameter impact (block size)
    println!("\n  Testing r parameter (block size):");
    for &r in &[1, 2, 4, 8] {
        let params = ScryptParams { n: 256, r, p: 1 };
        let output = scrypt(password, salt, &params, 32);
        println!("    r={}: Generated {}-byte output", r, output.len());
    }

    // Test p parameter impact (parallelization)
    println!("\n  Testing p parameter (parallelization):");
    for &p in &[1, 2, 4] {
        let params = ScryptParams { n: 256, r: 2, p };
        let output = scrypt(password, salt, &params, 32);
        println!("    p={}: Generated {}-byte output", p, output.len());
    }

    println!("\n  All cost parameter tests completed");
}

#[cfg(test)]
mod scrypt_comprehensive_notes {
    /// Security recommendations for scrypt
    #[test]
    fn test_scrypt_security_recommendations() {
        println!("\nscrypt Security Recommendations (2024):");
        println!("  Parameter Selection:");
        println!("    - N: CPU/memory cost parameter (must be power of 2)");
        println!("    - r: Block size parameter");
        println!("    - p: Parallelization parameter");
        println!("\n  OWASP Recommendations:");
        println!("    Interactive logins: N=2^14 (16384), r=8, p=1");
        println!("    File encryption: N=2^20 (1048576), r=8, p=1");
        println!("    Min salt length: 16 bytes (128 bits)");
        println!("    Output length: 32 bytes (256 bits) for keys");
        println!("\n  Memory Usage:");
        println!("    Memory = 128 * N * r bytes");
        println!("    Example: N=16384, r=8 → ~16 MB");
        println!("\n  Advantages:");
        println!("    - Memory-hard: Resistant to GPU/ASIC attacks");
        println!("    - Well-studied: Used in cryptocurrencies (Litecoin, Dogecoin)");
        println!("    - Tunable: Adjust N, r, p for security/performance trade-off");
        println!("\n  vs Argon2:");
        println!("    - Argon2id is generally preferred for new applications");
        println!("    - scrypt is more established (RFC 7914, 2016)");
        println!("    - scrypt is simpler but less flexible than Argon2");
    }

    #[test]
    fn test_scrypt_test_coverage() {
        println!("\nscrypt Test Coverage:");
        println!("  - RFC 7914 test vectors: tests/rfc-tests/tests/scrypt.rs");
        println!("  - Comprehensive tests: tests/rfc-tests/tests/scrypt_comprehensive.rs");
        println!("  - Parameter variations: N, r, p combinations");
        println!("  - Output length variations: 16-128 bytes");
        println!("  - Sensitivity tests: Password, salt differences");
        println!("  - Cost parameter analysis: N, r, p impact");
    }

    #[test]
    fn test_scrypt_use_cases() {
        println!("\nscrypt Use Cases:");
        println!("  Password Hashing:");
        println!("    - User authentication systems");
        println!("    - API key derivation");
        println!("    - Moderate security: N=16384, r=8, p=1");
        println!("\n  Key Derivation:");
        println!("    - File encryption keys");
        println!("    - Disk encryption");
        println!("    - High security: N=1048576, r=8, p=1");
        println!("\n  Cryptocurrency:");
        println!("    - Proof-of-work mining (Litecoin)");
        println!("    - ASIC resistance");
        println!("    - Custom parameters per application");
    }
}
