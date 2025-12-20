//! scrypt Functional Tests
//!
//! Property-based and functional tests for scrypt password-based KDF.
//! These tests verify behavior with various parameters, sensitivity to inputs,
//! and output length variations.

use hpcrypt_kdf::scrypt::{scrypt, ScryptParams};

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
        println!("    Generated {}-byte output", output.len());
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

    println!("  Password sensitivity verified");
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

    println!("  Salt sensitivity verified");
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
        println!("  Generated {}-byte output", len);
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
