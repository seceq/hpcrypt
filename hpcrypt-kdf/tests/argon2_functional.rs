//! Argon2 Functional Tests
//!
//! Property-based and functional tests for Argon2 password hashing.
//! These tests verify behavior with various parameters, sensitivity to inputs,
//! and variant differences.

use hpcrypt_kdf::argon2::{Argon2, Params, Variant};

/// Test Argon2 with various parameter combinations
#[test]
fn test_argon2_parameter_variations() {
    println!("\n=== Argon2 Parameter Variations ===");

    let password = b"test_password";
    let salt = b"random_salt_1234";

    let test_cases = vec![
        ("Low memory", 8, 1, 1),    // 8 KiB
        ("Medium memory", 64, 2, 1), // 64 KiB
        ("High memory", 256, 3, 2),  // 256 KiB
        ("High parallelism", 32, 3, 4),
    ];

    for (name, mem, iter, par) in test_cases {
        println!("\n  Testing: {}", name);
        println!("    Memory: {} KiB, Iterations: {}, Parallelism: {}", mem, iter, par);

        let params = Params::new(32, mem, iter, par).unwrap();
        let argon2 = Argon2::new(
            Variant::Argon2id,
            params,
        );

        match argon2.hash(password, salt) {
            Ok(hash) => {
                assert_eq!(hash.len(), 32);
                println!("    Generated {}-byte hash", hash.len());
            }
            Err(e) => panic!("    Failed: {:?}", e),
        }
    }

    println!("\n  All parameter variation tests passed");
}

/// Test that different passwords produce different hashes
#[test]
fn test_argon2_password_sensitivity() {
    println!("\n=== Argon2 Password Sensitivity ===");

    let salt = b"consistent_salt";
    let params = Params::new(32, 32, 3, 1).unwrap();
    let argon2 = Argon2::new(
        Variant::Argon2id,
        params,
    );

    let hash1 = argon2.hash(b"password1", salt).unwrap();
    let hash2 = argon2.hash(b"password2", salt).unwrap();
    let hash3 = argon2.hash(b"password1", salt).unwrap(); // Same as first

    assert_ne!(hash1, hash2, "Different passwords should produce different hashes");
    assert_eq!(hash1, hash3, "Same password should produce same hash with same salt");

    println!("  Password sensitivity verified");
}

/// Test that different salts produce different hashes
#[test]
fn test_argon2_salt_sensitivity() {
    println!("\n=== Argon2 Salt Sensitivity ===");

    let password = b"constant_password";
    let params = Params::new(32, 32, 3, 1).unwrap();
    let argon2 = Argon2::new(
        Variant::Argon2id,
        params,
    );

    let hash1 = argon2.hash(password, b"saltsalt1").unwrap();
    let hash2 = argon2.hash(password, b"saltsalt2").unwrap();
    let hash3 = argon2.hash(password, b"saltsalt1").unwrap(); // Same as first

    assert_ne!(hash1, hash2, "Different salts should produce different hashes");
    assert_eq!(hash1, hash3, "Same salt should produce same hash with same password");

    println!("  Salt sensitivity verified");
}

/// Test all three Argon2 variants produce different outputs
#[test]
fn test_argon2_variant_differences() {
    println!("\n=== Argon2 Variant Differences ===");

    let password = b"test_password";
    let salt = b"test_salt";
    let params = Params::new(32, 32, 3, 1).unwrap();

    let argon2d = Argon2::new(
        Variant::Argon2d,
        params.clone(),
    );
    let argon2i = Argon2::new(
        Variant::Argon2i,
        params.clone(),
    );
    let argon2id = Argon2::new(
        Variant::Argon2id,
        params,
    );

    let hash_d = argon2d.hash(password, salt).unwrap();
    let hash_i = argon2i.hash(password, salt).unwrap();
    let hash_id = argon2id.hash(password, salt).unwrap();

    assert_ne!(hash_d, hash_i, "Argon2d and Argon2i should produce different hashes");
    assert_ne!(hash_d, hash_id, "Argon2d and Argon2id should produce different hashes");
    assert_ne!(hash_i, hash_id, "Argon2i and Argon2id should produce different hashes");

    println!("  All three variants produce distinct outputs");
}
