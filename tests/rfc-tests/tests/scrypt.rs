//! RFC 7914 - scrypt Test Vectors
//!
//! Tests for scrypt password-based KDF using official RFC 7914 test vectors

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
fn test_scrypt_rfc7914() {
    let test_vectors: Vec<ScryptTestVector> = load_test_file("rfc7914-scrypt.json");

    println!("\n=== RFC 7914: scrypt Password-Based KDF ===");
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

        // Use hpcrypt_kdf::scrypt
        let params = hpcrypt_kdf::scrypt::ScryptParams {
            n: test.n as usize,
            r: test.r as usize,
            p: test.p as usize,
        };

        let result = hpcrypt_kdf::scrypt::scrypt(password, salt, &params, test.dk_len);

        if result == expected {
            println!("  Test passed");
            stats.passed += 1;
        } else {
            println!("  Test failed");
            println!("    Expected: {}", test.expected_output);
            println!("    Got:      {}", encode_hex(&result));
            stats.failed += 1;
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All scrypt RFC 7914 tests should pass");
}

#[test]
fn test_scrypt_vector_count() {
    let test_vectors: Vec<ScryptTestVector> = load_test_file("rfc7914-scrypt.json");
    assert_eq!(test_vectors.len(), 4, "RFC 7914 should have 4 test vectors");
}
