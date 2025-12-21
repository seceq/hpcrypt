//! RFC 8032 - EdDSA: Ed25519 Test Vectors
//!
//! Tests for Ed25519 digital signatures from RFC 8032 Section 7.1.
//!
//! Ed25519 provides:
//! - 128-bit security level
//! - 32-byte (256-bit) public keys
//! - 64-byte (512-bit) signatures
//! - Curve25519 (edwards25519)
//!
//! Note: This test file only covers basic Ed25519 (no context, no prehash).
//! Ed25519ph (prehashed) and Ed25519ctx (with context) are not yet supported.

use hpcrypt_curves::Ed25519;
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Ed25519TestVector {
    test_id: u32,
    source: String,
    section: String,
    description: String,
    algorithm: String,
    secret_key: String,
    public_key: String,
    message: String,
    signature: String,
    note: String,
}

#[test]
fn test_ed25519_rfc8032() {
    let test_vectors: Vec<Ed25519TestVector> = load_test_file("rfc8032-ed25519.json");

    println!("\n=== RFC 8032: Ed25519 Signature Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {} Section {}", test.source, test.section);
        println!("  Description: {}", test.description);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Note: {}", test.note);

        // Decode test data
        let secret_key_bytes = decode_hex(&test.secret_key);
        let expected_public_key_bytes = decode_hex(&test.public_key);
        let message = if test.message.is_empty() {
            vec![]
        } else {
            decode_hex(&test.message)
        };
        let expected_signature_bytes = decode_hex(&test.signature);

        // Validate sizes
        if secret_key_bytes.len() != 32 {
            println!(
                "  Test {} SKIPPED: Invalid secret key size {} (expected 32)",
                test.test_id,
                secret_key_bytes.len()
            );
            stats.skipped += 1;
            continue;
        }

        if expected_public_key_bytes.len() != 32 {
            println!(
                "  Test {} SKIPPED: Invalid public key size {} (expected 32)",
                test.test_id,
                expected_public_key_bytes.len()
            );
            stats.skipped += 1;
            continue;
        }

        if expected_signature_bytes.len() != 64 {
            println!(
                "  Test {} SKIPPED: Invalid signature size {} (expected 64)",
                test.test_id,
                expected_signature_bytes.len()
            );
            stats.skipped += 1;
            continue;
        }

        // Convert to fixed-size arrays
        let secret_key: [u8; 32] = secret_key_bytes.try_into().unwrap();
        let expected_public_key: [u8; 32] = expected_public_key_bytes.try_into().unwrap();
        let expected_signature: [u8; 64] = expected_signature_bytes.try_into().unwrap();

        // Test 1: Generate public key from secret key
        println!("  Testing public key generation...");
        let public_key = Ed25519::public_key(&secret_key);

        if public_key != expected_public_key {
            println!("  Test {} FAILED: Public key mismatch", test.test_id);
            println!("    Expected: {}", hex::encode(&expected_public_key));
            println!("    Got:      {}", hex::encode(&public_key));
            stats.failed += 1;
            continue;
        }
        println!("    Public key matches expected value");

        // Test 2: Sign the message
        println!("  Testing signature generation...");
        let signature = Ed25519::sign(&secret_key, &message);

        if signature != expected_signature {
            println!("  Test {} FAILED: Signature mismatch", test.test_id);
            println!("    Expected: {}", hex::encode(&expected_signature));
            println!("    Got:      {}", hex::encode(&signature));
            stats.failed += 1;
            continue;
        }
        println!("    Signature matches expected value");

        // Test 3: Verify the signature
        println!("  Testing signature verification...");
        let verified = Ed25519::verify(&expected_public_key, &message, &expected_signature);

        if !verified {
            println!(
                "  Test {} FAILED: Valid signature not verified",
                test.test_id
            );
            stats.failed += 1;
            continue;
        }
        println!("    Signature verified successfully");

        // Test 4: Verify with wrong message should fail
        if !message.is_empty() {
            println!("  Testing verification with wrong message...");
            let mut wrong_message = message.clone();
            wrong_message[0] ^= 0x01; // Flip one bit
            let wrong_verified = Ed25519::verify(&expected_public_key, &wrong_message, &expected_signature);

            if wrong_verified {
                println!(
                    "  Test {} FAILED: Signature verified with wrong message",
                    test.test_id
                );
                stats.failed += 1;
                continue;
            }
            println!("    Wrong message correctly rejected");
        }

        // Test 5: Verify with wrong signature should fail
        println!("  Testing verification with corrupted signature...");
        let mut wrong_signature = expected_signature;
        wrong_signature[0] ^= 0x01; // Flip one bit
        let wrong_sig_verified = Ed25519::verify(&expected_public_key, &message, &wrong_signature);

        if wrong_sig_verified {
            println!(
                "  Test {} FAILED: Corrupted signature accepted",
                test.test_id
            );
            stats.failed += 1;
            continue;
        }
        println!("    Corrupted signature correctly rejected");

        println!("  Test {} PASSED", test.test_id);
        stats.passed += 1;
    }

    // Print summary
    println!("\n=== Test Summary ===");
    println!("Total:   {}", stats.passed + stats.failed + stats.skipped);
    println!("Passed:  {}", stats.passed);
    println!("Failed:  {}", stats.failed);
    println!("Skipped: {}", stats.skipped);

    assert_eq!(
        stats.failed, 0,
        "{} test(s) failed. See details above.",
        stats.failed
    );
    assert!(
        stats.passed > 0,
        "No tests passed. Expected at least some passing tests."
    );
}
