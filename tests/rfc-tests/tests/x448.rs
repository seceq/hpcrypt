//! RFC 7748 - X448 Test Vectors
//!
//! Tests for X448 key exchange from RFC 7748 Sections 5.2 and 6.2.
//!
//! X448 provides:
//! - Elliptic Curve Diffie-Hellman (ECDH) key agreement
//! - 56-byte (448-bit) keys
//! - 56-byte (448-bit) shared secrets
//! - Curve448 (edwards448 Montgomery form, also known as Goldilocks)
//! - Constant-time scalar multiplication
//! - 224-bit security level (higher than X25519's 128-bit)
//!
//! Test types:
//! 1. Direct scalar multiplication (2 tests)
//! 2. Iterative computation (3 tests: 1, 1K, 1M iterations)
//! 3. Diffie-Hellman key agreement (1 test)

use hpcrypt_curves::X448;
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct X448TestVector {
    test_id: u32,
    source: String,
    section: String,
    description: String,
    algorithm: String,
    #[serde(default)]
    scalar: String,
    #[serde(default)]
    u_coordinate: String,
    #[serde(default)]
    expected_output: String,
    #[serde(default)]
    iterations: u32,
    #[serde(default)]
    alice_private: String,
    #[serde(default)]
    alice_public: String,
    #[serde(default)]
    bob_private: String,
    #[serde(default)]
    bob_public: String,
    #[serde(default)]
    shared_secret: String,
    note: String,
}

#[test]
fn test_x448_rfc7748() {
    let test_vectors: Vec<X448TestVector> = load_test_file("rfc7748-x448.json");

    println!("\n=== RFC 7748: X448 Key Exchange Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {} Section {}", test.source, test.section);
        println!("  Description: {}", test.description);
        println!("  Note: {}", test.note);

        // Test 6 is the Diffie-Hellman test
        if test.test_id == 6 {
            test_diffie_hellman(test, &mut stats);
        } else if test.iterations > 0 {
            // Tests 3-5 are iterative tests
            test_iterative(test, &mut stats);
        } else {
            // Tests 1-2 are direct scalar multiplication
            test_scalar_mult(test, &mut stats);
        }
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

fn test_scalar_mult(test: &X448TestVector, stats: &mut TestStats) {
    println!("  Testing direct scalar multiplication...");

    let scalar_bytes = decode_hex(&test.scalar);
    let u_bytes = decode_hex(&test.u_coordinate);
    let expected_output = decode_hex(&test.expected_output);

    if scalar_bytes.len() != 56 {
        println!(
            "  Test {} SKIPPED: Invalid scalar size {} (expected 56)",
            test.test_id,
            scalar_bytes.len()
        );
        stats.skipped += 1;
        return;
    }

    if u_bytes.len() != 56 {
        println!(
            "  Test {} SKIPPED: Invalid u-coordinate size {} (expected 56)",
            test.test_id,
            u_bytes.len()
        );
        stats.skipped += 1;
        return;
    }

    if expected_output.len() != 56 {
        println!(
            "  Test {} SKIPPED: Invalid expected output size {} (expected 56)",
            test.test_id,
            expected_output.len()
        );
        stats.skipped += 1;
        return;
    }

    let scalar: [u8; 56] = scalar_bytes.try_into().unwrap();
    let u: [u8; 56] = u_bytes.try_into().unwrap();
    let expected: [u8; 56] = expected_output.try_into().unwrap();

    // Perform scalar multiplication
    let result = match X448::shared_secret(&scalar, &u) {
        Ok(r) => r,
        Err(e) => {
            println!(
                "  Test {} FAILED: X448 computation error: {:?}",
                test.test_id, e
            );
            stats.failed += 1;
            return;
        }
    };

    if result != expected {
        println!("  Test {} FAILED: Output mismatch", test.test_id);
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&result));
        stats.failed += 1;
        return;
    }

    println!("    Output matches expected value");
    println!("  Test {} PASSED", test.test_id);
    stats.passed += 1;
}

fn test_iterative(test: &X448TestVector, stats: &mut TestStats) {
    println!("  Testing iterative computation ({} iterations)...", test.iterations);

    // For 1M iterations, this will take a while, so we skip it by default
    // Users can run it manually if they want to verify the implementation
    if test.iterations == 1_000_000 {
        println!("  Test {} SKIPPED: 1M iteration test takes too long (run manually if needed)", test.test_id);
        stats.skipped += 1;
        return;
    }

    let scalar_bytes = decode_hex(&test.scalar);
    let u_bytes = decode_hex(&test.u_coordinate);
    let expected_output = decode_hex(&test.expected_output);

    if scalar_bytes.len() != 56 || u_bytes.len() != 56 || expected_output.len() != 56 {
        println!("  Test {} SKIPPED: Invalid input sizes", test.test_id);
        stats.skipped += 1;
        return;
    }

    let mut k: [u8; 56] = scalar_bytes.try_into().unwrap();
    let mut u: [u8; 56] = u_bytes.try_into().unwrap();
    let expected: [u8; 56] = expected_output.try_into().unwrap();

    // RFC 7748 Section 5.2: For iteration count, compute k(u) repeatedly
    // After each iteration: k' = k(u), u' = k
    for i in 0..test.iterations {
        if i % 100 == 0 && i > 0 {
            println!("    Progress: {}/{} iterations", i, test.iterations);
        }

        let result = match X448::shared_secret(&k, &u) {
            Ok(r) => r,
            Err(e) => {
                println!(
                    "  Test {} FAILED: X448 computation error at iteration {}: {:?}",
                    test.test_id, i, e
                );
                stats.failed += 1;
                return;
            }
        };

        // u' = k, k' = result
        u = k;
        k = result;
    }

    if k != expected {
        println!("  Test {} FAILED: Output mismatch after {} iterations", test.test_id, test.iterations);
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&k));
        stats.failed += 1;
        return;
    }

    println!("    Output matches expected value after {} iterations", test.iterations);
    println!("  Test {} PASSED", test.test_id);
    stats.passed += 1;
}

fn test_diffie_hellman(test: &X448TestVector, stats: &mut TestStats) {
    println!("  Testing Diffie-Hellman key agreement...");

    let alice_private_bytes = decode_hex(&test.alice_private);
    let alice_public_bytes = decode_hex(&test.alice_public);
    let bob_private_bytes = decode_hex(&test.bob_private);
    let bob_public_bytes = decode_hex(&test.bob_public);
    let expected_shared_secret = decode_hex(&test.shared_secret);

    if alice_private_bytes.len() != 56
        || alice_public_bytes.len() != 56
        || bob_private_bytes.len() != 56
        || bob_public_bytes.len() != 56
        || expected_shared_secret.len() != 56
    {
        println!("  Test {} SKIPPED: Invalid key sizes", test.test_id);
        stats.skipped += 1;
        return;
    }

    let alice_private: [u8; 56] = alice_private_bytes.try_into().unwrap();
    let alice_public_expected: [u8; 56] = alice_public_bytes.try_into().unwrap();
    let bob_private: [u8; 56] = bob_private_bytes.try_into().unwrap();
    let bob_public_expected: [u8; 56] = bob_public_bytes.try_into().unwrap();
    let expected_secret: [u8; 56] = expected_shared_secret.try_into().unwrap();

    // Test 1: Verify Alice's public key generation
    println!("  Testing Alice's public key generation...");
    let alice_public_computed = X448::public_key(&alice_private);
    if alice_public_computed != alice_public_expected {
        println!("  Test {} FAILED: Alice's public key mismatch", test.test_id);
        println!("    Expected: {}", hex::encode(&alice_public_expected));
        println!("    Got:      {}", hex::encode(&alice_public_computed));
        stats.failed += 1;
        return;
    }
    println!("    Alice's public key matches expected value");

    // Test 2: Verify Bob's public key generation
    println!("  Testing Bob's public key generation...");
    let bob_public_computed = X448::public_key(&bob_private);
    if bob_public_computed != bob_public_expected {
        println!("  Test {} FAILED: Bob's public key mismatch", test.test_id);
        println!("    Expected: {}", hex::encode(&bob_public_expected));
        println!("    Got:      {}", hex::encode(&bob_public_computed));
        stats.failed += 1;
        return;
    }
    println!("    Bob's public key matches expected value");

    // Test 3: Verify shared secret (Alice's perspective)
    println!("  Testing shared secret (Alice computes with Bob's public key)...");
    let alice_shared_secret = match X448::shared_secret(&alice_private, &bob_public_expected) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "  Test {} FAILED: Alice's shared secret computation error: {:?}",
                test.test_id, e
            );
            stats.failed += 1;
            return;
        }
    };

    if alice_shared_secret != expected_secret {
        println!("  Test {} FAILED: Alice's shared secret mismatch", test.test_id);
        println!("    Expected: {}", hex::encode(&expected_secret));
        println!("    Got:      {}", hex::encode(&alice_shared_secret));
        stats.failed += 1;
        return;
    }
    println!("    Alice's shared secret matches expected value");

    // Test 4: Verify shared secret (Bob's perspective)
    println!("  Testing shared secret (Bob computes with Alice's public key)...");
    let bob_shared_secret = match X448::shared_secret(&bob_private, &alice_public_expected) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "  Test {} FAILED: Bob's shared secret computation error: {:?}",
                test.test_id, e
            );
            stats.failed += 1;
            return;
        }
    };

    if bob_shared_secret != expected_secret {
        println!("  Test {} FAILED: Bob's shared secret mismatch", test.test_id);
        println!("    Expected: {}", hex::encode(&expected_secret));
        println!("    Got:      {}", hex::encode(&bob_shared_secret));
        stats.failed += 1;
        return;
    }
    println!("    Bob's shared secret matches expected value");

    // Test 5: Verify Alice and Bob computed the same shared secret
    if alice_shared_secret != bob_shared_secret {
        println!(
            "  Test {} FAILED: Alice and Bob computed different shared secrets",
            test.test_id
        );
        println!("    Alice: {}", hex::encode(&alice_shared_secret));
        println!("    Bob:   {}", hex::encode(&bob_shared_secret));
        stats.failed += 1;
        return;
    }
    println!("    Alice and Bob computed the same shared secret");

    println!("  Test {} PASSED", test.test_id);
    stats.passed += 1;
}
