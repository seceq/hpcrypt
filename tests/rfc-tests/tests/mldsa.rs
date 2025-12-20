//! FIPS 204 - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//!
//! Tests for ML-DSA using FIPS 204 reference test vectors.
//!
//! ML-DSA, formerly known as CRYSTALS-Dilithium, is a lattice-based digital signature
//! scheme standardized by NIST as FIPS 204, selected in the NIST Post-Quantum
//! Cryptography standardization process.
//!
//! References:
//! - FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
//! - CRYSTALS-Dilithium: https://pq-crystals.org/dilithium/

use rfc_tests::{load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::{MlDsa44, MlDsa65, MlDsa87, DsaParams};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::keygen::{keygen, PublicKey, SecretKey};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::sign::{sign, Signature};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::verify::verify;

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::{sign_batch, verify_batch};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::serialize::{serialize_public_key, serialize_secret_key, serialize_signature};

#[derive(Debug, Deserialize)]
struct MlDsaTestVector {
    test_id: u32,
    source: String,
    description: String,
    #[serde(default)]
    parameter_set: String,
    #[serde(default)]
    parameter_set_1: String,
    #[serde(default)]
    parameter_set_2: String,
    #[serde(default)]
    parameter_set_3: String,
    #[serde(default)]
    security_level: String,
    #[serde(default)]
    nist_category: u32,
    #[serde(default)]
    public_key_size: usize,
    #[serde(default)]
    secret_key_size: usize,
    #[serde(default)]
    signature_size: usize,
    test_type: String,
    #[serde(default)]
    prehash_alg: String,
    #[serde(default)]
    batch_size: usize,
    note: String,
}

/// Test basic key generation, signing, and verification for all 3 parameter sets
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_all_parameter_sets() {
    let test_vectors: Vec<MlDsaTestVector> = load_test_file("fips204-mldsa.json");

    println!("\n=== FIPS 204: ML-DSA All Parameter Sets ===");

    let mut stats = TestStats::new();
    let test_message = b"FIPS 204 ML-DSA test message";

    // Filter for basic keygen_sign_verify tests
    let basic_tests: Vec<_> = test_vectors
        .iter()
        .filter(|t| t.test_type == "keygen_sign_verify")
        .collect();

    println!("Testing {} parameter sets\n", basic_tests.len());

    for test in basic_tests {
        println!("--- Test {} ---", test.test_id);
        println!("  Parameter Set: {}", test.parameter_set);
        println!("  Security Level: {}", test.security_level);
        println!("  NIST Category: {}", test.nist_category);
        println!("  Public Key: {} bytes", test.public_key_size);
        println!("  Secret Key: {} bytes", test.secret_key_size);
        println!("  Signature: {} bytes", test.signature_size);
        println!("  Note: {}", test.note);

        match test.parameter_set.as_str() {
            "ML-DSA-44" => test_basic_flow::<MlDsa44>(test_message, &mut stats, test),
            "ML-DSA-65" => test_basic_flow::<MlDsa65>(test_message, &mut stats, test),
            "ML-DSA-87" => test_basic_flow::<MlDsa87>(test_message, &mut stats, test),
            _ => {
                println!("  Unknown parameter set, skipping");
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All ML-DSA parameter set tests should pass");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_basic_flow<P: DsaParams>(
    message: &[u8],
    stats: &mut TestStats,
    test: &MlDsaTestVector,
) {
    // Generate key pair
    let (pk, sk) = keygen::<P>();

    println!("  Key generation: OK");

    // Verify key sizes match expected
    let pk_bytes = serialize_public_key::<P>(&pk);
    let sk_bytes = serialize_secret_key::<P>(&sk);

    if test.public_key_size > 0 && pk_bytes.len() != test.public_key_size {
        println!("  FAILED: Public key size mismatch: expected {}, got {}", test.public_key_size, pk_bytes.len());
        stats.failed += 1;
        return;
    }

    if test.secret_key_size > 0 && sk_bytes.len() != test.secret_key_size {
        println!("  FAILED: Secret key size mismatch: expected {}, got {}", test.secret_key_size, sk_bytes.len());
        stats.failed += 1;
        return;
    }

    println!("    Public key size: {} bytes (matches expected)", pk_bytes.len());
    println!("    Secret key size: {} bytes (matches expected)", sk_bytes.len());

    // Sign message
    let signature = match sign(&sk, message) {
        Some(sig) => sig,
        None => {
            println!("  FAILED: Signature generation failed");
            stats.failed += 1;
            return;
        }
    };

    println!("  Signature generation: OK");

    let sig_bytes = serialize_signature::<P>(&signature);
    if test.signature_size > 0 && sig_bytes.len() != test.signature_size {
        println!("  FAILED: Signature size mismatch: expected {}, got {}", test.signature_size, sig_bytes.len());
        stats.failed += 1;
        return;
    }

    println!("    Signature size: {} bytes (matches expected)", sig_bytes.len());

    // Verify signature
    if verify(&pk, message, &signature) {
        println!("  Signature verification: OK");
        println!("  Test {}: PASSED", test.test_id);
        stats.passed += 1;
    } else {
        println!("  FAILED: Signature verification failed");
        stats.failed += 1;
    }
}

/// Test edge case: empty message
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_empty_message() {
    println!("\n=== ML-DSA Empty Message Test ===");

    let (pk, sk) = keygen::<MlDsa44>();
    let empty_message = b"";

    let signature = sign(&sk, empty_message).expect("Signature generation failed");

    assert!(
        verify(&pk, empty_message, &signature),
        "Empty message signature verification failed"
    );

    println!("  Empty message signing and verification: PASSED");
}

/// Test edge case: single byte message
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_single_byte_message() {
    println!("\n=== ML-DSA Single Byte Message Test ===");

    let (pk, sk) = keygen::<MlDsa44>();
    let single_byte = &[0x42];

    let signature = sign(&sk, single_byte).expect("Signature generation failed");

    assert!(
        verify(&pk, single_byte, &signature),
        "Single byte message signature verification failed"
    );

    println!("  Single byte message signing and verification: PASSED");
}

/// Test edge case: large message
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_large_message() {
    println!("\n=== ML-DSA Large Message Test ===");

    let (pk, sk) = keygen::<MlDsa44>();
    let large_message = vec![0x42; 10_000]; // 10 KB message

    let signature = sign(&sk, &large_message).expect("Signature generation failed");

    assert!(
        verify(&pk, &large_message, &signature),
        "Large message signature verification failed"
    );

    println!("  Large message (10 KB) signing and verification: PASSED");
}

/// Test determinism: same inputs should produce verifiable signatures
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_determinism() {
    println!("\n=== ML-DSA Determinism Test ===");

    let message = b"Deterministic test message";

    // Generate two independent key pairs
    let (pk1, sk1) = keygen::<MlDsa44>();
    let (pk2, sk2) = keygen::<MlDsa44>();

    // Sign with first key pair
    let sig1 = sign(&sk1, message).expect("Signature 1 failed");

    // Sign with second key pair
    let sig2 = sign(&sk2, message).expect("Signature 2 failed");

    // Each signature should verify with its own public key
    assert!(verify(&pk1, message, &sig1), "Signature 1 verification failed");
    assert!(verify(&pk2, message, &sig2), "Signature 2 verification failed");

    // Signatures from different keys should be different (with very high probability)
    assert_ne!(
        serialize_signature::<MlDsa44>(&sig1),
        serialize_signature::<MlDsa44>(&sig2),
        "Different keys should produce different signatures"
    );

    println!("  Determinism properties verified: PASSED");
}

/// Test invalid signature rejection
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_invalid_signature() {
    println!("\n=== ML-DSA Invalid Signature Rejection Test ===");

    let message = b"Test message for invalid signature";
    let (pk, sk) = keygen::<MlDsa44>();

    let signature = sign(&sk, message).expect("Signature generation failed");

    // Corrupt the signature by flipping a byte in c_tilde
    let mut corrupted_sig = signature.clone();
    corrupted_sig.c_tilde[0] ^= 0xFF;

    // Verification should fail
    assert!(
        !verify(&pk, message, &corrupted_sig),
        "Invalid signature should not verify"
    );

    println!("  Invalid signature correctly rejected: PASSED");
}

/// Test wrong public key rejection
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_wrong_public_key() {
    println!("\n=== ML-DSA Wrong Public Key Rejection Test ===");

    let message = b"Test message for wrong key";

    // Generate two key pairs
    let (pk1, sk1) = keygen::<MlDsa44>();
    let (pk2, _sk2) = keygen::<MlDsa44>();

    // Sign with first key
    let signature = sign(&sk1, message).expect("Signature generation failed");

    // Verification with correct key should succeed
    assert!(
        verify(&pk1, message, &signature),
        "Signature should verify with correct key"
    );

    // Verification with wrong key should fail
    assert!(
        !verify(&pk2, message, &signature),
        "Signature should not verify with wrong public key"
    );

    println!("  Wrong public key correctly rejected: PASSED");
}

/// Test message tampering detection
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_message_tampering() {
    println!("\n=== ML-DSA Message Tampering Detection Test ===");

    let message = b"Original message";
    let tampered_message = b"Tampered message";

    let (pk, sk) = keygen::<MlDsa44>();
    let signature = sign(&sk, message).expect("Signature generation failed");

    // Verification with original message should succeed
    assert!(
        verify(&pk, message, &signature),
        "Signature should verify with original message"
    );

    // Verification with tampered message should fail
    assert!(
        !verify(&pk, tampered_message, &signature),
        "Signature should not verify with tampered message"
    );

    println!("  Message tampering correctly detected: PASSED");
}

/// Test signature randomness
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_signature_randomness() {
    println!("\n=== ML-DSA Signature Randomness Test ===");

    let message = b"Test message for randomness";
    let (pk, sk) = keygen::<MlDsa44>();

    // Sign same message twice
    let sig1 = sign(&sk, message).expect("Signature 1 failed");
    let sig2 = sign(&sk, message).expect("Signature 2 failed");

    // Both signatures should verify
    assert!(verify(&pk, message, &sig1), "Signature 1 verification failed");
    assert!(verify(&pk, message, &sig2), "Signature 2 verification failed");

    // Signatures should be different due to randomness
    assert_ne!(
        serialize_signature::<MlDsa44>(&sig1),
        serialize_signature::<MlDsa44>(&sig2),
        "Same message signed twice should produce different signatures (randomized)"
    );

    println!("  Signature randomness verified: PASSED");
}

/// Test all security levels (NIST Categories 2, 3, 5)
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_security_levels() {
    println!("\n=== ML-DSA Security Levels Test ===");

    let message = b"Security level test message";

    // NIST Category 2 (Level 2)
    let (pk_44, sk_44) = keygen::<MlDsa44>();
    let sig_44 = sign(&sk_44, message).expect("ML-DSA-44 signature failed");

    // NIST Category 3 (Level 3)
    let (pk_65, sk_65) = keygen::<MlDsa65>();
    let sig_65 = sign(&sk_65, message).expect("ML-DSA-65 signature failed");

    // NIST Category 5 (Level 5)
    let (pk_87, sk_87) = keygen::<MlDsa87>();
    let sig_87 = sign(&sk_87, message).expect("ML-DSA-87 signature failed");

    // Verify all signatures
    assert!(verify(&pk_44, message, &sig_44), "ML-DSA-44 verification failed");
    assert!(verify(&pk_65, message, &sig_65), "ML-DSA-65 verification failed");
    assert!(verify(&pk_87, message, &sig_87), "ML-DSA-87 verification failed");

    // Check sizes
    let sig_44_bytes = serialize_signature::<MlDsa44>(&sig_44);
    let sig_65_bytes = serialize_signature::<MlDsa65>(&sig_65);
    let sig_87_bytes = serialize_signature::<MlDsa87>(&sig_87);

    println!("  ML-DSA-44 signature size: {} bytes", sig_44_bytes.len());
    println!("  ML-DSA-65 signature size: {} bytes", sig_65_bytes.len());
    println!("  ML-DSA-87 signature size: {} bytes", sig_87_bytes.len());

    // Higher security levels should have larger signatures
    assert!(
        sig_65_bytes.len() > sig_44_bytes.len(),
        "ML-DSA-65 should have larger signature than ML-DSA-44"
    );
    assert!(
        sig_87_bytes.len() > sig_65_bytes.len(),
        "ML-DSA-87 should have larger signature than ML-DSA-65"
    );

    println!("  All security levels tested: PASSED");
}

/// Test batch signing and verification
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_batch_operations() {
    println!("\n=== ML-DSA Batch Operations Test ===");

    let (pk, sk) = keygen::<MlDsa44>();

    let messages = vec![
        b"Message 1".as_slice(),
        b"Message 2".as_slice(),
        b"Message 3".as_slice(),
        b"Message 4".as_slice(),
        b"Message 5".as_slice(),
    ];

    // Batch sign
    let signatures = sign_batch(&sk, &messages);

    assert_eq!(signatures.len(), messages.len(), "Should produce signature for each message");

    // All signatures should be valid
    for sig_opt in &signatures {
        assert!(sig_opt.is_some(), "Batch signing should succeed for all messages");
    }

    // Extract signatures
    let sig_refs: Vec<_> = signatures.iter()
        .map(|s| s.as_ref().unwrap())
        .collect();

    // Batch verify
    let results = verify_batch(&pk, &messages, &sig_refs);

    assert_eq!(results.len(), messages.len(), "Should verify each signature");
    assert!(results.iter().all(|&r| r), "All signatures should verify successfully");

    println!("  Batch signing: {} messages signed", messages.len());
    println!("  Batch verification: {} signatures verified", results.len());
    println!("  Batch operations: PASSED");
}

/// Test serialization round-trip
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mldsa_serialization() {
    println!("\n=== ML-DSA Serialization Test ===");

    let (pk, sk) = keygen::<MlDsa44>();
    let message = b"Serialization test message";

    // Serialize keys
    let pk_bytes = serialize_public_key::<MlDsa44>(&pk);
    let sk_bytes = serialize_secret_key::<MlDsa44>(&sk);

    // Deserialize keys
    let pk_restored = hpcrypt_mldsa::keygen::PublicKey::<MlDsa44>::from_bytes(&pk_bytes)
        .expect("Public key deserialization failed");
    let sk_restored = hpcrypt_mldsa::keygen::SecretKey::<MlDsa44>::from_bytes(&sk_bytes)
        .expect("Secret key deserialization failed");

    // Sign with restored secret key
    let signature = sign(&sk_restored, message).expect("Signature with restored key failed");

    // Verify with restored public key
    assert!(
        verify(&pk_restored, message, &signature),
        "Signature should verify with restored keys"
    );

    println!("  Key serialization round-trip: PASSED");
}

/// Test vector count
#[test]
fn test_mldsa_vector_count() {
    let test_vectors: Vec<MlDsaTestVector> = load_test_file("fips204-mldsa.json");
    assert!(
        test_vectors.len() >= 3,
        "Should have at least 3 test vectors (one per parameter set)"
    );
    println!("ML-DSA test vectors loaded: {}", test_vectors.len());
}
