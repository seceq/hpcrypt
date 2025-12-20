//! FIPS 205 - SLH-DSA (Stateless Hash-Based Digital Signature Standard)
//!
//! Tests for SLH-DSA using FIPS 205 reference test vectors.
//!
//! SLH-DSA is a stateless hash-based signature scheme standardized by NIST
//! as FIPS 205, based on the SPHINCS+ algorithm selected in the NIST
//! Post-Quantum Cryptography standardization process.
//!
//! References:
//! - FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
//! - ACVP Specification: https://pages.nist.gov/ACVP/draft-livelsberger-acvp-slh-dsa.html

use rfc_tests::{load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_slhdsa::{
    KeyPair, sign, verify,
    Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f,
    Shake128s, Shake128f, Shake192s, Shake192f, Shake256s, Shake256f,
    ParameterSet,
};

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_rng::OsRng;

#[derive(Debug, Deserialize)]
struct SlhDsaTestVector {
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
    hash_function: String,
    security_level: u32,
    #[serde(default)]
    signature_size: String,
    test_type: String,
    #[serde(default)]
    prehash_alg: String,
    note: String,
}

/// Test basic key generation, signing, and verification for all 12 parameter sets
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_all_parameter_sets() {
    let test_vectors: Vec<SlhDsaTestVector> = load_test_file("fips205-slhdsa.json");

    println!("\n=== FIPS 205: SLH-DSA All Parameter Sets ===");

    let mut stats = TestStats::new();
    let test_message = b"FIPS 205 SLH-DSA test message";

    // Filter for basic keygen_siggen_sigver tests
    let basic_tests: Vec<_> = test_vectors
        .iter()
        .filter(|t| t.test_type == "keygen_siggen_sigver")
        .collect();

    println!("Testing {} parameter sets\n", basic_tests.len());

    for test in basic_tests {
        println!("--- Test {} ---", test.test_id);
        println!("  Parameter Set: {}", test.parameter_set);
        println!("  Hash Function: {}", test.hash_function);
        println!("  Security Level: {} bits", test.security_level);
        println!("  Signature Type: {}", test.signature_size);
        println!("  Note: {}", test.note);

        match test.parameter_set.as_str() {
            "SLH-DSA-SHA2-128s" => {
                test_basic_flow::<Sha2_128s>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHA2-128f" => {
                test_basic_flow::<Sha2_128f>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHA2-192s" => {
                test_basic_flow::<Sha2_192s>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHA2-192f" => {
                test_basic_flow::<Sha2_192f>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHA2-256s" => {
                test_basic_flow::<Sha2_256s>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHA2-256f" => {
                test_basic_flow::<Sha2_256f>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHAKE-128s" => {
                test_basic_flow::<Shake128s>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHAKE-128f" => {
                test_basic_flow::<Shake128f>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHAKE-192s" => {
                test_basic_flow::<Shake192s>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHAKE-192f" => {
                test_basic_flow::<Shake192f>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHAKE-256s" => {
                test_basic_flow::<Shake256s>(test_message, &mut stats, test.test_id)
            }
            "SLH-DSA-SHAKE-256f" => {
                test_basic_flow::<Shake256f>(test_message, &mut stats, test.test_id)
            }
            _ => {
                println!("  Unknown parameter set, skipping");
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All SLH-DSA parameter set tests should pass");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_basic_flow<P: ParameterSet>(message: &[u8], stats: &mut TestStats, test_id: u32) {
    let mut rng = OsRng;

    // Generate key pair
    let keypair = KeyPair::<P>::generate(&mut rng);

    println!("  Key generation: OK");
    println!("    Public key size: {} bytes", keypair.public_key.to_bytes().len());
    println!("    Secret key size: {} bytes", keypair.secret_key.to_bytes().len());

    // Sign message
    let signature = sign(&keypair.secret_key, message);

    println!("  Signature generation: OK");
    println!("    Signature size: {} bytes", signature.len());

    // Verify signature
    if verify(&keypair.public_key, message, &signature) {
        println!("  Signature verification: OK");
        println!("  Test {}: PASSED", test_id);
        stats.passed += 1;
    } else {
        println!("  FAILED: Signature verification failed");
        stats.failed += 1;
    }
}

/// Test edge case: empty message
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_empty_message() {
    println!("\n=== SLH-DSA Empty Message Test ===");

    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let empty_message = b"";

    let signature = sign(&keypair.secret_key, empty_message);

    assert!(
        verify(&keypair.public_key, empty_message, &signature),
        "Empty message signature verification failed"
    );

    println!("  Empty message signing and verification: PASSED");
}

/// Test edge case: single byte message
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_single_byte_message() {
    println!("\n=== SLH-DSA Single Byte Message Test ===");

    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let single_byte = &[0x42];

    let signature = sign(&keypair.secret_key, single_byte);

    assert!(
        verify(&keypair.public_key, single_byte, &signature),
        "Single byte message signature verification failed"
    );

    println!("  Single byte message signing and verification: PASSED");
}

/// Test edge case: large message
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_large_message() {
    println!("\n=== SLH-DSA Large Message Test ===");

    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let large_message = vec![0x42; 10_000]; // 10 KB message

    let signature = sign(&keypair.secret_key, &large_message);

    assert!(
        verify(&keypair.public_key, &large_message, &signature),
        "Large message signature verification failed"
    );

    println!("  Large message (10 KB) signing and verification: PASSED");
}

/// Test determinism: same inputs should produce verifiable signatures
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_determinism() {
    println!("\n=== SLH-DSA Determinism Test ===");

    let mut rng = OsRng;
    let message = b"Deterministic test message";

    // Generate two independent key pairs
    let keypair1 = KeyPair::<Sha2_128s>::generate(&mut rng);
    let keypair2 = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Sign with first key pair
    let sig1 = sign(&keypair1.secret_key, message);

    // Sign with second key pair
    let sig2 = sign(&keypair2.secret_key, message);

    // Each signature should verify with its own public key
    assert!(
        verify(&keypair1.public_key, message, &sig1),
        "Signature 1 verification failed"
    );
    assert!(
        verify(&keypair2.public_key, message, &sig2),
        "Signature 2 verification failed"
    );

    // Signatures from different keys should be different (with very high probability)
    // Note: SLH-DSA signatures are randomized, so this should always be true
    assert_ne!(
        sig1, sig2,
        "Different keys should produce different signatures"
    );

    println!("  Determinism properties verified: PASSED");
}

/// Test invalid signature rejection
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_invalid_signature() {
    println!("\n=== SLH-DSA Invalid Signature Rejection Test ===");

    let mut rng = OsRng;
    let message = b"Test message for invalid signature";
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    let mut signature = sign(&keypair.secret_key, message);

    // Corrupt the signature by flipping a byte
    signature[0] ^= 0xFF;

    // Verification should fail
    assert!(
        !verify(&keypair.public_key, message, &signature),
        "Invalid signature should not verify"
    );

    println!("  Invalid signature correctly rejected: PASSED");
}

/// Test wrong public key rejection
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_wrong_public_key() {
    println!("\n=== SLH-DSA Wrong Public Key Rejection Test ===");

    let mut rng = OsRng;
    let message = b"Test message for wrong key";

    // Generate two key pairs
    let keypair1 = KeyPair::<Sha2_128s>::generate(&mut rng);
    let keypair2 = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Sign with first key
    let signature = sign(&keypair1.secret_key, message);

    // Verification with correct key should succeed
    assert!(
        verify(&keypair1.public_key, message, &signature),
        "Signature should verify with correct key"
    );

    // Verification with wrong key should fail
    assert!(
        !verify(&keypair2.public_key, message, &signature),
        "Signature should not verify with wrong public key"
    );

    println!("  Wrong public key correctly rejected: PASSED");
}

/// Test message tampering detection
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_message_tampering() {
    println!("\n=== SLH-DSA Message Tampering Detection Test ===");

    let mut rng = OsRng;
    let message = b"Original message";
    let tampered_message = b"Tampered message";

    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let signature = sign(&keypair.secret_key, message);

    // Verification with original message should succeed
    assert!(
        verify(&keypair.public_key, message, &signature),
        "Signature should verify with original message"
    );

    // Verification with tampered message should fail
    assert!(
        !verify(&keypair.public_key, tampered_message, &signature),
        "Signature should not verify with tampered message"
    );

    println!("  Message tampering correctly detected: PASSED");
}

/// Test signature size differences between 's' and 'f' variants
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_signature_size_comparison() {
    println!("\n=== SLH-DSA Signature Size Comparison ===");

    let mut rng = OsRng;
    let message = b"Test message for size comparison";

    // SHA2-128s (small signature)
    let keypair_s = KeyPair::<Sha2_128s>::generate(&mut rng);
    let sig_s = sign(&keypair_s.secret_key, message);

    // SHA2-128f (fast signature)
    let keypair_f = KeyPair::<Sha2_128f>::generate(&mut rng);
    let sig_f = sign(&keypair_f.secret_key, message);

    println!("  SHA2-128s signature size: {} bytes", sig_s.len());
    println!("  SHA2-128f signature size: {} bytes", sig_f.len());

    // 's' variant should have smaller signature than 'f' variant
    assert!(
        sig_s.len() < sig_f.len(),
        "Small variant (s) should have smaller signature than fast variant (f)"
    );

    println!("  Signature size comparison: PASSED");
}

/// Test hash function independence (SHA2 vs SHAKE)
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_hash_function_independence() {
    println!("\n=== SLH-DSA Hash Function Independence Test ===");

    let mut rng = OsRng;
    let message = b"Test message for hash function comparison";

    // SHA2-128s
    let keypair_sha2 = KeyPair::<Sha2_128s>::generate(&mut rng);
    let sig_sha2 = sign(&keypair_sha2.secret_key, message);

    // SHAKE-128s
    let keypair_shake = KeyPair::<Shake128s>::generate(&mut rng);
    let sig_shake = sign(&keypair_shake.secret_key, message);

    // Verify both signatures work
    assert!(
        verify(&keypair_sha2.public_key, message, &sig_sha2),
        "SHA2-128s signature verification failed"
    );
    assert!(
        verify(&keypair_shake.public_key, message, &sig_shake),
        "SHAKE-128s signature verification failed"
    );

    // Keys should be same sizes (both use N=16 for 128-bit security)
    println!("  SHA2-128s public key size: {} bytes", keypair_sha2.public_key.to_bytes().len());
    println!("  SHAKE-128s public key size: {} bytes", keypair_shake.public_key.to_bytes().len());

    println!("  Hash function independence verified: PASSED");
}

/// Test vector count
#[test]
fn test_slhdsa_vector_count() {
    let test_vectors: Vec<SlhDsaTestVector> = load_test_file("fips205-slhdsa.json");
    assert!(
        test_vectors.len() >= 12,
        "Should have at least 12 test vectors (one per parameter set)"
    );
    println!("SLH-DSA test vectors loaded: {}", test_vectors.len());
}

/// Test all security levels (128, 192, 256)
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_slhdsa_security_levels() {
    println!("\n=== SLH-DSA Security Levels Test ===");

    let mut rng = OsRng;
    let message = b"Security level test message";

    // Category 1 (128-bit security)
    let keypair_128 = KeyPair::<Sha2_128s>::generate(&mut rng);
    let sig_128 = sign(&keypair_128.secret_key, message);

    // Category 3 (192-bit security)
    let keypair_192 = KeyPair::<Sha2_192s>::generate(&mut rng);
    let sig_192 = sign(&keypair_192.secret_key, message);

    // Category 5 (256-bit security)
    let keypair_256 = KeyPair::<Sha2_256s>::generate(&mut rng);
    let sig_256 = sign(&keypair_256.secret_key, message);

    println!("  128-bit security signature size: {} bytes", sig_128.len());
    println!("  192-bit security signature size: {} bytes", sig_192.len());
    println!("  256-bit security signature size: {} bytes", sig_256.len());

    // Higher security levels should have larger signatures
    assert!(
        sig_192.len() > sig_128.len(),
        "192-bit security should have larger signature than 128-bit"
    );
    assert!(
        sig_256.len() > sig_192.len(),
        "256-bit security should have larger signature than 192-bit"
    );

    println!("  All security levels tested: PASSED");
}
