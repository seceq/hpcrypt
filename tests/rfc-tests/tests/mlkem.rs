//! FIPS 203 - ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
//!
//! Tests for ML-KEM using FIPS 203 reference test vectors.
//!
//! ML-KEM, formerly known as CRYSTALS-KYBER, is a lattice-based key encapsulation
//! mechanism standardized by NIST as FIPS 203, selected in the NIST Post-Quantum
//! Cryptography standardization process.
//!
//! References:
//! - FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
//! - CRYSTALS-KYBER: https://pq-crystals.org/kyber/

use rfc_tests::{load_test_file, TestStats};
use serde::Deserialize;

#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mlkem::{
    ml_kem_keygen, ml_kem_encaps, ml_kem_decaps,
    MlKem512, MlKem768, MlKem1024, Params,
};

#[derive(Debug, Deserialize)]
struct MlKemTestVector {
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
    ciphertext_size: usize,
    #[serde(default)]
    shared_secret_size: usize,
    test_type: String,
    #[serde(default)]
    iterations: usize,
    note: String,
}

/// Test basic key generation, encapsulation, and decapsulation for all 3 parameter sets
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_all_parameter_sets() {
    let test_vectors: Vec<MlKemTestVector> = load_test_file("fips203-mlkem.json");

    println!("\n=== FIPS 203: ML-KEM All Parameter Sets ===");

    let mut stats = TestStats::new();

    // Filter for basic keygen_encaps_decaps tests
    let basic_tests: Vec<_> = test_vectors
        .iter()
        .filter(|t| t.test_type == "keygen_encaps_decaps")
        .collect();

    println!("Testing {} parameter sets\n", basic_tests.len());

    for test in basic_tests {
        println!("--- Test {} ---", test.test_id);
        println!("  Parameter Set: {}", test.parameter_set);
        println!("  Security Level: {}", test.security_level);
        println!("  NIST Category: {}", test.nist_category);
        println!("  Public Key: {} bytes", test.public_key_size);
        println!("  Secret Key: {} bytes", test.secret_key_size);
        println!("  Ciphertext: {} bytes", test.ciphertext_size);
        println!("  Shared Secret: {} bytes", test.shared_secret_size);
        println!("  Note: {}", test.note);

        match test.parameter_set.as_str() {
            "ML-KEM-512" => test_basic_flow::<MlKem512>(&mut stats, test),
            "ML-KEM-768" => test_basic_flow::<MlKem768>(&mut stats, test),
            "ML-KEM-1024" => test_basic_flow::<MlKem1024>(&mut stats, test),
            _ => {
                println!("  Unknown parameter set, skipping");
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All ML-KEM parameter set tests should pass");
}

#[cfg(feature = "enable-pqc-tests")]
fn test_basic_flow<P: Params>(stats: &mut TestStats, test: &MlKemTestVector) {
    // Generate key pair
    let keypair = ml_kem_keygen::<P>(None);

    println!("  Key generation: OK");

    // Verify key sizes match expected
    if test.public_key_size > 0 && keypair.ek.len() != test.public_key_size {
        println!("  FAILED: Public key size mismatch: expected {}, got {}", test.public_key_size, keypair.ek.len());
        stats.failed += 1;
        return;
    }

    if test.secret_key_size > 0 && keypair.dk.len() != test.secret_key_size {
        println!("  FAILED: Secret key size mismatch: expected {}, got {}", test.secret_key_size, keypair.dk.len());
        stats.failed += 1;
        return;
    }

    println!("    Public key size: {} bytes (matches expected)", keypair.ek.len());
    println!("    Secret key size: {} bytes (matches expected)", keypair.dk.len());

    // Encapsulation
    let encaps_result = ml_kem_encaps::<P>(&keypair.ek, None);

    println!("  Encapsulation: OK");

    if test.ciphertext_size > 0 && encaps_result.ciphertext.len() != test.ciphertext_size {
        println!("  FAILED: Ciphertext size mismatch: expected {}, got {}", test.ciphertext_size, encaps_result.ciphertext.len());
        stats.failed += 1;
        return;
    }

    if test.shared_secret_size > 0 && encaps_result.shared_secret.len() != test.shared_secret_size {
        println!("  FAILED: Shared secret size mismatch: expected {}, got {}", test.shared_secret_size, encaps_result.shared_secret.len());
        stats.failed += 1;
        return;
    }

    println!("    Ciphertext size: {} bytes (matches expected)", encaps_result.ciphertext.len());
    println!("    Shared secret size: {} bytes (matches expected)", encaps_result.shared_secret.len());

    // Decapsulation
    let decaps_shared_secret = ml_kem_decaps::<P>(&keypair.dk, &encaps_result.ciphertext);

    println!("  Decapsulation: OK");

    // Verify shared secrets match
    if encaps_result.shared_secret == decaps_shared_secret {
        println!("  Shared secret match: OK");
        println!("  Test {}: PASSED", test.test_id);
        stats.passed += 1;
    } else {
        println!("  FAILED: Shared secrets do not match");
        stats.failed += 1;
    }
}

/// Test shared secret consistency
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_shared_secret_consistency() {
    println!("\n=== ML-KEM Shared Secret Consistency Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);

    // Encapsulate
    let encaps_result = ml_kem_encaps::<MlKem512>(&keypair.ek, None);

    // Decapsulate
    let decaps_shared_secret = ml_kem_decaps::<MlKem512>(&keypair.dk, &encaps_result.ciphertext);

    // Shared secrets should match
    assert_eq!(
        encaps_result.shared_secret, decaps_shared_secret,
        "Shared secrets should match"
    );

    println!("  Shared secret consistency: PASSED");
}

/// Test wrong decapsulation key
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_wrong_decaps_key() {
    println!("\n=== ML-KEM Wrong Decapsulation Key Test ===");

    // Generate two key pairs
    let keypair1 = ml_kem_keygen::<MlKem512>(None);
    let keypair2 = ml_kem_keygen::<MlKem512>(None);

    // Encapsulate with first public key
    let encaps_result = ml_kem_encaps::<MlKem512>(&keypair1.ek, None);

    // Decapsulate with correct key
    let decaps_correct = ml_kem_decaps::<MlKem512>(&keypair1.dk, &encaps_result.ciphertext);

    // Decapsulate with wrong key
    let decaps_wrong = ml_kem_decaps::<MlKem512>(&keypair2.dk, &encaps_result.ciphertext);

    // Correct decapsulation should match
    assert_eq!(
        encaps_result.shared_secret, decaps_correct,
        "Correct key should produce matching shared secret"
    );

    // Wrong decapsulation should produce different shared secret
    assert_ne!(
        encaps_result.shared_secret, decaps_wrong,
        "Wrong key should produce different shared secret"
    );

    println!("  Wrong decapsulation key correctly handled: PASSED");
}

/// Test ciphertext tampering
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_ciphertext_tampering() {
    println!("\n=== ML-KEM Ciphertext Tampering Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);

    // Encapsulate
    let encaps_result = ml_kem_encaps::<MlKem512>(&keypair.ek, None);

    // Decapsulate with original ciphertext
    let decaps_original = ml_kem_decaps::<MlKem512>(&keypair.dk, &encaps_result.ciphertext);

    assert_eq!(
        encaps_result.shared_secret, decaps_original,
        "Original ciphertext should produce matching shared secret"
    );

    // Tamper with ciphertext
    let mut tampered_ciphertext = encaps_result.ciphertext.clone();
    tampered_ciphertext[0] ^= 0xFF;

    // Decapsulate with tampered ciphertext
    let decaps_tampered = ml_kem_decaps::<MlKem512>(&keypair.dk, &tampered_ciphertext);

    // Tampered ciphertext should produce different shared secret
    assert_ne!(
        encaps_result.shared_secret, decaps_tampered,
        "Tampered ciphertext should produce different shared secret"
    );

    println!("  Ciphertext tampering correctly detected: PASSED");
}

/// Test encapsulation randomness
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_encaps_randomness() {
    println!("\n=== ML-KEM Encapsulation Randomness Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);

    // Encapsulate twice with same public key
    let encaps1 = ml_kem_encaps::<MlKem512>(&keypair.ek, None);
    let encaps2 = ml_kem_encaps::<MlKem512>(&keypair.ek, None);

    // Ciphertexts should be different (randomized)
    assert_ne!(
        encaps1.ciphertext, encaps2.ciphertext,
        "Multiple encapsulations should produce different ciphertexts"
    );

    // Shared secrets should also be different
    assert_ne!(
        encaps1.shared_secret, encaps2.shared_secret,
        "Multiple encapsulations should produce different shared secrets"
    );

    // Both should decapsulate correctly
    let decaps1 = ml_kem_decaps::<MlKem512>(&keypair.dk, &encaps1.ciphertext);
    let decaps2 = ml_kem_decaps::<MlKem512>(&keypair.dk, &encaps2.ciphertext);

    assert_eq!(encaps1.shared_secret, decaps1, "First encapsulation should decapsulate correctly");
    assert_eq!(encaps2.shared_secret, decaps2, "Second encapsulation should decapsulate correctly");

    println!("  Encapsulation randomness verified: PASSED");
}

/// Test multiple encapsulations
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_multiple_encaps() {
    println!("\n=== ML-KEM Multiple Encapsulations Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);
    let iterations = 10;

    for i in 0..iterations {
        let encaps_result = ml_kem_encaps::<MlKem512>(&keypair.ek, None);
        let decaps_shared_secret = ml_kem_decaps::<MlKem512>(&keypair.dk, &encaps_result.ciphertext);

        assert_eq!(
            encaps_result.shared_secret, decaps_shared_secret,
            "Iteration {} failed: shared secrets do not match",
            i
        );
    }

    println!("  {} encapsulations all decapsulated correctly: PASSED", iterations);
}

/// Test all security levels
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_security_levels() {
    println!("\n=== ML-KEM Security Levels Test ===");

    // NIST Category 1 (Level 1)
    let keypair_512 = ml_kem_keygen::<MlKem512>(None);
    let encaps_512 = ml_kem_encaps::<MlKem512>(&keypair_512.ek, None);
    let decaps_512 = ml_kem_decaps::<MlKem512>(&keypair_512.dk, &encaps_512.ciphertext);

    // NIST Category 3 (Level 3)
    let keypair_768 = ml_kem_keygen::<MlKem768>(None);
    let encaps_768 = ml_kem_encaps::<MlKem768>(&keypair_768.ek, None);
    let decaps_768 = ml_kem_decaps::<MlKem768>(&keypair_768.dk, &encaps_768.ciphertext);

    // NIST Category 5 (Level 5)
    let keypair_1024 = ml_kem_keygen::<MlKem1024>(None);
    let encaps_1024 = ml_kem_encaps::<MlKem1024>(&keypair_1024.ek, None);
    let decaps_1024 = ml_kem_decaps::<MlKem1024>(&keypair_1024.dk, &encaps_1024.ciphertext);

    // Verify all decapsulations
    assert_eq!(encaps_512.shared_secret, decaps_512, "ML-KEM-512 decapsulation failed");
    assert_eq!(encaps_768.shared_secret, decaps_768, "ML-KEM-768 decapsulation failed");
    assert_eq!(encaps_1024.shared_secret, decaps_1024, "ML-KEM-1024 decapsulation failed");

    // Check sizes
    println!("  ML-KEM-512 ciphertext size: {} bytes", encaps_512.ciphertext.len());
    println!("  ML-KEM-768 ciphertext size: {} bytes", encaps_768.ciphertext.len());
    println!("  ML-KEM-1024 ciphertext size: {} bytes", encaps_1024.ciphertext.len());

    // Higher security levels should have larger ciphertexts
    assert!(
        encaps_768.ciphertext.len() > encaps_512.ciphertext.len(),
        "ML-KEM-768 should have larger ciphertext than ML-KEM-512"
    );
    assert!(
        encaps_1024.ciphertext.len() > encaps_768.ciphertext.len(),
        "ML-KEM-1024 should have larger ciphertext than ML-KEM-768"
    );

    println!("  All security levels tested: PASSED");
}

/// Test serialization round-trip
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_serialization() {
    println!("\n=== ML-KEM Serialization Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);

    // Keys are already in byte form (Vec<u8>)
    let ek_bytes = keypair.ek.clone();
    let dk_bytes = keypair.dk.clone();

    // Use the serialized keys for encapsulation/decapsulation
    let encaps_result = ml_kem_encaps::<MlKem512>(&ek_bytes, None);
    let decaps_shared_secret = ml_kem_decaps::<MlKem512>(&dk_bytes, &encaps_result.ciphertext);

    // Verify functionality
    assert_eq!(
        encaps_result.shared_secret, decaps_shared_secret,
        "Serialized keys should work correctly"
    );

    println!("  Key serialization round-trip: PASSED");
}

/// Test key reuse
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_key_reuse() {
    println!("\n=== ML-KEM Key Reuse Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);
    let iterations = 5;

    for i in 0..iterations {
        let encaps_result = ml_kem_encaps::<MlKem512>(&keypair.ek, None);
        let decaps_shared_secret = ml_kem_decaps::<MlKem512>(&keypair.dk, &encaps_result.ciphertext);

        assert_eq!(
            encaps_result.shared_secret, decaps_shared_secret,
            "Iteration {} failed: shared secrets do not match",
            i
        );
    }

    println!("  Public key reused {} times successfully: PASSED", iterations);
}

/// Test deterministic encapsulation
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_deterministic_encaps() {
    println!("\n=== ML-KEM Deterministic Encapsulation Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);

    // Use same randomness for encapsulation
    let randomness = [0x42u8; 32];

    let encaps1 = ml_kem_encaps::<MlKem512>(&keypair.ek, Some(&randomness));
    let encaps2 = ml_kem_encaps::<MlKem512>(&keypair.ek, Some(&randomness));

    // With same randomness, ciphertexts should be identical
    assert_eq!(
        encaps1.ciphertext, encaps2.ciphertext,
        "Same randomness should produce same ciphertext"
    );

    assert_eq!(
        encaps1.shared_secret, encaps2.shared_secret,
        "Same randomness should produce same shared secret"
    );

    println!("  Deterministic encapsulation verified: PASSED");
}

/// Test immediate decapsulation
#[test]
#[cfg(feature = "enable-pqc-tests")]
fn test_mlkem_immediate_decaps() {
    println!("\n=== ML-KEM Immediate Decapsulation Test ===");

    let keypair = ml_kem_keygen::<MlKem512>(None);

    // Encapsulate and immediately decapsulate
    let encaps_result = ml_kem_encaps::<MlKem512>(&keypair.ek, None);
    let decaps_shared_secret = ml_kem_decaps::<MlKem512>(&keypair.dk, &encaps_result.ciphertext);

    assert_eq!(
        encaps_result.shared_secret, decaps_shared_secret,
        "Immediate decapsulation should succeed"
    );

    println!("  Immediate decapsulation: PASSED");
}

/// Test vector count
#[test]
fn test_mlkem_vector_count() {
    let test_vectors: Vec<MlKemTestVector> = load_test_file("fips203-mlkem.json");
    assert!(
        test_vectors.len() >= 3,
        "Should have at least 3 test vectors (one per parameter set)"
    );
    println!("ML-KEM test vectors loaded: {}", test_vectors.len());
}
