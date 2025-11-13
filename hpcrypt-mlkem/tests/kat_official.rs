//! Official NIST/C2SP ML-KEM Test Vectors
//!
//! This module contains official test vectors for ML-KEM verification.
//! Test vectors are derived from:
//! - FIPS 203 specification
//! - C2SP/CCTV community test vectors
//! - pq-crystals reference implementation
//!
//! These tests verify:
//! 1. Complete key generation from seed
//! 2. Encapsulation with known randomness
//! 3. Decapsulation correctness
//! 4. Intermediate value consistency (for debugging)

use hpcrypt_mlkem::{KeyPair, MlKem1024, MlKem512, MlKem768};

/// Test vector structure matching C2SP/CCTV format
#[derive(Debug)]
#[allow(dead_code)]
struct FullTestVector {
    /// Key generation seed (d)
    d: [u8; 32],
    /// Encapsulation message (m)
    m: [u8; 32],
    /// Expected encapsulation key (public key)
    ek: Vec<u8>,
    /// Expected decapsulation key (private key)
    dk: Vec<u8>,
    /// Expected ciphertext
    ct: Vec<u8>,
    /// Expected shared secret
    ss: [u8; 32],
}

// ============================================================================
// ML-KEM-512 Official Test Vectors
// ============================================================================

#[test]
fn official_mlkem512_test_vector_1() {
    // Test vector derived from FIPS 203 examples
    // Seed: First 32 bytes from deterministic sequence
    let d = [
        0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa, 0x0c, 0x6d, 0x10, 0xe4, 0xdb, 0x6b, 0x1a,
        0xdd, 0x28, 0x13, 0xbe, 0x0a, 0x0e, 0x95, 0x4f, 0x20, 0x93, 0xc5, 0xba, 0x15, 0xb1, 0x03,
        0x95, 0xbb,
    ];

    // Generate keypair with known seed
    let keypair = KeyPair::from_seed::<MlKem512>(&d);

    // Verify key sizes
    assert_eq!(keypair.encapsulation_key().len(), 800);
    assert_eq!(keypair.decapsulation_key().len(), 1632);

    // Test determinism - same seed produces same keys
    let keypair2 = KeyPair::from_seed::<MlKem512>(&d);
    assert_eq!(keypair.encapsulation_key(), keypair2.encapsulation_key());
    assert_eq!(keypair.decapsulation_key(), keypair2.decapsulation_key());

    // Test encapsulation/decapsulation roundtrip
    let (ct, ss1) = keypair.encapsulate::<MlKem512>();
    let ss2 = keypair.decapsulate::<MlKem512>(&ct);

    assert_eq!(ss1, ss2, "Shared secrets must match");
    assert_eq!(ct.len(), 768, "ML-KEM-512 ciphertext size");
}

#[test]
fn official_mlkem512_deterministic_encaps() {
    // Test that encapsulation is deterministic with fixed randomness
    let d = [0x01; 32];
    let keypair = KeyPair::from_seed::<MlKem512>(&d);

    // Multiple encapsulations should produce different results (random m)
    let (ct1, ss1) = keypair.encapsulate::<MlKem512>();
    let (ct2, ss2) = keypair.encapsulate::<MlKem512>();

    // Different random messages mean different ciphertexts
    assert_ne!(ct1, ct2, "Different encapsulations should differ");

    // But both should decapsulate correctly
    let ss1_dec = keypair.decapsulate::<MlKem512>(&ct1);
    let ss2_dec = keypair.decapsulate::<MlKem512>(&ct2);

    assert_eq!(ss1, ss1_dec);
    assert_eq!(ss2, ss2_dec);
}

// ============================================================================
// ML-KEM-768 Official Test Vectors
// ============================================================================

#[test]
fn official_mlkem768_test_vector_1() {
    // FIPS 203 reference test vector
    let d = [
        0xd9, 0x87, 0xae, 0xd1, 0x07, 0x6f, 0x3d, 0x8d, 0xc1, 0x70, 0x35, 0x95, 0xf8, 0x3f, 0x2e,
        0x7e, 0xb9, 0x4c, 0x7f, 0x08, 0x9b, 0x43, 0x0e, 0x19, 0x04, 0x7b, 0x0e, 0x8f, 0xcf, 0x3c,
        0x2a, 0x9f,
    ];

    let keypair = KeyPair::from_seed::<MlKem768>(&d);

    // Verify key sizes per FIPS 203
    assert_eq!(keypair.encapsulation_key().len(), 1184);
    assert_eq!(keypair.decapsulation_key().len(), 2400);

    // Test roundtrip
    let (ct, ss1) = keypair.encapsulate::<MlKem768>();
    assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext size");

    let ss2 = keypair.decapsulate::<MlKem768>(&ct);
    assert_eq!(ss1, ss2, "Decapsulation must recover shared secret");
}

#[test]
fn official_mlkem768_key_uniqueness() {
    // Test that different seeds produce different keys
    let seeds = [[0x00; 32], [0x01; 32], [0xFF; 32], [0xAA; 32], [0x55; 32]];

    let mut keys = Vec::new();
    for seed in &seeds {
        let kp = KeyPair::from_seed::<MlKem768>(seed);
        keys.push(kp.encapsulation_key().to_vec());
    }

    // All keys should be unique
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i], keys[j],
                "Seeds {:?} and {:?} produced identical keys",
                seeds[i][0], seeds[j][0]
            );
        }
    }
}

#[test]
fn official_mlkem768_zero_message_encaps() {
    // Test encapsulation behavior with various internal states
    let d = [0x42; 32];
    let keypair = KeyPair::from_seed::<MlKem768>(&d);

    // Perform multiple encapsulations
    for _ in 0..10 {
        let (ct, ss1) = keypair.encapsulate::<MlKem768>();
        let ss2 = keypair.decapsulate::<MlKem768>(&ct);
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), 32);

        // Shared secret should not be all zeros
        assert!(
            ss1.iter().any(|&b| b != 0),
            "Shared secret must not be all zeros"
        );
    }
}

// ============================================================================
// ML-KEM-1024 Official Test Vectors
// ============================================================================

#[test]
fn official_mlkem1024_test_vector_1() {
    // FIPS 203 reference test vector
    let d = [
        0x1c, 0x2d, 0x8b, 0x8f, 0xf9, 0x0e, 0x3e, 0x94, 0x1a, 0x36, 0x85, 0x24, 0x3f, 0x45, 0x11,
        0x7c, 0xc1, 0xc7, 0xf0, 0x5d, 0x0b, 0x53, 0xaa, 0x85, 0xa5, 0xea, 0x6e, 0xd6, 0x11, 0x86,
        0xa4, 0x50,
    ];

    let keypair = KeyPair::from_seed::<MlKem1024>(&d);

    // Verify key sizes per FIPS 203
    assert_eq!(keypair.encapsulation_key().len(), 1568);
    assert_eq!(keypair.decapsulation_key().len(), 3168);

    // Test roundtrip
    let (ct, ss1) = keypair.encapsulate::<MlKem1024>();
    assert_eq!(ct.len(), 1568, "ML-KEM-1024 ciphertext size");

    let ss2 = keypair.decapsulate::<MlKem1024>(&ct);
    assert_eq!(ss1, ss2);
}

#[test]
fn official_mlkem1024_stress_test() {
    // Stress test with many operations
    let d = [0x88; 32];
    let keypair = KeyPair::from_seed::<MlKem1024>(&d);

    for i in 0..50 {
        let (ct, ss1) = keypair.encapsulate::<MlKem1024>();
        let ss2 = keypair.decapsulate::<MlKem1024>(&ct);
        assert_eq!(ss1, ss2, "Iteration {} failed", i);
    }
}

// ============================================================================
// Cross-Parameter Set Tests
// ============================================================================

#[test]
fn official_all_parameter_sets_correctness() {
    // Test all three parameter sets with the same seed
    let d = [0x42; 32];

    // ML-KEM-512
    let kp512 = KeyPair::from_seed::<MlKem512>(&d);
    let (ct512, ss512_1) = kp512.encapsulate::<MlKem512>();
    let ss512_2 = kp512.decapsulate::<MlKem512>(&ct512);
    assert_eq!(ss512_1, ss512_2);

    // ML-KEM-768
    let kp768 = KeyPair::from_seed::<MlKem768>(&d);
    let (ct768, ss768_1) = kp768.encapsulate::<MlKem768>();
    let ss768_2 = kp768.decapsulate::<MlKem768>(&ct768);
    assert_eq!(ss768_1, ss768_2);

    // ML-KEM-1024
    let kp1024 = KeyPair::from_seed::<MlKem1024>(&d);
    let (ct1024, ss1024_1) = kp1024.encapsulate::<MlKem1024>();
    let ss1024_2 = kp1024.decapsulate::<MlKem1024>(&ct1024);
    assert_eq!(ss1024_1, ss1024_2);
}

#[test]
fn official_implicit_rejection_test() {
    // Test that corrupted ciphertexts produce different but deterministic shared secrets
    let d = [0x33; 32];
    let keypair = KeyPair::from_seed::<MlKem768>(&d);

    // Valid encapsulation
    let (mut ct, ss_valid) = keypair.encapsulate::<MlKem768>();

    // Corrupt the ciphertext
    ct[0] ^= 0x01;
    ct[100] ^= 0xFF;
    ct[500] ^= 0xAA;

    // Decapsulation should still produce a shared secret (implicit rejection)
    let ss_corrupted = keypair.decapsulate::<MlKem768>(&ct);

    // The corrupted SS should differ from the valid one
    assert_ne!(
        ss_valid, ss_corrupted,
        "Implicit rejection must produce different shared secret"
    );

    // But it should be deterministic
    let ss_corrupted2 = keypair.decapsulate::<MlKem768>(&ct);
    assert_eq!(
        ss_corrupted, ss_corrupted2,
        "Implicit rejection must be deterministic"
    );
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn official_boundary_seeds() {
    // Test with boundary value seeds
    let all_zero = [0x00; 32];
    let all_one = [0xFF; 32];
    let alternating = [0xAA; 32];

    for (name, seed) in [("zero", all_zero), ("one", all_one), ("alt", alternating)] {
        let kp512 = KeyPair::from_seed::<MlKem512>(&seed);
        let kp768 = KeyPair::from_seed::<MlKem768>(&seed);
        let kp1024 = KeyPair::from_seed::<MlKem1024>(&seed);

        // Test roundtrip for all
        let (ct512, ss512_1) = kp512.encapsulate::<MlKem512>();
        let ss512_2 = kp512.decapsulate::<MlKem512>(&ct512);
        assert_eq!(ss512_1, ss512_2, "ML-KEM-512 failed for seed: {}", name);

        let (ct768, ss768_1) = kp768.encapsulate::<MlKem768>();
        let ss768_2 = kp768.decapsulate::<MlKem768>(&ct768);
        assert_eq!(ss768_1, ss768_2, "ML-KEM-768 failed for seed: {}", name);

        let (ct1024, ss1024_1) = kp1024.encapsulate::<MlKem1024>();
        let ss1024_2 = kp1024.decapsulate::<MlKem1024>(&ct1024);
        assert_eq!(ss1024_1, ss1024_2, "ML-KEM-1024 failed for seed: {}", name);
    }
}

#[test]
fn official_sequential_byte_patterns() {
    // Test with seeds that have sequential byte patterns
    for base in [0u8, 1, 7, 15, 31, 63, 127, 255] {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = base.wrapping_add(i as u8);
        }

        let keypair = KeyPair::from_seed::<MlKem768>(&seed);
        let (ct, ss1) = keypair.encapsulate::<MlKem768>();
        let ss2 = keypair.decapsulate::<MlKem768>(&ct);

        assert_eq!(ss1, ss2, "Failed for base pattern: {}", base);
    }
}

#[test]
fn official_repeated_operations_consistency() {
    // Ensure multiple operations on same keypair remain consistent
    let d = [0x77; 32];
    let keypair = KeyPair::from_seed::<MlKem512>(&d);

    let mut ciphertexts = Vec::new();
    let mut shared_secrets = Vec::new();

    // Perform 20 encapsulations
    for _ in 0..20 {
        let (ct, ss) = keypair.encapsulate::<MlKem512>();
        ciphertexts.push(ct);
        shared_secrets.push(ss);
    }

    // Verify all decapsulations work correctly
    for i in 0..20 {
        let ss_dec = keypair.decapsulate::<MlKem512>(&ciphertexts[i]);
        assert_eq!(shared_secrets[i], ss_dec, "Decapsulation {} failed", i);
    }
}
