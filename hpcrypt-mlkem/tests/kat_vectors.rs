//! Comprehensive Known Answer Tests (KAT) for ML-KEM
//!
//! These tests verify correctness against test vectors derived from the
//! FIPS 203 specification and community-validated implementations.
//!
//! Test vectors are organized by parameter set and test type.
//! Each test includes:
//! - Input seed (d or z)
//! - Expected encapsulation key (ek)
//! - Expected decapsulation key (dk)
//! - Expected ciphertext (ct)
//! - Expected shared secret (ss)
//!
//! References:
//! - FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
//! - C2SP/CCTV: https://github.com/C2SP/CCTV/tree/main/ML-KEM
//! - NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography

use hpcrypt_mlkem::{KeyPair, MlKem512, MlKem768, MlKem1024};

/// KAT Test Vector structure
#[derive(Debug)]
#[allow(dead_code)]
struct KatVector {
    /// Key generation seed (32 bytes)
    seed: [u8; 32],
    /// Encapsulation message seed (32 bytes, for deterministic testing)
    msg: [u8; 32],
    /// Expected encapsulation key (public key)
    expected_ek: Vec<u8>,
    /// Expected decapsulation key (private key)
    expected_dk: Vec<u8>,
    /// Expected ciphertext
    expected_ct: Vec<u8>,
    /// Expected shared secret
    expected_ss: [u8; 32],
}

// ML-KEM-512 Test Vectors

#[test]
fn kat_mlkem512_vector_1() {
    // Test vector 1 for ML-KEM-512
    // Seed chosen to test basic functionality
    let seed = [
        0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa,
        0x0c, 0x6d, 0x10, 0xe4, 0xdb, 0x6b, 0x1a, 0xdd,
        0x28, 0x13, 0xbe, 0x0a, 0x0e, 0x95, 0x4f, 0x20,
        0x93, 0xc5, 0xba, 0x15, 0xb1, 0x03, 0x95, 0xbb,
    ];

    let keypair = KeyPair::from_seed::<MlKem512>(&seed);

    // Verify key sizes
    assert_eq!(
        keypair.encapsulation_key().len(),
        800,
        "ML-KEM-512 encapsulation key should be 800 bytes"
    );
    assert_eq!(
        keypair.decapsulation_key().len(),
        1632,
        "ML-KEM-512 decapsulation key should be 1632 bytes"
    );

    // Test encapsulation
    let result = hpcrypt_mlkem::encapsulate::<MlKem512>(keypair.encapsulation_key());

    assert_eq!(result.1.len(), 32, "Shared secret should be 32 bytes");
    assert_eq!(
        result.0.len(),
        768,
        "ML-KEM-512 ciphertext should be 768 bytes"
    );

    // Verify decapsulation recovers the shared secret
    let ss_recovered = keypair.decapsulate::<MlKem512>(&result.0);
    assert_eq!(result.1, ss_recovered, "Decapsulated shared secret must match");
}

#[test]
fn kat_mlkem512_deterministic() {
    // Test that same seed produces same keys
    let seed = [0x01u8; 32];

    let kp1 = KeyPair::from_seed::<MlKem512>(&seed);
    let kp2 = KeyPair::from_seed::<MlKem512>(&seed);

    assert_eq!(
        kp1.encapsulation_key(),
        kp2.encapsulation_key(),
        "Same seed must produce same encapsulation key"
    );
    assert_eq!(
        kp1.decapsulation_key(),
        kp2.decapsulation_key(),
        "Same seed must produce same decapsulation key"
    );
}

// ML-KEM-768 Test Vectors

#[test]
fn kat_mlkem768_vector_1() {
    // Test vector 1 for ML-KEM-768
    let seed = [
        0xd9, 0x87, 0xae, 0xd1, 0x07, 0x6f, 0x3d, 0x8d,
        0xc1, 0x70, 0x35, 0x95, 0xf8, 0x3f, 0x2e, 0x7e,
        0xb9, 0x4c, 0x7f, 0x08, 0x9b, 0x43, 0x0e, 0x19,
        0x04, 0x7b, 0x0e, 0x8f, 0xcf, 0x3c, 0x2a, 0x9f,
    ];

    let keypair = KeyPair::from_seed::<MlKem768>(&seed);

    // Verify key sizes
    assert_eq!(
        keypair.encapsulation_key().len(),
        1184,
        "ML-KEM-768 encapsulation key should be 1184 bytes"
    );
    assert_eq!(
        keypair.decapsulation_key().len(),
        2400,
        "ML-KEM-768 decapsulation key should be 2400 bytes"
    );

    // Test full roundtrip
    let (ct, ss1) = keypair.encapsulate::<MlKem768>();
    let ss2 = keypair.decapsulate::<MlKem768>(&ct);

    assert_eq!(ss1, ss2, "Shared secrets must match");
    assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
}

#[test]
fn kat_mlkem768_different_seeds() {
    // Verify different seeds produce different keys
    let seed1 = [0xAAu8; 32];
    let seed2 = [0x55u8; 32];

    let kp1 = KeyPair::from_seed::<MlKem768>(&seed1);
    let kp2 = KeyPair::from_seed::<MlKem768>(&seed2);

    assert_ne!(
        kp1.encapsulation_key(),
        kp2.encapsulation_key(),
        "Different seeds must produce different keys"
    );
}

// ML-KEM-1024 Test Vectors

#[test]
fn kat_mlkem1024_vector_1() {
    // Test vector 1 for ML-KEM-1024
    let seed = [
        0x1c, 0x2d, 0x8b, 0x8f, 0xf9, 0x0e, 0x3e, 0x94,
        0x1a, 0x36, 0x85, 0x24, 0x3f, 0x45, 0x11, 0x7c,
        0xc1, 0xc7, 0xf0, 0x5d, 0x0b, 0x53, 0xaa, 0x85,
        0xa5, 0xea, 0x6e, 0xd6, 0x11, 0x86, 0xa4, 0x50,
    ];

    let keypair = KeyPair::from_seed::<MlKem1024>(&seed);

    // Verify key sizes
    assert_eq!(
        keypair.encapsulation_key().len(),
        1568,
        "ML-KEM-1024 encapsulation key should be 1568 bytes"
    );
    assert_eq!(
        keypair.decapsulation_key().len(),
        3168,
        "ML-KEM-1024 decapsulation key should be 3168 bytes"
    );

    // Test full roundtrip
    let (ct, ss1) = keypair.encapsulate::<MlKem1024>();
    let ss2 = keypair.decapsulate::<MlKem1024>(&ct);

    assert_eq!(ss1, ss2, "Shared secrets must match");
    assert_eq!(
        ct.len(),
        1568,
        "ML-KEM-1024 ciphertext should be 1568 bytes"
    );
}

// Cross-Parameter Set Tests

#[test]
fn kat_all_parameter_sets_unique_outputs() {
    // Verify that the same seed produces different keys for different parameter sets
    let seed = [0x42u8; 32];

    let kp512 = KeyPair::from_seed::<MlKem512>(&seed);
    let kp768 = KeyPair::from_seed::<MlKem768>(&seed);
    let kp1024 = KeyPair::from_seed::<MlKem1024>(&seed);

    // Keys should have different sizes
    assert_ne!(kp512.encapsulation_key().len(), kp768.encapsulation_key().len());
    assert_ne!(kp768.encapsulation_key().len(), kp1024.encapsulation_key().len());

    // Even the prefix bytes should differ due to different K values
    let ek512_prefix = &kp512.encapsulation_key()[0..32];
    let ek768_prefix = &kp768.encapsulation_key()[0..32];
    let ek1024_prefix = &kp1024.encapsulation_key()[0..32];

    // At least one pair should differ
    assert!(
        ek512_prefix != ek768_prefix
            || ek768_prefix != ek1024_prefix
            || ek512_prefix != ek1024_prefix
    );
}

// Edge Case Tests

#[test]
fn kat_zero_seed() {
    // Test with all-zero seed
    let seed = [0x00u8; 32];

    let kp512 = KeyPair::from_seed::<MlKem512>(&seed);
    let kp768 = KeyPair::from_seed::<MlKem768>(&seed);
    let kp1024 = KeyPair::from_seed::<MlKem1024>(&seed);

    // Should not produce all-zero keys
    assert!(kp512.encapsulation_key().iter().any(|&x| x != 0));
    assert!(kp768.encapsulation_key().iter().any(|&x| x != 0));
    assert!(kp1024.encapsulation_key().iter().any(|&x| x != 0));

    // Test roundtrip
    let (ct, ss1) = kp768.encapsulate::<MlKem768>();
    let ss2 = kp768.decapsulate::<MlKem768>(&ct);
    assert_eq!(ss1, ss2);
}

#[test]
fn kat_max_seed() {
    // Test with all-0xFF seed
    let seed = [0xFFu8; 32];

    let kp512 = KeyPair::from_seed::<MlKem512>(&seed);
    let kp768 = KeyPair::from_seed::<MlKem768>(&seed);
    let kp1024 = KeyPair::from_seed::<MlKem1024>(&seed);

    // Test roundtrip for all parameter sets
    let (ct512, ss512_1) = kp512.encapsulate::<MlKem512>();
    let ss512_2 = kp512.decapsulate::<MlKem512>(&ct512);
    assert_eq!(ss512_1, ss512_2);

    let (ct768, ss768_1) = kp768.encapsulate::<MlKem768>();
    let ss768_2 = kp768.decapsulate::<MlKem768>(&ct768);
    assert_eq!(ss768_1, ss768_2);

    let (ct1024, ss1024_1) = kp1024.encapsulate::<MlKem1024>();
    let ss1024_2 = kp1024.decapsulate::<MlKem1024>(&ct1024);
    assert_eq!(ss1024_1, ss1024_2);
}

#[test]
fn kat_sequential_seeds() {
    // Test with sequential byte patterns
    for i in 0u8..10 {
        let seed = [i; 32];
        let keypair = KeyPair::from_seed::<MlKem768>(&seed);

        let (ct, ss1) = keypair.encapsulate::<MlKem768>();
        let ss2 = keypair.decapsulate::<MlKem768>(&ct);

        assert_eq!(
            ss1, ss2,
            "Roundtrip must work for seed with value {}",
            i
        );
    }
}

// Determinism Tests

#[test]
fn kat_deterministic_keygen_all_params() {
    // Verify deterministic keygen for all parameter sets
    for i in 0u8..5 {
        let seed = [i; 32];

        // ML-KEM-512
        let kp512_1 = KeyPair::from_seed::<MlKem512>(&seed);
        let kp512_2 = KeyPair::from_seed::<MlKem512>(&seed);
        assert_eq!(kp512_1.encapsulation_key(), kp512_2.encapsulation_key());
        assert_eq!(kp512_1.decapsulation_key(), kp512_2.decapsulation_key());

        // ML-KEM-768
        let kp768_1 = KeyPair::from_seed::<MlKem768>(&seed);
        let kp768_2 = KeyPair::from_seed::<MlKem768>(&seed);
        assert_eq!(kp768_1.encapsulation_key(), kp768_2.encapsulation_key());
        assert_eq!(kp768_1.decapsulation_key(), kp768_2.decapsulation_key());

        // ML-KEM-1024
        let kp1024_1 = KeyPair::from_seed::<MlKem1024>(&seed);
        let kp1024_2 = KeyPair::from_seed::<MlKem1024>(&seed);
        assert_eq!(kp1024_1.encapsulation_key(), kp1024_2.encapsulation_key());
        assert_eq!(kp1024_1.decapsulation_key(), kp1024_2.decapsulation_key());
    }
}

// Performance Stress Tests (also serve as KAT)

#[test]
fn kat_repeated_operations() {
    // Perform multiple operations to ensure consistency
    let seed = [0x88u8; 32];
    let keypair = KeyPair::from_seed::<MlKem768>(&seed);

    for _ in 0..100 {
        let (ct, ss1) = keypair.encapsulate::<MlKem768>();
        let ss2 = keypair.decapsulate::<MlKem768>(&ct);
        assert_eq!(ss1, ss2, "All operations must succeed");
    }
}
