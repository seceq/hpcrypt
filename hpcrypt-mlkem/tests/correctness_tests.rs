//! Correctness tests for ML-KEM implementation
//!
//! These tests verify the correctness of the ML-KEM implementation
//! by testing various properties and edge cases.

use hpcrypt_mlkem::{KeyPair, MlKem512, MlKem768, MlKem1024};

#[test]
fn test_encaps_decaps_correctness_mlkem512() {
    for _ in 0..10 {
        let keypair = KeyPair::generate::<MlKem512>();
        let (ciphertext, ss_encaps) = keypair.encapsulate::<MlKem512>();
        let ss_decaps = keypair.decapsulate::<MlKem512>(&ciphertext);

        assert_eq!(ss_encaps, ss_decaps, "Shared secrets must match");
    }
}

#[test]
fn test_encaps_decaps_correctness_mlkem768() {
    for _ in 0..10 {
        let keypair = KeyPair::generate::<MlKem768>();
        let (ciphertext, ss_encaps) = keypair.encapsulate::<MlKem768>();
        let ss_decaps = keypair.decapsulate::<MlKem768>(&ciphertext);

        assert_eq!(ss_encaps, ss_decaps, "Shared secrets must match");
    }
}

#[test]
fn test_encaps_decaps_correctness_mlkem1024() {
    for _ in 0..10 {
        let keypair = KeyPair::generate::<MlKem1024>();
        let (ciphertext, ss_encaps) = keypair.encapsulate::<MlKem1024>();
        let ss_decaps = keypair.decapsulate::<MlKem1024>(&ciphertext);

        assert_eq!(ss_encaps, ss_decaps, "Shared secrets must match");
    }
}

#[test]
fn test_deterministic_keygen() {
    let seed = [0x42u8; 32];

    let kp1 = KeyPair::from_seed::<MlKem768>(&seed);
    let kp2 = KeyPair::from_seed::<MlKem768>(&seed);

    assert_eq!(
        kp1.encapsulation_key(),
        kp2.encapsulation_key(),
        "Same seed should produce same encapsulation key"
    );
    assert_eq!(
        kp1.decapsulation_key(),
        kp2.decapsulation_key(),
        "Same seed should produce same decapsulation key"
    );
}

#[test]
fn test_different_seeds_produce_different_keys() {
    let seed1 = [0x11u8; 32];
    let seed2 = [0x22u8; 32];

    let kp1 = KeyPair::from_seed::<MlKem768>(&seed1);
    let kp2 = KeyPair::from_seed::<MlKem768>(&seed2);

    assert_ne!(
        kp1.encapsulation_key(),
        kp2.encapsulation_key(),
        "Different seeds should produce different keys"
    );
}

#[test]
fn test_key_sizes() {
    let kp512 = KeyPair::generate::<MlKem512>();
    assert_eq!(kp512.encapsulation_key().len(), 800);
    assert_eq!(kp512.decapsulation_key().len(), 1632);

    let kp768 = KeyPair::generate::<MlKem768>();
    assert_eq!(kp768.encapsulation_key().len(), 1184);
    assert_eq!(kp768.decapsulation_key().len(), 2400);

    let kp1024 = KeyPair::generate::<MlKem1024>();
    assert_eq!(kp1024.encapsulation_key().len(), 1568);
    assert_eq!(kp1024.decapsulation_key().len(), 3168);
}

#[test]
fn test_ciphertext_sizes() {
    let kp512 = KeyPair::generate::<MlKem512>();
    let (ct512, _) = kp512.encapsulate::<MlKem512>();
    assert_eq!(ct512.len(), 768);

    let kp768 = KeyPair::generate::<MlKem768>();
    let (ct768, _) = kp768.encapsulate::<MlKem768>();
    assert_eq!(ct768.len(), 1088);

    let kp1024 = KeyPair::generate::<MlKem1024>();
    let (ct1024, _) = kp1024.encapsulate::<MlKem1024>();
    assert_eq!(ct1024.len(), 1568);
}

#[test]
fn test_shared_secret_size() {
    let keypair = KeyPair::generate::<MlKem768>();
    let (_, ss) = keypair.encapsulate::<MlKem768>();
    assert_eq!(ss.len(), 32, "Shared secret must be 32 bytes");
}

#[test]
fn test_multiple_encapsulations_produce_different_ciphertexts() {
    let keypair = KeyPair::generate::<MlKem768>();

    let (ct1, ss1) = keypair.encapsulate::<MlKem768>();
    let (ct2, ss2) = keypair.encapsulate::<MlKem768>();

    // Different encapsulations should produce different ciphertexts
    assert_ne!(ct1, ct2);

    // But both should decapsulate correctly
    let ss1_decaps = keypair.decapsulate::<MlKem768>(&ct1);
    let ss2_decaps = keypair.decapsulate::<MlKem768>(&ct2);

    assert_eq!(ss1, ss1_decaps);
    assert_eq!(ss2, ss2_decaps);
}

#[test]
fn test_wrong_key_produces_different_shared_secret() {
    let kp1 = KeyPair::generate::<MlKem768>();
    let kp2 = KeyPair::generate::<MlKem768>();

    let (ct, ss1) = kp1.encapsulate::<MlKem768>();
    let ss2 = kp2.decapsulate::<MlKem768>(&ct);

    // Decapsulating with wrong key should produce different shared secret
    assert_ne!(ss1, ss2);
}

#[test]
fn test_corrupted_ciphertext_produces_different_shared_secret() {
    let keypair = KeyPair::generate::<MlKem768>();
    let (mut ct, ss_original) = keypair.encapsulate::<MlKem768>();

    // Corrupt the ciphertext
    ct[0] ^= 0x01;

    let ss_corrupted = keypair.decapsulate::<MlKem768>(&ct);

    // Corrupted ciphertext should produce different shared secret (implicit rejection)
    assert_ne!(ss_original, ss_corrupted);
}

#[test]
fn test_implicit_rejection_is_deterministic() {
    let keypair = KeyPair::generate::<MlKem768>();
    let (mut ct, _) = keypair.encapsulate::<MlKem768>();

    // Corrupt the ciphertext
    ct[10] ^= 0xFF;

    let ss1 = keypair.decapsulate::<MlKem768>(&ct);
    let ss2 = keypair.decapsulate::<MlKem768>(&ct);

    // Same corrupted ciphertext should produce same shared secret
    assert_eq!(ss1, ss2);
}
