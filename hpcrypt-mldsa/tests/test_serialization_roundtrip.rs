//! Test signature verification after key serialization/deserialization
//!
//! This test specifically checks if signing with a deserialized secret key
//! produces signatures that can be verified.

use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::params::{MlDsa44, MlDsa65, MlDsa87};
use hpcrypt_mldsa::serialize::{
    deserialize_public_key, deserialize_secret_key, serialize_public_key, serialize_secret_key,
};
use hpcrypt_mldsa::sign::sign;
use hpcrypt_mldsa::verify::verify;

#[test]
fn test_mldsa44_sign_verify() {
    println!("\n=== ML-DSA-44: Sign/Verify with Serialization ===");

    // Generate keypair
    let (pk_orig, sk_orig) = keygen::<MlDsa44>();
    println!("✓ Generated ML-DSA-44 keypair");

    // Test message
    let message = b"Test message for ML-DSA-44";

    // === Test 1: Direct sign/verify (no serialization) ===
    let sig_direct = sign(&sk_orig, message).expect("Direct signing failed");
    let valid_direct = verify::<MlDsa44>(&pk_orig, message, &sig_direct);
    println!("Test 1 - Direct sign/verify: {}", valid_direct);
    assert!(valid_direct, "Direct verification should succeed");

    // === Test 2: Sign with original key, verify with deserialized public key ===
    let pk_bytes = serialize_public_key::<MlDsa44>(&pk_orig);
    let pk_deser = deserialize_public_key::<MlDsa44>(&pk_bytes)
        .expect("PK deserialization failed");

    let valid_pk_deser = verify::<MlDsa44>(&pk_deser, message, &sig_direct);
    println!("Test 2 - Verify with deserialized PK: {}", valid_pk_deser);
    assert!(valid_pk_deser, "Verification with deserialized PK should succeed");

    // === Test 3: Sign with deserialized secret key ===
    let sk_bytes = serialize_secret_key::<MlDsa44>(&sk_orig);
    println!("SK size: {} bytes (expected 2560)", sk_bytes.len());
    assert_eq!(sk_bytes.len(), 2560, "SK size mismatch");

    let sk_deser = deserialize_secret_key::<MlDsa44>(&sk_bytes)
        .expect("SK deserialization failed");
    println!("✓ Deserialized secret key");

    let sig_deser = sign(&sk_deser, message).expect("Signing with deserialized SK failed");
    println!("✓ Signed with deserialized SK");

    // Verify with original public key
    let valid_sk_deser = verify::<MlDsa44>(&pk_orig, message, &sig_deser);
    println!("Test 3 - Sign with deserialized SK, verify with original PK: {}", valid_sk_deser);
    assert!(valid_sk_deser, "CRITICAL: Signature from deserialized SK should verify with original PK");

    // === Test 4: Full roundtrip - both keys deserialized ===
    let valid_full = verify::<MlDsa44>(&pk_deser, message, &sig_deser);
    println!("Test 4 - Both keys deserialized: {}", valid_full);
    assert!(valid_full, "Full roundtrip verification should succeed");

    println!("✓ All ML-DSA-44 tests passed\n");
}

#[test]
fn test_mldsa65_sign_verify() {
    println!("\n=== ML-DSA-65: Sign/Verify with Serialization ===");

    let (pk_orig, sk_orig) = keygen::<MlDsa65>();
    let message = b"Test message for ML-DSA-65";

    // Direct test
    let sig_direct = sign(&sk_orig, message).expect("Direct signing failed");
    assert!(verify::<MlDsa65>(&pk_orig, message, &sig_direct), "Direct verification failed");

    // Serialize and deserialize
    let sk_bytes = serialize_secret_key::<MlDsa65>(&sk_orig);
    let pk_bytes = serialize_public_key::<MlDsa65>(&pk_orig);

    assert_eq!(sk_bytes.len(), 4032, "SK size mismatch");
    assert_eq!(pk_bytes.len(), 1952, "PK size mismatch");

    let sk_deser = deserialize_secret_key::<MlDsa65>(&sk_bytes).expect("SK deser failed");
    let pk_deser = deserialize_public_key::<MlDsa65>(&pk_bytes).expect("PK deser failed");

    // Sign with deserialized key
    let sig_deser = sign(&sk_deser, message).expect("Signing with deserialized SK failed");

    // Verify
    assert!(
        verify::<MlDsa65>(&pk_orig, message, &sig_deser),
        "CRITICAL: Signature from deserialized SK should verify"
    );
    assert!(
        verify::<MlDsa65>(&pk_deser, message, &sig_deser),
        "Full roundtrip verification failed"
    );

    println!("✓ All ML-DSA-65 tests passed\n");
}

#[test]
fn test_mldsa87_sign_verify() {
    println!("\n=== ML-DSA-87: Sign/Verify with Serialization ===");

    let (pk_orig, sk_orig) = keygen::<MlDsa87>();
    let message = b"Test message for ML-DSA-87";

    // Direct test
    let sig_direct = sign(&sk_orig, message).expect("Direct signing failed");
    assert!(verify::<MlDsa87>(&pk_orig, message, &sig_direct), "Direct verification failed");

    // Serialize and deserialize
    let sk_bytes = serialize_secret_key::<MlDsa87>(&sk_orig);
    let pk_bytes = serialize_public_key::<MlDsa87>(&pk_orig);

    assert_eq!(sk_bytes.len(), 4896, "SK size mismatch");
    assert_eq!(pk_bytes.len(), 2592, "PK size mismatch");

    let sk_deser = deserialize_secret_key::<MlDsa87>(&sk_bytes).expect("SK deser failed");
    let pk_deser = deserialize_public_key::<MlDsa87>(&pk_bytes).expect("PK deser failed");

    // Sign with deserialized key
    let sig_deser = sign(&sk_deser, message).expect("Signing with deserialized SK failed");

    // Verify
    assert!(
        verify::<MlDsa87>(&pk_orig, message, &sig_deser),
        "CRITICAL: Signature from deserialized SK should verify"
    );
    assert!(
        verify::<MlDsa87>(&pk_deser, message, &sig_deser),
        "Full roundtrip verification failed"
    );

    println!("✓ All ML-DSA-87 tests passed\n");
}
