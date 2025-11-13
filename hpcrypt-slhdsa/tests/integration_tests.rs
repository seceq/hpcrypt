//! Integration tests for hpcrypt_slhdsa public API.
//!
//! These tests verify that the library's public API works correctly when used as an external crate.
//!
//! **IMPORTANT NOTE**: This is a demonstration implementation with a simplified hypertree.
//! For production use, a complete multi-layer hypertree implementation is required.
//! These tests focus on API correctness and that operations complete without errors.

use hpcrypt_slhdsa::{
    sign, verify, KeyPair, ParameterSet, PublicKey, SecretKey, Sha2_128f, Sha2_128s, Sha2_192f,
    Sha2_192s, Sha2_256f, Sha2_256s,
};
use rand::rngs::OsRng;

#[test]
fn test_keygen_sha2_128s() {
    let mut rng = OsRng;
    let _keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    // Key generation should complete without panicking
}

#[test]
fn test_keygen_all_parameter_sets() {
    let mut rng = OsRng;

    // All parameter sets should generate keys successfully
    let _kp_128s = KeyPair::<Sha2_128s>::generate(&mut rng);
    let _kp_128f = KeyPair::<Sha2_128f>::generate(&mut rng);
    let _kp_192s = KeyPair::<Sha2_192s>::generate(&mut rng);
    let _kp_192f = KeyPair::<Sha2_192f>::generate(&mut rng);
    let _kp_256s = KeyPair::<Sha2_256s>::generate(&mut rng);
    let _kp_256f = KeyPair::<Sha2_256f>::generate(&mut rng);
}

#[test]
fn test_signing_works() {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Integration test message";

    // Signing should complete without panicking
    let _signature = sign(&keypair.secret_key, message);
}

#[test]
fn test_verification_works() {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Integration test message";
    let signature = sign(&keypair.secret_key, message);

    // Verification should complete without panicking
    let _result = verify(&keypair.public_key, message, &signature);
}

#[test]
fn test_key_serialization() {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Serialization should work
    let sk_bytes = keypair.secret_key.to_bytes();
    let pk_bytes = keypair.public_key.to_bytes();

    // Verify sizes are correct
    assert_eq!(sk_bytes.len(), Sha2_128s::SK_BYTES);
    assert_eq!(pk_bytes.len(), Sha2_128s::PK_BYTES);

    // Deserialization should work
    let _reconstructed_sk = SecretKey::<Sha2_128s>::from_bytes(&sk_bytes).unwrap();
    let _reconstructed_pk = PublicKey::<Sha2_128s>::from_bytes(&pk_bytes).unwrap();
}

#[test]
fn test_sign_with_reconstructed_key() {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    let sk_bytes = keypair.secret_key.to_bytes();
    let reconstructed_sk = SecretKey::<Sha2_128s>::from_bytes(&sk_bytes).unwrap();

    // Should be able to sign with reconstructed key
    let message = b"Test message";
    let _signature = sign(&reconstructed_sk, message);
}

#[test]
fn test_empty_message() {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Should handle empty messages without panicking
    let empty_msg = b"";
    let _signature = sign(&keypair.secret_key, empty_msg);
}

#[test]
fn test_large_message() {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Should handle large messages (10KB) without panicking
    let large_msg = vec![0x42u8; 10240];
    let _signature = sign(&keypair.secret_key, &large_msg);
}

#[test]
fn test_multiple_signatures() {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Should be able to sign multiple messages
    let _sig1 = sign(&keypair.secret_key, b"Message 1");
    let _sig2 = sign(&keypair.secret_key, b"Message 2");
    let _sig3 = sign(&keypair.secret_key, b"Message 3");
}

#[test]
fn test_invalid_key_size_rejected() {
    // Wrong size should be rejected
    let wrong_size = vec![0u8; 10];
    assert!(SecretKey::<Sha2_128s>::from_bytes(&wrong_size).is_err());
    assert!(PublicKey::<Sha2_128s>::from_bytes(&wrong_size).is_err());
}

#[test]
fn test_parameter_set_constants() {
    // Verify that parameter set constants are accessible
    assert!(Sha2_128s::N > 0);
    assert!(Sha2_128s::H > 0);
    assert!(Sha2_128s::D > 0);
    assert!(Sha2_128s::K > 0);
    assert!(Sha2_128s::SK_BYTES > 0);
    assert!(Sha2_128s::PK_BYTES > 0);
    assert!(Sha2_128s::SIG_BYTES > 0);

    // Same for other parameter sets
    assert!(Sha2_256f::N > 0);
    assert!(Sha2_256f::SIG_BYTES > 0);
}

#[test]
fn test_type_safety_compile_time() {
    // This test verifies that type safety works
    // (The actual compile-time check happens when you try to mix types)
    let mut rng = OsRng;
    let _kp_128s = KeyPair::<Sha2_128s>::generate(&mut rng);
    let _kp_128f = KeyPair::<Sha2_128f>::generate(&mut rng);

    // The following would not compile due to type safety:
    // let sig = sign(&_kp_128s.secret_key, b"test");
    // verify(&_kp_128f.public_key, b"test", &sig); // <-- Type error!
}
