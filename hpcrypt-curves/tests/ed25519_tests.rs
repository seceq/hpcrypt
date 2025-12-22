//! Ed25519 tests

use hpcrypt_curves::ed25519::Ed25519;

#[test]
fn test_ed25519_sign_verify() {
    // Create a test keypair (use fixed bytes for determinism in tests)
    let private_key = [42u8; 32];
    let public_key = Ed25519::public_key(&private_key);

    // Test with empty message
    let msg1 = b"";
    let sig1 = Ed25519::sign(&private_key, msg1);
    assert!(
        Ed25519::verify(&public_key, msg1, &sig1),
        "Empty message signature should verify"
    );

    // Test with non-empty message
    let msg2 = b"Hello, Ed25519!";
    let sig2 = Ed25519::sign(&private_key, msg2);
    assert!(
        Ed25519::verify(&public_key, msg2, &sig2),
        "Regular message signature should verify"
    );

    // Signatures should be different
    assert_ne!(
        sig1, sig2,
        "Different messages should produce different signatures"
    );
}

#[test]
fn test_ed25519_verification_failure() {
    let private_key = [42u8; 32];
    let public_key = Ed25519::public_key(&private_key);
    let msg = b"Hello, Ed25519!";
    let sig = Ed25519::sign(&private_key, msg);

    // Wrong message should fail
    assert!(
        !Ed25519::verify(&public_key, b"wrong message", &sig),
        "Signature should not verify for wrong message"
    );

    // Modified signature should fail
    let mut modified_sig = sig;
    modified_sig[0] ^= 1;
    assert!(
        !Ed25519::verify(&public_key, msg, &modified_sig),
        "Modified signature should not verify"
    );

    // Wrong public key should fail
    let wrong_private = [99u8; 32];
    let wrong_public = Ed25519::public_key(&wrong_private);
    assert!(
        !Ed25519::verify(&wrong_public, msg, &sig),
        "Signature should not verify with wrong public key"
    );
}

#[test]
fn test_ed25519_deterministic_signatures() {
    // Test signature is deterministic (RFC 8032 requirement)
    let private_key = [42u8; 32];
    let msg = b"Hello, Ed25519!";

    let sig1 = Ed25519::sign(&private_key, msg);
    let sig2 = Ed25519::sign(&private_key, msg);
    assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
}
