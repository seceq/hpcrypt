//! Integration tests for the umbrella hpcrypt crate

#[cfg(feature = "hash")]
#[test]
fn test_umbrella_hash_imports() {
    // Test that hash sub-crate is accessible through the umbrella crate
    use hpcrypt::hash::Sha256;

    // Hash function should be available
    let mut hasher = Sha256::new();
    hasher.update(b"test");
    let _hash = hasher.finalize();
}

#[cfg(all(feature = "curves", feature = "signatures"))]
#[test]
fn test_ecdsa_through_umbrella() {
    use hpcrypt::signatures::ecdsa::SigningKey;

    let signing_key = SigningKey::generate().expect("Failed to generate signing key");
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message";
    let signature = signing_key.sign(message);

    assert!(verifying_key.verify(message, &signature));
}

#[cfg(feature = "hash")]
#[test]
fn test_hash_operations() {
    use hpcrypt::hash::{Sha256, Sha512};

    // SHA-256
    let mut hasher = Sha256::new();
    hasher.update(b"hello");
    let hash256 = hasher.finalize();
    assert_eq!(hash256.len(), 32);

    // SHA-512
    let mut hasher = Sha512::new();
    hasher.update(b"world");
    let hash512 = hasher.finalize();
    assert_eq!(hash512.len(), 64);
}

#[cfg(feature = "curves")]
#[test]
fn test_curves_through_umbrella() {
    use hpcrypt::curves::X25519;

    // Test that curves module is accessible
    let private_key = [1u8; 32];
    let public_key = X25519::public_key(&private_key);
    assert_eq!(public_key.len(), 32);
}
