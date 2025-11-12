//! Integration tests for the umbrella hpcrypt crate

#[cfg(feature = "full")]
#[test]
fn test_umbrella_crate_imports() {
    // Test that all sub-crates are accessible through the umbrella crate
    use hpcrypt::prelude::*;

    // Hash function should be available
    let mut hasher = Sha256::new();
    hasher.update(b"test");
    let _hash = hasher.finalize();

    // RNG should be available
    let _key: [u8; 32] = hpcrypt::rng::generate_key().expect("RNG failed");
}

#[cfg(feature = "pq-kem")]
#[test]
fn test_mlkem_through_umbrella() {
    use hpcrypt::mlkem::{KeyPair, MlKem768};

    let keypair = KeyPair::generate::<MlKem768>();
    let (ciphertext, shared_secret_alice) = keypair.encapsulate::<MlKem768>();
    let shared_secret_bob = keypair.decapsulate::<MlKem768>(&ciphertext);

    assert_eq!(shared_secret_alice, shared_secret_bob);
}

#[cfg(all(feature = "curves", feature = "signatures"))]
#[test]
fn test_ecdsa_through_umbrella() {
    use hpcrypt::signatures::ecdsa::{EcdsaP256, SigningKey};

    let signing_key = SigningKey::<EcdsaP256>::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message";
    let signature = signing_key.sign(message);

    assert!(verifying_key.verify(message, &signature).is_ok());
}

#[test]
fn test_hash_through_umbrella() {
    use hpcrypt::hash::{Digest, Sha256, Sha512};

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

#[test]
fn test_rng_through_umbrella() {
    use hpcrypt::rng::*;

    let key: [u8; 32] = generate_key().expect("RNG failed");
    assert_ne!(key, [0u8; 32]);

    let nonce: [u8; 12] = generate_nonce().expect("RNG failed");
    assert_ne!(nonce, [0u8; 12]);

    let salt: [u8; 16] = generate_salt().expect("RNG failed");
    assert_ne!(salt, [0u8; 16]);
}

#[cfg(feature = "curves")]
#[test]
fn test_curves_through_umbrella() {
    use hpcrypt::curves::x25519::*;

    let (private_key, public_key) = generate_keypair();
    assert_eq!(private_key.len(), 32);
    assert_eq!(public_key.len(), 32);
}

#[test]
fn test_prelude_imports() {
    use hpcrypt::prelude::*;

    // Digest trait should be in scope
    let mut hasher = Sha256::new();
    hasher.update(b"prelude test");
    let _result = hasher.finalize();

    // MlKemKeyPair should be in scope if feature enabled
    #[cfg(feature = "pq-kem")]
    {
        let _keypair = MlKemKeyPair::generate::<MlKem768>();
    }
}

#[test]
fn test_core_utilities() {
    use hpcrypt::core::ct::*;

    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    assert!(ct_eq(&a, &b));

    let c = [1u8, 2, 3, 5];
    assert!(!ct_eq(&a, &c));
}
