//! RSA integration tests

use hpcrypt_rsa::{oaep::*, pkcs1v15::*, pss::*, *};

#[test]
fn test_rsa_2048_generate_keypair() {
    let private_key = RsaPrivateKey::generate(2048).unwrap();

    assert_eq!(private_key.size(), 2048);
    assert_eq!(private_key.size_bytes(), 256);
}

#[test]
fn test_rsa_pkcs1v15_encrypt_decrypt() {
    let private_key = RsaPrivateKey::generate(2048).unwrap();
    let public_key = private_key.public_key();
    let message = b"RSA PKCS#1 v1.5 test";

    let ciphertext = encrypt_pkcs1v15(public_key, message).unwrap();
    let decrypted = decrypt_pkcs1v15(&private_key, &ciphertext).unwrap();

    assert_eq!(message, &decrypted[..]);
}

#[cfg(feature = "sha2")]
#[test]
fn test_rsa_oaep_encrypt_decrypt() {
    use hpcrypt_rsa::oaep::Sha256;

    let private_key = RsaPrivateKey::generate(2048).unwrap();
    let public_key = private_key.public_key();
    let message = b"RSA-OAEP test message";

    let ciphertext = encrypt_oaep::<Sha256>(public_key, message, b"").unwrap();
    let decrypted = decrypt_oaep::<Sha256>(&private_key, &ciphertext, b"").unwrap();

    assert_eq!(message, &decrypted[..]);
}

#[cfg(feature = "sha2")]
#[test]
fn test_rsa_sign_verify_pkcs1v15() {
    let private_key = RsaPrivateKey::generate(2048).unwrap();
    let public_key = private_key.public_key();
    let message = b"Message to sign";

    // Hash the message first using sha2 crate directly
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(message);
    let digest = hasher.finalize();

    // Create DigestInfo for PKCS#1 v1.5 signing
    let digest_info = create_digest_info(HashAlgorithm::Sha256, &digest);

    let signature = sign_pkcs1v15(&private_key, &digest_info).unwrap();
    let result = verify_pkcs1v15(public_key, &digest_info, &signature);

    assert!(result.is_ok());
}

#[cfg(feature = "sha2")]
#[test]
fn test_rsa_sign_verify_pss() {
    use hpcrypt_rsa::pss::Sha256;

    let private_key = RsaPrivateKey::generate(2048).unwrap();
    let public_key = private_key.public_key();
    let message = b"PSS signature test";

    let signature = sign_pss::<Sha256>(&private_key, message, 32).unwrap();
    let result = verify_pss::<Sha256>(public_key, message, &signature, 32);

    assert!(result.is_ok());
}

#[test]
fn test_rsa_wrong_key_decrypt_fails() {
    let private_key1 = RsaPrivateKey::generate(2048).unwrap();
    let public_key1 = private_key1.public_key();
    let private_key2 = RsaPrivateKey::generate(2048).unwrap();
    let message = b"Test";

    let ciphertext = encrypt_pkcs1v15(public_key1, message).unwrap();
    let result = decrypt_pkcs1v15(&private_key2, &ciphertext);

    assert!(result.is_err());
}

#[cfg(feature = "sha2")]
#[test]
fn test_rsa_wrong_message_verify_fails() {
    use sha2::{Digest, Sha256};

    let private_key = RsaPrivateKey::generate(2048).unwrap();
    let public_key = private_key.public_key();
    let message1 = b"Original message";
    let message2 = b"Different message";

    // Hash message1
    let mut hasher = Sha256::new();
    hasher.update(message1);
    let digest1 = hasher.finalize();
    let digest_info1 = create_digest_info(HashAlgorithm::Sha256, &digest1);

    // Hash message2
    let mut hasher = Sha256::new();
    hasher.update(message2);
    let digest2 = hasher.finalize();
    let digest_info2 = create_digest_info(HashAlgorithm::Sha256, &digest2);

    let signature = sign_pkcs1v15(&private_key, &digest_info1).unwrap();
    let result = verify_pkcs1v15(public_key, &digest_info2, &signature);

    assert!(result.is_err());
}

#[test]
fn test_rsa_3072_keygen() {
    let private_key = RsaPrivateKey::generate(3072).unwrap();
    assert_eq!(private_key.size(), 3072);
}

#[test]
fn test_rsa_4096_keygen() {
    let private_key = RsaPrivateKey::generate(4096).unwrap();
    assert_eq!(private_key.size(), 4096);
}
