//! RSA integration tests

use hpcrypt_rsa::*;

#[test]
fn test_rsa_2048_generate_keypair() {
    let keypair = generate_keypair(2048).unwrap();

    assert_eq!(keypair.public_key().bit_length(), 2048);
    assert!(keypair.private_key().is_valid());
}

#[test]
fn test_rsa_pkcs1v15_encrypt_decrypt() {
    let keypair = generate_keypair(2048).unwrap();
    let message = b"RSA PKCS#1 v1.5 test";

    let ciphertext = pkcs1v15_encrypt(keypair.public_key(), message).unwrap();
    let decrypted = pkcs1v15_decrypt(keypair.private_key(), &ciphertext).unwrap();

    assert_eq!(message, &decrypted[..]);
}

#[test]
fn test_rsa_oaep_encrypt_decrypt() {
    let keypair = generate_keypair(2048).unwrap();
    let message = b"RSA-OAEP test message";

    let ciphertext = oaep_encrypt(keypair.public_key(), message).unwrap();
    let decrypted = oaep_decrypt(keypair.private_key(), &ciphertext).unwrap();

    assert_eq!(message, &decrypted[..]);
}

#[test]
fn test_rsa_sign_verify_pkcs1v15() {
    let keypair = generate_keypair(2048).unwrap();
    let message = b"Message to sign";

    let signature = pkcs1v15_sign(keypair.private_key(), message).unwrap();
    let result = pkcs1v15_verify(keypair.public_key(), message, &signature);

    assert!(result.is_ok());
}

#[test]
fn test_rsa_sign_verify_pss() {
    let keypair = generate_keypair(2048).unwrap();
    let message = b"PSS signature test";

    let signature = pss_sign(keypair.private_key(), message).unwrap();
    let result = pss_verify(keypair.public_key(), message, &signature);

    assert!(result.is_ok());
}

#[test]
fn test_rsa_wrong_key_decrypt_fails() {
    let keypair1 = generate_keypair(2048).unwrap();
    let keypair2 = generate_keypair(2048).unwrap();
    let message = b"Test";

    let ciphertext = pkcs1v15_encrypt(keypair1.public_key(), message).unwrap();
    let result = pkcs1v15_decrypt(keypair2.private_key(), &ciphertext);

    assert!(result.is_err());
}

#[test]
fn test_rsa_wrong_message_verify_fails() {
    let keypair = generate_keypair(2048).unwrap();
    let message1 = b"Original message";
    let message2 = b"Different message";

    let signature = pkcs1v15_sign(keypair.private_key(), message1).unwrap();
    let result = pkcs1v15_verify(keypair.public_key(), message2, &signature);

    assert!(result.is_err());
}

#[test]
fn test_rsa_3072_keygen() {
    let keypair = generate_keypair(3072).unwrap();
    assert_eq!(keypair.public_key().bit_length(), 3072);
}

#[test]
fn test_rsa_4096_keygen() {
    let keypair = generate_keypair(4096).unwrap();
    assert_eq!(keypair.public_key().bit_length(), 4096);
}
