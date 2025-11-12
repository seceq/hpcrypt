//! ECIES integration tests

use hpcrypt_ecies::p256::*;

#[test]
fn test_p256_ecies_encrypt_decrypt() {
    let (private_key, public_key) = generate_keypair();
    let plaintext = b"ECIES test message";

    let ciphertext = encrypt(&public_key, plaintext).unwrap();
    let decrypted = decrypt(&private_key, &ciphertext).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_p256_ecies_empty_message() {
    let (private_key, public_key) = generate_keypair();
    let plaintext = b"";

    let ciphertext = encrypt(&public_key, plaintext).unwrap();
    let decrypted = decrypt(&private_key, &ciphertext).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_p256_ecies_large_message() {
    let (private_key, public_key) = generate_keypair();
    let plaintext = vec![0x42; 1024];

    let ciphertext = encrypt(&public_key, &plaintext).unwrap();
    let decrypted = decrypt(&private_key, &ciphertext).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_p256_ecies_wrong_key_fails() {
    let (_, public_key1) = generate_keypair();
    let (private_key2, _) = generate_keypair();
    let plaintext = b"Test";

    let ciphertext = encrypt(&public_key1, plaintext).unwrap();

    // Decryption with wrong private key should fail
    let result = decrypt(&private_key2, &ciphertext);
    assert!(result.is_err() || result.unwrap() != plaintext);
}

#[test]
fn test_p256_ecies_tampering_fails() {
    let (private_key, public_key) = generate_keypair();
    let plaintext = b"Authenticated message";

    let mut ciphertext = encrypt(&public_key, plaintext).unwrap();

    // Tamper with ciphertext
    if !ciphertext.is_empty() {
        ciphertext[ciphertext.len() / 2] ^= 1;
    }

    // Should fail to decrypt or produce wrong plaintext
    let result = decrypt(&private_key, &ciphertext);
    assert!(result.is_err() || result.unwrap() != plaintext);
}

#[test]
fn test_p256_ecies_deterministic_keys_different_ciphertexts() {
    let (private_key, public_key) = generate_keypair();
    let plaintext = b"Same message";

    // Encrypt same message twice
    let ciphertext1 = encrypt(&public_key, plaintext).unwrap();
    let ciphertext2 = encrypt(&public_key, plaintext).unwrap();

    // Ciphertexts should be different (due to random ephemeral key)
    assert_ne!(ciphertext1, ciphertext2);

    // But both should decrypt correctly
    let decrypted1 = decrypt(&private_key, &ciphertext1).unwrap();
    let decrypted2 = decrypt(&private_key, &ciphertext2).unwrap();

    assert_eq!(plaintext, &decrypted1[..]);
    assert_eq!(plaintext, &decrypted2[..]);
}
