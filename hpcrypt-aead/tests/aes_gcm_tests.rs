//! AES-GCM tests

use hpcrypt_aead::aes_gcm::*;

#[test]
fn test_aes128_gcm_encrypt_decrypt() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let plaintext = b"Hello, World!";
    let aad = b"Additional data";

    let ciphertext = aes128_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
    let decrypted = aes128_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_aes256_gcm_encrypt_decrypt() {
    let key = [0u8; 32];
    let nonce = [1u8; 12];
    let plaintext = b"Secret message";
    let aad = b"";

    let ciphertext = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
    let decrypted = aes256_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_aes_gcm_authentication_failure() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let plaintext = b"Test";
    let aad = b"AAD";

    let mut ciphertext = aes128_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();

    // Tamper with ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 1;
    }

    // Should fail authentication
    let result = aes128_gcm_decrypt(&key, &nonce, &ciphertext, aad);
    assert!(result.is_err());
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    let key = [0xAA; 16];
    let nonce = [0xBB; 12];
    let plaintext = b"";
    let aad = b"metadata";

    let ciphertext = aes128_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
    let decrypted = aes128_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}
