//! ChaCha20-Poly1305 tests

use hpcrypt_aead::ChaCha20Poly1305;

#[test]
fn test_chacha20poly1305_encrypt_decrypt() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"ChaCha20-Poly1305 test";
    let aad = b"Associated";

    let ciphertext = ChaCha20Poly1305::encrypt(&key, &nonce, plaintext, aad);
    let decrypted = ChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_chacha20poly1305_authentication_failure() {
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let plaintext = b"Authenticated";
    let aad = b"";

    let mut ciphertext = ChaCha20Poly1305::encrypt(&key, &nonce, plaintext, aad);

    // Tamper with tag
    let len = ciphertext.len();
    if len > 0 {
        ciphertext[len - 1] ^= 1;
    }

    let result = ChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext, aad);
    assert!(result.is_none());
}

#[test]
fn test_chacha20poly1305_different_keys() {
    let key1 = [0u8; 32];
    let key2 = [1u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"Test message";
    let aad = b"";

    let ciphertext = ChaCha20Poly1305::encrypt(&key1, &nonce, plaintext, aad);

    // Decryption with wrong key should fail
    let result = ChaCha20Poly1305::decrypt(&key2, &nonce, &ciphertext, aad);
    assert!(result.is_none());
}
