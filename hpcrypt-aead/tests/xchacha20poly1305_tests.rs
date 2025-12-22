//! XChaCha20-Poly1305 tests

use hpcrypt_aead::chacha20poly1305::XChaCha20Poly1305;

#[test]
fn test_xchacha20poly1305_encrypt_decrypt() {
    let key = [0u8; 32];
    let nonce = [0u8; 24]; // 24 bytes for XChaCha20

    // Test with empty message
    let ciphertext1 = XChaCha20Poly1305::encrypt(&key, &nonce, b"", b"");
    assert_eq!(
        ciphertext1.len(),
        16,
        "Empty message should produce 16-byte tag only"
    );

    let decrypted1 = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext1, b"");
    assert_eq!(
        decrypted1,
        Some(vec![]),
        "Decryption of empty message should succeed"
    );

    // Test with non-empty message
    let msg = b"Hello, XChaCha20-Poly1305!";
    let ciphertext2 = XChaCha20Poly1305::encrypt(&key, &nonce, msg, b"");
    assert_eq!(
        ciphertext2.len(),
        msg.len() + 16,
        "Ciphertext should be plaintext + 16-byte tag"
    );

    let decrypted2 = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext2, b"");
    assert_eq!(
        decrypted2,
        Some(msg.to_vec()),
        "Decryption should recover plaintext"
    );
}

#[test]
fn test_xchacha20poly1305_with_aad() {
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let msg = b"Hello, XChaCha20-Poly1305!";
    let aad = b"additional authenticated data";

    let ciphertext = XChaCha20Poly1305::encrypt(&key, &nonce, msg, aad);

    let decrypted = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext, aad);
    assert_eq!(
        decrypted,
        Some(msg.to_vec()),
        "Decryption with AAD should succeed"
    );

    // Wrong AAD should fail
    let decrypted_wrong = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext, b"wrong aad");
    assert_eq!(decrypted_wrong, None, "Decryption with wrong AAD should fail");
}

#[test]
fn test_xchacha20poly1305_authentication_failure() {
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let msg = b"Hello, XChaCha20-Poly1305!";

    let ciphertext = XChaCha20Poly1305::encrypt(&key, &nonce, msg, b"");

    // Modified ciphertext should fail
    let mut modified = ciphertext.clone();
    modified[0] ^= 1;
    let decrypted = XChaCha20Poly1305::decrypt(&key, &nonce, &modified, b"");
    assert_eq!(
        decrypted, None,
        "Decryption of modified ciphertext should fail"
    );

    // Modified tag should fail
    let mut modified_tag = ciphertext.clone();
    let len = modified_tag.len();
    modified_tag[len - 1] ^= 1;
    let decrypted_tag = XChaCha20Poly1305::decrypt(&key, &nonce, &modified_tag, b"");
    assert_eq!(decrypted_tag, None, "Decryption with modified tag should fail");
}
