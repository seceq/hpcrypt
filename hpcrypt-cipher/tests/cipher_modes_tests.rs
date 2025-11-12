//! Cipher modes tests

use hpcrypt_cipher::aes_modes::*;

#[test]
fn test_aes128_cbc_encrypt_decrypt() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let plaintext = b"Block cipher test message here!!!!";

    let ciphertext = aes128_cbc_encrypt(&key, &iv, plaintext).unwrap();
    let decrypted = aes128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_aes256_cbc_encrypt_decrypt() {
    let key = [0u8; 32];
    let iv = [1u8; 16];
    let plaintext = b"AES-256 CBC mode encryption test!!";

    let ciphertext = aes256_cbc_encrypt(&key, &iv, plaintext).unwrap();
    let decrypted = aes256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_aes128_ctr_encrypt_decrypt() {
    let key = [0xAA; 16];
    let nonce = [0xBB; 16];
    let plaintext = b"Counter mode is a stream cipher";

    let ciphertext = aes128_ctr_encrypt(&key, &nonce, plaintext).unwrap();
    let decrypted = aes128_ctr_decrypt(&key, &nonce, &ciphertext).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_aes_ctr_symmetry() {
    // CTR mode encryption and decryption are the same operation
    let key = [0x42; 16];
    let nonce = [0x99; 16];
    let plaintext = b"CTR mode test data";

    let ciphertext = aes128_ctr_encrypt(&key, &nonce, plaintext).unwrap();
    let re_encrypted = aes128_ctr_encrypt(&key, &nonce, &ciphertext).unwrap();

    // Encrypting ciphertext should give back plaintext
    assert_eq!(plaintext, &re_encrypted[..]);
}

#[test]
fn test_aes_cbc_different_ivs() {
    let key = [0x55; 16];
    let iv1 = [0x00; 16];
    let iv2 = [0xFF; 16];
    let plaintext = b"Test with different IVs!!!!!!!!!";

    let ciphertext1 = aes128_cbc_encrypt(&key, &iv1, plaintext).unwrap();
    let ciphertext2 = aes128_cbc_encrypt(&key, &iv2, plaintext).unwrap();

    // Different IVs should produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_aes_cbc_padding() {
    let key = [0x77; 16];
    let iv = [0x88; 16];

    // Test various plaintext lengths that require different padding
    for len in [1, 15, 16, 17, 31, 32] {
        let plaintext = vec![0x99u8; len];
        let ciphertext = aes128_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let decrypted = aes128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted, "Failed for length {}", len);
    }
}

#[test]
fn test_aes_ctr_no_padding_required() {
    let key = [0x11; 16];
    let nonce = [0x22; 16];

    // CTR mode doesn't require padding
    for len in [1, 7, 15, 16, 17, 31, 32, 33] {
        let plaintext = vec![0xAAu8; len];
        let ciphertext = aes128_ctr_encrypt(&key, &nonce, &plaintext).unwrap();

        // Ciphertext should be same length as plaintext
        assert_eq!(ciphertext.len(), len, "Failed for length {}", len);

        let decrypted = aes128_ctr_decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
