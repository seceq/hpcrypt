//! CMAC tests

use hpcrypt_mac::{aes_cmac_128, aes_cmac_256};

#[test]
fn test_cmac_aes128_basic() {
    let key = [0u8; 16];
    let message = b"Test message";

    let tag = aes_cmac_128(&key, message);

    // Tag should be 16 bytes
    assert_eq!(tag.len(), 16);

    // Tag should not be all zeros
    assert_ne!(tag, [0u8; 16]);
}

#[test]
fn test_cmac_aes128_empty_message() {
    let key = [0xAA; 16];
    let message = b"";

    let tag = aes_cmac_128(&key, message);
    assert_eq!(tag.len(), 16);
}

#[test]
fn test_cmac_aes128_deterministic() {
    let key = [0x42; 16];
    let message = b"Deterministic test";

    let tag1 = aes_cmac_128(&key, message);
    let tag2 = aes_cmac_128(&key, message);

    // Same input should produce same tag
    assert_eq!(tag1, tag2);
}

#[test]
fn test_cmac_aes128_different_messages() {
    let key = [0x55; 16];

    let tag1 = aes_cmac_128(&key, b"Message 1");
    let tag2 = aes_cmac_128(&key, b"Message 2");

    // Different messages should produce different tags
    assert_ne!(tag1, tag2);
}

#[test]
fn test_cmac_aes128_different_keys() {
    let key1 = [0x00; 16];
    let key2 = [0xFF; 16];
    let message = b"Same message";

    let tag1 = aes_cmac_128(&key1, message);
    let tag2 = aes_cmac_128(&key2, message);

    // Different keys should produce different tags
    assert_ne!(tag1, tag2);
}

#[test]
fn test_cmac_aes256_basic() {
    let key = [0u8; 32];
    let message = b"AES-256 CMAC test";

    let tag = aes_cmac_256(&key, message);
    assert_eq!(tag.len(), 16);
    assert_ne!(tag, [0u8; 16]);
}

#[test]
fn test_cmac_various_message_lengths() {
    let key = [0x77; 16];

    for len in [0, 1, 15, 16, 17, 31, 32, 33, 64, 128] {
        let message = vec![0x99u8; len];
        let tag = aes_cmac_128(&key, &message);
        assert_eq!(tag.len(), 16, "Failed for message length {}", len);
    }
}
