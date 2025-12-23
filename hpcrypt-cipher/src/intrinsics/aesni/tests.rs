//! Tests for AES-NI implementation.

use super::*;
use crate::aes_fixslice::AesFixslice;
use crate::intrinsics::has_aesni;

const AES128_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const AES128_PLAINTEXT: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const AES128_CIPHERTEXT: [u8; 16] = [
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
];

#[test]
fn test_aes128_encrypt() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi128::new(&AES128_KEY);
        let mut block = AES128_PLAINTEXT;
        cipher.encrypt_block(&mut block);
        assert_eq!(block, AES128_CIPHERTEXT);
    }
}

#[test]
fn test_aes128_decrypt() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi128::new(&AES128_KEY);
        let mut block = AES128_CIPHERTEXT;
        cipher.decrypt_block(&mut block);
        assert_eq!(block, AES128_PLAINTEXT);
    }
}

#[test]
fn test_aes128_roundtrip() {
    if !has_aesni() {
        return;
    }
    let key = [0x42u8; 16];
    let original = [0xabu8; 16];
    unsafe {
        let cipher = AesNi128::new(&key);
        let mut block = original;
        cipher.encrypt_block(&mut block);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, original);
    }
}

#[test]
fn test_aes128_vs_fixslice() {
    if !has_aesni() {
        return;
    }
    let key = [0x13u8; 16];
    let plaintext = [0x42u8; 16];
    let fixslice = AesFixslice::new_128(&key);
    let expected = fixslice.encrypt_block(&plaintext);
    unsafe {
        let aesni = AesNi128::new(&key);
        let mut actual = plaintext;
        aesni.encrypt_block(&mut actual);
        assert_eq!(actual, expected);
    }
}

#[test]
fn test_aes192_vs_fixslice() {
    if !has_aesni() {
        return;
    }
    let key = [0u8; 24];
    let plaintext = [
        0xBF, 0xF5, 0x25, 0x10, 0x09, 0x5F, 0x51, 0x8E,
        0xCC, 0xA6, 0x0A, 0xF4, 0x20, 0x54, 0x44, 0xBB,
    ];
    // Expected from NIST ACVP: 4A3650C3371CE2EB35E389A171427440
    let expected_ct = [
        0x4A, 0x36, 0x50, 0xC3, 0x37, 0x1C, 0xE2, 0xEB,
        0x35, 0xE3, 0x89, 0xA1, 0x71, 0x42, 0x74, 0x40,
    ];

    let fixslice = AesFixslice::new_192(&key);
    let fixslice_ct = fixslice.encrypt_block(&plaintext);
    assert_eq!(fixslice_ct, expected_ct, "Fixslice should match NIST vector");

    unsafe {
        let aesni = AesNi192::new(&key);
        let mut actual = plaintext;
        aesni.encrypt_block(&mut actual);
        assert_eq!(actual, expected_ct, "AES-NI should match NIST vector");
    }
}

#[test]
fn test_aes256_vs_fixslice() {
    if !has_aesni() {
        return;
    }
    let key = [0x13u8; 32];
    let plaintext = [0x42u8; 16];
    let fixslice = AesFixslice::new_256(&key);
    let expected = fixslice.encrypt_block(&plaintext);
    unsafe {
        let aesni = AesNi256::new(&key);
        let mut actual = plaintext;
        aesni.encrypt_block(&mut actual);
        assert_eq!(actual, expected);
    }
}
