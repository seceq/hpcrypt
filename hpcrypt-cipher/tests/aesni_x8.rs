//! Unit tests for AES-NI 8-block parallel operations.
//!
//! Tests that encrypt_8_blocks/decrypt_8_blocks produce the same results
//! as calling encrypt_block/decrypt_block 8 times individually.

#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]

use hpcrypt_cipher::intrinsics::{has_aesni, AesNi128, AesNi192, AesNi256};

const TEST_KEY_128: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

const TEST_KEY_192: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
];

const TEST_KEY_256: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn make_test_blocks() -> [[u8; 16]; 8] {
    [
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00],
        [0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0x01],
        [0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0x02],
        [0x04, 0x15, 0x26, 0x37, 0x48, 0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0x03],
        [0x05, 0x16, 0x27, 0x38, 0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xc0, 0xc1, 0xd2, 0xe3, 0x04],
        [0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0, 0xc1, 0xc2, 0xd3, 0xe4, 0x05],
        [0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0xa0, 0xa1, 0xc2, 0xc3, 0xd4, 0xe5, 0x06],
    ]
}

#[test]
fn test_aes128_encrypt_8_blocks_vs_single() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        // Encrypt 8 blocks in parallel
        let mut parallel = original;
        cipher.encrypt_8_blocks(&mut parallel);

        // Encrypt each block individually
        let mut individual = original;
        for block in individual.iter_mut() {
            cipher.encrypt_block(block);
        }

        // Results must match
        assert_eq!(parallel, individual, "8-block parallel encrypt must match individual encrypts");
    }
}

#[test]
fn test_aes128_decrypt_8_blocks_vs_single() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        // Encrypt first to get ciphertext
        let mut ciphertext = original;
        cipher.encrypt_8_blocks(&mut ciphertext);

        // Decrypt 8 blocks in parallel
        let mut parallel = ciphertext;
        cipher.decrypt_8_blocks(&mut parallel);

        // Decrypt each block individually
        let mut individual = ciphertext;
        for block in individual.iter_mut() {
            cipher.decrypt_block(block);
        }

        // Results must match
        assert_eq!(parallel, individual, "8-block parallel decrypt must match individual decrypts");
        assert_eq!(parallel, original, "Decrypt must recover original plaintext");
    }
}

#[test]
fn test_aes128_8_blocks_roundtrip() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        let mut blocks = original;
        cipher.encrypt_8_blocks(&mut blocks);
        cipher.decrypt_8_blocks(&mut blocks);

        assert_eq!(blocks, original, "Roundtrip must recover original");
    }
}

#[test]
fn test_aes192_encrypt_8_blocks_vs_single() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        // Encrypt 8 blocks in parallel
        let mut parallel = original;
        cipher.encrypt_8_blocks(&mut parallel);

        // Encrypt each block individually
        let mut individual = original;
        for block in individual.iter_mut() {
            cipher.encrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-192: 8-block parallel encrypt must match individual encrypts");
    }
}

#[test]
fn test_aes192_decrypt_8_blocks_vs_single() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        // Encrypt first to get ciphertext
        let mut ciphertext = original;
        cipher.encrypt_8_blocks(&mut ciphertext);

        // Decrypt 8 blocks in parallel
        let mut parallel = ciphertext;
        cipher.decrypt_8_blocks(&mut parallel);

        // Decrypt each block individually
        let mut individual = ciphertext;
        for block in individual.iter_mut() {
            cipher.decrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-192: 8-block parallel decrypt must match individual decrypts");
        assert_eq!(parallel, original, "AES-192: Decrypt must recover original plaintext");
    }
}

#[test]
fn test_aes192_8_blocks_roundtrip() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        let mut blocks = original;
        cipher.encrypt_8_blocks(&mut blocks);
        cipher.decrypt_8_blocks(&mut blocks);

        assert_eq!(blocks, original, "AES-192: Roundtrip must recover original");
    }
}

#[test]
fn test_aes256_encrypt_8_blocks_vs_single() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        // Encrypt 8 blocks in parallel
        let mut parallel = original;
        cipher.encrypt_8_blocks(&mut parallel);

        // Encrypt each block individually
        let mut individual = original;
        for block in individual.iter_mut() {
            cipher.encrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-256: 8-block parallel encrypt must match individual encrypts");
    }
}

#[test]
fn test_aes256_decrypt_8_blocks_vs_single() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        // Encrypt first to get ciphertext
        let mut ciphertext = original;
        cipher.encrypt_8_blocks(&mut ciphertext);

        // Decrypt 8 blocks in parallel
        let mut parallel = ciphertext;
        cipher.decrypt_8_blocks(&mut parallel);

        // Decrypt each block individually
        let mut individual = ciphertext;
        for block in individual.iter_mut() {
            cipher.decrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-256: 8-block parallel decrypt must match individual decrypts");
        assert_eq!(parallel, original, "AES-256: Decrypt must recover original plaintext");
    }
}

#[test]
fn test_aes256_8_blocks_roundtrip() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        let mut blocks = original;
        cipher.encrypt_8_blocks(&mut blocks);
        cipher.decrypt_8_blocks(&mut blocks);

        assert_eq!(blocks, original, "AES-256: Roundtrip must recover original");
    }
}

#[test]
fn test_aes128_8_blocks_different_from_plaintext() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        let mut encrypted = original;
        cipher.encrypt_8_blocks(&mut encrypted);

        // Encrypted blocks must be different from plaintext
        assert_ne!(encrypted, original, "Ciphertext must differ from plaintext");
    }
}

#[test]
fn test_aes192_8_blocks_different_from_plaintext() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        let mut encrypted = original;
        cipher.encrypt_8_blocks(&mut encrypted);

        assert_ne!(encrypted, original, "AES-192: Ciphertext must differ from plaintext");
    }
}

#[test]
fn test_aes256_8_blocks_different_from_plaintext() {
    if !has_aesni() {
        return;
    }
    unsafe {
        let cipher = AesNi256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        let mut encrypted = original;
        cipher.encrypt_8_blocks(&mut encrypted);

        assert_ne!(encrypted, original, "AES-256: Ciphertext must differ from plaintext");
    }
}
