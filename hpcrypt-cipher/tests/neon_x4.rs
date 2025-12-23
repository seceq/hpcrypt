//! Unit tests for ARM NEON 4-block parallel operations.
//!
//! Tests that encrypt_4_blocks/decrypt_4_blocks produce the same results
//! as calling encrypt_block/decrypt_block 4 times individually.

#![cfg(target_arch = "aarch64")]

use hpcrypt_cipher::intrinsics::{has_aes_neon, AesNeon128, AesNeon192, AesNeon256};

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

fn make_test_blocks() -> [[u8; 16]; 4] {
    [
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00],
        [0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0x01],
        [0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0x02],
    ]
}

#[test]
fn test_aes128_encrypt_4_blocks_vs_single() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        // Encrypt 4 blocks in parallel
        let mut parallel = original;
        cipher.encrypt_4_blocks(&mut parallel);

        // Encrypt each block individually
        let mut individual = original;
        for block in individual.iter_mut() {
            cipher.encrypt_block(block);
        }

        // Results must match
        assert_eq!(parallel, individual, "4-block parallel encrypt must match individual encrypts");
    }
}

#[test]
fn test_aes128_decrypt_4_blocks_vs_single() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        // Encrypt first to get ciphertext
        let mut ciphertext = original;
        cipher.encrypt_4_blocks(&mut ciphertext);

        // Decrypt 4 blocks in parallel
        let mut parallel = ciphertext;
        cipher.decrypt_4_blocks(&mut parallel);

        // Decrypt each block individually
        let mut individual = ciphertext;
        for block in individual.iter_mut() {
            cipher.decrypt_block(block);
        }

        // Results must match
        assert_eq!(parallel, individual, "4-block parallel decrypt must match individual decrypts");
        assert_eq!(parallel, original, "Decrypt must recover original plaintext");
    }
}

#[test]
fn test_aes128_4_blocks_roundtrip() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        let mut blocks = original;
        cipher.encrypt_4_blocks(&mut blocks);
        cipher.decrypt_4_blocks(&mut blocks);

        assert_eq!(blocks, original, "Roundtrip must recover original");
    }
}

#[test]
fn test_aes192_encrypt_4_blocks_vs_single() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        // Encrypt 4 blocks in parallel
        let mut parallel = original;
        cipher.encrypt_4_blocks(&mut parallel);

        // Encrypt each block individually
        let mut individual = original;
        for block in individual.iter_mut() {
            cipher.encrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-192: 4-block parallel encrypt must match individual encrypts");
    }
}

#[test]
fn test_aes192_decrypt_4_blocks_vs_single() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        // Encrypt first to get ciphertext
        let mut ciphertext = original;
        cipher.encrypt_4_blocks(&mut ciphertext);

        // Decrypt 4 blocks in parallel
        let mut parallel = ciphertext;
        cipher.decrypt_4_blocks(&mut parallel);

        // Decrypt each block individually
        let mut individual = ciphertext;
        for block in individual.iter_mut() {
            cipher.decrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-192: 4-block parallel decrypt must match individual decrypts");
        assert_eq!(parallel, original, "AES-192: Decrypt must recover original plaintext");
    }
}

#[test]
fn test_aes192_4_blocks_roundtrip() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        let mut blocks = original;
        cipher.encrypt_4_blocks(&mut blocks);
        cipher.decrypt_4_blocks(&mut blocks);

        assert_eq!(blocks, original, "AES-192: Roundtrip must recover original");
    }
}

#[test]
fn test_aes256_encrypt_4_blocks_vs_single() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        // Encrypt 4 blocks in parallel
        let mut parallel = original;
        cipher.encrypt_4_blocks(&mut parallel);

        // Encrypt each block individually
        let mut individual = original;
        for block in individual.iter_mut() {
            cipher.encrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-256: 4-block parallel encrypt must match individual encrypts");
    }
}

#[test]
fn test_aes256_decrypt_4_blocks_vs_single() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        // Encrypt first to get ciphertext
        let mut ciphertext = original;
        cipher.encrypt_4_blocks(&mut ciphertext);

        // Decrypt 4 blocks in parallel
        let mut parallel = ciphertext;
        cipher.decrypt_4_blocks(&mut parallel);

        // Decrypt each block individually
        let mut individual = ciphertext;
        for block in individual.iter_mut() {
            cipher.decrypt_block(block);
        }

        assert_eq!(parallel, individual, "AES-256: 4-block parallel decrypt must match individual decrypts");
        assert_eq!(parallel, original, "AES-256: Decrypt must recover original plaintext");
    }
}

#[test]
fn test_aes256_4_blocks_roundtrip() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        let mut blocks = original;
        cipher.encrypt_4_blocks(&mut blocks);
        cipher.decrypt_4_blocks(&mut blocks);

        assert_eq!(blocks, original, "AES-256: Roundtrip must recover original");
    }
}

#[test]
fn test_aes128_4_blocks_different_from_plaintext() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon128::new(&TEST_KEY_128);
        let original = make_test_blocks();

        let mut encrypted = original;
        cipher.encrypt_4_blocks(&mut encrypted);

        // Encrypted blocks must be different from plaintext
        assert_ne!(encrypted, original, "Ciphertext must differ from plaintext");
    }
}

#[test]
fn test_aes192_4_blocks_different_from_plaintext() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon192::new(&TEST_KEY_192);
        let original = make_test_blocks();

        let mut encrypted = original;
        cipher.encrypt_4_blocks(&mut encrypted);

        assert_ne!(encrypted, original, "AES-192: Ciphertext must differ from plaintext");
    }
}

#[test]
fn test_aes256_4_blocks_different_from_plaintext() {
    if !has_aes_neon() {
        return;
    }
    unsafe {
        let cipher = AesNeon256::new(&TEST_KEY_256);
        let original = make_test_blocks();

        let mut encrypted = original;
        cipher.encrypt_4_blocks(&mut encrypted);

        assert_ne!(encrypted, original, "AES-256: Ciphertext must differ from plaintext");
    }
}
