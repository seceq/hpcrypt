//! HKDF tests

use hpcrypt_kdf::{hkdf_blake2b, hkdf_sha256, hkdf_sha512, HkdfBlake2b};

#[test]
fn test_hkdf_sha256_basic() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"info";
    let mut okm = [0u8; 32];

    hkdf_sha256(salt, ikm, info, &mut okm);

    // Output should not be all zeros
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn test_hkdf_sha256_empty_salt() {
    let ikm = b"input key material";
    let salt = b"";
    let info = b"info";
    let mut okm = [0u8; 32];

    hkdf_sha256(salt, ikm, info, &mut okm);
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn test_hkdf_sha256_empty_info() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"";
    let mut okm = [0u8; 32];

    hkdf_sha256(salt, ikm, info, &mut okm);
    assert_ne!(okm, [0u8; 32]);
}

#[test]
fn test_hkdf_sha256_deterministic() {
    let ikm = b"input";
    let salt = b"salt";
    let info = b"info";
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];

    hkdf_sha256(salt, ikm, info, &mut okm1);
    hkdf_sha256(salt, ikm, info, &mut okm2);

    // Same inputs should produce same output
    assert_eq!(okm1, okm2);
}

#[test]
fn test_hkdf_sha256_different_info() {
    let ikm = b"input";
    let salt = b"salt";
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];

    hkdf_sha256(salt, ikm, b"info1", &mut okm1);
    hkdf_sha256(salt, ikm, b"info2", &mut okm2);

    // Different info should produce different output
    assert_ne!(okm1, okm2);
}

#[test]
fn test_hkdf_sha512_basic() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"info";
    let mut okm = [0u8; 64];

    hkdf_sha512(salt, ikm, info, &mut okm);
    assert_ne!(okm, [0u8; 64]);
}

#[test]
fn test_hkdf_variable_output_lengths() {
    let ikm = b"ikm";
    let salt = b"salt";
    let info = b"info";

    // Test various output lengths
    for len in [16, 32, 48, 64] {
        let mut okm = vec![0u8; len];
        hkdf_sha256(salt, ikm, info, &mut okm);
        assert!(
            okm.iter().any(|&b| b != 0),
            "OKM should not be all zeros for length {}",
            len
        );
    }
}

// =============================================================================
// HKDF-BLAKE2b Tests
// =============================================================================

/// Basic extract and expand test
#[test]
fn test_hkdf_blake2b_basic_extract_expand() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 42];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    assert!(okm.iter().any(|&b| b != 0), "OKM should not be all zeros");
}

/// Empty salt test (uses zero salt internally)
#[test]
fn test_hkdf_blake2b_empty_salt() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt: &[u8] = &[];
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 42];
    hkdf_blake2b(salt, &ikm, &info, &mut okm);

    assert!(okm.iter().any(|&b| b != 0), "OKM should not be all zeros with empty salt");
}

/// Empty info test
#[test]
fn test_hkdf_blake2b_empty_info() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info: &[u8] = &[];

    let mut okm = [0u8; 42];
    hkdf_blake2b(&salt, &ikm, info, &mut okm);

    assert!(okm.iter().any(|&b| b != 0), "OKM should not be all zeros with empty info");
}

/// Long output test (128 bytes = 2 BLAKE2b blocks)
#[test]
fn test_hkdf_blake2b_long_output() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 128];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    assert_eq!(okm.len(), 128);
    assert!(okm.iter().any(|&b| b != 0), "Long output should not be all zeros");
}

/// Exact hash length output (64 bytes)
#[test]
fn test_hkdf_blake2b_exact_hash_length_output() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 64];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    assert_eq!(okm.len(), 64);
    assert!(okm.iter().any(|&b| b != 0));
}

/// Short output test (16 bytes)
#[test]
fn test_hkdf_blake2b_short_output() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 16];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    assert_eq!(okm.len(), 16);
    assert!(okm.iter().any(|&b| b != 0));
}

/// PRK length test (should be 64 bytes for BLAKE2b)
#[test]
fn test_hkdf_blake2b_prk_length() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");

    let prk = HkdfBlake2b::extract(&salt, &ikm);

    assert_eq!(prk.len(), 64, "PRK should be 64 bytes (BLAKE2b hash length)");
}

/// Determinism test
#[test]
fn test_hkdf_blake2b_determinism() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm1 = [0u8; 42];
    let mut okm2 = [0u8; 42];

    hkdf_blake2b(&salt, &ikm, &info, &mut okm1);
    hkdf_blake2b(&salt, &ikm, &info, &mut okm2);

    assert_eq!(okm1, okm2, "HKDF-BLAKE2b should be deterministic");
}

/// IKM sensitivity test
#[test]
fn test_hkdf_blake2b_ikm_sensitivity() {
    let ikm1 = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let ikm2 = hex_literal::hex!("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm1 = [0u8; 42];
    let mut okm2 = [0u8; 42];

    hkdf_blake2b(&salt, &ikm1, &info, &mut okm1);
    hkdf_blake2b(&salt, &ikm2, &info, &mut okm2);

    assert_ne!(okm1, okm2, "Different IKM should produce different OKM");
}

/// Salt sensitivity test
#[test]
fn test_hkdf_blake2b_salt_sensitivity() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt1 = hex_literal::hex!("000102030405060708090a0b0c");
    let salt2 = hex_literal::hex!("0d0e0f101112131415161718");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm1 = [0u8; 42];
    let mut okm2 = [0u8; 42];

    hkdf_blake2b(&salt1, &ikm, &info, &mut okm1);
    hkdf_blake2b(&salt2, &ikm, &info, &mut okm2);

    assert_ne!(okm1, okm2, "Different salt should produce different OKM");
}

/// Info sensitivity test
#[test]
fn test_hkdf_blake2b_info_sensitivity() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info1 = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");
    let info2 = hex_literal::hex!("fafbfcfdfeff00010203");

    let mut okm1 = [0u8; 42];
    let mut okm2 = [0u8; 42];

    hkdf_blake2b(&salt, &ikm, &info1, &mut okm1);
    hkdf_blake2b(&salt, &ikm, &info2, &mut okm2);

    assert_ne!(okm1, okm2, "Different info should produce different OKM");
}

/// Struct vs function equivalence test
#[test]
fn test_hkdf_blake2b_struct_vs_function() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    // Using function
    let mut okm_func = [0u8; 42];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm_func);

    // Using struct
    let hkdf = HkdfBlake2b::new(&salt, &ikm);
    let mut okm_struct = [0u8; 42];
    hkdf.expand(&info, &mut okm_struct).unwrap();

    assert_eq!(okm_func, okm_struct, "Struct and function should produce same output");
}

/// from_prk equivalence test
#[test]
fn test_hkdf_blake2b_from_prk() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    // Using new()
    let hkdf1 = HkdfBlake2b::new(&salt, &ikm);
    let mut okm1 = [0u8; 42];
    hkdf1.expand(&info, &mut okm1).unwrap();

    // Using extract + from_prk
    let prk = HkdfBlake2b::extract(&salt, &ikm);
    let hkdf2 = HkdfBlake2b::from_prk(&prk);
    let mut okm2 = [0u8; 42];
    hkdf2.expand(&info, &mut okm2).unwrap();

    assert_eq!(okm1, okm2, "from_prk should produce same output as new");
}

/// PRK reuse test
#[test]
fn test_hkdf_blake2b_prk_reuse() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info1 = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");
    let info2 = hex_literal::hex!("fafbfcfdfeff00010203");

    let prk = HkdfBlake2b::extract(&salt, &ikm);
    let hkdf = HkdfBlake2b::from_prk(&prk);

    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];

    hkdf.expand(&info1, &mut okm1).unwrap();
    hkdf.expand(&info2, &mut okm2).unwrap();

    assert_ne!(okm1, okm2, "PRK reuse with different info should produce different outputs");
    assert!(okm1.iter().any(|&b| b != 0));
    assert!(okm2.iter().any(|&b| b != 0));
}

/// BLAKE2b differs from SHA-512 test
#[test]
fn test_hkdf_blake2b_differs_from_sha512() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm_blake2b = [0u8; 42];
    let mut okm_sha512 = [0u8; 42];

    hkdf_blake2b(&salt, &ikm, &info, &mut okm_blake2b);
    hkdf_sha512(&salt, &ikm, &info, &mut okm_sha512);

    assert_ne!(okm_blake2b, okm_sha512, "HKDF-BLAKE2b should differ from HKDF-SHA512");
}

/// Long inputs test
#[test]
fn test_hkdf_blake2b_long_inputs() {
    // 80-byte IKM
    let ikm = hex_literal::hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
    );
    // 80-byte salt
    let salt = hex_literal::hex!(
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    );
    // 80-byte info
    let info = hex_literal::hex!(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    );

    let mut okm = [0u8; 82];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    assert!(okm.iter().any(|&b| b != 0), "Long inputs should produce non-zero output");
}

/// Multi-block expand test (192 bytes = 3 BLAKE2b blocks)
#[test]
fn test_hkdf_blake2b_multi_block_expand() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 192];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Verify all three blocks are different
    let block1 = &okm[0..64];
    let block2 = &okm[64..128];
    let block3 = &okm[128..192];

    assert_ne!(block1, block2, "Block 1 and 2 should differ");
    assert_ne!(block2, block3, "Block 2 and 3 should differ");
    assert_ne!(block1, block3, "Block 1 and 3 should differ");
}

/// Single byte output test
#[test]
fn test_hkdf_blake2b_single_byte_output() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 1];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Single byte output should work (value doesn't matter, just shouldn't panic)
    assert_eq!(okm.len(), 1);
}

/// Variable output lengths test
#[test]
fn test_hkdf_blake2b_variable_output_lengths() {
    let ikm = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_literal::hex!("000102030405060708090a0b0c");
    let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");

    for len in [1, 16, 32, 48, 64, 128, 192] {
        let mut okm = vec![0u8; len];
        hkdf_blake2b(&salt, &ikm, &info, &mut okm);
        assert!(
            okm.iter().any(|&b| b != 0),
            "OKM should not be all zeros for length {}",
            len
        );
    }
}
