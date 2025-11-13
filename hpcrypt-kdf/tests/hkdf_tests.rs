//! HKDF tests

use hpcrypt_kdf::{hkdf_sha256, hkdf_sha512};

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
