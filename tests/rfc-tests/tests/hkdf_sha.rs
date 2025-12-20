//! RFC 5869 - HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
//!
//! Tests for HKDF using SHA-256, SHA-384, and SHA-512 as the underlying hash functions.
//! Includes official RFC 5869 test vectors and additional generated test cases.

use hpcrypt_kdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct HkdfTestVector {
    test_id: u32,
    algorithm: String,
    source: String,
    description: String,
    ikm: String,
    salt: String,
    info: String,
    length: usize,
    prk: String,
    okm: String,
}

#[test]
fn test_hkdf_sha_rfc5869() {
    let test_vectors: Vec<HkdfTestVector> = load_test_file("hkdf-sha.json");

    println!("\n=== HKDF-SHA Tests (RFC 5869) ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);

        let ikm = decode_hex(&test.ikm);
        let salt = if test.salt.is_empty() {
            vec![]
        } else {
            decode_hex(&test.salt)
        };
        let info = if test.info.is_empty() {
            vec![]
        } else {
            decode_hex(&test.info)
        };
        let expected_prk = decode_hex(&test.prk);
        let expected_okm = decode_hex(&test.okm);

        match test.algorithm.as_str() {
            "HKDF-SHA256" => {
                test_hkdf_sha256(
                    &ikm,
                    &salt,
                    &info,
                    test.length,
                    &expected_prk,
                    &expected_okm,
                    &mut stats,
                    test.test_id,
                );
            }
            "HKDF-SHA384" => {
                test_hkdf_sha384(
                    &ikm,
                    &salt,
                    &info,
                    test.length,
                    &expected_prk,
                    &expected_okm,
                    &mut stats,
                    test.test_id,
                );
            }
            "HKDF-SHA512" => {
                test_hkdf_sha512(
                    &ikm,
                    &salt,
                    &info,
                    test.length,
                    &expected_prk,
                    &expected_okm,
                    &mut stats,
                    test.test_id,
                );
            }
            _ => {
                println!("  Unknown algorithm: {}", test.algorithm);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All HKDF-SHA tests should pass");
}

fn test_hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
    expected_prk: &[u8],
    expected_okm: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    // Test extract step
    let prk = HkdfSha256::extract(salt, ikm);

    if &prk[..] != expected_prk {
        eprintln!("  Test case {} FAILED: PRK mismatch", tc_id);
        eprintln!("    Expected PRK: {}", hex::encode(expected_prk));
        eprintln!("    Got PRK:      {}", hex::encode(&prk));
        stats.failed += 1;
        return;
    }

    println!("  PRK matches: {}...", hex::encode(&prk[..16]));

    // Test expand step
    let hkdf = HkdfSha256::from_prk(&prk);
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).unwrap();

    if okm == expected_okm {
        println!("  OKM matches: {}...", hex::encode(&okm[..16.min(okm.len())]));
        stats.passed += 1;
    } else {
        eprintln!("  Test case {} FAILED: OKM mismatch", tc_id);
        eprintln!("    Expected OKM: {}", hex::encode(expected_okm));
        eprintln!("    Got OKM:      {}", hex::encode(&okm));
        stats.failed += 1;
    }
}

fn test_hkdf_sha384(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
    expected_prk: &[u8],
    expected_okm: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    // Test extract step
    let prk = HkdfSha384::extract(salt, ikm);

    if &prk[..] != expected_prk {
        eprintln!("  Test case {} FAILED: PRK mismatch", tc_id);
        eprintln!("    Expected PRK: {}", hex::encode(expected_prk));
        eprintln!("    Got PRK:      {}", hex::encode(&prk));
        stats.failed += 1;
        return;
    }

    println!("  PRK matches: {}...", hex::encode(&prk[..16]));

    // Test expand step
    let hkdf = HkdfSha384::from_prk(&prk);
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).unwrap();

    if okm == expected_okm {
        println!("  OKM matches: {}...", hex::encode(&okm[..16.min(okm.len())]));
        stats.passed += 1;
    } else {
        eprintln!("  Test case {} FAILED: OKM mismatch", tc_id);
        eprintln!("    Expected OKM: {}", hex::encode(expected_okm));
        eprintln!("    Got OKM:      {}", hex::encode(&okm));
        stats.failed += 1;
    }
}

fn test_hkdf_sha512(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
    expected_prk: &[u8],
    expected_okm: &[u8],
    stats: &mut TestStats,
    tc_id: u32,
) {
    // Test extract step
    let prk = HkdfSha512::extract(salt, ikm);

    if &prk[..] != expected_prk {
        eprintln!("  Test case {} FAILED: PRK mismatch", tc_id);
        eprintln!("    Expected PRK: {}", hex::encode(expected_prk));
        eprintln!("    Got PRK:      {}", hex::encode(&prk));
        stats.failed += 1;
        return;
    }

    println!("  PRK matches: {}...", hex::encode(&prk[..16]));

    // Test expand step
    let hkdf = HkdfSha512::from_prk(&prk);
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).unwrap();

    if okm == expected_okm {
        println!("  OKM matches: {}...", hex::encode(&okm[..16.min(okm.len())]));
        stats.passed += 1;
    } else {
        eprintln!("  Test case {} FAILED: OKM mismatch", tc_id);
        eprintln!("    Expected OKM: {}", hex::encode(expected_okm));
        eprintln!("    Got OKM:      {}", hex::encode(&okm));
        stats.failed += 1;
    }
}

#[test]
fn test_hkdf_sha256_basic() {
    println!("\n=== HKDF-SHA256 Basic Tests ===");

    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    let hkdf = HkdfSha256::new(salt, ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm).unwrap();

    assert_ne!(okm, [0u8; 32], "HKDF-SHA256 should produce non-zero output");
    println!("  Basic HKDF-SHA256 works");
    println!("    OKM: {}", hex::encode(&okm));
}

#[test]
fn test_hkdf_sha384_basic() {
    println!("\n=== HKDF-SHA384 Basic Tests ===");

    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    let hkdf = HkdfSha384::new(salt, ikm);
    let mut okm = [0u8; 48];
    hkdf.expand(info, &mut okm).unwrap();

    assert_ne!(okm, [0u8; 48], "HKDF-SHA384 should produce non-zero output");
    println!("  Basic HKDF-SHA384 works");
    println!("    OKM: {}", hex::encode(&okm));
}

#[test]
fn test_hkdf_sha512_basic() {
    println!("\n=== HKDF-SHA512 Basic Tests ===");

    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    let hkdf = HkdfSha512::new(salt, ikm);
    let mut okm = [0u8; 64];
    hkdf.expand(info, &mut okm).unwrap();

    assert_ne!(okm, [0u8; 64], "HKDF-SHA512 should produce non-zero output");
    println!("  Basic HKDF-SHA512 works");
    println!("    OKM: {}", hex::encode(&okm));
}

#[test]
fn test_hkdf_sha256_determinism() {
    println!("\n=== HKDF-SHA256 Determinism ===");

    let ikm = b"test input material";
    let salt = b"test salt";
    let info = b"test info";

    let hkdf1 = HkdfSha256::new(salt, ikm);
    let mut okm1 = [0u8; 42];
    hkdf1.expand(info, &mut okm1).unwrap();

    let hkdf2 = HkdfSha256::new(salt, ikm);
    let mut okm2 = [0u8; 42];
    hkdf2.expand(info, &mut okm2).unwrap();

    assert_eq!(okm1, okm2, "HKDF-SHA256 should be deterministic");
    println!("  HKDF-SHA256 is deterministic");
    println!("    OKM: {}...", hex::encode(&okm1[..16]));
}

#[test]
fn test_hkdf_empty_salt_info() {
    println!("\n=== HKDF with Empty Salt and Info ===");

    let ikm = b"input keying material";
    let salt = b"";
    let info = b"";

    // SHA-256
    let hkdf256 = HkdfSha256::new(salt, ikm);
    let mut okm256 = [0u8; 32];
    hkdf256.expand(info, &mut okm256).unwrap();
    assert_ne!(okm256, [0u8; 32], "HKDF-SHA256 with empty salt/info should work");
    println!("  HKDF-SHA256 with empty salt/info works");

    // SHA-384
    let hkdf384 = HkdfSha384::new(salt, ikm);
    let mut okm384 = [0u8; 48];
    hkdf384.expand(info, &mut okm384).unwrap();
    assert_ne!(okm384, [0u8; 48], "HKDF-SHA384 with empty salt/info should work");
    println!("  HKDF-SHA384 with empty salt/info works");

    // SHA-512
    let hkdf512 = HkdfSha512::new(salt, ikm);
    let mut okm512 = [0u8; 64];
    hkdf512.expand(info, &mut okm512).unwrap();
    assert_ne!(okm512, [0u8; 64], "HKDF-SHA512 with empty salt/info should work");
    println!("  HKDF-SHA512 with empty salt/info works");
}

#[test]
fn test_hkdf_prk_reuse() {
    println!("\n=== HKDF PRK Reuse ===");

    let ikm = b"input keying material";
    let salt = b"salt";
    let info1 = b"context1";
    let info2 = b"context2";

    // Extract once
    let prk = HkdfSha256::extract(salt, ikm);
    let hkdf = HkdfSha256::from_prk(&prk);

    // Expand with different contexts
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    hkdf.expand(info1, &mut okm1).unwrap();
    hkdf.expand(info2, &mut okm2).unwrap();

    assert_ne!(okm1, okm2, "Different info should produce different OKM");
    println!("  PRK can be reused with different contexts");
    println!("    Context 1 OKM: {}...", hex::encode(&okm1[..16]));
    println!("    Context 2 OKM: {}...", hex::encode(&okm2[..16]));
}

#[test]
fn test_hkdf_different_hash_functions() {
    println!("\n=== HKDF with Different Hash Functions ===");

    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    let hkdf256 = HkdfSha256::new(salt, ikm);
    let mut okm256 = [0u8; 32];
    hkdf256.expand(info, &mut okm256).unwrap();

    let hkdf384 = HkdfSha384::new(salt, ikm);
    let mut okm384 = [0u8; 32];
    hkdf384.expand(info, &mut okm384).unwrap();

    let hkdf512 = HkdfSha512::new(salt, ikm);
    let mut okm512 = [0u8; 32];
    hkdf512.expand(info, &mut okm512).unwrap();

    // All three should produce different outputs
    assert_ne!(okm256, okm384, "SHA-256 and SHA-384 should differ");
    assert_ne!(okm384, okm512, "SHA-384 and SHA-512 should differ");
    assert_ne!(okm256, okm512, "SHA-256 and SHA-512 should differ");

    println!("  Different hash functions produce different outputs");
    println!("    SHA-256: {}...", hex::encode(&okm256[..16]));
    println!("    SHA-384: {}...", hex::encode(&okm384[..16]));
    println!("    SHA-512: {}...", hex::encode(&okm512[..16]));
}

#[test]
fn test_hkdf_variable_output_lengths() {
    println!("\n=== HKDF Variable Output Lengths ===");

    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    let hkdf = HkdfSha256::new(salt, ikm);

    // Test various output lengths
    for length in [1, 16, 32, 64, 128, 255] {
        let mut okm = vec![0u8; length];
        let result = hkdf.expand(info, &mut okm);
        assert!(result.is_ok(), "Should expand to {} bytes", length);
        assert!(okm.iter().any(|&b| b != 0), "Output should be non-zero");
        println!("  {} bytes: OK", length);
    }

    // Test maximum output length (255 * 32 = 8160 bytes)
    let mut okm_max = vec![0u8; 255 * 32];
    assert!(hkdf.expand(info, &mut okm_max).is_ok());
    println!("  Maximum length (8160 bytes): OK");
}
