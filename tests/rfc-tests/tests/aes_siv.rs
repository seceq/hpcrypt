//! RFC 5297 - AES-SIV (Synthetic Initialization Vector) Tests
//!
//! Comprehensive tests for AES-SIV implementation including:
//! - RFC 5297 Appendix A.1 (Deterministic Authenticated Encryption)
//! - RFC 5297 Appendix A.2 (Nonce-Based Authenticated Encryption with multiple AAD)
//! - Wycheproof edge cases (empty inputs, extreme SIV values)
//! - AES-128-SIV and AES-256-SIV variants
//! - Multi-AAD component support
//! - Empty message and AAD-only authentication

use hpcrypt_aead::{Aes128Siv, Aes256Siv};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

const SIV_SIZE: usize = 16; // SIV/IV size (128 bits)

#[derive(Debug, Deserialize)]
struct AesSivTestVector {
    test_id: u32,
    source: String,
    description: String,
    algorithm: String,
    key: String,
    nonce: String,
    #[serde(default)]
    aad: String,
    #[serde(default)]
    aad_components: Option<Vec<String>>,
    plaintext: String,
    siv: String,
    ciphertext: String,
    siv_and_ciphertext: String,
    note: String,
}

#[test]
fn test_aes_siv_rfc5297() {
    let test_vectors: Vec<AesSivTestVector> = load_test_file("rfc5297-aes-siv.json");

    println!("\n=== AES-SIV RFC 5297 Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Note: {}", test.note);

        let key = decode_hex(&test.key);
        let nonce = if test.nonce.is_empty() {
            vec![]
        } else {
            decode_hex(&test.nonce)
        };
        let plaintext = if test.plaintext.is_empty() {
            vec![]
        } else {
            decode_hex(&test.plaintext)
        };
        let expected_siv = decode_hex(&test.siv);
        let expected_ciphertext = if test.ciphertext.is_empty() {
            vec![]
        } else {
            decode_hex(&test.ciphertext)
        };
        let expected_full = decode_hex(&test.siv_and_ciphertext);

        // Verify expected values are consistent
        let mut check_full = Vec::new();
        check_full.extend_from_slice(&expected_siv);
        check_full.extend_from_slice(&expected_ciphertext);
        assert_eq!(
            check_full, expected_full,
            "Test vector internal consistency check failed"
        );

        // Perform encryption test
        let result = match test.algorithm.as_str() {
            "AES-128-SIV" => {
                if key.len() != 32 {
                    eprintln!(
                        "  Test {} SKIPPED: Invalid key size {} for AES-128-SIV (expected 32)",
                        test.test_id,
                        key.len()
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 32] = key.clone().try_into().unwrap();

                // Check if we have multiple AAD components
                if let Some(ref aad_components) = test.aad_components {
                    // Multi-AAD mode
                    let aad_bytes: Vec<Vec<u8>> = aad_components
                        .iter()
                        .map(|s| {
                            if s.is_empty() {
                                vec![]
                            } else {
                                decode_hex(s)
                            }
                        })
                        .collect();
                    let aad_refs: Vec<&[u8]> = aad_bytes.iter().map(|v| v.as_slice()).collect();

                    Aes128Siv::encrypt_with_aad_components(&key_array, &aad_refs, &nonce, &plaintext)
                } else {
                    // Single AAD mode
                    let aad = if test.aad.is_empty() {
                        vec![]
                    } else {
                        decode_hex(&test.aad)
                    };
                    Aes128Siv::encrypt(&key_array, &nonce, &plaintext, &aad)
                }
            }
            "AES-256-SIV" => {
                if key.len() != 64 {
                    eprintln!(
                        "  Test {} SKIPPED: Invalid key size {} for AES-256-SIV (expected 64)",
                        test.test_id,
                        key.len()
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 64] = key.clone().try_into().unwrap();
                let aad = if test.aad.is_empty() {
                    vec![]
                } else {
                    decode_hex(&test.aad)
                };
                Aes256Siv::encrypt(&key_array, &nonce, &plaintext, &aad)
            }
            _ => {
                eprintln!(
                    "  Test {} SKIPPED: Unknown algorithm '{}'",
                    test.test_id, test.algorithm
                );
                stats.skipped += 1;
                continue;
            }
        };

        // Extract SIV and ciphertext
        if result.len() < SIV_SIZE {
            eprintln!(
                "  Test {} FAILED: Result too short (got {} bytes, minimum {})",
                test.test_id,
                result.len(),
                SIV_SIZE
            );
            stats.failed += 1;
            continue;
        }

        let got_siv = &result[..SIV_SIZE];
        let got_ciphertext = &result[SIV_SIZE..];

        // Verify SIV
        if got_siv != expected_siv.as_slice() {
            eprintln!("  Test {} FAILED: SIV mismatch", test.test_id);
            eprintln!("    Expected SIV: {}", hex::encode(&expected_siv));
            eprintln!("    Got SIV:      {}", hex::encode(got_siv));
            stats.failed += 1;
            continue;
        }

        // Verify ciphertext
        if got_ciphertext != expected_ciphertext.as_slice() {
            eprintln!("  Test {} FAILED: Ciphertext mismatch", test.test_id);
            eprintln!("    Expected CT: {}", hex::encode(&expected_ciphertext));
            eprintln!("    Got CT:      {}", hex::encode(got_ciphertext));
            stats.failed += 1;
            continue;
        }

        // Verify full result
        if result != expected_full {
            eprintln!("  Test {} FAILED: Full result mismatch", test.test_id);
            stats.failed += 1;
            continue;
        }

        // Test decryption (roundtrip)
        let decrypted = match test.algorithm.as_str() {
            "AES-128-SIV" => {
                let key_array: [u8; 32] = key.try_into().unwrap();

                if let Some(ref aad_components) = test.aad_components {
                    // Multi-AAD mode
                    let aad_bytes: Vec<Vec<u8>> = aad_components
                        .iter()
                        .map(|s| {
                            if s.is_empty() {
                                vec![]
                            } else {
                                decode_hex(s)
                            }
                        })
                        .collect();
                    let aad_refs: Vec<&[u8]> = aad_bytes.iter().map(|v| v.as_slice()).collect();

                    Aes128Siv::decrypt_with_aad_components(&key_array, &aad_refs, &nonce, &result)
                } else {
                    let aad = if test.aad.is_empty() {
                        vec![]
                    } else {
                        decode_hex(&test.aad)
                    };
                    Aes128Siv::decrypt(&key_array, &nonce, &result, &aad)
                }
            }
            "AES-256-SIV" => {
                let key_array: [u8; 64] = key.try_into().unwrap();
                let aad = if test.aad.is_empty() {
                    vec![]
                } else {
                    decode_hex(&test.aad)
                };
                Aes256Siv::decrypt(&key_array, &nonce, &result, &aad)
            }
            _ => {
                unreachable!("Algorithm already validated")
            }
        };

        match decrypted {
            Ok(dec_plaintext) => {
                if dec_plaintext != plaintext {
                    eprintln!("  Test {} FAILED: Decryption produced wrong plaintext", test.test_id);
                    eprintln!("    Expected: {}", hex::encode(&plaintext));
                    eprintln!("    Got:      {}", hex::encode(&dec_plaintext));
                    stats.failed += 1;
                    continue;
                }
            }
            Err(e) => {
                eprintln!("  Test {} FAILED: Decryption error: {:?}", test.test_id, e);
                stats.failed += 1;
                continue;
            }
        }

        println!("  PASSED (SIV: {}...)", hex::encode(&got_siv[..8]));
        stats.passed += 1;
    }

    println!("\n=== Test Summary ===");
    println!("Passed:  {}", stats.passed);
    println!("Failed:  {}", stats.failed);
    println!("Skipped: {}", stats.skipped);
    println!("Total:   {}", test_vectors.len());

    assert_eq!(
        stats.failed, 0,
        "RFC 5297 AES-SIV tests failed: {} failures",
        stats.failed
    );
}
