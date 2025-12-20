//! NIST LWC (Lightweight Cryptography) - Ascon AEAD Tests
//!
//! Comprehensive tests for Ascon AEAD implementation including:
//! - Official KAT (Known Answer Test) vectors from ascon-c repository
//! - NIST SP 800-232 standard compliance
//! - Ascon-128 variant
//! - Empty plaintext/AAD edge cases
//! - Various plaintext lengths (1, 2, 4, 8, 16, 28, 32 bytes)
//! - AAD-only authentication
//! - Combined plaintext and AAD scenarios

use hpcrypt_aead::ascon::Ascon128Nist;
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

const TAG_SIZE: usize = 16; // Ascon tag size (128 bits)

#[derive(Debug, Deserialize)]
struct AsconTestVector {
    test_id: u32,
    source: String,
    description: String,
    algorithm: String,
    key: String,
    nonce: String,
    plaintext: String,
    aad: String,
    ciphertext: String,
    tag: String,
    ciphertext_and_tag: String,
    note: String,
}

#[test]
fn test_ascon_aead_kat() {
    let test_vectors: Vec<AsconTestVector> = load_test_file("ascon-aead.json");

    println!("\n=== Ascon AEAD KAT Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Note: {}", test.note);

        let key = decode_hex(&test.key);
        let nonce = decode_hex(&test.nonce);
        let plaintext = if test.plaintext.is_empty() {
            vec![]
        } else {
            decode_hex(&test.plaintext)
        };
        let aad = if test.aad.is_empty() {
            vec![]
        } else {
            decode_hex(&test.aad)
        };
        let expected_ciphertext = if test.ciphertext.is_empty() {
            vec![]
        } else {
            decode_hex(&test.ciphertext)
        };
        let expected_tag = decode_hex(&test.tag);
        let expected_full = decode_hex(&test.ciphertext_and_tag);

        // Verify expected values are consistent
        let mut check_full = Vec::new();
        check_full.extend_from_slice(&expected_ciphertext);
        check_full.extend_from_slice(&expected_tag);
        assert_eq!(
            check_full, expected_full,
            "Test vector internal consistency check failed"
        );

        // Perform encryption test
        let result = match test.algorithm.as_str() {
            "Ascon-128" => {
                if key.len() != 16 {
                    eprintln!(
                        "  Test {} SKIPPED: Invalid key size {} for Ascon-128 (expected 16)",
                        test.test_id,
                        key.len()
                    );
                    stats.skipped += 1;
                    continue;
                }
                if nonce.len() != 16 {
                    eprintln!(
                        "  Test {} SKIPPED: Invalid nonce size {} for Ascon-128 (expected 16)",
                        test.test_id,
                        nonce.len()
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 16] = key.clone().try_into().unwrap();
                let nonce_array: [u8; 16] = nonce.clone().try_into().unwrap();

                Ascon128Nist::encrypt(&key_array, &nonce_array, &plaintext, &aad)
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

        // Extract ciphertext and tag
        if result.len() < TAG_SIZE {
            eprintln!(
                "  Test {} FAILED: Result too short (got {} bytes, minimum {})",
                test.test_id,
                result.len(),
                TAG_SIZE
            );
            stats.failed += 1;
            continue;
        }

        let got_ciphertext = &result[..result.len() - TAG_SIZE];
        let got_tag = &result[result.len() - TAG_SIZE..];

        // Verify ciphertext
        if got_ciphertext != expected_ciphertext.as_slice() {
            eprintln!("  Test {} FAILED: Ciphertext mismatch", test.test_id);
            eprintln!("    Expected CT: {}", hex::encode(&expected_ciphertext));
            eprintln!("    Got CT:      {}", hex::encode(got_ciphertext));
            stats.failed += 1;
            continue;
        }

        // Verify tag
        if got_tag != expected_tag.as_slice() {
            eprintln!("  Test {} FAILED: Tag mismatch", test.test_id);
            eprintln!("    Expected Tag: {}", hex::encode(&expected_tag));
            eprintln!("    Got Tag:      {}", hex::encode(got_tag));
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
            "Ascon-128" => {
                let key_array: [u8; 16] = key.try_into().unwrap();
                let nonce_array: [u8; 16] = nonce.try_into().unwrap();

                match Ascon128Nist::decrypt(&key_array, &nonce_array, &result, &aad) {
                    Some(pt) => pt,
                    None => {
                        eprintln!("  Test {} FAILED: Decryption failed (authentication error)", test.test_id);
                        stats.failed += 1;
                        continue;
                    }
                }
            }
            _ => unreachable!(),
        };

        // Verify roundtrip
        if decrypted != plaintext {
            eprintln!("  Test {} FAILED: Roundtrip mismatch", test.test_id);
            eprintln!("    Original PT: {}", hex::encode(&plaintext));
            eprintln!("    Decrypted PT: {}", hex::encode(&decrypted));
            stats.failed += 1;
            continue;
        }

        println!("  Test {} PASSED", test.test_id);
        stats.passed += 1;
    }

    // Print summary
    println!("\n=== Test Summary ===");
    println!("Total:   {}", stats.passed + stats.failed + stats.skipped);
    println!("Passed:  {}", stats.passed);
    println!("Failed:  {}", stats.failed);
    println!("Skipped: {}", stats.skipped);

    assert_eq!(
        stats.failed, 0,
        "{} test(s) failed. See details above.",
        stats.failed
    );
    assert!(
        stats.passed > 0,
        "No tests passed. Expected at least some passing tests."
    );
}
