//! NIST SP 800-38A - AES-OFB Mode Tests
//!
//! Tests AES-OFB (Output Feedback mode) encryption and decryption using
//! official test vectors from NIST SP 800-38A Appendix F.4.
//!
//! Test vectors cover:
//! - OFB-AES128 (Section F.4.1-F.4.2)
//! - OFB-AES192 (Section F.4.3-F.4.4)
//! - OFB-AES256 (Section F.4.5-F.4.6)
//!
//! Note: In OFB mode, encryption and decryption use the same operation
//! (XOR with keystream), so decrypt tests verify the same transformation.

use hpcrypt_cipher::{AesOfb128, AesOfb192, AesOfb256};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OFBTestVector {
    test_id: u32,
    source: String,
    description: String,
    algorithm: String,
    section: String,
    key: String,
    iv: String,
    plaintext: String,
    ciphertext: String,
    note: String,
}

#[test]
fn test_nist_sp800_38a_ofb() {
    let test_vectors: Vec<OFBTestVector> = load_test_file("nist-sp800-38a-ofb.json");

    println!("\n=== NIST SP 800-38A AES-OFB Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {}", test.source);
        println!("  Section: {}", test.section);
        println!("  Description: {}", test.description);
        println!("  Algorithm: {}", test.algorithm);
        println!("  Note: {}", test.note);

        let key = decode_hex(&test.key);
        let iv = decode_hex(&test.iv);
        let plaintext = decode_hex(&test.plaintext);
        let expected_ciphertext = decode_hex(&test.ciphertext);

        // Determine which algorithm to use based on key length
        let result = match key.len() {
            16 => {
                // AES-128
                if !test.algorithm.contains("AES128") {
                    eprintln!(
                        "  Test {} SKIPPED: Key length {} does not match algorithm {}",
                        test.test_id,
                        key.len(),
                        test.algorithm
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 16] = key.clone().try_into().unwrap();
                let iv_array: [u8; 16] = iv.clone().try_into().unwrap();
                let cipher = AesOfb128::new(&key_array);
                cipher.process(&iv_array, &plaintext)
            }
            24 => {
                // AES-192
                if !test.algorithm.contains("AES192") {
                    eprintln!(
                        "  Test {} SKIPPED: Key length {} does not match algorithm {}",
                        test.test_id,
                        key.len(),
                        test.algorithm
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 24] = key.clone().try_into().unwrap();
                let iv_array: [u8; 16] = iv.clone().try_into().unwrap();
                let cipher = AesOfb192::new(&key_array);
                cipher.process(&iv_array, &plaintext)
            }
            32 => {
                // AES-256
                if !test.algorithm.contains("AES256") {
                    eprintln!(
                        "  Test {} SKIPPED: Key length {} does not match algorithm {}",
                        test.test_id,
                        key.len(),
                        test.algorithm
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 32] = key.clone().try_into().unwrap();
                let iv_array: [u8; 16] = iv.clone().try_into().unwrap();
                let cipher = AesOfb256::new(&key_array);
                cipher.process(&iv_array, &plaintext)
            }
            _ => {
                eprintln!(
                    "  Test {} SKIPPED: Invalid key length {} (expected 16, 24, or 32)",
                    test.test_id,
                    key.len()
                );
                stats.skipped += 1;
                continue;
            }
        };

        // Verify encryption result
        if result != expected_ciphertext {
            eprintln!("  Test {} FAILED: Ciphertext mismatch", test.test_id);
            eprintln!("    Expected: {}", hex::encode(&expected_ciphertext));
            eprintln!("    Got:      {}", hex::encode(&result));
            stats.failed += 1;
            continue;
        }

        // Test roundtrip (OFB mode: encryption and decryption are the same operation)
        let decrypted = match key.len() {
            16 => {
                let key_array: [u8; 16] = key.try_into().unwrap();
                let iv_array: [u8; 16] = iv.try_into().unwrap();
                let cipher = AesOfb128::new(&key_array);
                cipher.process(&iv_array, &result)
            }
            24 => {
                let key_array: [u8; 24] = key.try_into().unwrap();
                let iv_array: [u8; 16] = iv.try_into().unwrap();
                let cipher = AesOfb192::new(&key_array);
                cipher.process(&iv_array, &result)
            }
            32 => {
                let key_array: [u8; 32] = key.try_into().unwrap();
                let iv_array: [u8; 16] = iv.try_into().unwrap();
                let cipher = AesOfb256::new(&key_array);
                cipher.process(&iv_array, &result)
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
