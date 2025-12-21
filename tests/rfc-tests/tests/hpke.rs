//! RFC 9180 - HPKE (Hybrid Public Key Encryption) Test Vectors
//!
//! Tests for HPKE using official CFRG test vectors from RFC 9180

use rfc_tests::{decode_hex, encode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct HpkeEncryption {
    aad: String,
    ct: String,
    nonce: String,
    pt: String,
}

#[derive(Debug, Deserialize)]
struct HpkeTestVector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "ikmR")]
    ikm_r: String,
    #[serde(rename = "ikmE")]
    ikm_e: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    #[serde(rename = "skEm")]
    sk_em: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    #[serde(rename = "pkEm")]
    pk_em: String,
    enc: String,
    shared_secret: String,
    key_schedule_context: String,
    secret: String,
    key: String,
    base_nonce: String,
    exporter_secret: String,
    encryptions: Vec<HpkeEncryption>,
}

#[test]
fn test_hpke_rfc9180() {
    let test_vectors: Vec<HpkeTestVector> = load_test_file("rfc9180-hpke.json");

    println!("\n=== RFC 9180: HPKE (Hybrid Public Key Encryption) ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for (idx, test) in test_vectors.iter().enumerate() {
        // Check if this configuration is supported
        let kem_supported = matches!(test.kem_id, 32 | 16); // X25519=32, P-256=16
        let mode_supported = test.mode <= 3; // 0=Base, 1=PSK, 2=Auth, 3=AuthPSK
        let kdf_supported = matches!(test.kdf_id, 1 | 2 | 3); // HKDF-SHA256/384/512
        let aead_supported = matches!(test.aead_id, 1 | 2 | 3); // AES-128/256-GCM, ChaCha20

        if !kem_supported || !mode_supported || !kdf_supported || !aead_supported {
            stats.skipped += 1;
            continue;
        }

        println!("\n--- Test {} ---", idx + 1);
        let mode_name = match test.mode {
            0 => "Base",
            1 => "PSK",
            2 => "Auth",
            3 => "AuthPSK",
            _ => "Unknown",
        };
        let kem_name = match test.kem_id {
            16 => "P-256",
            32 => "X25519",
            _ => "Unknown",
        };
        let kdf_name = match test.kdf_id {
            1 => "HKDF-SHA256",
            2 => "HKDF-SHA384",
            3 => "HKDF-SHA512",
            _ => "Unknown",
        };
        let aead_name = match test.aead_id {
            1 => "AES-128-GCM",
            2 => "AES-256-GCM",
            3 => "ChaCha20-Poly1305",
            _ => "Unknown",
        };

        println!("  Mode: {} ({})", test.mode, mode_name);
        println!("  KEM: {} ({})", test.kem_id, kem_name);
        println!("  KDF: {} ({})", test.kdf_id, kdf_name);
        println!("  AEAD: {} ({})", test.aead_id, aead_name);
        println!("  Encryptions: {}", test.encryptions.len());

        // Currently only Base mode with X25519 is tested
        // TODO: Add support for all modes and KEMs
        if test.mode != 0 {
            println!("  SKIP: Only Base mode implemented in tests");
            stats.skipped += 1;
            continue;
        }

        if test.kem_id != 32 {
            println!("  SKIP: Only X25519 KEM implemented in tests");
            stats.skipped += 1;
            continue;
        }

        if test.kdf_id != 1 {
            println!("  SKIP: Only HKDF-SHA256 configured in tests");
            stats.skipped += 1;
            continue;
        }

        // Decode keys and setup values
        let sk_r = decode_hex(&test.sk_rm);
        let enc = decode_hex(&test.enc);
        let info = decode_hex(&test.info);

        // Setup recipient context with appropriate AEAD
        let hpke = match test.aead_id {
            1 => hpcrypt_hpke::HpkeX25519::new(),           // AES-128-GCM
            2 => hpcrypt_hpke::HpkeX25519::with_aes256(),   // AES-256-GCM
            3 => hpcrypt_hpke::HpkeX25519::with_chacha(),   // ChaCha20-Poly1305
            _ => {
                println!("  SKIP: Unsupported AEAD ID {}", test.aead_id);
                stats.skipped += 1;
                continue;
            }
        };

        let mut recipient_ctx = match hpke.setup_base_recipient(&enc, &sk_r, &info) {
            Ok(ctx) => ctx,
            Err(e) => {
                println!("  FAIL: Failed to setup recipient: {:?}", e);
                stats.failed += 1;
                continue;
            }
        };

        // Test each encryption
        let mut test_passed = 0;
        let mut test_failed = 0;

        for (enc_idx, encryption) in test.encryptions.iter().enumerate() {
            let aad = decode_hex(&encryption.aad);
            let ct = decode_hex(&encryption.ct);
            let pt_expected = decode_hex(&encryption.pt);

            // Decrypt using recipient context
            match recipient_ctx.open(&aad, &ct) {
                Ok(pt) if pt == pt_expected => {
                    test_passed += 1;
                }
                Ok(pt) => {
                    println!("    Encryption {}: Plaintext mismatch", enc_idx);
                    println!("      Expected: {}", encryption.pt);
                    println!("      Got:      {}", encode_hex(&pt));
                    test_failed += 1;
                }
                Err(e) => {
                    // Only show first few failures for ChaCha20 to avoid spam
                    if test.aead_id == 3 && enc_idx < 5 {
                        println!("    Encryption {}: Decryption failed: {:?}", enc_idx, e);
                        println!("      Nonce: {}", &encryption.nonce);
                        println!("      AAD: {}", &encryption.aad);
                        println!("      CT length: {}", encryption.ct.len());
                    } else if test.aead_id != 3 {
                        println!("    Encryption {}: Decryption failed: {:?}", enc_idx, e);
                    }
                    test_failed += 1;
                }
            }
        }

        if test_failed == 0 {
            println!("  All {} encryptions passed", test_passed);
            stats.passed += 1;
        } else {
            println!("  {}/{} encryptions failed", test_failed, test.encryptions.len());
            stats.failed += 1;
        }
    }

    stats.print_summary();

    // HPKE implementation is now RFC 9180 compliant for X25519 + HKDF-SHA256 + AES-128-GCM
    assert_eq!(stats.failed, 0, "HPKE RFC 9180 tests should not fail");
}

#[test]
fn test_hpke_vector_count() {
    let test_vectors: Vec<HpkeTestVector> = load_test_file("rfc9180-hpke.json");
    assert!(test_vectors.len() > 0, "RFC 9180 should have test vectors");
    println!("HPKE test vectors loaded: {}", test_vectors.len());
}
