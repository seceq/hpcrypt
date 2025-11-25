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
        // Filter for supported configurations (X25519, Base mode, AES-128-GCM)
        if test.kem_id != 32 {
            // Skip non-X25519 tests
            stats.skipped += 1;
            continue;
        }

        if test.mode != 0 {
            // Skip non-Base mode tests for now (PSK, Auth, AuthPSK)
            stats.skipped += 1;
            continue;
        }

        if test.aead_id != 1 {
            // Skip non-AES-128-GCM tests for now
            stats.skipped += 1;
            continue;
        }

        if test.kdf_id != 1 {
            // Skip non-HKDF-SHA256 tests for now
            stats.skipped += 1;
            continue;
        }

        println!("\n--- Test {} ---", idx + 1);
        println!("  Mode: {} (Base)", test.mode);
        println!("  KEM: {} (X25519)", test.kem_id);
        println!("  KDF: {} (HKDF-SHA256)", test.kdf_id);
        println!("  AEAD: {} (AES-128-GCM)", test.aead_id);
        println!("  Encryptions: {}", test.encryptions.len());

        // Decode keys and setup values
        let sk_r = decode_hex(&test.sk_rm);
        let enc = decode_hex(&test.enc);
        let info = decode_hex(&test.info);

        // Setup recipient context
        let hpke = hpcrypt_hpke::HpkeX25519::new();
        let mut recipient_ctx = match hpke.setup_base_recipient(&enc, &sk_r, &info) {
            Ok(ctx) => ctx,
            Err(e) => {
                println!("  Failed to setup recipient: {:?}", e);
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
                    println!("    Encryption {}: Decryption failed: {:?}", enc_idx, e);
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
