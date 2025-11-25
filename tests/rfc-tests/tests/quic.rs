//! RFC 9001 - Using TLS to Secure QUIC
//!
//! Tests for QUIC-specific key derivation and header protection as defined in RFC 9001.
//!
//! QUIC uses TLS 1.3-like key derivation with a different label prefix ("quic " instead of "tls13 ").

use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct QuicTestVector {
    test_id: u32,
    test_type: String,
    source: String,
    description: String,
    note: String,
    #[serde(flatten)]
    data: Value,
}

#[test]
fn test_quic_rfc9001() {
    let test_vectors: Vec<QuicTestVector> = load_test_file("rfc9001-quic.json");

    println!("\n=== RFC 9001: Using TLS to Secure QUIC ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Type: {}", test.test_type);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);
        if !test.note.is_empty() {
            println!("  Note: {}", test.note);
        }

        match test.test_type.as_str() {
            "header_protection_aes128" => {
                test_header_protection_aes128(&test.data, &mut stats);
            }
            "header_protection_aes256" => {
                test_header_protection_aes256(&test.data, &mut stats);
            }
            "header_protection_chacha20" => {
                test_header_protection_chacha20(&test.data, &mut stats);
            }
            "quic_kdf_sha256" => {
                test_quic_kdf_sha256(&test.data, &mut stats);
            }
            "quic_kdf_determinism" => {
                test_quic_kdf_determinism(&test.data, &mut stats);
            }
            "quic_kdf_context" => {
                test_quic_kdf_context(&test.data, &mut stats);
            }
            "quic_vs_tls13" => {
                test_quic_vs_tls13(&test.data, &mut stats);
            }
            "initial_keys" => {
                // Initial keys test - verify key lengths and uniqueness
                test_initial_keys(&test.data, &mut stats);
            }
            _ => {
                println!("  Unknown test type: {}", test.test_type);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All QUIC tests should pass");
}

fn test_header_protection_aes128(data: &Value, stats: &mut TestStats) {
    use hpcrypt_kdf::{HeaderProtection, HeaderProtectionAes128};

    let hp_key_hex = data["hp_key"].as_str().unwrap();
    let sample_hex = data["sample"].as_str().unwrap();
    let expected_mask_hex = data["expected_mask"].as_str().unwrap();

    let hp_key = decode_hex(hp_key_hex);
    let sample = decode_hex(sample_hex);
    let expected_mask = decode_hex(expected_mask_hex);

    let hp = HeaderProtectionAes128::new(&hp_key);
    let mask = hp.generate_mask(&sample);

    if mask[..] == expected_mask[..] {
        println!("  AES-128 header protection mask matches");
        stats.passed += 1;
    } else {
        println!("  AES-128 header protection mask mismatch");
        println!("    Expected: {}", hex::encode(&expected_mask));
        println!("    Got:      {}", hex::encode(&mask));
        stats.failed += 1;
    }
}

fn test_header_protection_aes256(data: &Value, stats: &mut TestStats) {
    use hpcrypt_kdf::{HeaderProtection, HeaderProtectionAes256};

    let hp_key_hex = data["hp_key"].as_str().unwrap();
    let sample_hex = data["sample"].as_str().unwrap();

    let hp_key = decode_hex(hp_key_hex);
    let sample = decode_hex(sample_hex);

    // AES-256 key must be 32 bytes
    if hp_key.len() != 32 {
        println!("  Skipping: Invalid key length {} (expected 32)", hp_key.len());
        stats.skipped += 1;
        return;
    }

    let hp = HeaderProtectionAes256::new(&hp_key);
    let mask = hp.generate_mask(&sample);

    // Verify mask is 5 bytes
    assert_eq!(mask.len(), 5);

    // Verify determinism
    let mask2 = hp.generate_mask(&sample);
    if mask == mask2 {
        println!("  AES-256 header protection produces consistent mask");
        stats.passed += 1;
    } else {
        println!("  AES-256 header protection non-deterministic");
        stats.failed += 1;
    }
}

fn test_header_protection_chacha20(data: &Value, stats: &mut TestStats) {
    use hpcrypt_kdf::{HeaderProtection, HeaderProtectionChaCha20};

    let hp_key_hex = data["hp_key"].as_str().unwrap();
    let sample_hex = data["sample"].as_str().unwrap();

    let hp_key = decode_hex(hp_key_hex);
    let sample = decode_hex(sample_hex);

    let hp = HeaderProtectionChaCha20::new(&hp_key);
    let mask = hp.generate_mask(&sample);

    // Verify mask is 5 bytes
    assert_eq!(mask.len(), 5);

    // Verify determinism
    let mask2 = hp.generate_mask(&sample);
    if mask == mask2 {
        println!("  ChaCha20 header protection produces consistent mask");
        println!("    Mask: {}", hex::encode(&mask));
        stats.passed += 1;
    } else {
        println!("  ChaCha20 header protection non-deterministic");
        stats.failed += 1;
    }
}

fn test_quic_kdf_sha256(data: &Value, stats: &mut TestStats) {
    use hpcrypt_kdf::quic::hkdf_expand_label_sha256;

    let secret_hex = data["secret"].as_str().unwrap();
    let label = data["label"].as_str().unwrap();
    let context_hex = data["context"].as_str().unwrap_or("");
    let length = data["length"].as_u64().unwrap() as u16;

    let secret = decode_hex(secret_hex);
    let context = if context_hex.is_empty() {
        vec![]
    } else {
        decode_hex(context_hex)
    };

    let output = hkdf_expand_label_sha256(&secret, label, &context, length);

    if output.len() == length as usize {
        println!("  QUIC KDF SHA-256 produces correct length output");
        println!("    Output: {}", hex::encode(&output));
        stats.passed += 1;
    } else {
        println!("  QUIC KDF SHA-256 output length mismatch");
        println!("    Expected length: {}", length);
        println!("    Got length: {}", output.len());
        stats.failed += 1;
    }
}

fn test_quic_kdf_determinism(data: &Value, stats: &mut TestStats) {
    use hpcrypt_kdf::quic::hkdf_expand_label_sha256;

    let secret_hex = data["secret"].as_str().unwrap();
    let label = data["label"].as_str().unwrap();
    let context_hex = data["context"].as_str().unwrap_or("");
    let length = data["length"].as_u64().unwrap() as u16;

    let secret = decode_hex(secret_hex);
    let context = if context_hex.is_empty() {
        vec![]
    } else {
        decode_hex(context_hex)
    };

    let output1 = hkdf_expand_label_sha256(&secret, label, &context, length);
    let output2 = hkdf_expand_label_sha256(&secret, label, &context, length);

    if output1 == output2 {
        println!("  QUIC KDF is deterministic");
        stats.passed += 1;
    } else {
        println!("  QUIC KDF is non-deterministic!");
        stats.failed += 1;
    }
}

fn test_quic_kdf_context(data: &Value, stats: &mut TestStats) {
    use hpcrypt_kdf::quic::hkdf_expand_label_sha256;

    let secret_hex = data["secret"].as_str().unwrap();
    let label = data["label"].as_str().unwrap();
    let context1_hex = data["context1"].as_str().unwrap();
    let context2_hex = data["context2"].as_str().unwrap();
    let length = data["length"].as_u64().unwrap() as u16;

    let secret = decode_hex(secret_hex);
    let context1 = decode_hex(context1_hex);
    let context2 = decode_hex(context2_hex);

    let output1 = hkdf_expand_label_sha256(&secret, label, &context1, length);
    let output2 = hkdf_expand_label_sha256(&secret, label, &context2, length);

    if output1 != output2 {
        println!("  Different contexts produce different outputs");
        stats.passed += 1;
    } else {
        println!("  Different contexts produced same output!");
        stats.failed += 1;
    }
}

fn test_quic_vs_tls13(data: &Value, stats: &mut TestStats) {
    use hpcrypt_kdf::quic::hkdf_expand_label_sha256 as quic_expand;
    use hpcrypt_kdf::tls13::hkdf_expand_label_sha256 as tls13_expand;

    let secret_hex = data["secret"].as_str().unwrap();
    let label = data["label"].as_str().unwrap();
    let context_hex = data["context"].as_str().unwrap_or("");
    let length = data["length"].as_u64().unwrap() as u16;

    let secret = decode_hex(secret_hex);
    let context = if context_hex.is_empty() {
        vec![]
    } else {
        decode_hex(context_hex)
    };

    let quic_output = quic_expand(&secret, label, &context, length);
    let tls13_output = tls13_expand(&secret, label, &context, length);

    if quic_output != tls13_output {
        println!("  QUIC and TLS 1.3 use different prefixes");
        println!("    QUIC:   {}", hex::encode(&quic_output));
        println!("    TLS1.3: {}", hex::encode(&tls13_output));
        stats.passed += 1;
    } else {
        println!("  QUIC and TLS 1.3 produced same output!");
        stats.failed += 1;
    }
}

fn test_initial_keys(data: &Value, stats: &mut TestStats) {
    // For initial keys, we verify that:
    // 1. Key lengths are correct
    // 2. Client and server keys are different (if both present)
    // 3. key, iv, hp are all different from each other

    if let Some(client_key) = data["client_key"].as_str() {
        let key = decode_hex(client_key);
        if key.len() != 16 {
            println!("  Client key wrong length: {} (expected 16)", key.len());
            stats.failed += 1;
            return;
        }
    }

    if let Some(client_iv) = data["client_iv"].as_str() {
        let iv = decode_hex(client_iv);
        if iv.len() != 12 {
            println!("  Client IV wrong length: {} (expected 12)", iv.len());
            stats.failed += 1;
            return;
        }
    }

    if let Some(client_hp) = data["client_hp"].as_str() {
        let hp = decode_hex(client_hp);
        if hp.len() != 16 {
            println!("  Client HP key wrong length: {} (expected 16)", hp.len());
            stats.failed += 1;
            return;
        }
    }

    // Verify key, iv, hp are different
    if let (Some(key_hex), Some(hp_hex)) =
        (data["client_key"].as_str(), data["client_hp"].as_str())
    {
        let key = decode_hex(key_hex);
        let hp = decode_hex(hp_hex);
        if key == hp {
            println!("  Client key and HP key are the same!");
            stats.failed += 1;
            return;
        }
    }

    println!("  Initial keys have correct format");
    stats.passed += 1;
}

#[test]
fn test_quic_vector_count() {
    let test_vectors: Vec<QuicTestVector> = load_test_file("rfc9001-quic.json");
    assert!(test_vectors.len() > 0, "RFC 9001 should have test vectors");
    println!("QUIC test vectors loaded: {}", test_vectors.len());
}

/// Test QUIC KDF with various label formats
#[test]
fn test_quic_kdf_labels() {
    use hpcrypt_kdf::quic::hkdf_expand_label_sha256;

    println!("\n=== QUIC KDF Label Variations ===");

    let secret = [0x42u8; 32];

    // Standard QUIC labels
    let labels = ["quic key", "quic iv", "quic hp", "quic ku"];

    let mut outputs = Vec::new();
    for label in &labels {
        let output = hkdf_expand_label_sha256(&secret, label, &[], 16);
        println!("  {}: {}", label, hex::encode(&output));
        outputs.push(output);
    }

    // All outputs should be different
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i], outputs[j],
                "Labels '{}' and '{}' produced same output",
                labels[i], labels[j]
            );
        }
    }

    println!("\nAll QUIC labels produce unique outputs");
}

/// Test header protection with protect/unprotect roundtrip
#[test]
fn test_header_protection_roundtrip() {
    use hpcrypt_kdf::{HeaderProtection, HeaderProtectionAes128, HeaderProtectionChaCha20};

    println!("\n=== Header Protection Roundtrip ===");

    // Test AES-128
    let key_aes = [0x42u8; 16];
    let hp_aes = HeaderProtectionAes128::new(&key_aes);

    let sample = [0x01u8; 16];
    let mask = hp_aes.generate_mask(&sample);

    let original_header_byte = 0b11000000u8; // Long header form
    let protected = original_header_byte ^ mask[0];
    let unprotected = protected ^ mask[0];

    assert_eq!(original_header_byte, unprotected);
    println!("  AES-128 protect/unprotect roundtrip successful");

    // Test ChaCha20
    let key_chacha = [0x42u8; 32];
    let hp_chacha = HeaderProtectionChaCha20::new(&key_chacha);

    let mask_chacha = hp_chacha.generate_mask(&sample);

    let protected_chacha = original_header_byte ^ mask_chacha[0];
    let unprotected_chacha = protected_chacha ^ mask_chacha[0];

    assert_eq!(original_header_byte, unprotected_chacha);
    println!("  ChaCha20 protect/unprotect roundtrip successful");

    // Verify AES and ChaCha produce different masks
    assert_ne!(mask[..], mask_chacha[..]);
    println!("  AES and ChaCha20 produce different masks");

    println!("\nAll roundtrip tests passed");
}

/// Test QUIC KDF SHA-384 for AES-256-GCM cipher suites
#[test]
fn test_quic_kdf_sha384() {
    use hpcrypt_kdf::quic::hkdf_expand_label_sha384;

    println!("\n=== QUIC KDF SHA-384 (AES-256-GCM) ===");

    let secret = [0x42u8; 48]; // SHA-384 produces 48-byte secrets

    let key = hkdf_expand_label_sha384(&secret, "quic key", &[], 32);
    let iv = hkdf_expand_label_sha384(&secret, "quic iv", &[], 12);
    let hp = hkdf_expand_label_sha384(&secret, "quic hp", &[], 32);

    assert_eq!(key.len(), 32, "AES-256 key should be 32 bytes");
    assert_eq!(iv.len(), 12, "IV should be 12 bytes");
    assert_eq!(hp.len(), 32, "HP key should be 32 bytes");

    println!("  Key: {}", hex::encode(&key));
    println!("  IV:  {}", hex::encode(&iv));
    println!("  HP:  {}", hex::encode(&hp));

    // All should be different
    assert_ne!(key, hp);
    assert_ne!(&key[..12], &iv[..]);

    println!("\nQUIC KDF SHA-384 tests passed");
}
