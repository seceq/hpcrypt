//! RFC 8446/8448 - TLS 1.3 Key Derivation Function Tests
//!
//! Tests for TLS 1.3 HKDF-Expand-Label using SHA-256 and SHA-384.
//! Test vectors from RFC 8448 (Example Handshake Traces for TLS 1.3).

use hpcrypt_kdf::tls13::{hkdf_expand_label_sha256, hkdf_expand_label_sha384};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Tls13TestVector {
    test_id: u32,
    source: String,
    description: String,
    algorithm: String,
    secret: String,
    label: String,
    context: String,
    length: u16,
    expected: String,
}

#[test]
fn test_tls13_kdf_rfc8448() {
    let test_vectors: Vec<Tls13TestVector> = load_test_file("rfc8448-tls13-kdf.json");

    println!("\n=== TLS 1.3 KDF Tests (RFC 8448) ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);
        println!("  Algorithm: {}", test.algorithm);

        let secret = decode_hex(&test.secret);
        let context = if test.context.is_empty() {
            vec![]
        } else {
            decode_hex(&test.context)
        };
        let expected = decode_hex(&test.expected);

        let output = match test.algorithm.as_str() {
            "HKDF-Expand-Label-SHA256" => {
                hkdf_expand_label_sha256(&secret, &test.label, &context, test.length)
            }
            "HKDF-Expand-Label-SHA384" => {
                hkdf_expand_label_sha384(&secret, &test.label, &context, test.length)
            }
            _ => {
                println!("  Unknown algorithm: {}", test.algorithm);
                stats.skipped += 1;
                continue;
            }
        };

        if output == expected {
            println!("  Output matches: {}...", hex::encode(&output[..16.min(output.len())]));
            stats.passed += 1;
        } else {
            eprintln!("  Test case {} FAILED: Output mismatch", test.test_id);
            eprintln!("    Label: '{}'", test.label);
            eprintln!("    Length: {} bytes", test.length);
            eprintln!("    Expected: {}", hex::encode(&expected));
            eprintln!("    Got:      {}", hex::encode(&output));
            stats.failed += 1;
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All TLS 1.3 KDF tests should pass");
}

#[test]
fn test_tls13_hkdf_expand_label_basic() {
    println!("\n=== TLS 1.3 HKDF-Expand-Label Basic Tests ===");

    let secret = [0u8; 32];

    // Test key derivation
    let key = hkdf_expand_label_sha256(&secret, "key", &[], 16);
    assert_eq!(key.len(), 16);
    println!("  Key derivation (16 bytes): OK");

    // Test IV derivation
    let iv = hkdf_expand_label_sha256(&secret, "iv", &[], 12);
    assert_eq!(iv.len(), 12);
    println!("  IV derivation (12 bytes): OK");

    // Test traffic secret derivation with context
    let context = [0u8; 32];
    let traffic_secret = hkdf_expand_label_sha256(&secret, "c hs traffic", &context, 32);
    assert_eq!(traffic_secret.len(), 32);
    println!("  Traffic secret derivation (32 bytes): OK");
}

#[test]
fn test_tls13_different_labels() {
    println!("\n=== TLS 1.3 Different Labels ===");

    let secret = [0x42; 32];

    let key1 = hkdf_expand_label_sha256(&secret, "key", &[], 16);
    let key2 = hkdf_expand_label_sha256(&secret, "iv", &[], 16);
    let key3 = hkdf_expand_label_sha256(&secret, "c hs traffic", &[], 16);

    assert_ne!(key1, key2, "Different labels should produce different outputs");
    assert_ne!(key2, key3, "Different labels should produce different outputs");
    assert_ne!(key1, key3, "Different labels should produce different outputs");

    println!("  Different labels produce different outputs");
    println!("    'key':          {}...", hex::encode(&key1[..8]));
    println!("    'iv':           {}...", hex::encode(&key2[..8]));
    println!("    'c hs traffic': {}...", hex::encode(&key3[..8]));
}

#[test]
fn test_tls13_context_sensitivity() {
    println!("\n=== TLS 1.3 Context Sensitivity ===");

    let secret = [0x42; 32];
    let context1 = [0x00; 32];
    let context2 = [0x01; 32];

    let out1 = hkdf_expand_label_sha256(&secret, "key", &context1, 16);
    let out2 = hkdf_expand_label_sha256(&secret, "key", &context2, 16);

    assert_ne!(out1, out2, "Different contexts should produce different outputs");

    println!("  Different contexts produce different outputs");
    println!("    Context [0x00...]: {}...", hex::encode(&out1[..8]));
    println!("    Context [0x01...]: {}...", hex::encode(&out2[..8]));
}

#[test]
fn test_tls13_sha256_cipher_suite() {
    println!("\n=== TLS 1.3 SHA-256 Cipher Suite (TLS_AES_128_GCM_SHA256) ===");

    // Simulate handshake secret
    let handshake_secret = [0x33; 32];
    let transcript_hash = [0x11; 32];

    // Derive client handshake traffic secret
    let client_hs_traffic =
        hkdf_expand_label_sha256(&handshake_secret, "c hs traffic", &transcript_hash, 32);
    assert_eq!(client_hs_traffic.len(), 32);
    println!("  Client handshake traffic secret: OK");

    // Derive server handshake traffic secret
    let server_hs_traffic =
        hkdf_expand_label_sha256(&handshake_secret, "s hs traffic", &transcript_hash, 32);
    assert_eq!(server_hs_traffic.len(), 32);
    println!("  Server handshake traffic secret: OK");

    // Derive key and IV from client traffic secret
    let client_key = hkdf_expand_label_sha256(&client_hs_traffic, "key", &[], 16);
    let client_iv = hkdf_expand_label_sha256(&client_hs_traffic, "iv", &[], 12);
    assert_eq!(client_key.len(), 16); // AES-128 key
    assert_eq!(client_iv.len(), 12); // GCM nonce
    println!("  Client key and IV: OK");

    // Derive key and IV from server traffic secret
    let server_key = hkdf_expand_label_sha256(&server_hs_traffic, "key", &[], 16);
    let server_iv = hkdf_expand_label_sha256(&server_hs_traffic, "iv", &[], 12);
    assert_eq!(server_key.len(), 16); // AES-128 key
    assert_eq!(server_iv.len(), 12); // GCM nonce
    println!("  Server key and IV: OK");

    // Verify client and server keys are different
    assert_ne!(client_key, server_key);
    assert_ne!(client_iv, server_iv);
    println!("  Client and server keys differ: OK");
}

#[test]
fn test_tls13_sha384_cipher_suite() {
    println!("\n=== TLS 1.3 SHA-384 Cipher Suite (TLS_AES_256_GCM_SHA384) ===");

    // Simulate handshake secret with SHA-384
    let handshake_secret = [0x33; 48];
    let transcript_hash = [0x11; 48];

    // Derive client handshake traffic secret
    let client_hs_traffic =
        hkdf_expand_label_sha384(&handshake_secret, "c hs traffic", &transcript_hash, 48);
    assert_eq!(client_hs_traffic.len(), 48);
    println!("  Client handshake traffic secret: OK");

    // Derive server handshake traffic secret
    let server_hs_traffic =
        hkdf_expand_label_sha384(&handshake_secret, "s hs traffic", &transcript_hash, 48);
    assert_eq!(server_hs_traffic.len(), 48);
    println!("  Server handshake traffic secret: OK");

    // Derive key and IV from client traffic secret
    let client_key = hkdf_expand_label_sha384(&client_hs_traffic, "key", &[], 32);
    let client_iv = hkdf_expand_label_sha384(&client_hs_traffic, "iv", &[], 12);
    assert_eq!(client_key.len(), 32); // AES-256 key
    assert_eq!(client_iv.len(), 12); // GCM nonce
    println!("  Client key and IV: OK");

    // Derive key and IV from server traffic secret
    let server_key = hkdf_expand_label_sha384(&server_hs_traffic, "key", &[], 32);
    let server_iv = hkdf_expand_label_sha384(&server_hs_traffic, "iv", &[], 12);
    assert_eq!(server_key.len(), 32); // AES-256 key
    assert_eq!(server_iv.len(), 12); // GCM nonce
    println!("  Server key and IV: OK");

    // Verify client and server keys are different
    assert_ne!(client_key, server_key);
    assert_ne!(client_iv, server_iv);
    println!("  Client and server keys differ: OK");
}

#[test]
fn test_tls13_variable_output_lengths() {
    println!("\n=== TLS 1.3 Variable Output Lengths ===");

    let secret = [0x42; 32];

    // Test various output lengths used in TLS 1.3
    for length in [12, 16, 32, 48, 64] {
        let output = hkdf_expand_label_sha256(&secret, "test", &[], length);
        assert_eq!(output.len(), length as usize);
        println!("  {} bytes: OK", length);
    }
}

#[test]
fn test_tls13_empty_context() {
    println!("\n=== TLS 1.3 Empty Context ===");

    let secret = [0x42; 32];

    // Empty context (used for key/IV derivation)
    let key_empty = hkdf_expand_label_sha256(&secret, "key", &[], 16);

    // With context (used for traffic secret derivation)
    let context = [0x11; 32];
    let key_with_context = hkdf_expand_label_sha256(&secret, "key", &context, 16);

    assert_ne!(
        key_empty, key_with_context,
        "Empty and non-empty contexts should produce different outputs"
    );

    println!("  Empty context works correctly");
    println!("    No context: {}...", hex::encode(&key_empty[..8]));
    println!("    With context: {}...", hex::encode(&key_with_context[..8]));
}

#[test]
fn test_tls13_determinism() {
    println!("\n=== TLS 1.3 Determinism ===");

    let secret = [0x42; 32];
    let context = [0x11; 32];

    let out1 = hkdf_expand_label_sha256(&secret, "c hs traffic", &context, 32);
    let out2 = hkdf_expand_label_sha256(&secret, "c hs traffic", &context, 32);

    assert_eq!(out1, out2, "TLS 1.3 KDF should be deterministic");

    println!("  TLS 1.3 KDF is deterministic");
    println!("    Output: {}...", hex::encode(&out1[..16]));
}
