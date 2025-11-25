//! RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols
//!
//! Tests for standalone ChaCha20 stream cipher as specified in RFC 8439.
//! This tests ChaCha20 independently from the ChaCha20-Poly1305 AEAD.

use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct ChaCha20TestVector {
    test_id: u32,
    test_type: String,
    source: String,
    description: String,
    note: String,
    #[serde(flatten)]
    data: Value,
}

#[test]
fn test_chacha20_rfc8439() {
    let test_vectors: Vec<ChaCha20TestVector> = load_test_file("rfc8439-chacha20.json");

    println!("\n=== RFC 8439: ChaCha20 Stream Cipher ===");
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
            "chacha20_block" => {
                test_chacha20_block(&test.data, &mut stats);
            }
            "chacha20_encryption" => {
                test_chacha20_encryption(&test.data, &mut stats);
            }
            "xchacha20" => {
                test_xchacha20_encryption(&test.data, &mut stats);
            }
            "xchacha20_roundtrip" => {
                test_xchacha20_roundtrip(&test.data, &mut stats);
            }
            "hchacha20" => {
                test_hchacha20(&test.data, &mut stats);
            }
            "chacha20_roundtrip" => {
                test_chacha20_roundtrip(&test.data, &mut stats);
            }
            "chacha20_seek" => {
                test_chacha20_seek(&test.data, &mut stats);
            }
            "chacha20_partial_blocks" => {
                test_chacha20_partial_blocks(&test.data, &mut stats);
            }
            _ => {
                println!("  Unknown test type: {}", test.test_type);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All ChaCha20 tests should pass");
}

fn test_chacha20_block(data: &Value, stats: &mut TestStats) {
    use hpcrypt_cipher::ChaCha20;

    let key_hex = data["key"].as_str().unwrap();
    let nonce_hex = data["nonce"].as_str().unwrap();
    let counter = data["counter"].as_u64().unwrap() as u32;
    let expected_keystream_hex = data["expected_keystream"].as_str().unwrap();

    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);
    let expected_keystream = decode_hex(expected_keystream_hex);

    let key_array: [u8; 32] = key.try_into().expect("Key must be 32 bytes");
    let nonce_array: [u8; 12] = nonce.try_into().expect("Nonce must be 12 bytes");

    let mut chacha = ChaCha20::new(&key_array, &nonce_array, counter);

    // Generate keystream by encrypting zeros
    let mut output = vec![0u8; expected_keystream.len()];
    chacha.encrypt(&mut output);

    if output == expected_keystream {
        println!("  ChaCha20 block function matches expected keystream");
        stats.passed += 1;
    } else {
        println!("  ChaCha20 block function mismatch");
        println!("    Expected: {}", hex::encode(&expected_keystream));
        println!("    Got:      {}", hex::encode(&output));
        stats.failed += 1;
    }
}

fn test_chacha20_encryption(data: &Value, stats: &mut TestStats) {
    use hpcrypt_cipher::ChaCha20;

    let key_hex = data["key"].as_str().unwrap();
    let nonce_hex = data["nonce"].as_str().unwrap();
    let counter = data["counter"].as_u64().unwrap() as u32;
    let plaintext_hex = data["plaintext"].as_str().unwrap();
    let ciphertext_hex = data["ciphertext"].as_str().unwrap();

    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);
    let plaintext = decode_hex(plaintext_hex);
    let expected_ciphertext = decode_hex(ciphertext_hex);

    let key_array: [u8; 32] = key.try_into().expect("Key must be 32 bytes");
    let nonce_array: [u8; 12] = nonce.try_into().expect("Nonce must be 12 bytes");

    // Test encryption
    let mut chacha = ChaCha20::new(&key_array, &nonce_array, counter);
    let mut ciphertext = plaintext.clone();
    chacha.encrypt(&mut ciphertext);

    if ciphertext == expected_ciphertext {
        println!("  ChaCha20 encryption matches expected ciphertext");

        // Also verify decryption
        let mut chacha_dec = ChaCha20::new(&key_array, &nonce_array, counter);
        let mut decrypted = ciphertext.clone();
        chacha_dec.decrypt(&mut decrypted);

        if decrypted == plaintext {
            println!("  ChaCha20 decryption recovers plaintext");
            stats.passed += 1;
        } else {
            println!("  ChaCha20 decryption failed");
            stats.failed += 1;
        }
    } else {
        println!("  ChaCha20 encryption mismatch");
        println!("    Expected: {}", hex::encode(&expected_ciphertext));
        println!("    Got:      {}", hex::encode(&ciphertext));
        stats.failed += 1;
    }
}

fn test_xchacha20_encryption(data: &Value, stats: &mut TestStats) {
    use hpcrypt_cipher::XChaCha20;

    let key_hex = data["key"].as_str().unwrap();
    let nonce_hex = data["nonce"].as_str().unwrap();
    let counter = data["counter"].as_u64().unwrap() as u32;
    let plaintext_hex = data["plaintext"].as_str().unwrap();
    let ciphertext_hex = data["ciphertext"].as_str().unwrap();

    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);
    let plaintext = decode_hex(plaintext_hex);
    let expected_ciphertext = decode_hex(ciphertext_hex);

    if nonce.len() != 24 {
        println!("  Skipping: XChaCha20 nonce must be 24 bytes, got {}", nonce.len());
        stats.skipped += 1;
        return;
    }

    let key_array: [u8; 32] = key.try_into().expect("Key must be 32 bytes");
    let nonce_array: [u8; 24] = nonce.try_into().expect("Nonce must be 24 bytes");

    // Test encryption
    let mut xchacha = XChaCha20::new(&key_array, &nonce_array, counter);
    let mut ciphertext = plaintext.clone();
    xchacha.encrypt(&mut ciphertext);

    if ciphertext == expected_ciphertext {
        println!("  XChaCha20 encryption matches expected ciphertext");

        // Also verify decryption
        let mut xchacha_dec = XChaCha20::new(&key_array, &nonce_array, counter);
        let mut decrypted = ciphertext.clone();
        xchacha_dec.decrypt(&mut decrypted);

        if decrypted == plaintext {
            println!("  XChaCha20 decryption recovers plaintext");
            stats.passed += 1;
        } else {
            println!("  XChaCha20 decryption failed");
            stats.failed += 1;
        }
    } else {
        println!("  XChaCha20 encryption mismatch");
        println!("    Expected: {}", hex::encode(&expected_ciphertext));
        println!("    Got:      {}", hex::encode(&ciphertext));
        // Still test roundtrip for XChaCha20
        let mut xchacha_dec = XChaCha20::new(&key_array, &nonce_array, counter);
        let mut decrypted = ciphertext.clone();
        xchacha_dec.decrypt(&mut decrypted);
        if decrypted == plaintext {
            println!("    Note: Roundtrip works, test vector may be incorrect");
        }
        stats.failed += 1;
    }
}

fn test_xchacha20_roundtrip(data: &Value, stats: &mut TestStats) {
    use hpcrypt_cipher::XChaCha20;

    let key_hex = data["key"].as_str().unwrap();
    let nonce_hex = data["nonce"].as_str().unwrap();
    let counter = data["counter"].as_u64().unwrap() as u32;
    let plaintext_hex = data["plaintext"].as_str().unwrap();

    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);
    let plaintext = decode_hex(plaintext_hex);

    if nonce.len() != 24 {
        println!("  Skipping: XChaCha20 nonce must be 24 bytes, got {}", nonce.len());
        stats.skipped += 1;
        return;
    }

    let key_array: [u8; 32] = key.try_into().expect("Key must be 32 bytes");
    let nonce_array: [u8; 24] = nonce.try_into().expect("Nonce must be 24 bytes");

    // Encrypt
    let mut xchacha_enc = XChaCha20::new(&key_array, &nonce_array, counter);
    let mut ciphertext = plaintext.clone();
    xchacha_enc.encrypt(&mut ciphertext);

    // Verify ciphertext differs from plaintext
    if ciphertext == plaintext {
        println!("  Ciphertext should differ from plaintext");
        stats.failed += 1;
        return;
    }

    // Decrypt
    let mut xchacha_dec = XChaCha20::new(&key_array, &nonce_array, counter);
    let mut decrypted = ciphertext.clone();
    xchacha_dec.decrypt(&mut decrypted);

    if decrypted == plaintext {
        println!("  XChaCha20 roundtrip successful");
        stats.passed += 1;
    } else {
        println!("  XChaCha20 roundtrip failed");
        stats.failed += 1;
    }
}

fn test_hchacha20(_data: &Value, stats: &mut TestStats) {
    // HChaCha20 is internal, but we can verify via XChaCha20 behavior
    // For now, skip this test as HChaCha20 is not publicly exposed
    println!("  Skipping: HChaCha20 is internal function");
    stats.skipped += 1;
}

fn test_chacha20_roundtrip(data: &Value, stats: &mut TestStats) {
    use hpcrypt_cipher::ChaCha20;

    let key_hex = data["key"].as_str().unwrap();
    let nonce_hex = data["nonce"].as_str().unwrap();
    let counter = data["counter"].as_u64().unwrap() as u32;
    let plaintext_hex = data["plaintext"].as_str().unwrap();

    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);
    let plaintext = decode_hex(plaintext_hex);

    let key_array: [u8; 32] = key.try_into().expect("Key must be 32 bytes");
    let nonce_array: [u8; 12] = nonce.try_into().expect("Nonce must be 12 bytes");

    // Encrypt
    let mut chacha_enc = ChaCha20::new(&key_array, &nonce_array, counter);
    let mut ciphertext = plaintext.clone();
    chacha_enc.encrypt(&mut ciphertext);

    // Verify ciphertext is different from plaintext
    if ciphertext == plaintext {
        println!("  Ciphertext should differ from plaintext");
        stats.failed += 1;
        return;
    }

    // Decrypt
    let mut chacha_dec = ChaCha20::new(&key_array, &nonce_array, counter);
    let mut decrypted = ciphertext.clone();
    chacha_dec.decrypt(&mut decrypted);

    if decrypted == plaintext {
        println!("  Encrypt/decrypt roundtrip successful");
        stats.passed += 1;
    } else {
        println!("  Roundtrip failed - decrypted doesn't match plaintext");
        println!("    Original:  {}", hex::encode(&plaintext));
        println!("    Decrypted: {}", hex::encode(&decrypted));
        stats.failed += 1;
    }
}

fn test_chacha20_seek(data: &Value, stats: &mut TestStats) {
    use hpcrypt_cipher::ChaCha20;

    let key_hex = data["key"].as_str().unwrap();
    let nonce_hex = data["nonce"].as_str().unwrap();
    let seek_block = data["seek_to_block"].as_u64().unwrap() as u32;
    let plaintext_hex = data["plaintext"].as_str().unwrap();

    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);
    let plaintext = decode_hex(plaintext_hex);

    let key_array: [u8; 32] = key.try_into().expect("Key must be 32 bytes");
    let nonce_array: [u8; 12] = nonce.try_into().expect("Nonce must be 12 bytes");

    // Generate keystream starting from block 0, skip to block `seek_block`
    let mut chacha_full = ChaCha20::new(&key_array, &nonce_array, 0);
    let skip_bytes = (seek_block as usize) * 64;
    let mut skip_data = vec![0u8; skip_bytes + plaintext.len()];
    chacha_full.encrypt(&mut skip_data);
    let expected_keystream = skip_data[skip_bytes..].to_vec();

    // Now seek directly to block `seek_block`
    let mut chacha_seek = ChaCha20::new(&key_array, &nonce_array, 0);
    chacha_seek.seek(seek_block);
    let mut output = plaintext.clone();
    chacha_seek.encrypt(&mut output);

    // Compare - both should produce same result
    let mut expected = plaintext.clone();
    for (e, k) in expected.iter_mut().zip(expected_keystream.iter()) {
        *e ^= k;
    }

    if output == expected {
        println!("  Seek to block {} produces correct keystream", seek_block);
        stats.passed += 1;
    } else {
        println!("  Seek produced different keystream");
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&output));
        stats.failed += 1;
    }
}

fn test_chacha20_partial_blocks(data: &Value, stats: &mut TestStats) {
    use hpcrypt_cipher::ChaCha20;

    let key_hex = data["key"].as_str().unwrap();
    let nonce_hex = data["nonce"].as_str().unwrap();
    let counter = data["counter"].as_u64().unwrap() as u32;
    let test_lengths: Vec<usize> = data["test_lengths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as usize)
        .collect();

    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);

    let key_array: [u8; 32] = key.try_into().expect("Key must be 32 bytes");
    let nonce_array: [u8; 12] = nonce.try_into().expect("Nonce must be 12 bytes");

    let mut all_passed = true;

    for len in test_lengths {
        // Generate plaintext
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();

        // Encrypt
        let mut chacha_enc = ChaCha20::new(&key_array, &nonce_array, counter);
        let mut ciphertext = plaintext.clone();
        chacha_enc.encrypt(&mut ciphertext);

        // Decrypt
        let mut chacha_dec = ChaCha20::new(&key_array, &nonce_array, counter);
        let mut decrypted = ciphertext.clone();
        chacha_dec.decrypt(&mut decrypted);

        if decrypted != plaintext {
            println!("    Roundtrip failed for length {}", len);
            all_passed = false;
        }
    }

    if all_passed {
        println!("  All partial block lengths roundtrip correctly");
        stats.passed += 1;
    } else {
        stats.failed += 1;
    }
}

#[test]
fn test_chacha20_vector_count() {
    let test_vectors: Vec<ChaCha20TestVector> = load_test_file("rfc8439-chacha20.json");
    assert!(test_vectors.len() > 0, "RFC 8439 should have test vectors");
    println!("ChaCha20 test vectors loaded: {}", test_vectors.len());
}

/// Test ChaCha20 with various message sizes
#[test]
fn test_chacha20_various_sizes() {
    use hpcrypt_cipher::ChaCha20;

    println!("\n=== ChaCha20 Various Message Sizes ===");

    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];

    let sizes = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 128, 256, 1000];

    for size in sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let mut chacha_enc = ChaCha20::new(&key, &nonce, 0);
        let mut ciphertext = plaintext.clone();
        chacha_enc.encrypt(&mut ciphertext);

        let mut chacha_dec = ChaCha20::new(&key, &nonce, 0);
        let mut decrypted = ciphertext.clone();
        chacha_dec.decrypt(&mut decrypted);

        assert_eq!(
            decrypted, plaintext,
            "Roundtrip failed for size {}",
            size
        );
    }

    println!("  All message sizes passed");
}

/// Test that different keys produce different ciphertexts
#[test]
fn test_chacha20_key_sensitivity() {
    use hpcrypt_cipher::ChaCha20;

    println!("\n=== ChaCha20 Key Sensitivity ===");

    let nonce = [0x01u8; 12];
    let plaintext = b"Hello, ChaCha20!";

    let key1 = [0x00u8; 32];
    let key2 = [0x01u8; 32];

    let mut ct1 = plaintext.to_vec();
    ChaCha20::new(&key1, &nonce, 0).encrypt(&mut ct1);

    let mut ct2 = plaintext.to_vec();
    ChaCha20::new(&key2, &nonce, 0).encrypt(&mut ct2);

    assert_ne!(ct1, ct2, "Different keys should produce different ciphertexts");
    println!("  Different keys produce different ciphertexts");
}

/// Test that different nonces produce different ciphertexts
#[test]
fn test_chacha20_nonce_sensitivity() {
    use hpcrypt_cipher::ChaCha20;

    println!("\n=== ChaCha20 Nonce Sensitivity ===");

    let key = [0x42u8; 32];
    let plaintext = b"Hello, ChaCha20!";

    let nonce1 = [0x00u8; 12];
    let nonce2 = [0x01u8; 12];

    let mut ct1 = plaintext.to_vec();
    ChaCha20::new(&key, &nonce1, 0).encrypt(&mut ct1);

    let mut ct2 = plaintext.to_vec();
    ChaCha20::new(&key, &nonce2, 0).encrypt(&mut ct2);

    assert_ne!(ct1, ct2, "Different nonces should produce different ciphertexts");
    println!("  Different nonces produce different ciphertexts");
}

/// Test incremental encryption matches single-shot
#[test]
fn test_chacha20_incremental() {
    use hpcrypt_cipher::ChaCha20;

    println!("\n=== ChaCha20 Incremental Encryption ===");

    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let plaintext = b"The quick brown fox jumps over the lazy dog. 1234567890!";

    // Single-shot encryption
    let mut chacha_single = ChaCha20::new(&key, &nonce, 0);
    let mut ct_single = plaintext.to_vec();
    chacha_single.encrypt(&mut ct_single);

    // Incremental encryption
    let mut chacha_inc = ChaCha20::new(&key, &nonce, 0);
    let mut ct_inc = plaintext.to_vec();
    chacha_inc.encrypt(&mut ct_inc[..10]);
    chacha_inc.encrypt(&mut ct_inc[10..30]);
    chacha_inc.encrypt(&mut ct_inc[30..]);

    assert_eq!(
        ct_single, ct_inc,
        "Incremental encryption should match single-shot"
    );
    println!("  Incremental encryption matches single-shot");
}

/// Test XChaCha20 roundtrip standalone
#[test]
fn test_xchacha20_roundtrip_standalone() {
    use hpcrypt_cipher::XChaCha20;

    println!("\n=== XChaCha20 Roundtrip (Standalone) ===");

    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24]; // 24-byte nonce for XChaCha20
    let plaintext = b"XChaCha20 with extended nonce!";

    let mut ciphertext = plaintext.to_vec();
    XChaCha20::new(&key, &nonce, 0).encrypt(&mut ciphertext);

    assert_ne!(&ciphertext[..], &plaintext[..], "Ciphertext should differ");

    let mut decrypted = ciphertext.clone();
    XChaCha20::new(&key, &nonce, 0).decrypt(&mut decrypted);

    assert_eq!(&decrypted[..], &plaintext[..], "Decryption should recover plaintext");
    println!("  XChaCha20 roundtrip successful");
}
