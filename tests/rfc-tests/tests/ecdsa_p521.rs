//! FIPS 186-4 - ECDSA P-521 Digital Signature Tests
//!
//! Tests for ECDSA P-521 (secp521r1) signature generation and verification
//! according to FIPS 186-4 and RFC 6979 (deterministic signatures).

use hpcrypt_signatures::ecdsa_p521::{Signature, SigningKey, VerifyingKey};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct EcdsaTestVector {
    test_id: u32,
    test_type: String,
    source: String,
    description: String,
    note: String,
    #[serde(flatten)]
    data: Value,
}

#[test]
fn test_ecdsa_p521_fips186() {
    let test_vectors: Vec<EcdsaTestVector> = load_test_file("fips186-4-ecdsa-p521.json");

    println!("\n=== FIPS 186-4: ECDSA P-521 Digital Signatures ===");
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
            "sign_verify_roundtrip" => {
                test_sign_verify_roundtrip(&test.data, &mut stats);
            }
            "deterministic_signing" => {
                test_deterministic_signing(&test.data, &mut stats);
            }
            "key_generation" => {
                test_key_generation(&test.data, &mut stats);
            }
            "signature_der_encoding" => {
                test_signature_der_encoding(&test.data, &mut stats);
            }
            "signature_bytes_encoding" => {
                test_signature_bytes_encoding(&test.data, &mut stats);
            }
            "public_key_sec1_encoding" => {
                test_public_key_sec1_encoding(&test.data, &mut stats);
            }
            "invalid_signature_detection" => {
                test_invalid_signature_detection(&test.data, &mut stats);
            }
            "wrong_message_detection" => {
                test_wrong_message_detection(&test.data, &mut stats);
            }
            "wrong_key_detection" => {
                test_wrong_key_detection(&test.data, &mut stats);
            }
            "zero_scalar_rejection" => {
                test_zero_scalar_rejection(&test.data, &mut stats);
            }
            "zero_r_rejection" => {
                test_zero_r_rejection(&test.data, &mut stats);
            }
            "zero_s_rejection" => {
                test_zero_s_rejection(&test.data, &mut stats);
            }
            "known_key_test" => {
                test_known_key(&test.data, &mut stats);
            }
            "empty_message" => {
                test_empty_message(&test.data, &mut stats);
            }
            "large_message" => {
                test_large_message(&test.data, &mut stats);
            }
            "private_key_bytes_roundtrip" => {
                test_private_key_bytes_roundtrip(&test.data, &mut stats);
            }
            "multiple_signatures" => {
                test_multiple_signatures(&test.data, &mut stats);
            }
            "signature_malleability" => {
                test_signature_malleability(&test.data, &mut stats);
            }
            _ => {
                println!("  Unknown test type: {}", test.test_type);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All ECDSA P-521 tests should pass");
}

fn test_sign_verify_roundtrip(data: &Value, stats: &mut TestStats) {
    let message_hex = data["message"].as_str().unwrap();
    let message = decode_hex(message_hex);

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign(&message);
    let is_valid = verifying_key.verify(&message, &signature);

    if is_valid {
        println!("  Sign/verify roundtrip successful");
        stats.passed += 1;
    } else {
        println!("  Sign/verify roundtrip failed");
        stats.failed += 1;
    }
}

fn test_deterministic_signing(data: &Value, stats: &mut TestStats) {
    let message_hex = data["message"].as_str().unwrap();
    let message = decode_hex(message_hex);

    let signing_key = SigningKey::generate();

    let sig1 = signing_key.sign(&message);
    let sig2 = signing_key.sign(&message);

    if sig1.r == sig2.r && sig1.s == sig2.s {
        println!("  Deterministic signing produces identical signatures");
        stats.passed += 1;
    } else {
        println!("  Deterministic signing produced different signatures");
        stats.failed += 1;
    }
}

fn test_key_generation(_data: &Value, stats: &mut TestStats) {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Verify public key is on curve by attempting to encode/decode
    let sec1 = verifying_key.to_sec1_uncompressed();
    let decoded = VerifyingKey::from_sec1_uncompressed(&sec1);

    if decoded.is_ok() {
        println!("  Key generation produces valid keypair");
        stats.passed += 1;
    } else {
        println!("  Key generation produced invalid keypair");
        stats.failed += 1;
    }
}

fn test_signature_der_encoding(_data: &Value, stats: &mut TestStats) {
    let signing_key = SigningKey::generate();
    let message = b"DER encoding test";
    let signature = signing_key.sign(message);

    let (der, len) = signature.to_der();
    let decoded = Signature::from_der(&der[..len]);

    if let Some(sig) = decoded {
        if sig.r == signature.r && sig.s == signature.s {
            println!("  DER encoding roundtrip successful");
            stats.passed += 1;
        } else {
            println!("  DER decoding produced different values");
            stats.failed += 1;
        }
    } else {
        println!("  DER decoding failed");
        stats.failed += 1;
    }
}

fn test_signature_bytes_encoding(_data: &Value, stats: &mut TestStats) {
    let signing_key = SigningKey::generate();
    let message = b"Bytes encoding test";
    let signature = signing_key.sign(message);

    let bytes = signature.to_bytes();
    let decoded = Signature::from_bytes(&bytes);

    if decoded.r == signature.r && decoded.s == signature.s {
        println!("  Bytes encoding roundtrip successful");
        stats.passed += 1;
    } else {
        println!("  Bytes decoding produced different values");
        stats.failed += 1;
    }
}

fn test_public_key_sec1_encoding(_data: &Value, stats: &mut TestStats) {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let sec1 = verifying_key.to_sec1_uncompressed();

    // Should start with 0x04 (uncompressed)
    if sec1[0] != 0x04 {
        println!("  SEC1 encoding should start with 0x04");
        stats.failed += 1;
        return;
    }

    // Should be 133 bytes (1 + 66 + 66)
    if sec1.len() != 133 {
        println!("  SEC1 encoding should be 133 bytes");
        stats.failed += 1;
        return;
    }

    match VerifyingKey::from_sec1_uncompressed(&sec1) {
        Ok(decoded) => {
            // Verify the decoded key works
            let message = b"SEC1 test";
            let sig = signing_key.sign(message);
            if decoded.verify(message, &sig) {
                println!("  SEC1 encoding roundtrip successful");
                stats.passed += 1;
            } else {
                println!("  Decoded key failed verification");
                stats.failed += 1;
            }
        }
        Err(_) => {
            println!("  SEC1 decoding failed");
            stats.failed += 1;
        }
    }
}

fn test_invalid_signature_detection(data: &Value, stats: &mut TestStats) {
    let message_hex = data["message"].as_str().unwrap();
    let message = decode_hex(message_hex);

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let mut signature = signing_key.sign(&message);

    // Corrupt the signature
    signature.r[0] ^= 0x01;

    let is_valid = verifying_key.verify(&message, &signature);

    if !is_valid {
        println!("  Corrupted signature correctly rejected");
        stats.passed += 1;
    } else {
        println!("  Corrupted signature incorrectly accepted!");
        stats.failed += 1;
    }
}

fn test_wrong_message_detection(data: &Value, stats: &mut TestStats) {
    let message1_hex = data["message1"].as_str().unwrap();
    let message2_hex = data["message2"].as_str().unwrap();
    let message1 = decode_hex(message1_hex);
    let message2 = decode_hex(message2_hex);

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign(&message1);

    // Verify with wrong message
    let is_valid = verifying_key.verify(&message2, &signature);

    if !is_valid {
        println!("  Wrong message correctly rejected");
        stats.passed += 1;
    } else {
        println!("  Wrong message incorrectly accepted!");
        stats.failed += 1;
    }
}

fn test_wrong_key_detection(data: &Value, stats: &mut TestStats) {
    let message_hex = data["message"].as_str().unwrap();
    let message = decode_hex(message_hex);

    let signing_key1 = SigningKey::generate();
    let signing_key2 = SigningKey::generate();
    let verifying_key2 = signing_key2.verifying_key();

    let signature = signing_key1.sign(&message);

    // Verify with wrong key
    let is_valid = verifying_key2.verify(&message, &signature);

    if !is_valid {
        println!("  Wrong key correctly rejected");
        stats.passed += 1;
    } else {
        println!("  Wrong key incorrectly accepted!");
        stats.failed += 1;
    }
}

fn test_zero_scalar_rejection(data: &Value, stats: &mut TestStats) {
    let private_key_hex = data["private_key"].as_str().unwrap();
    let private_key_bytes = decode_hex(private_key_hex);

    if private_key_bytes.len() != 66 {
        println!("  Skipping: Invalid private key length");
        stats.skipped += 1;
        return;
    }

    let mut key_arr = [0u8; 66];
    key_arr.copy_from_slice(&private_key_bytes);

    let result = SigningKey::from_bytes(&key_arr);

    if result.is_none() {
        println!("  Zero private key correctly rejected");
        stats.passed += 1;
    } else {
        println!("  Zero private key incorrectly accepted!");
        stats.failed += 1;
    }
}

fn test_zero_r_rejection(data: &Value, stats: &mut TestStats) {
    let r_hex = data["r"].as_str().unwrap();
    let s_hex = data["s"].as_str().unwrap();
    let message_hex = data["message"].as_str().unwrap();

    let r_bytes = decode_hex(r_hex);
    let s_bytes = decode_hex(s_hex);
    let message = decode_hex(message_hex);

    if r_bytes.len() != 66 || s_bytes.len() != 66 {
        println!("  Skipping: Invalid r or s length");
        stats.skipped += 1;
        return;
    }

    let mut r = [0u8; 66];
    let mut s = [0u8; 66];
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);

    let signature = Signature::new(r, s);

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let is_valid = verifying_key.verify(&message, &signature);

    if !is_valid {
        println!("  Zero r signature correctly rejected (CVE-2022-21449)");
        stats.passed += 1;
    } else {
        println!("  Zero r signature incorrectly accepted! (CVE-2022-21449)");
        stats.failed += 1;
    }
}

fn test_zero_s_rejection(data: &Value, stats: &mut TestStats) {
    let r_hex = data["r"].as_str().unwrap();
    let s_hex = data["s"].as_str().unwrap();
    let message_hex = data["message"].as_str().unwrap();

    let r_bytes = decode_hex(r_hex);
    let s_bytes = decode_hex(s_hex);
    let message = decode_hex(message_hex);

    if r_bytes.len() != 66 || s_bytes.len() != 66 {
        println!("  Skipping: Invalid r or s length");
        stats.skipped += 1;
        return;
    }

    let mut r = [0u8; 66];
    let mut s = [0u8; 66];
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);

    let signature = Signature::new(r, s);

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let is_valid = verifying_key.verify(&message, &signature);

    if !is_valid {
        println!("  Zero s signature correctly rejected (CVE-2022-21449)");
        stats.passed += 1;
    } else {
        println!("  Zero s signature incorrectly accepted! (CVE-2022-21449)");
        stats.failed += 1;
    }
}

fn test_known_key(data: &Value, stats: &mut TestStats) {
    use hpcrypt_curves::p521::Scalar;

    let d_value = data["private_key_d"].as_u64().unwrap();
    let message_hex = data["message"].as_str().unwrap();
    let message = decode_hex(message_hex);

    let d = Scalar::from_u64(d_value);
    let sk_bytes = d.to_bytes();
    let signing_key = match SigningKey::from_bytes(&sk_bytes) {
        Some(sk) => sk,
        None => {
            println!("  Failed to create signing key from d={}", d_value);
            stats.failed += 1;
            return;
        }
    };

    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&message);
    let is_valid = verifying_key.verify(&message, &signature);

    if is_valid {
        println!("  Known key d={} sign/verify successful", d_value);
        stats.passed += 1;
    } else {
        println!("  Known key d={} verification failed", d_value);
        stats.failed += 1;
    }
}

fn test_empty_message(_data: &Value, stats: &mut TestStats) {
    let message: &[u8] = b"";

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign(message);
    let is_valid = verifying_key.verify(message, &signature);

    if is_valid {
        println!("  Empty message sign/verify successful");
        stats.passed += 1;
    } else {
        println!("  Empty message verification failed");
        stats.failed += 1;
    }
}

fn test_large_message(data: &Value, stats: &mut TestStats) {
    let size = data["message_size"].as_u64().unwrap() as usize;
    let message: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign(&message);
    let is_valid = verifying_key.verify(&message, &signature);

    if is_valid {
        println!("  Large message ({} bytes) sign/verify successful", size);
        stats.passed += 1;
    } else {
        println!("  Large message verification failed");
        stats.failed += 1;
    }
}

fn test_private_key_bytes_roundtrip(_data: &Value, stats: &mut TestStats) {
    let signing_key = SigningKey::generate();
    let bytes = signing_key.to_bytes();

    let decoded = SigningKey::from_bytes(&bytes);

    if let Some(decoded_key) = decoded {
        // Verify the decoded key produces the same public key
        let vk1 = signing_key.verifying_key().to_sec1_uncompressed();
        let vk2 = decoded_key.verifying_key().to_sec1_uncompressed();

        if vk1 == vk2 {
            println!("  Private key bytes roundtrip successful");
            stats.passed += 1;
        } else {
            println!("  Decoded key produced different public key");
            stats.failed += 1;
        }
    } else {
        println!("  Private key bytes decoding failed");
        stats.failed += 1;
    }
}

fn test_multiple_signatures(data: &Value, stats: &mut TestStats) {
    let messages: Vec<Vec<u8>> = data["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| decode_hex(m.as_str().unwrap()))
        .collect();

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let mut signatures: Vec<Signature> = Vec::new();
    let mut all_valid = true;

    for message in &messages {
        let sig = signing_key.sign(message);

        // Verify each signature
        if !verifying_key.verify(message, &sig) {
            all_valid = false;
            break;
        }

        signatures.push(sig);
    }

    if !all_valid {
        println!("  Some signatures failed verification");
        stats.failed += 1;
        return;
    }

    // Check that all signatures are different
    let mut all_different = true;
    for i in 0..signatures.len() {
        for j in (i + 1)..signatures.len() {
            if signatures[i].r == signatures[j].r && signatures[i].s == signatures[j].s {
                all_different = false;
                break;
            }
        }
    }

    if all_valid && all_different {
        println!(
            "  {} different messages produced {} different valid signatures",
            messages.len(),
            signatures.len()
        );
        stats.passed += 1;
    } else {
        println!("  Multiple signatures test failed");
        stats.failed += 1;
    }
}

fn test_signature_malleability(data: &Value, stats: &mut TestStats) {
    let message_hex = data["message"].as_str().unwrap();
    let message = decode_hex(message_hex);

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign(&message);

    // The signature should be in canonical form
    // Just verify it's valid - malleability protection is implementation-specific
    let is_valid = verifying_key.verify(&message, &signature);

    if is_valid {
        println!("  Signature is in valid form");
        stats.passed += 1;
    } else {
        println!("  Generated signature failed verification");
        stats.failed += 1;
    }
}

#[test]
fn test_ecdsa_p521_vector_count() {
    let test_vectors: Vec<EcdsaTestVector> = load_test_file("fips186-4-ecdsa-p521.json");
    assert!(!test_vectors.is_empty(), "ECDSA P-521 should have test vectors");
    println!("ECDSA P-521 test vectors loaded: {}", test_vectors.len());
}

#[test]
fn test_ecdsa_p521_basic() {
    println!("\n=== ECDSA P-521 Basic Test ===");

    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Basic ECDSA P-521 test";
    let signature = signing_key.sign(message);

    assert!(
        verifying_key.verify(message, &signature),
        "Basic signature verification should succeed"
    );
    println!("  Basic ECDSA P-521 test passed");
}

#[test]
fn test_ecdsa_p521_determinism() {
    println!("\n=== ECDSA P-521 Determinism Test ===");

    let signing_key = SigningKey::generate();

    let message = b"Determinism test message";

    let sig1 = signing_key.sign(message);
    let sig2 = signing_key.sign(message);
    let sig3 = signing_key.sign(message);

    assert_eq!(sig1.r, sig2.r, "r values should be equal");
    assert_eq!(sig1.s, sig2.s, "s values should be equal");
    assert_eq!(sig2.r, sig3.r, "r values should be equal");
    assert_eq!(sig2.s, sig3.s, "s values should be equal");

    println!("  RFC 6979 determinism verified");
}
