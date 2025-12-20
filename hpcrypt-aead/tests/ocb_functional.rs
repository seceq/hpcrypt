//! AES-OCB3 Functional Tests
//!
//! Property-based and functional tests for OCB3 authenticated encryption mode.
//! These tests verify behavior with various message lengths, AAD sizes,
//! authentication failure detection, and nonce variations.

use hpcrypt_aead::{Aes128Ocb, Aes256Ocb};

#[test]
fn test_aes128_ocb_basic_roundtrip() {
    println!("\n=== AES-OCB3: Basic Roundtrip Tests ===");

    // AES-128-OCB
    let key128 = [0x00u8; 16];
    let nonce = [0x00u8; 12];
    let plaintext = b"Hello, AES-OCB3!";
    let aad = b"associated data";

    let ct = Aes128Ocb::encrypt(&key128, &nonce, plaintext, aad);
    let pt = Aes128Ocb::decrypt(&key128, &nonce, &ct, aad).expect("AES-128-OCB decrypt failed");
    assert_eq!(pt, plaintext);
    println!("  [PASS] AES-128-OCB basic roundtrip");

    // AES-256-OCB
    let key256 = [0x42u8; 32];
    let ct = Aes256Ocb::encrypt(&key256, &nonce, plaintext, aad);
    let pt = Aes256Ocb::decrypt(&key256, &nonce, &ct, aad).expect("AES-256-OCB decrypt failed");
    assert_eq!(pt, plaintext);
    println!("  [PASS] AES-256-OCB basic roundtrip");
}

#[test]
fn test_aes_ocb_various_lengths() {
    println!("\n=== AES-OCB3: Various Message Lengths ===");

    let key = [0x01u8; 16];
    let nonce = [0x02u8; 12];
    let aad = b"test aad";

    // Test various lengths including block boundaries
    let lengths = [0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 100, 256, 1000];

    for len in lengths {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let ct = Aes128Ocb::encrypt(&key, &nonce, &plaintext, aad);

        // Verify ciphertext length = plaintext + 16 (tag)
        assert_eq!(ct.len(), len + 16, "Length {}: wrong ciphertext size", len);

        let pt = Aes128Ocb::decrypt(&key, &nonce, &ct, aad)
            .unwrap_or_else(|_| panic!("Length {}: decrypt failed", len));
        assert_eq!(pt, plaintext, "Length {}: roundtrip mismatch", len);
    }

    println!("  [PASS] Tested {} different message lengths", lengths.len());
}

#[test]
fn test_aes_ocb_aad_variations() {
    println!("\n=== AES-OCB3: AAD Variations ===");

    let key = [0x03u8; 16];
    let nonce = [0x04u8; 12];
    let plaintext = b"test message";

    // Test various AAD lengths
    let aad_lengths = [0, 1, 15, 16, 17, 32, 100];

    for len in aad_lengths {
        let aad: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let ct = Aes128Ocb::encrypt(&key, &nonce, plaintext, &aad);

        let pt = Aes128Ocb::decrypt(&key, &nonce, &ct, &aad)
            .unwrap_or_else(|_| panic!("AAD length {}: decrypt failed", len));
        assert_eq!(pt, plaintext, "AAD length {}: roundtrip mismatch", len);
    }

    println!("  [PASS] Tested {} different AAD lengths", aad_lengths.len());
}

#[test]
fn test_aes_ocb_authentication_failure() {
    println!("\n=== AES-OCB3: Authentication Failure Detection ===");

    let key = [0x05u8; 16];
    let nonce = [0x06u8; 12];
    let plaintext = b"secret message";
    let aad = b"authenticated";

    let mut ct = Aes128Ocb::encrypt(&key, &nonce, plaintext, aad);

    // Test 1: Tamper with ciphertext
    ct[0] ^= 0x01;
    assert!(
        Aes128Ocb::decrypt(&key, &nonce, &ct, aad).is_err(),
        "Ciphertext tampering NOT detected"
    );
    println!("  [PASS] Ciphertext tampering detected");
    ct[0] ^= 0x01; // Restore

    // Test 2: Tamper with tag
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert!(
        Aes128Ocb::decrypt(&key, &nonce, &ct, aad).is_err(),
        "Tag tampering NOT detected"
    );
    println!("  [PASS] Tag tampering detected");
    ct[last] ^= 0x01; // Restore

    // Test 3: Wrong AAD
    assert!(
        Aes128Ocb::decrypt(&key, &nonce, &ct, b"wrong aad").is_err(),
        "Wrong AAD NOT detected"
    );
    println!("  [PASS] Wrong AAD detected");

    // Test 4: Wrong key
    let wrong_key = [0xFFu8; 16];
    assert!(
        Aes128Ocb::decrypt(&wrong_key, &nonce, &ct, aad).is_err(),
        "Wrong key NOT detected"
    );
    println!("  [PASS] Wrong key detected");

    // Test 5: Wrong nonce
    let wrong_nonce = [0xFFu8; 12];
    assert!(
        Aes128Ocb::decrypt(&key, &wrong_nonce, &ct, aad).is_err(),
        "Wrong nonce NOT detected"
    );
    println!("  [PASS] Wrong nonce detected");
}

#[test]
fn test_aes_ocb_nonce_variations() {
    println!("\n=== AES-OCB3: Nonce Variations ===");

    let key = [0x07u8; 16];
    let plaintext = b"nonce test";
    let aad = b"aad";

    // OCB supports nonce sizes 1-15 bytes (recommended: 12)
    let nonce_lengths = [1, 8, 12, 15];

    for len in nonce_lengths {
        let nonce: Vec<u8> = (0..len).map(|i| (i + 1) as u8).collect();
        let ct = Aes128Ocb::encrypt(&key, &nonce, plaintext, aad);

        let pt = Aes128Ocb::decrypt(&key, &nonce, &ct, aad)
            .unwrap_or_else(|_| panic!("Nonce length {}: decrypt failed", len));
        assert_eq!(pt, plaintext, "Nonce length {}: roundtrip mismatch", len);
    }

    println!("  [PASS] Tested {} different nonce lengths", nonce_lengths.len());
}

#[test]
fn test_aes_ocb_different_ciphertexts() {
    println!("\n=== AES-OCB3: Unique Ciphertexts ===");

    let key = [0x08u8; 16];
    let plaintext = b"same message";
    let aad = b"same aad";

    // Different nonces should produce different ciphertexts
    let nonce1 = [0x01u8; 12];
    let nonce2 = [0x02u8; 12];

    let ct1 = Aes128Ocb::encrypt(&key, &nonce1, plaintext, aad);
    let ct2 = Aes128Ocb::encrypt(&key, &nonce2, plaintext, aad);

    assert_ne!(ct1, ct2, "Different nonces produced SAME ciphertext");
    println!("  [PASS] Different nonces produce different ciphertexts");

    // Same nonce should produce same ciphertext (deterministic)
    let ct3 = Aes128Ocb::encrypt(&key, &nonce1, plaintext, aad);
    assert_eq!(ct1, ct3, "Same inputs produced DIFFERENT ciphertext");
    println!("  [PASS] Same inputs produce same ciphertext (deterministic)");
}

#[test]
fn test_aes_ocb_empty_inputs() {
    println!("\n=== AES-OCB3: Empty Input Handling ===");

    let key = [0x09u8; 16];
    let nonce = [0x0Au8; 12];

    // Empty plaintext, empty AAD
    let ct = Aes128Ocb::encrypt(&key, &nonce, b"", b"");
    assert_eq!(ct.len(), 16, "Wrong ciphertext length for empty plaintext");
    let pt = Aes128Ocb::decrypt(&key, &nonce, &ct, b"").expect("Empty pt + empty AAD failed");
    assert!(pt.is_empty());
    println!("  [PASS] Empty plaintext + empty AAD");

    // Empty plaintext, non-empty AAD
    let ct = Aes128Ocb::encrypt(&key, &nonce, b"", b"some aad");
    let pt = Aes128Ocb::decrypt(&key, &nonce, &ct, b"some aad")
        .expect("Empty pt + non-empty AAD failed");
    assert!(pt.is_empty());
    println!("  [PASS] Empty plaintext + non-empty AAD");

    // Non-empty plaintext, empty AAD
    let ct = Aes128Ocb::encrypt(&key, &nonce, b"message", b"");
    let pt =
        Aes128Ocb::decrypt(&key, &nonce, &ct, b"").expect("Non-empty pt + empty AAD failed");
    assert_eq!(pt, b"message");
    println!("  [PASS] Non-empty plaintext + empty AAD");
}

#[test]
fn test_aes256_ocb_comprehensive() {
    println!("\n=== AES-256-OCB3: Comprehensive Tests ===");

    let key = [0x42u8; 32];

    // Test various combinations
    let test_cases: [([u8; 12], &[u8], &[u8]); 3] = [
        ([0x01u8; 12], b"short", b"aad"),
        ([0x02u8; 12], b"exactly 16 bytes", b""),
        (
            [0x03u8; 12],
            b"longer message that spans multiple blocks",
            b"associated authenticated data",
        ),
    ];

    for (i, (nonce, plaintext, aad)) in test_cases.iter().enumerate() {
        let ct = Aes256Ocb::encrypt(&key, nonce, plaintext, aad);

        let pt = Aes256Ocb::decrypt(&key, nonce, &ct, aad)
            .unwrap_or_else(|_| panic!("Test case {} failed", i));
        assert_eq!(pt, *plaintext, "Test case {} mismatch", i);
    }

    println!("  [PASS] Tested {} AES-256-OCB cases", test_cases.len());
}
