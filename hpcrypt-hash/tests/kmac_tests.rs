//! KMAC128 and KMAC256 test vectors and functionality tests
//!
//! Test vectors from NIST SP 800-185 and additional functional tests

use hex_literal::hex;
use hpcrypt_hash::kmac::{kmac128, kmac256, Kmac128, Kmac256};

// ===== NIST SP 800-185 Test Vectors =====

#[test]
fn test_kmac128_sample_1() {
    // NIST SP 800-185 Sample #1
    // K = 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
    //     50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
    // X = 00 01 02 03
    // L = 256
    // S = ""
    let key = hex!("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    let data = hex!("00010203");
    let expected = hex!(
        "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"
    );

    let output = kmac128(&key, &data, b"", 32);
    assert_eq!(&output[..], &expected[..], "KMAC128 Sample #1 failed");
}

#[test]
fn test_kmac128_sample_4() {
    // NIST SP 800-185 Sample #4 (with customization string)
    // K = 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
    //     50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
    // X = 00 01 02 03
    // L = 256
    // S = "My Tagged Application"
    let key = hex!("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    let data = hex!("00010203");
    let customization = b"My Tagged Application";
    let expected = hex!(
        "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"
    );

    let output = kmac128(&key, &data, customization, 32);
    assert_eq!(&output[..], &expected[..], "KMAC128 Sample #4 failed");
}

#[test]
fn test_kmac256_sample_5() {
    // NIST SP 800-185 Sample #5
    // K = 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
    //     50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
    // X = 00 01 02 03
    // L = 512
    // S = "My Tagged Application"
    let key = hex!("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    let data = hex!("00010203");
    let customization = b"My Tagged Application";
    let expected = hex!(
        "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
        "F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"
    );

    let output = kmac256(&key, &data, customization, 64);
    assert_eq!(&output[..], &expected[..], "KMAC256 Sample #5 failed");
}

// ===== Functional Tests =====

#[test]
fn test_kmac128_empty_message() {
    let key = b"test-key";
    let mac = kmac128(key, b"", b"", 32);

    // Should produce deterministic output for empty message
    let mac2 = kmac128(key, b"", b"", 32);
    assert_eq!(mac, mac2, "Empty message should be deterministic");
}

#[test]
fn test_kmac256_empty_message() {
    let key = b"test-key";
    let mac = kmac256(key, b"", b"", 64);

    // Should produce deterministic output
    let mac2 = kmac256(key, b"", b"", 64);
    assert_eq!(mac, mac2, "Empty message should be deterministic");
}

#[test]
fn test_kmac128_incremental() {
    let key = b"incremental-key";
    let data = b"Hello, World!";

    // Process all at once
    let mac1 = kmac128(key, data, b"", 32);

    // Process incrementally
    let mut kmac2 = Kmac128::new(key, b"");
    kmac2.update(b"Hello, ");
    kmac2.update(b"World!");
    let mac2 = kmac2.finalize(32);

    assert_eq!(mac1, mac2, "Incremental processing should match");
}

#[test]
fn test_kmac256_incremental() {
    let key = b"incremental-key";
    let data = b"abcdefghijklmnopqrstuvwxyz";

    // Single update
    let mac1 = kmac256(key, data, b"", 64);

    // Multiple small updates
    let mut kmac2 = Kmac256::new(key, b"");
    for c in data {
        kmac2.update(&[*c]);
    }
    let mac2 = kmac2.finalize(64);

    assert_eq!(mac1, mac2, "Byte-by-byte should match bulk");
}

#[test]
fn test_kmac_different_keys() {
    let key1 = b"key1";
    let key2 = b"key2";
    let message = b"same message";

    let mac1 = kmac128(key1, message, b"", 32);
    let mac2 = kmac128(key2, message, b"", 32);

    assert_ne!(mac1, mac2, "Different keys should produce different MACs");
}

#[test]
fn test_kmac_different_messages() {
    let key = b"same-key";

    let mac1 = kmac128(key, b"message1", b"", 32);
    let mac2 = kmac128(key, b"message2", b"", 32);

    assert_ne!(mac1, mac2, "Different messages should produce different MACs");
}

#[test]
fn test_kmac_different_customization() {
    let key = b"key";
    let message = b"message";

    let mac1 = kmac128(key, message, b"custom1", 32);
    let mac2 = kmac128(key, message, b"custom2", 32);

    assert_ne!(
        mac1, mac2,
        "Different customization strings should produce different MACs"
    );
}

#[test]
fn test_kmac128_variable_output() {
    let key = b"var-output-key";
    let message = b"test message";

    // KMAC can produce different output lengths
    let mac_16 = kmac128(key, message, b"", 16);
    let mac_32 = kmac128(key, message, b"", 32);
    let mac_64 = kmac128(key, message, b"", 64);

    assert_eq!(mac_16.len(), 16, "16-byte output should be 16 bytes");
    assert_eq!(mac_32.len(), 32, "32-byte output should be 32 bytes");
    assert_eq!(mac_64.len(), 64, "64-byte output should be 64 bytes");

    // Different output lengths produce independent outputs (not prefixes)
    // because KMAC encodes the output length in the input
    assert_ne!(&mac_32[..16], &mac_16[..], "Different lengths produce different outputs");
    assert_ne!(&mac_64[..32], &mac_32[..], "Different lengths produce different outputs");
}

#[test]
fn test_kmac256_variable_output() {
    let key = b"var-output-key";
    let message = b"test message";

    let mac_16 = kmac256(key, message, b"", 16);
    let mac_32 = kmac256(key, message, b"", 32);
    let mac_64 = kmac256(key, message, b"", 64);

    assert_eq!(mac_16.len(), 16, "16-byte output should be 16 bytes");
    assert_eq!(mac_32.len(), 32, "32-byte output should be 32 bytes");
    assert_eq!(mac_64.len(), 64, "64-byte output should be 64 bytes");

    // Different output lengths produce independent outputs
    assert_ne!(&mac_32[..16], &mac_16[..]);
    assert_ne!(&mac_64[..32], &mac_32[..]);
}

#[test]
fn test_kmac128_verification() {
    let key = b"verify-key";
    let message = b"authentic message";

    // Generate MAC
    let mac = kmac128(key, message, b"", 32);

    // Verify correct MAC
    assert!(Kmac128::verify(key, message, b"", &mac), "Correct MAC should verify");

    // Verify tampered MAC
    let mut tampered_mac = mac.clone();
    tampered_mac[0] ^= 0x01;
    assert!(!Kmac128::verify(key, message, b"", &tampered_mac), "Tampered MAC should not verify");

    // Verify with wrong key
    assert!(!Kmac128::verify(b"wrong-key", message, b"", &mac), "Wrong key should not verify");

    // Verify with wrong message
    assert!(!Kmac128::verify(key, b"wrong message", b"", &mac), "Wrong message should not verify");
}

#[test]
fn test_kmac256_verification() {
    let key = b"verify-key";
    let message = b"authentic message";

    let mac = kmac256(key, message, b"", 64);

    // Correct verification
    assert!(Kmac256::verify(key, message, b"", &mac));

    // Wrong length should not verify
    assert!(!Kmac256::verify(key, message, b"", &mac[..32]));
}

#[test]
fn test_kmac_long_key() {
    // Test with key longer than rate
    let long_key = vec![0x42; 200];
    let message = b"test";

    let mac = kmac128(&long_key, message, b"", 32);
    assert_eq!(mac.len(), 32, "Should handle long keys");
}

#[test]
fn test_kmac_long_message() {
    let key = b"key";
    let long_message = vec![0xAA; 10000];

    let mac = kmac128(key, &long_message, b"", 32);
    assert_eq!(mac.len(), 32, "Should handle long messages");
}

#[test]
fn test_kmac_long_customization() {
    let key = b"key";
    let message = b"message";
    let long_custom = vec![0x55; 1000];

    let mac = kmac128(key, message, &long_custom, 32);
    assert_eq!(mac.len(), 32, "Should handle long customization strings");
}

#[test]
fn test_kmac128_deterministic() {
    let key = b"deterministic-key";
    let message = b"deterministic message";

    let mac1 = kmac128(key, message, b"test", 32);
    let mac2 = kmac128(key, message, b"test", 32);

    assert_eq!(mac1, mac2, "KMAC should be deterministic");
}

#[test]
fn test_kmac256_deterministic() {
    let key = b"deterministic-key";
    let message = b"deterministic message";

    let mac1 = kmac256(key, message, b"test", 64);
    let mac2 = kmac256(key, message, b"test", 64);

    assert_eq!(mac1, mac2, "KMAC should be deterministic");
}

#[test]
fn test_kmac_convenience_vs_direct() {
    let key = b"test-key";
    let message = b"test message";

    // Using convenience function
    let mac1 = kmac128(key, message, b"", 32);

    // Using direct API
    let mut kmac = Kmac128::new(key, b"");
    kmac.update(message);
    let mac2 = kmac.finalize(32);

    assert_eq!(
        &mac1[..],
        &mac2[..],
        "Convenience function should match direct API"
    );
}

#[test]
fn test_kmac_clone() {
    let key = b"clone-key";
    let message1 = b"part1";
    let message2 = b"part2";

    let mut kmac1 = Kmac128::new(key, b"");
    kmac1.update(message1);

    // Clone the state
    let mut kmac2 = kmac1.clone();

    // Continue with different data
    kmac1.update(message2);
    let mac1 = kmac1.finalize(32);

    kmac2.update(b"different");
    let mac2 = kmac2.finalize(32);

    assert_ne!(mac1, mac2, "Cloned instances should be independent");
}

#[test]
fn test_kmac_boundary_output_sizes() {
    let key = b"boundary-key";
    let message = b"test";

    // Test various output sizes including edge cases
    for size in [
        1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256,
    ] {
        let mac = kmac128(key, message, b"", size);
        assert_eq!(mac.len(), size, "Output size should match requested");
    }
}

#[test]
fn test_kmac_mac_static_method() {
    let key = b"static-key";
    let message = b"static message";

    // Using static mac() method
    let mac1 = Kmac128::mac(key, message, b"", 32);

    // Using convenience function (which calls mac())
    let mac2 = kmac128(key, message, b"", 32);

    assert_eq!(mac1, mac2, "Static mac() should match convenience function");
}
