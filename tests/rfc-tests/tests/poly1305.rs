//! RFC 7539/8439 - Poly1305 One-Time Authenticator Tests
//!
//! Comprehensive tests for Poly1305 MAC implementation including:
//! - RFC 7539/8439 test vectors
//! - Edge cases (empty messages, various lengths)
//! - Key clamping verification
//! - Streaming vs one-shot API consistency
//! - Multi-block message handling
//! - Determinism tests

use hpcrypt_mac::poly1305::{poly1305, Poly1305, KEY_SIZE, TAG_SIZE};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Poly1305TestVector {
    test_id: u32,
    source: String,
    description: String,
    key: String,
    message: String,
    expected_tag: String,
}

#[test]
fn test_poly1305_rfc7539() {
    let test_vectors: Vec<Poly1305TestVector> = load_test_file("rfc8439-poly1305.json");

    println!("\n=== Poly1305 RFC 7539/8439 Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);

        let key_bytes = decode_hex(&test.key);
        if key_bytes.len() != KEY_SIZE {
            eprintln!(
                "  Test {} SKIPPED: Invalid key size {} (expected {})",
                test.test_id,
                key_bytes.len(),
                KEY_SIZE
            );
            stats.skipped += 1;
            continue;
        }

        let key: [u8; KEY_SIZE] = key_bytes.try_into().unwrap();
        let message = decode_hex(&test.message);
        let expected_tag = decode_hex(&test.expected_tag);

        if expected_tag.len() != TAG_SIZE {
            eprintln!(
                "  Test {} SKIPPED: Invalid tag size {} (expected {})",
                test.test_id,
                expected_tag.len(),
                TAG_SIZE
            );
            stats.skipped += 1;
            continue;
        }

        let tag = poly1305(&key, &message);

        if tag.as_slice() == expected_tag.as_slice() {
            println!(
                "  Tag matches: {}...",
                hex::encode(&tag[..8.min(tag.len())])
            );
            stats.passed += 1;
        } else {
            eprintln!("  Test {} FAILED: Tag mismatch", test.test_id);
            eprintln!("    Expected: {}", hex::encode(&expected_tag));
            eprintln!("    Got:      {}", hex::encode(&tag));
            stats.failed += 1;
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All Poly1305 RFC tests should pass");
}

#[test]
fn test_poly1305_rfc8439_section_2_5_2() {
    println!("\n=== Poly1305 RFC 8439 Section 2.5.2 ===");

    // Test vector from RFC 8439 Section 2.5.2
    let key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let msg = b"Cryptographic Forum Research Group";

    let tag = poly1305(&key, msg);

    let expected = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];

    assert_eq!(tag, expected);
    println!("  RFC 8439 Section 2.5.2 test vector: PASSED");
}

#[test]
fn test_poly1305_streaming_api() {
    println!("\n=== Poly1305 Streaming API Tests ===");

    let key = [0x42; KEY_SIZE];
    let data = b"The quick brown fox jumps over the lazy dog";

    // One-shot computation
    let tag_oneshot = poly1305(&key, data);

    // Streaming computation - single update
    let mut mac1 = Poly1305::new(&key);
    mac1.update(data);
    let tag_streaming1 = mac1.finalize();

    assert_eq!(tag_oneshot, tag_streaming1);
    println!("  One-shot vs single-update streaming: PASSED");

    // Streaming computation - multiple updates
    let mut mac2 = Poly1305::new(&key);
    mac2.update(&data[..16]);
    mac2.update(&data[16..32]);
    mac2.update(&data[32..]);
    let tag_streaming2 = mac2.finalize();

    assert_eq!(tag_oneshot, tag_streaming2);
    println!("  Multi-update streaming: PASSED");

    // Streaming computation - byte-by-byte
    let mut mac3 = Poly1305::new(&key);
    for byte in data.iter() {
        mac3.update(&[*byte]);
    }
    let tag_streaming3 = mac3.finalize();

    assert_eq!(tag_oneshot, tag_streaming3);
    println!("  Byte-by-byte streaming: PASSED");
}

#[test]
fn test_poly1305_empty_message() {
    println!("\n=== Poly1305 Empty Message Test ===");

    let key = [0x00; KEY_SIZE];
    let empty = b"";

    let tag = poly1305(&key, empty);
    assert_eq!(tag.len(), TAG_SIZE);

    // Empty message with zero key should produce zero tag
    let expected_zero_tag = [0x00; TAG_SIZE];
    assert_eq!(tag, expected_zero_tag);

    println!("  Empty message with zero key: PASSED");

    // Empty message with non-zero key
    let key2 = [0x42; KEY_SIZE];
    let tag2 = poly1305(&key2, empty);
    assert_eq!(tag2.len(), TAG_SIZE);
    // Should be different from zero tag (due to s addition)
    assert_ne!(tag2, expected_zero_tag);

    println!("  Empty message with non-zero key: PASSED");
}

#[test]
fn test_poly1305_various_lengths() {
    println!("\n=== Poly1305 Various Message Lengths ===");

    let key = [0x42; KEY_SIZE];

    // Test various message lengths around block boundaries (16 bytes)
    let test_lengths = [
        1, 2, 8, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 127, 128, 129, 255, 256, 257, 512, 1024,
    ];

    for &length in &test_lengths {
        let message = vec![0xAA; length];
        let tag = poly1305(&key, &message);
        assert_eq!(tag.len(), TAG_SIZE);
        println!("  Message length {}: OK", length);
    }
}

#[test]
fn test_poly1305_block_boundaries() {
    println!("\n=== Poly1305 Block Boundary Tests ===");

    let key = [0x42; KEY_SIZE];

    // Test messages at exact block boundaries
    let block_size = 16;

    for num_blocks in 1..=10 {
        let message = vec![0x55; num_blocks * block_size];
        let tag = poly1305(&key, &message);
        assert_eq!(tag.len(), TAG_SIZE);
        println!("  {} blocks ({} bytes): OK", num_blocks, message.len());
    }

    // Test messages just before/after block boundaries
    for num_blocks in 1..=5 {
        let base_len = num_blocks * block_size;

        // One byte before
        let msg_before = vec![0x55; base_len - 1];
        let tag_before = poly1305(&key, &msg_before);
        assert_eq!(tag_before.len(), TAG_SIZE);

        // One byte after
        let msg_after = vec![0x55; base_len + 1];
        let tag_after = poly1305(&key, &msg_after);
        assert_eq!(tag_after.len(), TAG_SIZE);

        // Tags should be different
        assert_ne!(tag_before, tag_after);
        println!(
            "  Block boundary {}: before/after tags differ: OK",
            num_blocks
        );
    }
}

#[test]
fn test_poly1305_key_sensitivity() {
    println!("\n=== Poly1305 Key Sensitivity Tests ===");

    let message = b"Test message for key sensitivity";

    // Test that different keys produce different tags
    let key1 = [0x00; KEY_SIZE];
    let key2 = [0x01; KEY_SIZE];
    let mut key3 = [0x00; KEY_SIZE];
    key3[31] = 0x01; // Only change last byte

    let tag1 = poly1305(&key1, message);
    let tag2 = poly1305(&key2, message);
    let tag3 = poly1305(&key3, message);

    assert_ne!(tag1, tag2, "Different keys should produce different tags");
    assert_ne!(tag1, tag3, "Different keys should produce different tags");
    assert_ne!(tag2, tag3, "Different keys should produce different tags");

    println!("  Key sensitivity verified: Different keys → different tags");
}

#[test]
fn test_poly1305_message_sensitivity() {
    println!("\n=== Poly1305 Message Sensitivity Tests ===");

    let key = [0x42; KEY_SIZE];

    // Test that different messages produce different tags
    let msg1 = b"Message A";
    let msg2 = b"Message B";
    let msg3 = b"Message C";

    let tag1 = poly1305(&key, msg1);
    let tag2 = poly1305(&key, msg2);
    let tag3 = poly1305(&key, msg3);

    assert_ne!(
        tag1, tag2,
        "Different messages should produce different tags"
    );
    assert_ne!(
        tag1, tag3,
        "Different messages should produce different tags"
    );
    assert_ne!(
        tag2, tag3,
        "Different messages should produce different tags"
    );

    println!("  Message sensitivity verified: Different messages → different tags");
}

#[test]
fn test_poly1305_determinism() {
    println!("\n=== Poly1305 Determinism Tests ===");

    let key = [0x42; KEY_SIZE];
    let message = b"Determinism test message";

    // Compute tag multiple times
    let tag1 = poly1305(&key, message);
    let tag2 = poly1305(&key, message);
    let tag3 = poly1305(&key, message);

    assert_eq!(tag1, tag2, "Poly1305 should be deterministic");
    assert_eq!(tag2, tag3, "Poly1305 should be deterministic");

    println!("  Determinism verified: Same inputs → same output");
}

#[test]
fn test_poly1305_edge_patterns() {
    println!("\n=== Poly1305 Edge Pattern Tests ===");

    let key = [0x42; KEY_SIZE];

    // All zeros message
    let all_zeros = vec![0x00; 128];
    let tag_zeros = poly1305(&key, &all_zeros);
    assert_eq!(tag_zeros.len(), TAG_SIZE);
    println!("  All zeros message: OK");

    // All ones message
    let all_ones = vec![0xFF; 128];
    let tag_ones = poly1305(&key, &all_ones);
    assert_eq!(tag_ones.len(), TAG_SIZE);
    assert_ne!(
        tag_zeros, tag_ones,
        "All zeros and all ones should produce different tags"
    );
    println!("  All ones message: OK");

    // Alternating pattern
    let alternating: Vec<u8> = (0..128).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
    let tag_alt = poly1305(&key, &alternating);
    assert_eq!(tag_alt.len(), TAG_SIZE);
    println!("  Alternating pattern: OK");
}

#[test]
fn test_poly1305_incremental_16_byte() {
    println!("\n=== Poly1305 Incremental 16-byte Block Test ===");

    let key = [0x42; KEY_SIZE];
    let block = [0x55; 16];

    // One-shot: single 16-byte block
    let tag1 = poly1305(&key, &block);

    // Streaming: same 16-byte block
    let mut mac = Poly1305::new(&key);
    mac.update(&block);
    let tag2 = mac.finalize();

    assert_eq!(tag1, tag2);
    println!("  16-byte block: one-shot == streaming");
}

#[test]
fn test_poly1305_incremental_17_byte() {
    println!("\n=== Poly1305 Incremental 17-byte Test ===");

    let key = [0x42; KEY_SIZE];
    let message = [0x55; 17];

    // One-shot
    let tag1 = poly1305(&key, &message);

    // Streaming: 16 + 1
    let mut mac2 = Poly1305::new(&key);
    mac2.update(&message[..16]);
    mac2.update(&message[16..]);
    let tag2 = mac2.finalize();

    assert_eq!(tag1, tag2);
    println!("  17-byte message: one-shot == streaming (16+1)");

    // Streaming: 1 + 16
    let mut mac3 = Poly1305::new(&key);
    mac3.update(&message[..1]);
    mac3.update(&message[1..]);
    let tag3 = mac3.finalize();

    assert_eq!(tag1, tag3);
    println!("  17-byte message: one-shot == streaming (1+16)");
}

#[test]
fn test_poly1305_single_byte_messages() {
    println!("\n=== Poly1305 Single Byte Messages ===");

    let key = [0x42; KEY_SIZE];

    // Test all possible single-byte values
    for byte_val in 0..=255u8 {
        let message = [byte_val];
        let tag = poly1305(&key, &message);
        assert_eq!(tag.len(), TAG_SIZE);
    }

    println!("  All 256 single-byte messages: OK");

    // Verify different bytes produce different tags
    let tag_00 = poly1305(&key, &[0x00]);
    let tag_01 = poly1305(&key, &[0x01]);
    let tag_ff = poly1305(&key, &[0xFF]);

    assert_ne!(tag_00, tag_01);
    assert_ne!(tag_00, tag_ff);
    assert_ne!(tag_01, tag_ff);

    println!("  Single-byte sensitivity verified");
}

#[test]
fn test_poly1305_clone() {
    println!("\n=== Poly1305 Clone Test ===");

    let key = [0x42; KEY_SIZE];
    let data1 = b"First part of message";
    let data2 = b" second part";

    // Create MAC and update with first part
    let mut mac1 = Poly1305::new(&key);
    mac1.update(data1);

    // Clone the state
    let mut mac2 = mac1.clone();

    // Update both with second part
    mac1.update(data2);
    mac2.update(data2);

    // Both should produce the same tag
    let tag1 = mac1.finalize();
    let tag2 = mac2.finalize();

    assert_eq!(tag1, tag2);
    println!("  Clone produces identical state: PASSED");
}

#[test]
fn test_poly1305_key_clamping() {
    println!("\n=== Poly1305 Key Clamping Verification ===");

    // Test that key clamping is applied correctly
    // According to RFC 7539, the r portion of the key is clamped:
    // - Clear top 4 bits of bytes 3, 7, 11, 15
    // - Clear bottom 2 bits of bytes 4, 8, 12

    let mut key_unclamped = [0xFF; KEY_SIZE];
    let message = b"Test message";

    let tag1 = poly1305(&key_unclamped, message);

    // Manually clamp the key
    key_unclamped[3] &= 0x0F;
    key_unclamped[7] &= 0x0F;
    key_unclamped[11] &= 0x0F;
    key_unclamped[15] &= 0x0F;
    key_unclamped[4] &= 0xFC;
    key_unclamped[8] &= 0xFC;
    key_unclamped[12] &= 0xFC;

    let tag2 = poly1305(&key_unclamped, message);

    // Both should produce the same result (implementation clamps automatically)
    assert_eq!(tag1, tag2);
    println!("  Key clamping is applied correctly: PASSED");
}

#[test]
fn test_poly1305_zero_key_zero_message() {
    println!("\n=== Poly1305 Zero Key + Zero Message ===");

    let key = [0x00; KEY_SIZE];
    let message = vec![0x00; 64];

    let tag = poly1305(&key, &message);
    let expected = [0x00; TAG_SIZE];

    assert_eq!(tag, expected);
    println!("  Zero key + zero message → zero tag: PASSED");
}

#[test]
fn test_poly1305_partial_block_final() {
    println!("\n=== Poly1305 Partial Final Block Tests ===");

    let key = [0x42; KEY_SIZE];

    // Test various partial block sizes (1-15 bytes as final block)
    for final_block_size in 1..16 {
        let full_blocks = vec![0x55; 16 * 2]; // Two full blocks
        let partial_block = vec![0xAA; final_block_size];

        let mut full_message = full_blocks.clone();
        full_message.extend_from_slice(&partial_block);

        let tag = poly1305(&key, &full_message);
        assert_eq!(tag.len(), TAG_SIZE);
        println!("  2 full blocks + {} byte partial: OK", final_block_size);
    }
}
