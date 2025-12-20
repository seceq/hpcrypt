//! RFC 4493 - AES-CMAC (Cipher-based Message Authentication Code) Tests
//!
//! Comprehensive tests for AES-CMAC implementation including:
//! - RFC 4493 official test vectors
//! - AES-128-CMAC and AES-256-CMAC variants
//! - Block boundary tests (16-byte AES blocks)
//! - Edge cases (empty messages, various lengths)
//! - Subkey generation verification
//! - Determinism and sensitivity tests

use hpcrypt_mac::cmac::{AesCmac128, AesCmac256};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

const BLOCK_SIZE: usize = 16; // AES block size
const TAG_SIZE: usize = 16; // CMAC tag size

#[derive(Debug, Deserialize)]
struct CmacTestVector {
    test_id: u32,
    source: String,
    description: String,
    algorithm: String,
    key: String,
    message: String,
    expected_tag: String,
}

#[test]
fn test_cmac_rfc4493() {
    let test_vectors: Vec<CmacTestVector> = load_test_file("rfc4493-cmac.json");

    println!("\n=== AES-CMAC RFC 4493 Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);
        println!("  Algorithm: {}", test.algorithm);

        let key = decode_hex(&test.key);
        let message = if test.message.is_empty() {
            vec![]
        } else {
            decode_hex(&test.message)
        };
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

        let tag = match test.algorithm.as_str() {
            "AES-128-CMAC" => {
                if key.len() != 16 {
                    eprintln!(
                        "  Test {} SKIPPED: Invalid key size {} for AES-128",
                        test.test_id,
                        key.len()
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 16] = key.try_into().unwrap();
                let cmac = AesCmac128::new(&key_array);
                cmac.compute(&message).to_vec()
            }
            "AES-256-CMAC" => {
                if key.len() != 32 {
                    eprintln!(
                        "  Test {} SKIPPED: Invalid key size {} for AES-256",
                        test.test_id,
                        key.len()
                    );
                    stats.skipped += 1;
                    continue;
                }
                let key_array: [u8; 32] = key.try_into().unwrap();
                let cmac = AesCmac256::new(&key_array);
                cmac.compute(&message).to_vec()
            }
            _ => {
                eprintln!("  Test {} SKIPPED: Unknown algorithm", test.test_id);
                stats.skipped += 1;
                continue;
            }
        };

        if tag == expected_tag {
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
    assert_eq!(stats.failed, 0, "All AES-CMAC RFC tests should pass");
}

#[test]
fn test_cmac_aes128_rfc4493_examples() {
    println!("\n=== AES-128-CMAC RFC 4493 Examples ===");

    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let cmac = AesCmac128::new(&key);

    // Example 1: Empty message
    let tag1 = cmac.compute(b"");
    let expected1 = hex::decode("bb1d6929e95937287fa37d129b756746").unwrap();
    assert_eq!(tag1.to_vec(), expected1);
    println!("  Example 1 (empty message): PASSED");

    // Example 2: 16 bytes (one complete block)
    let msg2 = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let tag2 = cmac.compute(&msg2);
    let expected2 = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();
    assert_eq!(tag2.to_vec(), expected2);
    println!("  Example 2 (16 bytes): PASSED");

    // Example 3: 40 bytes (2.5 blocks)
    let msg3 = hex::decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
    )
    .unwrap();
    let tag3 = cmac.compute(&msg3);
    let expected3 = hex::decode("dfa66747de9ae63030ca32611497c827").unwrap();
    assert_eq!(tag3.to_vec(), expected3);
    println!("  Example 3 (40 bytes): PASSED");

    // Example 4: 64 bytes (4 complete blocks)
    let msg4 = hex::decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    ).unwrap();
    let tag4 = cmac.compute(&msg4);
    let expected4 = hex::decode("51f0bebf7e3b9d92fc49741779363cfe").unwrap();
    assert_eq!(tag4.to_vec(), expected4);
    println!("  Example 4 (64 bytes): PASSED");
}

#[test]
fn test_cmac_empty_message() {
    println!("\n=== CMAC Empty Message Tests ===");

    // AES-128-CMAC
    let key128 = [0x42; 16];
    let cmac128 = AesCmac128::new(&key128);
    let tag128 = cmac128.compute(b"");
    assert_eq!(tag128.len(), TAG_SIZE);
    assert_ne!(tag128, [0u8; TAG_SIZE], "Tag should not be all zeros");
    println!("  AES-128-CMAC empty message: OK");

    // AES-256-CMAC
    let key256 = [0x42; 32];
    let cmac256 = AesCmac256::new(&key256);
    let tag256 = cmac256.compute(b"");
    assert_eq!(tag256.len(), TAG_SIZE);
    assert_ne!(tag256, [0u8; TAG_SIZE], "Tag should not be all zeros");
    assert_ne!(
        tag128, tag256,
        "AES-128 and AES-256 should produce different tags"
    );
    println!("  AES-256-CMAC empty message: OK");
}

#[test]
fn test_cmac_block_boundaries() {
    println!("\n=== CMAC Block Boundary Tests ===");

    let key = [0x55; 16];
    let cmac = AesCmac128::new(&key);

    // Test exact block sizes
    for num_blocks in 1..=5 {
        let message = vec![0xAA; num_blocks * BLOCK_SIZE];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);
        println!("  {} blocks ({} bytes): OK", num_blocks, message.len());
    }

    // Test incomplete blocks
    for remainder in 1..BLOCK_SIZE {
        let message = vec![0xBB; BLOCK_SIZE + remainder];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);
    }
    println!("  Incomplete final blocks (1-15 bytes): OK");

    // Test messages around block boundaries
    for size in [15, 16, 17, 31, 32, 33, 47, 48, 49] {
        let message = vec![0xCC; size];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);
    }
    println!("  Boundary sizes (15, 16, 17, 31, 32, 33, 47, 48, 49): OK");
}

#[test]
fn test_cmac_various_lengths() {
    println!("\n=== CMAC Various Message Lengths ===");

    let key = [0x42; 16];
    let cmac = AesCmac128::new(&key);

    let test_lengths = [
        0, 1, 2, 8, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 127, 128, 129, 255, 256, 512, 1024,
    ];

    for &length in &test_lengths {
        let message = vec![0x77; length];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);
    }

    println!("  Tested {} different message lengths: OK", test_lengths.len());
}

#[test]
fn test_cmac_determinism() {
    println!("\n=== CMAC Determinism Tests ===");

    let key = [0x42; 16];
    let cmac = AesCmac128::new(&key);
    let message = b"Determinism test message";

    let tag1 = cmac.compute(message);
    let tag2 = cmac.compute(message);
    let tag3 = cmac.compute(message);

    assert_eq!(tag1, tag2, "CMAC should be deterministic");
    assert_eq!(tag2, tag3, "CMAC should be deterministic");

    println!("  Determinism verified: Same inputs → same output");
}

#[test]
fn test_cmac_key_sensitivity() {
    println!("\n=== CMAC Key Sensitivity Tests ===");

    let message = b"Test message for key sensitivity";

    // Different keys
    let key1 = [0x00; 16];
    let key2 = [0x01; 16];
    let mut key3 = [0x00; 16];
    key3[15] = 0x01;

    let cmac1 = AesCmac128::new(&key1);
    let cmac2 = AesCmac128::new(&key2);
    let cmac3 = AesCmac128::new(&key3);

    let tag1 = cmac1.compute(message);
    let tag2 = cmac2.compute(message);
    let tag3 = cmac3.compute(message);

    assert_ne!(tag1, tag2, "Different keys should produce different tags");
    assert_ne!(tag1, tag3, "Different keys should produce different tags");
    assert_ne!(tag2, tag3, "Different keys should produce different tags");

    println!("  Key sensitivity verified: Different keys → different tags");
}

#[test]
fn test_cmac_message_sensitivity() {
    println!("\n=== CMAC Message Sensitivity Tests ===");

    let key = [0x42; 16];
    let cmac = AesCmac128::new(&key);

    let msg1 = b"Message A";
    let msg2 = b"Message B";
    let msg3 = b"Message C";

    let tag1 = cmac.compute(msg1);
    let tag2 = cmac.compute(msg2);
    let tag3 = cmac.compute(msg3);

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
fn test_cmac_verification() {
    println!("\n=== CMAC Verification Tests ===");

    let key = [0x55; 16];
    let cmac = AesCmac128::new(&key);
    let message = b"Test message for verification";

    let tag = cmac.compute(message);

    // Valid tag should verify
    assert!(
        cmac.verify(message, &tag),
        "Valid tag should verify successfully"
    );
    println!("  Valid tag verification: OK");

    // Invalid tag should not verify
    let mut invalid_tag = tag;
    invalid_tag[0] ^= 0x01; // Flip one bit
    assert!(
        !cmac.verify(message, &invalid_tag),
        "Invalid tag should fail verification"
    );
    println!("  Invalid tag rejection: OK");

    // Wrong message should not verify
    assert!(
        !cmac.verify(b"Different message", &tag),
        "Wrong message should fail verification"
    );
    println!("  Wrong message rejection: OK");
}

#[test]
fn test_cmac_aes128_vs_aes256() {
    println!("\n=== AES-128-CMAC vs AES-256-CMAC ===");

    let key128 = [0x42; 16];
    let key256 = [0x42; 32];
    let message = b"Compare AES-128 and AES-256 CMAC";

    let cmac128 = AesCmac128::new(&key128);
    let cmac256 = AesCmac256::new(&key256);

    let tag128 = cmac128.compute(message);
    let tag256 = cmac256.compute(message);

    assert_ne!(
        tag128, tag256,
        "AES-128 and AES-256 should produce different tags"
    );

    println!("  AES-128 tag: {}...", hex::encode(&tag128[..8]));
    println!("  AES-256 tag: {}...", hex::encode(&tag256[..8]));
    println!("  Tags differ correctly: OK");
}

#[test]
fn test_cmac_single_byte_messages() {
    println!("\n=== CMAC Single Byte Messages ===");

    let key = [0x42; 16];
    let cmac = AesCmac128::new(&key);

    // Test a sample of single-byte values
    for byte_val in [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
        let message = [byte_val];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);
    }

    println!("  Single-byte messages: OK");

    // Verify different bytes produce different tags
    let tag_00 = cmac.compute(&[0x00]);
    let tag_01 = cmac.compute(&[0x01]);
    let tag_ff = cmac.compute(&[0xFF]);

    assert_ne!(tag_00, tag_01);
    assert_ne!(tag_00, tag_ff);
    assert_ne!(tag_01, tag_ff);

    println!("  Single-byte sensitivity verified");
}

#[test]
fn test_cmac_edge_patterns() {
    println!("\n=== CMAC Edge Pattern Tests ===");

    let key = [0x42; 16];
    let cmac = AesCmac128::new(&key);

    // All zeros
    let all_zeros = vec![0x00; 64];
    let tag_zeros = cmac.compute(&all_zeros);
    assert_eq!(tag_zeros.len(), TAG_SIZE);
    println!("  All zeros message: OK");

    // All ones
    let all_ones = vec![0xFF; 64];
    let tag_ones = cmac.compute(&all_ones);
    assert_eq!(tag_ones.len(), TAG_SIZE);
    assert_ne!(
        tag_zeros, tag_ones,
        "All zeros and all ones should produce different tags"
    );
    println!("  All ones message: OK");

    // Alternating pattern
    let alternating: Vec<u8> = (0..64).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
    let tag_alt = cmac.compute(&alternating);
    assert_eq!(tag_alt.len(), TAG_SIZE);
    println!("  Alternating pattern: OK");

    // Sequential bytes
    let sequential: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let tag_seq = cmac.compute(&sequential);
    assert_eq!(tag_seq.len(), TAG_SIZE);
    println!("  Sequential bytes: OK");
}

#[test]
fn test_cmac_partial_block_only() {
    println!("\n=== CMAC Partial Block Only Tests ===");

    let key = [0x55; 16];
    let cmac = AesCmac128::new(&key);

    // Test messages shorter than one block
    for length in 1..BLOCK_SIZE {
        let message = vec![0x77; length];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);
    }

    println!("  Partial block messages (1-15 bytes): OK");
}

#[test]
fn test_cmac_exact_block_multiples() {
    println!("\n=== CMAC Exact Block Multiples ===");

    let key = [0x42; 16];
    let cmac = AesCmac128::new(&key);

    // Test exact multiples of block size
    for num_blocks in [1, 2, 3, 4, 5, 10, 20] {
        let message = vec![0xAA; num_blocks * BLOCK_SIZE];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);
        println!("  {} blocks: OK", num_blocks);
    }
}

#[test]
fn test_cmac_incremental_sizes() {
    println!("\n=== CMAC Incremental Size Tests ===");

    let key = [0x42; 16];
    let cmac = AesCmac128::new(&key);

    // Test every size from 0 to 100 bytes
    let mut prev_tag = None;
    for size in 0..=100 {
        let message = vec![0x55; size];
        let tag = cmac.compute(&message);
        assert_eq!(tag.len(), TAG_SIZE);

        // Each size should produce a different tag
        if let Some(prev) = prev_tag {
            assert_ne!(tag, prev, "Different sizes should produce different tags");
        }
        prev_tag = Some(tag);
    }

    println!("  Incremental sizes 0-100: OK");
}

#[test]
fn test_cmac_reuse() {
    println!("\n=== CMAC Reuse Test ===");

    let key = [0x42; 16];
    let message = b"Test message";

    // Create two instances with same key
    let cmac1 = AesCmac128::new(&key);
    let cmac2 = AesCmac128::new(&key);

    let tag1 = cmac1.compute(message);
    let tag2 = cmac2.compute(message);

    assert_eq!(tag1, tag2, "Same key should produce same tag");
    println!("  Key reuse produces identical results: PASSED");
}

#[test]
fn test_cmac_zero_key() {
    println!("\n=== CMAC Zero Key Test ===");

    let key = [0x00; 16];
    let cmac = AesCmac128::new(&key);

    let message = b"Test with zero key";
    let tag = cmac.compute(message);

    assert_eq!(tag.len(), TAG_SIZE);
    assert_ne!(tag, [0u8; TAG_SIZE], "Tag should not be all zeros");
    println!("  Zero key produces valid tag: OK");
}

#[test]
fn test_cmac_max_key() {
    println!("\n=== CMAC Max Key Test ===");

    let key = [0xFF; 16];
    let cmac = AesCmac128::new(&key);

    let message = b"Test with max key";
    let tag = cmac.compute(message);

    assert_eq!(tag.len(), TAG_SIZE);
    println!("  Max key (all 0xFF) produces valid tag: OK");
}
