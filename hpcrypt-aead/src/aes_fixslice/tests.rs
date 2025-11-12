//! Tests for fixsliced AES implementation

use super::*;
use std::println;

#[test]
fn test_isolated_sbox_single_byte() {
    // Test S-box with a single input byte in one block
    println!("\n=== Testing Isolated S-box ===");

    // Input: 0x19 in byte 0, all other bytes zero
    let block = [0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let blocks = [block; 4];

    let mut state = bitslice::bitslice_4blocks(&blocks);

    println!("Before S-box:");
    for i in 0..8 {
        println!("  state[{}]: 0x{:016x}", i, state[i]);
    }

    // Apply S-box
    sbox::sub_bytes(&mut state);

    println!("\nAfter S-box (without NOTs):");
    for i in 0..8 {
        println!("  state[{}]: 0x{:016x}", i, state[i]);
    }

    // Apply NOT compensation
    sbox::sub_bytes_nots(&mut state);

    println!("\nAfter NOT compensation:");
    for i in 0..8 {
        println!("  state[{}]: 0x{:016x}", i, state[i]);
    }

    // Unbitslice
    let result_blocks = bitslice::unbitslice_4blocks(&state);
    println!("\nResult byte 0: 0x{:02x}", result_blocks[0][0]);
    println!("Expected:      0xd4");

    // Standard AES S-box says SBOX[0x19] = 0xd4
    assert_eq!(result_blocks[0][0], 0xd4, "S-box should transform 0x19 -> 0xd4");
}

#[test]
fn test_compare_with_rustcrypto_aes() {
    // Compare my implementation directly with RustCrypto's
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};

    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

    let plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

    // RustCrypto's AES
    let rust_crypto_cipher = Aes128::new(&key.into());
    let mut rust_crypto_block = plaintext.into();
    rust_crypto_cipher.encrypt_block(&mut rust_crypto_block);
    let rust_crypto_output: [u8; 16] = rust_crypto_block.into();

    // My fixsliced AES
    let my_cipher = AesFixslice::new_128(&key);
    let my_output = my_cipher.encrypt_block(&plaintext);

    println!("\n=== Comparison with RustCrypto ===");
    println!("Plaintext:            {:02x?}", plaintext);
    println!("RustCrypto output:    {:02x?}", rust_crypto_output);
    println!("My fixslice output:   {:02x?}", my_output);
    println!("NIST expected output: [39, 25, 84, 1d, 02, dc, 09, fb, dc, 11, 85, 97, 19, 6a, 0b, 32]");

    assert_eq!(rust_crypto_output, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                                     0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32],
               "RustCrypto should match NIST");

    println!("\n=== Testing with 4-block API ===");
    let mut four_blocks = [plaintext; 4];
    my_cipher.encrypt_blocks_4(&mut four_blocks);
    println!("4-block encryption output:");
    for (i, block) in four_blocks.iter().enumerate() {
        println!("  Block {}: {:02x?}", i, block);
    }
    println!("All 4 blocks should be identical to: {:02x?}", rust_crypto_output);

    if four_blocks[0] == rust_crypto_output {
        println!("✓ Block 0 MATCHES RustCrypto!");
    } else {
        println!("✗ Block 0 differs from RustCrypto");
    }

    // Don't assert for now, just show the difference
    // assert_eq!(my_output, rust_crypto_output, "My implementation should match RustCrypto");

    // Let's trace through the first round step-by-step
    println!("\n=== First Round Trace ===");

    let cipher = AesFixslice::new_128(&key);
    let blocks = [plaintext; 4];
    let mut state = bitslice::bitslice_4blocks(&blocks);

    println!("After bitslice:");
    for i in 0..8 {
        println!("  state[{}]: 0x{:016x}", i, state[i]);
    }

    // Initial round key
    bitslice::xor_round_key(&mut state, &cipher.round_keys[0]);
    println!("\nAfter initial key XOR:");
    for i in 0..8 {
        println!("  state[{}]: 0x{:016x}", i, state[i]);
    }

    // First SubBytes
    sbox::sub_bytes(&mut state);
    println!("\nAfter first SubBytes:");
    for i in 0..8 {
        println!("  state[{}]: 0x{:016x}", i, state[i]);
    }

    let after_subbytes = bitslice::unbitslice_4blocks(&state);
    let first_block_after_subbytes = after_subbytes[0];
    println!("First block after SubBytes: {:02x?}", first_block_after_subbytes);

    // NIST expected value after SubBytes in first round:
    // After AddRoundKey: state = plaintext XOR key[0]
    // After SubBytes: each byte goes through S-box
    let expected_after_subbytes = [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1,
                                    0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30];
    println!("Expected after SubBytes: {:02x?}", expected_after_subbytes);

    if first_block_after_subbytes == expected_after_subbytes {
        println!("✅ SubBytes output MATCHES!");
    } else {
        println!("❌ MISMATCH after SubBytes!");
        println!("Byte-by-byte comparison:");
        for i in 0..16 {
            println!("  Byte {}: got 0x{:02x}, expected 0x{:02x}",
                i, first_block_after_subbytes[i], expected_after_subbytes[i]);
        }
    }
}

#[test]
fn test_compare_bitslicing_with_rustcrypto() {
    println!("\n=== Testing Bitslicing Format ===");

    // Test with simple input to verify bit plane ordering
    println!("\n=== Testing with Simple Input ===");
    let simple_block = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // Only MSB of byte 0 set
    let simple_blocks = [simple_block; 4];
    let simple_state = bitslice::bitslice_4blocks(&simple_blocks);

    println!("Input: single byte 0x80 (MSB only) at position 0");
    println!("Expected: only state[0] (bit 7 plane) should have bits set");
    println!("Actual state:");
    for i in 0..8 {
        let val = simple_state[i];
        let lowest_bits = val & 0xFFFF;
        println!("  state[{}] (bit {}): lowest 16 bits = 0x{:04x} {}",
            i, 7-i, lowest_bits,
            if val == 0 { "" } else { "✓" }
        );
    }

    if simple_state[0] != 0 && simple_state[1] == 0 && simple_state[2] == 0 &&
       simple_state[3] == 0 && simple_state[4] == 0 && simple_state[5] == 0 &&
       simple_state[6] == 0 && simple_state[7] == 0 {
        println!("✅ Bit plane ordering is CORRECT!");
    } else {
        println!("❌ Bit plane ordering issue detected");
    }

    // Test with different blocks to verify block ordering
    println!("\n=== Testing Block Ordering ===");
    let block0 = [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // LSB only
    let block1 = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // bit 1 only
    let block2 = [0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // bit 2 only
    let block3 = [0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // bit 3 only
    let test_blocks = [block0, block1, block2, block3];
    let test_state = bitslice::bitslice_4blocks(&test_blocks);

    println!("Testing 4 different blocks with different bits set:");
    for i in 0..8 {
        let lowest_4 = test_state[i] & 0xF;
        println!("  state[{}] (bit {}): lowest 4 bits = {:04b}", i, 7-i, lowest_4);
    }

    // state[7] (bit 0) should have lowest 4 bits = 0001 (block 0 at bit position 0)
    // state[6] (bit 1) should have lowest 4 bits = 0010 (block 1 at bit position 1)
    // state[5] (bit 2) should have lowest 4 bits = 0100 (block 2 at bit position 2)
    // state[4] (bit 3) should have lowest 4 bits = 1000 (block 3 at bit position 3)

    let byte0_bits = [
        (test_state[7] & 0xF) as u8,  // bit 0
        (test_state[6] & 0xF) as u8,  // bit 1
        (test_state[5] & 0xF) as u8,  // bit 2
        (test_state[4] & 0xF) as u8,  // bit 3
    ];

    if byte0_bits[0] == 0b0001 && byte0_bits[1] == 0b0010 &&
       byte0_bits[2] == 0b0100 && byte0_bits[3] == 0b1000 {
        println!("✅ Block ordering is CORRECT!");
    } else {
        println!("❌ Block ordering issue detected");
    }
}

#[test]
fn test_nist_aes128_encrypt() {
    // NIST FIPS 197, Appendix C.1
    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

    let plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    let expected_ciphertext = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                               0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];

    let cipher = AesFixslice::new_128(&key);
    let ciphertext = cipher.encrypt_block(&plaintext);

    assert_eq!(ciphertext, expected_ciphertext, "AES-128 encryption should match NIST test vector");
}

#[test]
fn test_nist_aes128_encrypt_c1() {
    // NIST FIPS 197, Appendix C.1 - another test vector
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

    let plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

    let expected_ciphertext = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                               0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];

    let cipher = AesFixslice::new_128(&key);
    let ciphertext = cipher.encrypt_block(&plaintext);

    assert_eq!(ciphertext, expected_ciphertext, "AES-128 encryption should match NIST test vector C.1");
}

#[test]
fn test_nist_aes128_decrypt() {
    // NIST FIPS 197, Appendix C.1
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

    let ciphertext = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                      0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];

    let expected_plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                              0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

    let cipher = AesFixslice::new_128(&key);
    let plaintext = cipher.decrypt_block(&ciphertext);

    assert_eq!(plaintext, expected_plaintext, "AES-128 decryption should match NIST test vector");
}

#[test]
fn test_aes256_encrypt_decrypt_roundtrip() {
    // Test AES-256 variant
    let key = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
               0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
               0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
               0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];

    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];

    let cipher = AesFixslice::new_256(&key);

    let mut blocks = [plaintext; 4];
    cipher.encrypt_blocks_4(&mut blocks);
    cipher.decrypt_blocks_4(&mut blocks);

    assert_eq!(blocks[0], plaintext, "AES-256 roundtrip should work");
}

#[test]
fn test_different_blocks_in_parallel() {
    // Test that 4 different blocks are processed correctly in parallel
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

    let block1 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let block2 = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
    let block3 = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f];
    let block4 = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f];

    let cipher = AesFixslice::new_128(&key);

    let mut blocks = [block1, block2, block3, block4];
    let originals = blocks;

    cipher.encrypt_blocks_4(&mut blocks);
    cipher.decrypt_blocks_4(&mut blocks);

    // After encrypt then decrypt, should get back originals
    assert_eq!(blocks, originals, "Encrypt-decrypt roundtrip should work for 4 different blocks");
}

#[test]
fn test_edge_case_all_zeros() {
    // Test with all zero key and plaintext
    let key = [0u8; 16];
    let plaintext = [0u8; 16];

    let cipher = AesFixslice::new_128(&key);
    let ciphertext = cipher.encrypt_block(&plaintext);
    let decrypted = cipher.decrypt_block(&ciphertext);

    assert_eq!(plaintext, decrypted, "All zeros roundtrip should work");
    // All zeros should not encrypt to all zeros (that would be a weakness)
    assert_ne!(ciphertext, plaintext, "All zeros should not encrypt to all zeros");
}

#[test]
fn test_edge_case_all_ones() {
    // Test with all 0xFF bytes
    let key = [0xFFu8; 16];
    let plaintext = [0xFFu8; 16];

    let cipher = AesFixslice::new_128(&key);
    let ciphertext = cipher.encrypt_block(&plaintext);
    let decrypted = cipher.decrypt_block(&ciphertext);

    assert_eq!(plaintext, decrypted, "All ones roundtrip should work");
}

#[test]
fn test_edge_case_alternating_bits() {
    // Test with alternating bit patterns
    let key = [0x55u8; 16]; // 01010101...
    let plaintext = [0xAAu8; 16]; // 10101010...

    let cipher = AesFixslice::new_128(&key);
    let ciphertext = cipher.encrypt_block(&plaintext);
    let decrypted = cipher.decrypt_block(&ciphertext);

    assert_eq!(plaintext, decrypted, "Alternating bits roundtrip should work");
}

#[test]
fn test_edge_case_single_bit() {
    // Test with single bit set in each position
    let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    for bit_pos in 0..128 {
        let byte_idx = bit_pos / 8;
        let bit_idx = bit_pos % 8;

        let mut plaintext = [0u8; 16];
        plaintext[byte_idx] = 1u8 << bit_idx;

        let cipher = AesFixslice::new_128(&key);
        let ciphertext = cipher.encrypt_block(&plaintext);
        let decrypted = cipher.decrypt_block(&ciphertext);

        assert_eq!(plaintext, decrypted,
            "Single bit at position {} roundtrip should work", bit_pos);
    }
}

#[test]
fn test_key_equals_plaintext() {
    // Test when key equals plaintext (edge case)
    let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

    let cipher = AesFixslice::new_128(&data);
    let ciphertext = cipher.encrypt_block(&data);
    let decrypted = cipher.decrypt_block(&ciphertext);

    assert_eq!(data, decrypted, "Key=plaintext roundtrip should work");
}

#[test]
fn test_sequential_encryptions() {
    // Test multiple sequential encryptions produce consistent results
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

    let cipher = AesFixslice::new_128(&key);

    // Encrypt the same plaintext multiple times
    let ciphertext1 = cipher.encrypt_block(&plaintext);
    let ciphertext2 = cipher.encrypt_block(&plaintext);
    let ciphertext3 = cipher.encrypt_block(&plaintext);

    assert_eq!(ciphertext1, ciphertext2, "Encryption should be deterministic");
    assert_eq!(ciphertext2, ciphertext3, "Encryption should be deterministic");
}

#[test]
fn test_parallel_consistency() {
    // Test that processing 4 identical blocks gives identical results
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

    let cipher = AesFixslice::new_128(&key);

    // Encrypt 4 identical blocks
    let mut blocks = [plaintext; 4];
    cipher.encrypt_blocks_4(&mut blocks);

    // All 4 outputs should be identical
    assert_eq!(blocks[0], blocks[1], "Parallel encryption should produce identical results");
    assert_eq!(blocks[1], blocks[2], "Parallel encryption should produce identical results");
    assert_eq!(blocks[2], blocks[3], "Parallel encryption should produce identical results");
}

#[test]
fn test_block_independence() {
    // Test that different blocks are processed independently
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

    let block1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let block2 = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                  0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00];

    let cipher = AesFixslice::new_128(&key);

    // Encrypt blocks separately
    let cipher1_solo = cipher.encrypt_block(&block1);
    let cipher2_solo = cipher.encrypt_block(&block2);

    // Encrypt blocks together
    let mut blocks_together = [block1, block2, block1, block2];
    cipher.encrypt_blocks_4(&mut blocks_together);

    // Results should match (blocks are processed independently)
    assert_eq!(cipher1_solo, blocks_together[0], "Block 1 should match solo encryption");
    assert_eq!(cipher2_solo, blocks_together[1], "Block 2 should match solo encryption");
    assert_eq!(cipher1_solo, blocks_together[2], "Block 1 duplicate should match");
    assert_eq!(cipher2_solo, blocks_together[3], "Block 2 duplicate should match");
}
