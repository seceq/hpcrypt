//! Comprehensive SHA-1 test suite
//!
//! This test suite covers:
//! - Official FIPS 180-4 test vectors
//! - Edge cases (empty, single-block, multi-block)
//! - Incremental hashing
//! - Long messages
//! - Aligned block handling
//! - Performance-critical paths

use hpcrypt_hash::sha1::{sha1, AlignedBlock, Sha1};

#[test]
fn test_empty_string() {
    let hash = sha1(b"");
    let expected = hex_literal::hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hash, expected, "Empty string hash failed");
}

#[test]
fn test_abc() {
    let hash = sha1(b"abc");
    let expected = hex_literal::hex!("a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hash, expected, "Simple 'abc' test failed");
}

#[test]
fn test_448_bits() {
    // Test vector from FIPS 180-4
    let hash = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    let expected = hex_literal::hex!("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    assert_eq!(hash, expected, "448-bit message test failed");
}

#[test]
fn test_single_byte() {
    let hash = sha1(b"a");
    let expected = hex_literal::hex!("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
    assert_eq!(hash, expected, "Single byte test failed");
}

#[test]
fn test_two_blocks() {
    // Test a message that spans exactly two blocks
    let message = vec![b'a'; 56];
    let hash = sha1(&message);
    let expected = hex_literal::hex!("c2db330f6083854c99d4b5bfb6e8f29f201be699");
    assert_eq!(hash, expected, "Two-block message test failed");
}

#[test]
fn test_55_bytes() {
    // Boundary case: 55 bytes is the largest single-block message
    let message = vec![b'a'; 55];
    let hash = sha1(&message);

    // Verify incremental hashing gives same result
    let mut hasher = Sha1::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();
    assert_eq!(hash, hash_incremental, "55-byte incremental hash mismatch");
}

#[test]
fn test_56_bytes() {
    // Boundary case: 56 bytes requires two blocks
    let message = vec![b'a'; 56];
    let hash = sha1(&message);

    let mut hasher = Sha1::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();
    assert_eq!(hash, hash_incremental, "56-byte incremental hash mismatch");
}

#[test]
fn test_64_bytes() {
    // Exactly one block
    let message = vec![b'a'; 64];
    let hash = sha1(&message);
    let expected = hex_literal::hex!("0098ba824b5c16427bd7a1122a5a442a25ec644d");
    assert_eq!(hash, expected, "64-byte message test failed");
}

#[test]
fn test_million_a() {
    // Test with 1,000,000 'a' characters (from FIPS 180-4)
    let message = vec![b'a'; 1_000_000];
    let hash = sha1(&message);
    let expected = hex_literal::hex!("34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    assert_eq!(hash, expected, "Million 'a' test failed");
}

#[test]
fn test_incremental_hashing() {
    let mut hasher = Sha1::new();
    hasher.update(b"The quick brown ");
    hasher.update(b"fox jumps over ");
    hasher.update(b"the lazy dog");
    let hash = hasher.finalize();

    let hash_direct = sha1(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(hash, hash_direct, "Incremental hashing mismatch");
}

#[test]
fn test_incremental_single_bytes() {
    let mut hasher = Sha1::new();
    let message = b"abcdef";
    for &byte in message.iter() {
        hasher.update(&[byte]);
    }
    let hash = hasher.finalize();

    let hash_direct = sha1(message);
    assert_eq!(
        hash, hash_direct,
        "Single-byte incremental hashing mismatch"
    );
}

#[test]
fn test_boundary_lengths() {
    // Test various boundary lengths
    let lengths = [0, 1, 54, 55, 56, 63, 64, 65, 119, 120, 121, 127, 128];

    for &len in &lengths {
        let message = vec![b'x'; len];
        let hash1 = sha1(&message);

        let mut hasher = Sha1::new();
        hasher.update(&message);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2, "Boundary length {} failed", len);
    }
}

#[test]
fn test_aligned_block() {
    let mut block = AlignedBlock::zeroed();
    block.data[..3].copy_from_slice(b"abc");

    // We can't directly test process_aligned_block as it's private,
    // but we can verify the AlignedBlock type works correctly
    assert_eq!(block.data[0], b'a');
    assert_eq!(block.data[1], b'b');
    assert_eq!(block.data[2], b'c');
}

#[test]
fn test_multiple_updates() {
    let mut hasher = Sha1::new();

    // Update with various sizes to test buffer handling
    hasher.update(b"a"); // 1 byte
    hasher.update(b"bc"); // 2 bytes
    hasher.update(b"def"); // 3 bytes
    hasher.update(b"ghijklm"); // 7 bytes
    hasher.update(&vec![b'n'; 50]); // 50 bytes (total: 63)
    hasher.update(b"o"); // 1 byte (triggers block processing)
    hasher.update(b"pqr"); // 3 more bytes

    let hash = hasher.finalize();

    // Create the same message in one go
    let mut message = Vec::new();
    message.push(b'a');
    message.extend_from_slice(b"bc");
    message.extend_from_slice(b"def");
    message.extend_from_slice(b"ghijklm");
    message.extend_from_slice(&vec![b'n'; 50]);
    message.push(b'o');
    message.extend_from_slice(b"pqr");

    let hash_direct = sha1(&message);
    assert_eq!(hash, hash_direct, "Multiple updates test failed");
}

#[test]
fn test_all_zero_bytes() {
    let message = vec![0u8; 100];
    let hash = sha1(&message);

    let mut hasher = Sha1::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "All-zero bytes test failed");
}

#[test]
fn test_all_ff_bytes() {
    let message = vec![0xFFu8; 100];
    let hash = sha1(&message);

    let mut hasher = Sha1::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "All-FF bytes test failed");
}

#[test]
fn test_pattern() {
    // Test with repeating pattern
    let pattern = b"0123456789";
    let mut message = Vec::new();
    for _ in 0..10 {
        message.extend_from_slice(pattern);
    }

    let hash = sha1(&message);

    let mut hasher = Sha1::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "Pattern test failed");
}

#[test]
fn test_default_trait() {
    let hasher1 = Sha1::new();
    let hasher2 = Sha1::default();

    // Both should start with the same initial state
    // We can't directly compare the structs, but we can hash the same data
    let test_data = b"test";

    let mut h1 = hasher1;
    h1.update(test_data);
    let hash1 = h1.finalize();

    let mut h2 = hasher2;
    h2.update(test_data);
    let hash2 = h2.finalize();

    assert_eq!(hash1, hash2, "Default trait test failed");
}

#[test]
fn test_rfc_3174_test_vector_1() {
    // Test vector from RFC 3174
    let hash = sha1(b"abc");
    let expected = hex_literal::hex!("a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hash, expected);
}

#[test]
fn test_rfc_3174_test_vector_2() {
    // Test vector from RFC 3174
    let hash = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    let expected = hex_literal::hex!("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    assert_eq!(hash, expected);
}

#[test]
fn test_srp_compatibility() {
    // SHA-1 is used in SRP-6a (RFC 5054)
    // Test a typical SRP use case
    let username = b"alice";
    let password = b"password123";

    let mut hasher = Sha1::new();
    hasher.update(username);
    hasher.update(b":");
    hasher.update(password);
    let hash = hasher.finalize();

    // Verify it produces consistent output
    let mut hasher2 = Sha1::new();
    hasher2.update(b"alice:password123");
    let hash2 = hasher2.finalize();

    assert_eq!(hash, hash2, "SRP compatibility test failed");
}

#[test]
fn test_hmac_compatibility() {
    // SHA-1 is commonly used with HMAC
    // Test that we can hash typical HMAC block sizes
    let key = vec![0x0b; 20]; // 20-byte key
    let data = b"Hi There";

    // Inner hash: hash((key ^ ipad) || data)
    let ipad = vec![0x36; 64];
    let mut inner_input = Vec::new();
    for i in 0..64 {
        if i < key.len() {
            inner_input.push(key[i] ^ ipad[i]);
        } else {
            inner_input.push(ipad[i]);
        }
    }
    inner_input.extend_from_slice(data);

    let inner_hash = sha1(&inner_input);
    assert_eq!(inner_hash.len(), 20, "HMAC compatibility test failed");
}

#[test]
fn test_large_buffer_incremental() {
    // Test incremental hashing with large buffers
    let chunk_size = 1024;
    let num_chunks = 100;

    let mut hasher = Sha1::new();
    let mut full_message = Vec::new();

    for i in 0..num_chunks {
        let chunk = vec![(i % 256) as u8; chunk_size];
        hasher.update(&chunk);
        full_message.extend_from_slice(&chunk);
    }

    let hash_incremental = hasher.finalize();
    let hash_direct = sha1(&full_message);

    assert_eq!(
        hash_incremental, hash_direct,
        "Large buffer incremental test failed"
    );
}
