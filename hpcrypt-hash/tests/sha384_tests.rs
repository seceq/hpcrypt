// Comprehensive SHA-384 tests

use hpcrypt_hash::sha384::Sha384;

#[test]
fn test_empty() {
    let hasher = Sha384::new();
    let hash = hasher.finalize();
    let expected = hex_literal::hex!(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da
         274edebfe76f65fbd51ad2f14898b95b"
    );
    assert_eq!(hash, expected, "Empty message test failed");
}

#[test]
fn test_single_byte() {
    let mut hasher = Sha384::new();
    hasher.update(b"a");
    let hash = hasher.finalize();
    let expected = hex_literal::hex!(
        "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
    );
    assert_eq!(hash, expected, "Single byte test failed");
}

#[test]
fn test_abc() {
    // NIST test vector
    let mut hasher = Sha384::new();
    hasher.update(b"abc");
    let hash = hasher.finalize();
    let expected = hex_literal::hex!(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed
         8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(hash, expected, "ABC test failed");
}

#[test]
fn test_448_bits() {
    // NIST test vector: 448 bits (56 bytes)
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let mut hasher = Sha384::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let expected = hex_literal::hex!(
        "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6
         b0455a8520bc4e6f5fe95b1fe3c8452b"
    );
    assert_eq!(hash, expected, "448-bit message test failed");
}

#[test]
fn test_896_bits() {
    // NIST test vector: 896 bits
    let message =
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let mut hasher = Sha384::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let expected = hex_literal::hex!(
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712
         fcc7c71a557e2db966c3e9fa91746039"
    );
    assert_eq!(hash, expected, "896-bit message test failed");
}

#[test]
fn test_hello_world() {
    let mut hasher = Sha384::new();
    hasher.update(b"Hello, World!");
    let hash = hasher.finalize();
    let expected = hex_literal::hex!(
        "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515"
    );
    assert_eq!(hash, expected, "Hello World test failed");
}

#[test]
fn test_incremental_hashing() {
    let mut hasher1 = Sha384::new();
    hasher1.update(b"The quick brown fox ");
    hasher1.update(b"jumps over the lazy dog");
    let hash_incremental = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(b"The quick brown fox jumps over the lazy dog");
    let hash_direct = hasher2.finalize();

    assert_eq!(
        hash_incremental, hash_direct,
        "Incremental hashing failed"
    );
}

#[test]
fn test_multiple_updates() {
    let mut hasher = Sha384::new();

    // Update with various sizes to test buffer handling
    hasher.update(b"a"); // 1 byte
    hasher.update(b"bc"); // 2 bytes
    hasher.update(b"def"); // 3 bytes
    hasher.update(b"ghijklm"); // 7 bytes
    hasher.update(&[b'n'; 100]); // 100 bytes
    hasher.update(b"o"); // 1 byte
    hasher.update(b"pqr"); // 3 more bytes

    let expected_message = {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"a");
        msg.extend_from_slice(b"bc");
        msg.extend_from_slice(b"def");
        msg.extend_from_slice(b"ghijklm");
        msg.extend_from_slice(&[b'n'; 100]);
        msg.extend_from_slice(b"o");
        msg.extend_from_slice(b"pqr");
        msg
    };

    let hash = hasher.finalize();

    let mut hasher_direct = Sha384::new();
    hasher_direct.update(&expected_message);
    let hash_direct = hasher_direct.finalize();

    assert_eq!(hash, hash_direct, "Multiple updates test failed");
}

#[test]
fn test_boundary_111_bytes() {
    // 111 bytes is the largest message that fits in one block with padding
    let message = vec![b'a'; 111];

    let mut hasher1 = Sha384::new();
    hasher1.update(&message);
    let hash = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(&message);
    let hash_incremental = hasher2.finalize();

    assert_eq!(
        hash, hash_incremental,
        "111-byte boundary incremental hash mismatch"
    );
}

#[test]
fn test_boundary_112_bytes() {
    // 112 bytes requires two blocks
    let message = vec![b'a'; 112];

    let mut hasher1 = Sha384::new();
    hasher1.update(&message);
    let hash = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(&message);
    let hash_incremental = hasher2.finalize();

    assert_eq!(hash, hash_incremental, "112-byte boundary test failed");
}

#[test]
fn test_boundary_128_bytes() {
    // Exactly one block (SHA-384 uses SHA-512 block size: 128 bytes)
    let message = vec![b'a'; 128];

    let mut hasher1 = Sha384::new();
    hasher1.update(&message);
    let hash = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(&message);
    let hash_incremental = hasher2.finalize();

    assert_eq!(hash, hash_incremental, "128-byte boundary test failed");
}

#[test]
fn test_large_message() {
    // Test with a larger message (multiple blocks)
    let message = vec![b'A'; 2000];

    let mut hasher1 = Sha384::new();
    hasher1.update(&message);
    let hash = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(&message);
    let hash_incremental = hasher2.finalize();

    assert_eq!(hash, hash_incremental, "Large message test failed");
}

#[test]
fn test_split_across_blocks() {
    // Test updating in chunks that cross block boundaries
    let message = vec![b'B'; 500];

    let mut hasher1 = Sha384::new();
    for chunk in message.chunks(60) {
        hasher1.update(chunk);
    }
    let hash_chunked = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(&message);
    let hash_direct = hasher2.finalize();

    assert_eq!(hash_chunked, hash_direct, "Cross-block split test failed");
}

#[test]
fn test_deterministic() {
    // Same input should always produce same output
    let message = b"deterministic test for SHA-384";

    let mut hasher1 = Sha384::new();
    hasher1.update(message);
    let hash1 = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(message);
    let hash2 = hasher2.finalize();

    assert_eq!(hash1, hash2, "SHA-384 is not deterministic");
}

#[test]
fn test_different_inputs_different_outputs() {
    let mut hasher1 = Sha384::new();
    hasher1.update(b"message1");
    let hash1 = hasher1.finalize();

    let mut hasher2 = Sha384::new();
    hasher2.update(b"message2");
    let hash2 = hasher2.finalize();

    assert_ne!(
        hash1, hash2,
        "Different inputs should produce different hashes"
    );
}

#[test]
fn test_long_message() {
    // Test with 10,000 bytes
    let message = vec![b'X'; 10_000];

    let mut hasher1 = Sha384::new();
    hasher1.update(&message);
    let hash = hasher1.finalize();

    // Verify incremental hashing
    let mut hasher2 = Sha384::new();
    for chunk in message.chunks(1000) {
        hasher2.update(chunk);
    }
    let hash_incremental = hasher2.finalize();

    assert_eq!(hash, hash_incremental, "Long message test failed");
}

#[test]
fn test_million_a() {
    // NIST test: one million 'a' characters
    // This test is slow, but verifies correct handling of very large inputs
    let message = vec![b'a'; 1_000_000];
    let mut hasher = Sha384::new();
    hasher.update(&message);
    let hash = hasher.finalize();
    let expected = hex_literal::hex!(
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b
         07b8b3dc38ecc4ebae97ddd87f3d8985"
    );
    assert_eq!(hash, expected, "Million 'a' test failed");
}
