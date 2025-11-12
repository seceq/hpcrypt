// Comprehensive SHA-256 tests

use hpcrypt_hash::sha256::{sha256, Sha256};

#[test]
fn test_empty() {
    let hash = sha256(b"");
    let expected =
        hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hash, expected, "Empty message test failed");
}

#[test]
fn test_single_byte() {
    let hash = sha256(b"a");
    let expected =
        hex_literal::hex!("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    assert_eq!(hash, expected, "Single byte test failed");
}

#[test]
fn test_hello_world() {
    let hash = sha256(b"Hello, World!");
    let expected =
        hex_literal::hex!("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    assert_eq!(hash, expected, "Hello World test failed");
}

#[test]
fn test_abc() {
    // NIST test vector
    let hash = sha256(b"abc");
    let expected =
        hex_literal::hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hash, expected, "ABC test failed");
}

#[test]
fn test_448_bits() {
    // NIST test vector: 448 bits (56 bytes)
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let hash = sha256(message);
    let expected =
        hex_literal::hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_eq!(hash, expected, "448-bit message test failed");
}

#[test]
fn test_896_bits() {
    // NIST test vector: 896 bits
    let message =
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let hash = sha256(message);
    let expected =
        hex_literal::hex!("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    assert_eq!(hash, expected, "896-bit message test failed");
}

#[test]
fn test_incremental_hashing() {
    let mut hasher = Sha256::new();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let hash_incremental = hasher.finalize();

    let hash_direct = sha256(b"Hello, World!");

    assert_eq!(hash_incremental, hash_direct, "Incremental hashing failed");
}

#[test]
fn test_multiple_updates() {
    let mut hasher = Sha256::new();

    // Update with various sizes to test buffer handling
    hasher.update(b"a"); // 1 byte
    hasher.update(b"bc"); // 2 bytes
    hasher.update(b"def"); // 3 bytes
    hasher.update(b"ghijklm"); // 7 bytes
    hasher.update(&[b'n'; 50]); // 50 bytes (total: 63)
    hasher.update(b"o"); // 1 byte (triggers block processing at 64)
    hasher.update(b"pqr"); // 3 more bytes

    let expected_message = {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"a");
        msg.extend_from_slice(b"bc");
        msg.extend_from_slice(b"def");
        msg.extend_from_slice(b"ghijklm");
        msg.extend_from_slice(&[b'n'; 50]);
        msg.extend_from_slice(b"o");
        msg.extend_from_slice(b"pqr");
        msg
    };

    let hash = hasher.finalize();
    let hash_direct = sha256(&expected_message);

    assert_eq!(hash, hash_direct, "Multiple updates test failed");
}

#[test]
fn test_boundary_55_bytes() {
    // 55 bytes is the largest message that fits in one block with padding
    let message = vec![b'a'; 55];
    let hash = sha256(&message);

    // Verify incremental hashing gives same result
    let mut hasher = Sha256::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(
        hash, hash_incremental,
        "55-byte boundary incremental hash mismatch"
    );
}

#[test]
fn test_boundary_56_bytes() {
    // 56 bytes requires two blocks
    let message = vec![b'a'; 56];
    let hash = sha256(&message);

    let mut hasher = Sha256::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "56-byte boundary test failed");
}

#[test]
fn test_boundary_64_bytes() {
    // Exactly one block
    let message = vec![b'a'; 64];
    let hash = sha256(&message);

    let mut hasher = Sha256::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "64-byte boundary test failed");
}

#[test]
fn test_large_message() {
    // Test with a larger message (multiple blocks)
    let message = vec![b'A'; 1000];
    let hash = sha256(&message);

    let mut hasher = Sha256::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "Large message test failed");
}

#[test]
fn test_split_across_blocks() {
    // Test updating in chunks that cross block boundaries
    let message = vec![b'B'; 200];

    let mut hasher = Sha256::new();
    for chunk in message.chunks(30) {
        hasher.update(chunk);
    }
    let hash_chunked = hasher.finalize();

    let hash_direct = sha256(&message);

    assert_eq!(hash_chunked, hash_direct, "Cross-block split test failed");
}

#[test]
fn test_deterministic() {
    // Same input should always produce same output
    let message = b"deterministic test";

    let hash1 = sha256(message);
    let hash2 = sha256(message);

    assert_eq!(hash1, hash2, "SHA-256 is not deterministic");
}

#[test]
fn test_different_inputs_different_outputs() {
    let hash1 = sha256(b"message1");
    let hash2 = sha256(b"message2");

    assert_ne!(
        hash1, hash2,
        "Different inputs should produce different hashes"
    );
}

#[test]
fn test_million_a() {
    // NIST test: one million 'a' characters
    // This test is slow, but verifies correct handling of very large inputs
    let message = vec![b'a'; 1_000_000];
    let hash = sha256(&message);
    let expected =
        hex_literal::hex!("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    assert_eq!(hash, expected, "Million 'a' test failed");
}
