// Comprehensive SHA-512 tests

use hpcrypt_hash::sha512::{sha512, Sha512};

#[test]
fn test_empty() {
    let hash = sha512(b"");
    let expected = hex_literal::hex!(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    assert_eq!(hash, expected, "Empty message test failed");
}

#[test]
fn test_single_byte() {
    let hash = sha512(b"a");
    let expected = hex_literal::hex!(
        "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f53
         02860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
    );
    assert_eq!(hash, expected, "Single byte test failed");
}

#[test]
fn test_abc() {
    // NIST test vector
    let hash = sha512(b"abc");
    let expected = hex_literal::hex!(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(hash, expected, "ABC test failed");
}

#[test]
fn test_448_bits() {
    // NIST test vector: 448 bits (56 bytes)
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let hash = sha512(message);
    let expected = hex_literal::hex!(
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335
         96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    );
    assert_eq!(hash, expected, "448-bit message test failed");
}

#[test]
fn test_896_bits() {
    // NIST test vector: 896 bits
    let message =
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let hash = sha512(message);
    let expected = hex_literal::hex!(
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018
         501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    );
    assert_eq!(hash, expected, "896-bit message test failed");
}

#[test]
fn test_hello_world() {
    let hash = sha512(b"Hello, World!");
    let expected = hex_literal::hex!(
        "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6c
         c69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
    );
    assert_eq!(hash, expected, "Hello World test failed");
}

#[test]
fn test_incremental_hashing() {
    let mut hasher = Sha512::new();
    hasher.update(b"The quick brown fox ");
    hasher.update(b"jumps over the lazy dog");
    let hash_incremental = hasher.finalize();

    let hash_direct = sha512(b"The quick brown fox jumps over the lazy dog");

    assert_eq!(hash_incremental, hash_direct, "Incremental hashing failed");
}

#[test]
fn test_multiple_updates() {
    let mut hasher = Sha512::new();

    // Update with various sizes to test buffer handling
    hasher.update(b"a"); // 1 byte
    hasher.update(b"bc"); // 2 bytes
    hasher.update(b"def"); // 3 bytes
    hasher.update(b"ghijklm"); // 7 bytes
    hasher.update(&vec![b'n'; 100]); // 100 bytes
    hasher.update(b"o"); // 1 byte
    hasher.update(b"pqr"); // 3 more bytes

    let expected_message = {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"a");
        msg.extend_from_slice(b"bc");
        msg.extend_from_slice(b"def");
        msg.extend_from_slice(b"ghijklm");
        msg.extend_from_slice(&vec![b'n'; 100]);
        msg.extend_from_slice(b"o");
        msg.extend_from_slice(b"pqr");
        msg
    };

    let hash = hasher.finalize();
    let hash_direct = sha512(&expected_message);

    assert_eq!(hash, hash_direct, "Multiple updates test failed");
}

#[test]
fn test_boundary_111_bytes() {
    // 111 bytes is the largest message that fits in one block with padding
    let message = vec![b'a'; 111];
    let hash = sha512(&message);

    let mut hasher = Sha512::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(
        hash, hash_incremental,
        "111-byte boundary incremental hash mismatch"
    );
}

#[test]
fn test_boundary_112_bytes() {
    // 112 bytes requires two blocks
    let message = vec![b'a'; 112];
    let hash = sha512(&message);

    let mut hasher = Sha512::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "112-byte boundary test failed");
}

#[test]
fn test_boundary_128_bytes() {
    // Exactly one block (SHA-512 has 128-byte blocks)
    let message = vec![b'a'; 128];
    let hash = sha512(&message);

    let mut hasher = Sha512::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "128-byte boundary test failed");
}

#[test]
fn test_large_message() {
    // Test with a larger message (multiple blocks)
    let message = vec![b'A'; 2000];
    let hash = sha512(&message);

    let mut hasher = Sha512::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "Large message test failed");
}

#[test]
fn test_split_across_blocks() {
    // Test updating in chunks that cross block boundaries
    let message = vec![b'B'; 500];

    let mut hasher = Sha512::new();
    for chunk in message.chunks(60) {
        hasher.update(chunk);
    }
    let hash_chunked = hasher.finalize();

    let hash_direct = sha512(&message);

    assert_eq!(hash_chunked, hash_direct, "Cross-block split test failed");
}

#[test]
fn test_deterministic() {
    // Same input should always produce same output
    let message = b"deterministic test for SHA-512";

    let hash1 = sha512(message);
    let hash2 = sha512(message);

    assert_eq!(hash1, hash2, "SHA-512 is not deterministic");
}

#[test]
fn test_different_inputs_different_outputs() {
    let hash1 = sha512(b"message1");
    let hash2 = sha512(b"message2");

    assert_ne!(
        hash1, hash2,
        "Different inputs should produce different hashes"
    );
}

#[test]
fn test_long_message() {
    // Test with 10,000 bytes
    let message = vec![b'X'; 10_000];
    let hash = sha512(&message);

    // Verify incremental hashing
    let mut hasher = Sha512::new();
    for chunk in message.chunks(1000) {
        hasher.update(chunk);
    }
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "Long message test failed");
}

#[test]
fn test_million_a() {
    // NIST test: one million 'a' characters
    // This test is slow, but verifies correct handling of very large inputs
    let message = vec![b'a'; 1_000_000];
    let hash = sha512(&message);
    let expected = hex_literal::hex!(
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb
         de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
    assert_eq!(hash, expected, "Million 'a' test failed");
}
