// Comprehensive SHA3 family tests
// Tests for SHA3-224, SHA3-256, SHA3-384, and SHA3-512

use hpcrypt_hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

// ============================================================================
// SHA3-224 Tests
// ============================================================================

#[test]
fn test_sha3_224_empty() {
    let hash = Sha3_224::digest(b"");
    let expected = hex_literal::hex!("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    assert_eq!(hash, expected, "SHA3-224 empty message test failed");
}

#[test]
fn test_sha3_224_abc() {
    // NIST test vector
    let hash = Sha3_224::digest(b"abc");
    let expected = hex_literal::hex!("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    assert_eq!(hash, expected, "SHA3-224 'abc' test failed");
}

#[test]
fn test_sha3_224_fox() {
    let hash = Sha3_224::digest(b"The quick brown fox jumps over the lazy dog");
    let expected = hex_literal::hex!("d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795");
    assert_eq!(hash, expected, "SHA3-224 fox test failed");
}

#[test]
fn test_sha3_224_incremental() {
    let mut hasher = Sha3_224::new();
    hasher.update(b"The quick brown fox ");
    hasher.update(b"jumps over the lazy dog");
    let hash_incremental = hasher.finalize();

    let hash_direct = Sha3_224::digest(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
        hash_incremental, hash_direct,
        "SHA3-224 incremental hashing failed"
    );
}

// ============================================================================
// SHA3-256 Tests
// ============================================================================

#[test]
fn test_sha3_256_empty() {
    let hash = Sha3_256::digest(b"");
    let expected =
        hex_literal::hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq!(hash, expected, "SHA3-256 empty message test failed");
}

#[test]
fn test_sha3_256_abc() {
    // NIST test vector
    let hash = Sha3_256::digest(b"abc");
    let expected =
        hex_literal::hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    assert_eq!(hash, expected, "SHA3-256 'abc' test failed");
}

#[test]
fn test_sha3_256_fox() {
    let hash = Sha3_256::digest(b"The quick brown fox jumps over the lazy dog");
    let expected =
        hex_literal::hex!("69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04");
    assert_eq!(hash, expected, "SHA3-256 fox test failed");
}

#[test]
fn test_sha3_256_single_byte() {
    let hash = Sha3_256::digest(b"a");
    let expected =
        hex_literal::hex!("80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b");
    assert_eq!(hash, expected, "SHA3-256 single byte test failed");
}

#[test]
fn test_sha3_256_incremental() {
    let mut hasher = Sha3_256::new();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let hash_incremental = hasher.finalize();

    let hash_direct = Sha3_256::digest(b"Hello, World!");
    assert_eq!(
        hash_incremental, hash_direct,
        "SHA3-256 incremental hashing failed"
    );
}

#[test]
fn test_sha3_256_multiple_updates() {
    let mut hasher = Sha3_256::new();
    hasher.update(b"a");
    hasher.update(b"bc");
    hasher.update(b"def");
    hasher.update(b"ghij");
    let hash = hasher.finalize();

    let hash_direct = Sha3_256::digest(b"abcdefghij");
    assert_eq!(hash, hash_direct, "SHA3-256 multiple updates failed");
}

#[test]
fn test_sha3_256_long_message() {
    // Test with 1600 bits (one rate for SHA3-256 is 1088 bits)
    let message = vec![b'a'; 200];
    let hash = Sha3_256::digest(&message);

    let mut hasher = Sha3_256::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash, hash_incremental, "SHA3-256 long message test failed");
}

#[test]
fn test_sha3_256_448_bits() {
    // NIST-like test vector: 448 bits (56 bytes)
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let hash = Sha3_256::digest(message);
    let expected =
        hex_literal::hex!("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    assert_eq!(hash, expected, "SHA3-256 448-bit message test failed");
}

#[test]
fn test_sha3_256_896_bits() {
    // NIST-like test vector: 896 bits
    let message =
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let hash = Sha3_256::digest(message);
    let expected =
        hex_literal::hex!("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");
    assert_eq!(hash, expected, "SHA3-256 896-bit message test failed");
}

// ============================================================================
// SHA3-384 Tests
// ============================================================================

#[test]
fn test_sha3_384_empty() {
    let hash = Sha3_384::digest(b"");
    let expected = hex_literal::hex!(
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    );
    assert_eq!(hash, expected, "SHA3-384 empty message test failed");
}

#[test]
fn test_sha3_384_abc() {
    // NIST test vector
    let hash = Sha3_384::digest(b"abc");
    let expected = hex_literal::hex!(
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    );
    assert_eq!(hash, expected, "SHA3-384 'abc' test failed");
}

#[test]
fn test_sha3_384_fox() {
    let hash = Sha3_384::digest(b"The quick brown fox jumps over the lazy dog");
    let expected = hex_literal::hex!(
        "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41"
    );
    assert_eq!(hash, expected, "SHA3-384 fox test failed");
}

#[test]
fn test_sha3_384_incremental() {
    let mut hasher = Sha3_384::new();
    hasher.update(b"The quick brown fox ");
    hasher.update(b"jumps over the lazy dog");
    let hash_incremental = hasher.finalize();

    let hash_direct = Sha3_384::digest(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
        hash_incremental, hash_direct,
        "SHA3-384 incremental hashing failed"
    );
}

#[test]
fn test_sha3_384_448_bits() {
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let hash = Sha3_384::digest(message);
    let expected = hex_literal::hex!(
        "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"
    );
    assert_eq!(hash, expected, "SHA3-384 448-bit message test failed");
}

// ============================================================================
// SHA3-512 Tests
// ============================================================================

#[test]
fn test_sha3_512_empty() {
    let hash = Sha3_512::digest(b"");
    let expected = hex_literal::hex!(
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );
    assert_eq!(hash, expected, "SHA3-512 empty message test failed");
}

#[test]
fn test_sha3_512_abc() {
    // NIST test vector
    let hash = Sha3_512::digest(b"abc");
    let expected = hex_literal::hex!(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
    assert_eq!(hash, expected, "SHA3-512 'abc' test failed");
}

#[test]
fn test_sha3_512_fox() {
    let hash = Sha3_512::digest(b"The quick brown fox jumps over the lazy dog");
    let expected = hex_literal::hex!(
        "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450"
    );
    assert_eq!(hash, expected, "SHA3-512 fox test failed");
}

#[test]
fn test_sha3_512_incremental() {
    let mut hasher = Sha3_512::new();
    hasher.update(b"The quick brown fox ");
    hasher.update(b"jumps over the lazy dog");
    let hash_incremental = hasher.finalize();

    let hash_direct = Sha3_512::digest(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
        hash_incremental, hash_direct,
        "SHA3-512 incremental hashing failed"
    );
}

#[test]
fn test_sha3_512_448_bits() {
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let hash = Sha3_512::digest(message);
    let expected = hex_literal::hex!(
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
    );
    assert_eq!(hash, expected, "SHA3-512 448-bit message test failed");
}

// ============================================================================
// Cross-variant Tests
// ============================================================================

#[test]
fn test_deterministic() {
    let message = b"deterministic test";

    let hash1 = Sha3_256::digest(message);
    let hash2 = Sha3_256::digest(message);
    assert_eq!(hash1, hash2, "SHA3-256 is not deterministic");

    let hash3 = Sha3_512::digest(message);
    let hash4 = Sha3_512::digest(message);
    assert_eq!(hash3, hash4, "SHA3-512 is not deterministic");
}

#[test]
fn test_different_inputs() {
    let hash1 = Sha3_256::digest(b"message1");
    let hash2 = Sha3_256::digest(b"message2");
    assert_ne!(
        hash1, hash2,
        "Different inputs should produce different hashes"
    );
}

#[test]
fn test_large_message() {
    // Test with 10KB message
    let message = vec![b'A'; 10240];

    let hash_direct = Sha3_256::digest(&message);

    let mut hasher = Sha3_256::new();
    hasher.update(&message);
    let hash_incremental = hasher.finalize();

    assert_eq!(hash_direct, hash_incremental, "Large message test failed");
}

#[test]
fn test_chunked_updates() {
    let message = vec![b'B'; 1000];

    let mut hasher = Sha3_256::new();
    for chunk in message.chunks(137) {
        // 137 is close to SHA3-256 rate
        hasher.update(chunk);
    }
    let hash_chunked = hasher.finalize();

    let hash_direct = Sha3_256::digest(&message);
    assert_eq!(hash_chunked, hash_direct, "Chunked updates test failed");
}

#[test]
fn test_boundary_rates() {
    // SHA3-256 rate is 136 bytes (1088 bits)
    // Test around this boundary

    // Just under one rate
    let msg_135 = vec![b'a'; 135];
    let hash_135 = Sha3_256::digest(&msg_135);
    let mut hasher = Sha3_256::new();
    hasher.update(&msg_135);
    assert_eq!(hash_135, hasher.finalize());

    // Exactly one rate
    let msg_136 = vec![b'a'; 136];
    let hash_136 = Sha3_256::digest(&msg_136);
    let mut hasher = Sha3_256::new();
    hasher.update(&msg_136);
    assert_eq!(hash_136, hasher.finalize());

    // Just over one rate
    let msg_137 = vec![b'a'; 137];
    let hash_137 = Sha3_256::digest(&msg_137);
    let mut hasher = Sha3_256::new();
    hasher.update(&msg_137);
    assert_eq!(hash_137, hasher.finalize());
}
