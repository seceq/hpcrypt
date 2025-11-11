// Comprehensive SHAKE (XOF) tests
// Tests for SHAKE128 and SHAKE256

use hpcrypt_hash::sha3::{Shake128, Shake256};

// ============================================================================
// SHAKE128 Tests
// ============================================================================

#[test]
fn test_shake128_empty_32bytes() {
    let mut output = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"");
    shake.finalize(&mut output);

    // First 32 bytes of SHAKE128("")
    let expected = hex_literal::hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    assert_eq!(
        output, expected,
        "SHAKE128 empty message (32 bytes) test failed"
    );
}

#[test]
fn test_shake128_empty_64bytes() {
    let mut output = vec![0u8; 64];
    let mut shake = Shake128::new();
    shake.update(b"");
    shake.finalize(&mut output);

    let expected = hex_literal::hex!(
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b443e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f"
    );
    assert_eq!(
        output, expected,
        "SHAKE128 empty message (64 bytes) test failed"
    );
}

#[test]
fn test_shake128_abc_16bytes() {
    let mut output = vec![0u8; 16];
    let mut shake = Shake128::new();
    shake.update(b"abc");
    shake.finalize(&mut output);

    let expected = hex_literal::hex!("5881092dd818bf5cf8a3ddb793fbcba7");
    assert_eq!(output, expected, "SHAKE128 'abc' (16 bytes) test failed");
}

#[test]
fn test_shake128_abc_32bytes() {
    let mut output = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"abc");
    shake.finalize(&mut output);

    let expected = hex_literal::hex!("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
    assert_eq!(output, expected, "SHAKE128 'abc' (32 bytes) test failed");
}

#[test]
fn test_shake128_variable_output() {
    // Test that longer output contains shorter output as prefix
    let message = b"test message";

    let mut out_16 = vec![0u8; 16];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out_16);

    let mut out_32 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out_32);

    // First 16 bytes of 32-byte output should match 16-byte output
    assert_eq!(
        &out_32[..16],
        &out_16[..],
        "SHAKE128 output prefix consistency failed"
    );
}

#[test]
fn test_shake128_incremental() {
    let mut out1 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"Hello, ");
    shake.update(b"World!");
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"Hello, World!");
    shake.finalize(&mut out2);

    assert_eq!(out1, out2, "SHAKE128 incremental hashing failed");
}

#[test]
fn test_shake128_multiple_updates() {
    let mut out1 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"a");
    shake.update(b"bc");
    shake.update(b"def");
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"abcdef");
    shake.finalize(&mut out2);

    assert_eq!(out1, out2, "SHAKE128 multiple updates failed");
}

#[test]
fn test_shake128_large_output() {
    // Test with large output (1KB)
    let mut output = vec![0u8; 1024];
    let mut shake = Shake128::new();
    shake.update(b"large output test");
    shake.finalize(&mut output);

    // Verify it doesn't panic and produces non-zero output
    assert!(
        output.iter().any(|&x| x != 0),
        "SHAKE128 large output is all zeros"
    );
}

// ============================================================================
// SHAKE256 Tests
// ============================================================================

#[test]
fn test_shake256_empty_32bytes() {
    let mut output = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(b"");
    shake.finalize(&mut output);

    let expected = hex_literal::hex!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    assert_eq!(
        output, expected,
        "SHAKE256 empty message (32 bytes) test failed"
    );
}

#[test]
fn test_shake256_empty_64bytes() {
    let mut output = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(b"");
    shake.finalize(&mut output);

    let expected = hex_literal::hex!(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    );
    assert_eq!(
        output, expected,
        "SHAKE256 empty message (64 bytes) test failed"
    );
}

#[test]
fn test_shake256_abc_32bytes() {
    let mut output = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(b"abc");
    shake.finalize(&mut output);

    let expected = hex_literal::hex!("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
    assert_eq!(output, expected, "SHAKE256 'abc' (32 bytes) test failed");
}

#[test]
fn test_shake256_abc_64bytes() {
    let mut output = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(b"abc");
    shake.finalize(&mut output);

    let expected = hex_literal::hex!(
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
    );
    assert_eq!(output, expected, "SHAKE256 'abc' (64 bytes) test failed");
}

#[test]
fn test_shake256_variable_output() {
    // Test that longer output contains shorter output as prefix
    let message = b"test message";

    let mut out_32 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_32);

    let mut out_64 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_64);

    // First 32 bytes of 64-byte output should match 32-byte output
    assert_eq!(
        &out_64[..32],
        &out_32[..],
        "SHAKE256 output prefix consistency failed"
    );
}

#[test]
fn test_shake256_incremental() {
    let mut out1 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(b"Hello, ");
    shake.update(b"World!");
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(b"Hello, World!");
    shake.finalize(&mut out2);

    assert_eq!(out1, out2, "SHAKE256 incremental hashing failed");
}

#[test]
fn test_shake256_multiple_updates() {
    let mut out1 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(b"a");
    shake.update(b"bc");
    shake.update(b"def");
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(b"abcdef");
    shake.finalize(&mut out2);

    assert_eq!(out1, out2, "SHAKE256 multiple updates failed");
}

#[test]
fn test_shake256_large_output() {
    // Test with large output (2KB)
    let mut output = vec![0u8; 2048];
    let mut shake = Shake256::new();
    shake.update(b"large output test");
    shake.finalize(&mut output);

    // Verify it doesn't panic and produces non-zero output
    assert!(
        output.iter().any(|&x| x != 0),
        "SHAKE256 large output is all zeros"
    );
}

// ============================================================================
// Cross-variant Tests
// ============================================================================

#[test]
fn test_deterministic() {
    let message = b"deterministic test";

    let mut out1 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out2);

    assert_eq!(out1, out2, "SHAKE128 is not deterministic");

    let mut out3 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out3);

    let mut out4 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out4);

    assert_eq!(out3, out4, "SHAKE256 is not deterministic");
}

#[test]
fn test_different_inputs() {
    let mut out1 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"message1");
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"message2");
    shake.finalize(&mut out2);

    assert_ne!(
        out1, out2,
        "Different inputs should produce different outputs"
    );
}

#[test]
fn test_shake128_vs_shake256() {
    // Same input should produce different outputs for SHAKE128 vs SHAKE256
    let message = b"compare shake variants";

    let mut out_128 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out_128);

    let mut out_256 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_256);

    assert_ne!(
        out_128, out_256,
        "SHAKE128 and SHAKE256 should produce different outputs"
    );
}

#[test]
fn test_long_message() {
    // Test with 10KB message
    let message = vec![b'A'; 10240];

    let mut out1 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(&message);
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 32];
    let mut shake = Shake256::new();
    for chunk in message.chunks(100) {
        shake.update(chunk);
    }
    shake.finalize(&mut out2);

    assert_eq!(out1, out2, "Long message incremental test failed");
}

#[test]
fn test_boundary_rates() {
    // SHAKE128 rate is 168 bytes, SHAKE256 rate is 136 bytes

    // Test around SHAKE256 rate boundary (136 bytes)
    let msg_135 = vec![b'a'; 135];
    let mut out1 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(&msg_135);
    shake.finalize(&mut out1);

    let mut out2 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(&msg_135);
    shake.finalize(&mut out2);
    assert_eq!(out1, out2);

    let msg_137 = vec![b'a'; 137];
    let mut out3 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(&msg_137);
    shake.finalize(&mut out3);

    let mut out4 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(&msg_137);
    shake.finalize(&mut out4);
    assert_eq!(out3, out4);
}

#[test]
fn test_zero_length_output() {
    // Test that zero-length output doesn't panic
    let mut output = vec![0u8; 0];
    let mut shake = Shake128::new();
    shake.update(b"test");
    shake.finalize(&mut output);
    // Should not panic
}

#[test]
fn test_odd_output_sizes() {
    // Test with non-power-of-2 output sizes
    let message = b"odd sizes";

    for size in [1, 3, 7, 15, 33, 100, 255].iter() {
        let mut output = vec![0u8; *size];
        let mut shake = Shake256::new();
        shake.update(message);
        shake.finalize(&mut output);
        // Should not panic and should fill entire buffer
        assert_eq!(output.len(), *size);
    }
}
