// Comprehensive correctness tests for SHAKE256 AVX2 implementation
//
// This test suite validates that the AVX2-accelerated fips202x4 implementation
// produces bit-exact identical output to the reference sha3 crate implementation.

#![cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Reference SHAKE256 implementation using sha3 crate
fn shake256_reference(input: &[u8], outlen: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; outlen];
    reader.read(&mut output);
    output
}

/// Test helper: run 4-way AVX2 and compare each output with reference
fn test_shake256x4_against_reference(inputs: [&[u8]; 4], output_len: usize, test_name: &str) {
    use mldsa::simd::keccak::shake256x4_batch;

    // Compute with AVX2
    let avx2_outputs = shake256x4_batch(inputs, output_len);

    // Compute reference for each input
    for i in 0..4 {
        let reference = shake256_reference(inputs[i], output_len);

        assert_eq!(
            avx2_outputs[i], reference,
            "{}: Output {} mismatch (AVX2 vs reference)",
            test_name, i
        );
    }
}

#[test]
fn test_1_empty_input() {
    let inputs = [&[] as &[u8]; 4];
    test_shake256x4_against_reference(inputs, 32, "Empty input");
}

#[test]
fn test_2_short_inputs() {
    // All inputs must have same length for fips202x4
    let inputs = [b"aaa" as &[u8], b"bbb", b"ccc", b"ddd"];
    test_shake256x4_against_reference(inputs, 32, "Short inputs");
}

#[test]
fn test_3_single_block() {
    // SHAKE256 rate is 136 bytes, test inputs < 136 bytes
    // All inputs must have same length for fips202x4
    let input = b"The quick brown fox jumps over the lazy dog";
    let inputs = [input as &[u8]; 4];

    test_shake256x4_against_reference(inputs, 64, "Single block");
}

#[test]
fn test_4_exactly_one_block() {
    // Exactly 136 bytes (SHAKE256 rate)
    let input = &[0x42u8; 136];
    let inputs = [input as &[u8]; 4];
    test_shake256x4_against_reference(inputs, 64, "Exactly one block");
}

#[test]
fn test_5_multi_block() {
    // More than 136 bytes → requires multiple Keccak permutations
    let input = &[0x5Au8; 300];
    let inputs = [input as &[u8]; 4];
    test_shake256x4_against_reference(inputs, 128, "Multi-block input");
}

#[test]
fn test_6_large_input() {
    // Large input (> 1KB)
    let input = &[0x7Fu8; 2048];
    let inputs = [input as &[u8]; 4];
    test_shake256x4_against_reference(inputs, 256, "Large input");
}

#[test]
fn test_7_varying_lengths() {
    // Different output lengths for same input
    let input = b"SHAKE256 extendable output";
    let inputs = [input as &[u8]; 4];

    for outlen in [16, 32, 64, 128, 200, 500] {
        test_shake256x4_against_reference(inputs, outlen, &format!("Output length {}", outlen));
    }
}

#[test]
fn test_8_binary_data() {
    // Binary data (not UTF-8)
    let in0 = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let in1 = &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let in2 = &[0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];
    let in3 = &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

    test_shake256x4_against_reference([in0, in1, in2, in3], 48, "Binary data");
}

#[test]
fn test_9_all_zeros() {
    let input = &[0x00u8; 256];
    let inputs = [input as &[u8]; 4];
    test_shake256x4_against_reference(inputs, 64, "All zeros");
}

#[test]
fn test_10_all_ones() {
    let input = &[0xFFu8; 256];
    let inputs = [input as &[u8]; 4];
    test_shake256x4_against_reference(inputs, 64, "All ones");
}

#[test]
fn test_11_incremental_squeezing() {
    // Test that incremental squeezing produces same result as all-at-once
    use mldsa::simd::keccak::{Shake256X4, SHAKE256_RATE};

    let inputs = [b"test0" as &[u8], b"test1", b"test2", b"test3"];

    // Incremental: squeeze 3 blocks one at a time
    let mut xof = Shake256X4::absorb_once(inputs);
    let block1 = xof.squeeze_blocks(1);
    let block2 = xof.squeeze_blocks(1);
    let block3 = xof.squeeze_blocks(1);

    // For each stream, concatenate blocks and compare with reference
    for i in 0..4 {
        let avx2_output = [&block1[i][..], &block2[i][..], &block3[i][..]].concat();
        let reference = shake256_reference(inputs[i], 3 * SHAKE256_RATE);

        assert_eq!(
            avx2_output, reference,
            "Incremental squeezing: Output {} mismatch",
            i
        );
    }
}

#[test]
fn test_12_nist_kat_vectors() {
    // Test vectors from NIST SHAKE256 test suite
    // (These are known-good values)

    // Example: SHAKE256("abc") first 32 bytes
    let input = b"abc";
    let expected_start = [
        0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11,
        0x4d, 0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b,
        0x57, 0x39,
    ];

    use mldsa::simd::keccak::shake256x4_batch;
    let outputs = shake256x4_batch([input; 4], 32);

    for i in 0..4 {
        assert_eq!(
            &outputs[i][..32],
            &expected_start[..],
            "NIST KAT: Output {} mismatch",
            i
        );
    }
}

#[test]
fn test_13_different_inputs_different_outputs() {
    // Verify that different inputs produce different outputs (no collisions)
    use mldsa::simd::keccak::shake256x4_batch;

    let inputs = [b"input0" as &[u8], b"input1", b"input2", b"input3"];

    let outputs = shake256x4_batch(inputs, 64);

    // All outputs should be different
    for i in 0..4 {
        for j in (i + 1)..4 {
            assert_ne!(
                outputs[i], outputs[j],
                "Collision detected: outputs {} and {} are identical",
                i, j
            );
        }
    }
}

#[test]
fn test_14_determinism() {
    // Same input should always produce same output (deterministic)
    use mldsa::simd::keccak::shake256x4_batch;

    let inputs = [b"determinism" as &[u8]; 4];

    let run1 = shake256x4_batch(inputs, 128);
    let run2 = shake256x4_batch(inputs, 128);
    let run3 = shake256x4_batch(inputs, 128);

    for i in 0..4 {
        assert_eq!(run1[i], run2[i], "Run 1 vs 2 mismatch at output {}", i);
        assert_eq!(run2[i], run3[i], "Run 2 vs 3 mismatch at output {}", i);
    }
}

#[test]
fn test_15_ml_dsa_parameters() {
    // Test with ML-DSA-specific parameters
    // ML-DSA-65: K=6, L=5

    // Simulate ExpandS input: 32-byte seed + 2-byte nonce
    let mut seed = [0x42u8; 32];
    seed[0] = 0x01; // Different seeds
    seed[1] = 0x02;
    seed[2] = 0x03;
    seed[3] = 0x04;

    let nonce0 = 0u16.to_le_bytes();
    let nonce1 = 1u16.to_le_bytes();
    let nonce2 = 2u16.to_le_bytes();
    let nonce3 = 3u16.to_le_bytes();

    let in0 = [&seed[..], &nonce0[..]].concat();
    let in1 = [&seed[..], &nonce1[..]].concat();
    let in2 = [&seed[..], &nonce2[..]].concat();
    let in3 = [&seed[..], &nonce3[..]].concat();

    // ML-DSA eta=4 sampling needs ~256 bytes per polynomial
    test_shake256x4_against_reference(
        [&in0[..], &in1[..], &in2[..], &in3[..]],
        256,
        "ML-DSA ExpandS simulation",
    );
}

#[test]
fn test_16_stress_large_output() {
    // Stress test: generate very large output (10KB per stream)
    let input = b"stress test";
    let inputs = [input as &[u8]; 4];

    test_shake256x4_against_reference(inputs, 10240, "Stress test large output");
}

#[test]
fn test_17_edge_case_rate_boundary() {
    // Test at rate boundaries (135, 136, 137 bytes)
    for len in [135, 136, 137] {
        let input = vec![0xABu8; len];
        let inputs = [&input[..]; 4];
        test_shake256x4_against_reference(inputs, 64, &format!("Rate boundary: {} bytes", len));
    }
}
