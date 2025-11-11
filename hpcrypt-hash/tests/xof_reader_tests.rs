//! Comprehensive tests for XOF Reader
//!
//! Tests streaming output extraction from SHAKE128 and SHAKE256

use hpcrypt_hash::sha3::{Shake128, Shake256};

// ===== Basic Functionality Tests =====

#[test]
fn test_basic_read() {
    let mut shake = Shake128::new();
    shake.update(b"test");
    let mut reader = shake.finalize_xof();

    let mut output = [0u8; 64];
    reader.read(&mut output);

    // Output should not be all zeros
    assert_ne!(output, [0u8; 64], "Output should not be all zeros");
}

#[test]
fn test_sequential_reads() {
    let mut shake = Shake128::new();
    shake.update(b"sequential");
    let mut reader = shake.finalize_xof();

    let mut chunk1 = [0u8; 32];
    let mut chunk2 = [0u8; 32];

    reader.read(&mut chunk1);
    reader.read(&mut chunk2);

    // Sequential chunks should be different
    assert_ne!(chunk1, chunk2, "Sequential chunks should be different");
}

#[test]
fn test_empty_read() {
    let mut shake = Shake128::new();
    shake.update(b"empty read test");
    let mut reader = shake.finalize_xof();

    // Reading zero bytes should not panic
    let mut empty = [];
    reader.read(&mut empty);

    // Subsequent reads should work normally
    let mut output = [0u8; 16];
    reader.read(&mut output);
    assert_ne!(output, [0u8; 16]);
}

// ===== Consistency Tests =====

#[test]
fn test_xof_vs_finalize_consistency() {
    let input = b"consistency test";

    // One-shot finalize
    let mut shake1 = Shake128::new();
    shake1.update(input);
    let mut expected = vec![0u8; 256];
    shake1.finalize(&mut expected);

    // XOF reader
    let mut shake2 = Shake128::new();
    shake2.update(input);
    let mut reader = shake2.finalize_xof();
    let mut actual = vec![0u8; 256];
    reader.read(&mut actual);

    assert_eq!(expected, actual, "XOF reader should match one-shot finalize");
}

#[test]
fn test_incremental_consistency() {
    let input = b"incremental test";

    // All at once
    let mut shake1 = Shake256::new();
    shake1.update(input);
    let mut reader1 = shake1.finalize_xof();
    let mut all_at_once = vec![0u8; 500];
    reader1.read(&mut all_at_once);

    // Incremental reads
    let mut shake2 = Shake256::new();
    shake2.update(input);
    let mut reader2 = shake2.finalize_xof();
    let mut incremental = vec![0u8; 500];

    reader2.read(&mut incremental[0..100]);
    reader2.read(&mut incremental[100..200]);
    reader2.read(&mut incremental[200..350]);
    reader2.read(&mut incremental[350..500]);

    assert_eq!(all_at_once, incremental, "Incremental reads should match all-at-once");
}

#[test]
fn test_single_byte_reads() {
    let input = b"byte by byte";

    // Read normally
    let mut shake1 = Shake128::new();
    shake1.update(input);
    let mut reader1 = shake1.finalize_xof();
    let mut normal = [0u8; 100];
    reader1.read(&mut normal);

    // Read byte by byte
    let mut shake2 = Shake128::new();
    shake2.update(input);
    let mut reader2 = shake2.finalize_xof();
    let mut byte_by_byte = [0u8; 100];

    for byte in &mut byte_by_byte {
        reader2.read(core::slice::from_mut(byte));
    }

    assert_eq!(normal, byte_by_byte, "Byte-by-byte reading should match normal read");
}

// ===== Fork Tests =====

#[test]
fn test_fork_independence() {
    let mut shake = Shake128::new();
    shake.update(b"fork test");
    let mut reader1 = shake.finalize_xof();

    // Read some data
    let mut initial = [0u8; 32];
    reader1.read(&mut initial);

    // Fork the reader
    let mut reader2 = reader1.fork();

    // Both should produce identical output from this point
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];

    reader1.read(&mut out1);
    reader2.read(&mut out2);

    assert_eq!(out1, out2, "Forked readers should produce identical output");
}

#[test]
fn test_multiple_forks() {
    let mut shake = Shake256::new();
    shake.update(b"multiple forks");
    let mut reader = shake.finalize_xof();

    // Read initial data
    let initial: [u8; 16] = reader.read_array();

    // Create multiple forks
    let mut fork1 = reader.fork();
    let mut fork2 = reader.fork();
    let mut fork3 = reader.fork();

    // All should produce identical output
    let out_orig: [u8; 32] = reader.read_array();
    let out1: [u8; 32] = fork1.read_array();
    let out2: [u8; 32] = fork2.read_array();
    let out3: [u8; 32] = fork3.read_array();

    assert_eq!(out_orig, out1);
    assert_eq!(out_orig, out2);
    assert_eq!(out_orig, out3);
    assert_ne!(initial, out_orig[..16]);
}

#[test]
fn test_fork_at_different_positions() {
    let mut shake = Shake128::new();
    shake.update(b"position test");
    let reader = shake.finalize_xof();

    // Fork at start
    let mut fork_at_start = reader.clone();

    // Fork after reading
    let mut reader_after = reader.clone();
    let _: [u8; 50] = reader_after.read_array();
    let mut fork_after_50 = reader_after.clone();

    // Read from both
    let start_output: [u8; 32] = fork_at_start.read_array();
    let after_output: [u8; 32] = fork_after_50.read_array();

    // They should produce different output
    assert_ne!(start_output, after_output);
}

// ===== read_array Tests =====

#[test]
fn test_read_array_basic() {
    let mut shake = Shake128::new();
    shake.update(b"array test");
    let mut reader = shake.finalize_xof();

    let array1: [u8; 32] = reader.read_array();
    let array2: [u8; 32] = reader.read_array();

    assert_ne!(array1, array2, "Sequential arrays should be different");
}

#[test]
fn test_read_array_vs_read_slice() {
    let input = b"array vs slice";

    // Using read_array
    let mut shake1 = Shake256::new();
    shake1.update(input);
    let mut reader1 = shake1.finalize_xof();
    let array_output: [u8; 48] = reader1.read_array();

    // Using read with slice
    let mut shake2 = Shake256::new();
    shake2.update(input);
    let mut reader2 = shake2.finalize_xof();
    let mut slice_output = [0u8; 48];
    reader2.read(&mut slice_output);

    assert_eq!(array_output, slice_output, "read_array should match read");
}

#[test]
fn test_read_array_various_sizes() {
    let mut shake = Shake128::new();
    shake.update(b"size test");
    let mut reader = shake.finalize_xof();

    let _a1: [u8; 1] = reader.read_array();
    let _a7: [u8; 7] = reader.read_array();
    let _a16: [u8; 16] = reader.read_array();
    let _a31: [u8; 31] = reader.read_array();
    let _a64: [u8; 64] = reader.read_array();
    let _a100: [u8; 100] = reader.read_array();
    let _a256: [u8; 256] = reader.read_array();

    // Should not panic and should work correctly
}

// ===== Different XOF Types Tests =====

#[test]
fn test_shake128_xof() {
    let mut shake = Shake128::new();
    shake.update(b"SHAKE128 test");
    let mut reader = shake.finalize_xof();

    let output: [u8; 64] = reader.read_array();
    assert_ne!(output, [0u8; 64]);
}

#[test]
fn test_shake256_xof() {
    let mut shake = Shake256::new();
    shake.update(b"SHAKE256 test");
    let mut reader = shake.finalize_xof();

    let output: [u8; 64] = reader.read_array();
    assert_ne!(output, [0u8; 64]);
}

#[test]
fn test_different_xof_produce_different_output() {
    let input = b"same input";

    let mut shake128 = Shake128::new();
    shake128.update(input);
    let mut reader128 = shake128.finalize_xof();
    let out128: [u8; 32] = reader128.read_array();

    let mut shake256 = Shake256::new();
    shake256.update(input);
    let mut reader256 = shake256.finalize_xof();
    let out256: [u8; 32] = reader256.read_array();

    // SHAKE128 and SHAKE256 should produce different outputs
    assert_ne!(out128, out256);
}

// ===== Large Output Tests =====

#[test]
fn test_large_output() {
    let mut shake = Shake128::new();
    shake.update(b"large output test");
    let mut reader = shake.finalize_xof();

    let mut large_output = vec![0u8; 10000];
    reader.read(&mut large_output);

    // Should not be all zeros
    assert!(large_output.iter().any(|&b| b != 0));
}

#[test]
fn test_very_large_streaming() {
    let mut shake = Shake256::new();
    shake.update(b"streaming test");
    let mut reader = shake.finalize_xof();

    // Read 100 KB in chunks
    let chunk_size = 1024;
    let num_chunks = 100;

    for _ in 0..num_chunks {
        let mut chunk = vec![0u8; chunk_size];
        reader.read(&mut chunk);
        // Each chunk should have non-zero bytes
        assert!(chunk.iter().any(|&b| b != 0));
    }
}

// ===== Boundary Tests =====

#[test]
fn test_rate_boundary_reads() {
    let mut shake = Shake128::new();
    shake.update(b"boundary test");
    let mut reader = shake.finalize_xof();

    // SHAKE128 has rate = 168 bytes
    // Read exactly at rate boundary
    let mut output = [0u8; 168];
    reader.read(&mut output);
    assert_ne!(output, [0u8; 168]);

    // Read one more byte (crosses boundary)
    let mut single = [0u8; 1];
    reader.read(&mut single);
    assert_ne!(single[0], 0);
}

#[test]
fn test_reads_across_multiple_blocks() {
    let mut shake = Shake256::new();
    shake.update(b"multi-block test");
    let mut reader = shake.finalize_xof();

    // SHAKE256 has rate = 136 bytes
    // Read multiple blocks worth
    let mut output = vec![0u8; 500]; // ~3.7 blocks
    reader.read(&mut output);

    assert_ne!(output, vec![0u8; 500]);
}

// ===== Clone Tests =====

#[test]
fn test_clone_equivalence() {
    let mut shake = Shake128::new();
    shake.update(b"clone test");
    let reader = shake.finalize_xof();

    let mut clone = reader.clone();

    // Both should produce identical output
    let mut out1 = [0u8; 128];
    let mut out2 = [0u8; 128];

    let mut reader = reader; // Make mutable
    reader.read(&mut out1);
    clone.read(&mut out2);

    assert_eq!(out1, out2, "Clone should produce identical output");
}

// ===== Determinism Tests =====

#[test]
fn test_deterministic_output() {
    let input = b"determinism test";

    let mut shake1 = Shake128::new();
    shake1.update(input);
    let mut reader1 = shake1.finalize_xof();
    let out1: [u8; 100] = reader1.read_array();

    let mut shake2 = Shake128::new();
    shake2.update(input);
    let mut reader2 = shake2.finalize_xof();
    let out2: [u8; 100] = reader2.read_array();

    assert_eq!(out1, out2, "Same input should produce same output");
}

#[test]
fn test_different_input_different_output() {
    let mut shake1 = Shake256::new();
    shake1.update(b"input1");
    let mut reader1 = shake1.finalize_xof();
    let out1: [u8; 64] = reader1.read_array();

    let mut shake2 = Shake256::new();
    shake2.update(b"input2");
    let mut reader2 = shake2.finalize_xof();
    let out2: [u8; 64] = reader2.read_array();

    assert_ne!(out1, out2, "Different inputs should produce different outputs");
}

// ===== Use Case Tests =====

#[test]
fn test_key_derivation_use_case() {
    let master_secret = b"master-secret";
    let context = b"key-derivation-context";

    let mut shake = Shake256::new();
    shake.update(master_secret);
    shake.update(context);
    let mut reader = shake.finalize_xof();

    // Derive multiple keys
    let encryption_key: [u8; 32] = reader.read_array();
    let mac_key: [u8; 64] = reader.read_array();
    let iv: [u8; 16] = reader.read_array();
    let salt: [u8; 32] = reader.read_array();

    // All should be different
    assert_ne!(&encryption_key[..], &mac_key[..32]);
    assert_ne!(&encryption_key[..16], &iv[..]);
    assert_ne!(encryption_key, salt);

    // All should be non-zero
    assert!(encryption_key.iter().any(|&b| b != 0));
    assert!(mac_key.iter().any(|&b| b != 0));
    assert!(iv.iter().any(|&b| b != 0));
    assert!(salt.iter().any(|&b| b != 0));
}

#[test]
fn test_stream_cipher_use_case() {
    let key = b"stream-cipher-key";
    let nonce = b"nonce";

    let mut shake = Shake128::new();
    shake.update(key);
    shake.update(nonce);
    let mut reader = shake.finalize_xof();

    // Generate keystream
    let keystream_chunk1: [u8; 256] = reader.read_array();
    let keystream_chunk2: [u8; 256] = reader.read_array();

    // Chunks should be different
    assert_ne!(keystream_chunk1, keystream_chunk2);

    // Each chunk should have entropy
    assert!(keystream_chunk1.iter().any(|&b| b != 0));
    assert!(keystream_chunk2.iter().any(|&b| b != 0));
}
