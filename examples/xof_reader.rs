//! XOF Reader examples for SHAKE128 and SHAKE256
//!
//! Demonstrates streaming output extraction from extendable-output functions

use hpcrypt_hash::sha3::{Shake128, Shake256};

fn main() {
    println!("=== XOF Reader Examples ===\n");

    // Example 1: Basic XOF Reader usage
    println!("1. Basic XOF Reader Usage");
    let mut shake = Shake128::new();
    shake.update(b"Hello, World!");
    let mut reader = shake.finalize_xof();

    let mut output1 = [0u8; 32];
    reader.read(&mut output1);
    println!("   First 32 bytes:  {}", hex::encode(&output1));

    let mut output2 = [0u8; 32];
    reader.read(&mut output2);
    println!("   Next 32 bytes:   {}", hex::encode(&output2));
    println!();

    // Example 2: Fixed-size array extraction
    println!("2. Fixed-Size Array Extraction");
    let mut shake = Shake128::new();
    shake.update(b"test data");
    let mut reader = shake.finalize_xof();

    let chunk1: [u8; 16] = reader.read_array();
    let chunk2: [u8; 16] = reader.read_array();
    let chunk3: [u8; 16] = reader.read_array();

    println!("   Chunk 1 (16 bytes): {}", hex::encode(&chunk1));
    println!("   Chunk 2 (16 bytes): {}", hex::encode(&chunk2));
    println!("   Chunk 3 (16 bytes): {}", hex::encode(&chunk3));
    println!();

    // Example 3: Variable-length output
    println!("3. Variable-Length Output");
    let mut shake = Shake256::new();
    shake.update(b"input");
    let mut reader = shake.finalize_xof();

    // Read different sizes
    let mut small = [0u8; 8];
    reader.read(&mut small);
    println!("   8 bytes:   {}", hex::encode(&small));

    let mut medium = [0u8; 64];
    reader.read(&mut medium);
    println!("   64 bytes:  {}...", hex::encode(&medium[..16]));

    let mut large = [0u8; 256];
    reader.read(&mut large);
    println!("   256 bytes: {}...", hex::encode(&large[..16]));
    println!();

    // Example 4: Forking readers
    println!("4. Forking XOF Readers");
    let mut shake = Shake128::new();
    shake.update(b"fork test");
    let mut reader1 = shake.finalize_xof();

    // Read some data
    let mut initial = [0u8; 32];
    reader1.read(&mut initial);
    println!("   Initial read: {}", hex::encode(&initial[..8]));

    // Fork the reader
    let mut reader2 = reader1.fork();

    // Both readers now produce the same output
    let output_a: [u8; 16] = reader1.read_array();
    let output_b: [u8; 16] = reader2.read_array();

    println!("   Reader 1: {}", hex::encode(&output_a));
    println!("   Reader 2: {}", hex::encode(&output_b));
    println!("   Match: {}", output_a == output_b);
    println!();

    // Example 5: Comparing XOF vs one-shot finalize
    println!("5. XOF Reader vs One-Shot Finalize");
    let input = b"comparison test";

    // One-shot finalize
    let mut shake1 = Shake128::new();
    shake1.update(input);
    let mut oneshot = vec![0u8; 128];
    shake1.finalize(&mut oneshot);

    // XOF reader
    let mut shake2 = Shake128::new();
    shake2.update(input);
    let mut reader = shake2.finalize_xof();
    let mut streamed = vec![0u8; 128];
    reader.read(&mut streamed);

    println!("   One-shot: {}...", hex::encode(&oneshot[..16]));
    println!("   Streamed: {}...", hex::encode(&streamed[..16]));
    println!("   Match: {}", oneshot == streamed);
    println!();

    // Example 6: Key derivation with XOF
    println!("6. Key Derivation with XOF");
    let master_secret = b"master-secret-2024";
    let mut shake = Shake256::new();
    shake.update(master_secret);
    shake.update(b"context-info");
    let mut reader = shake.finalize_xof();

    let encryption_key: [u8; 32] = reader.read_array();
    let mac_key: [u8; 32] = reader.read_array();
    let iv: [u8; 16] = reader.read_array();

    println!("   Encryption key: {}", hex::encode(&encryption_key));
    println!("   MAC key:        {}", hex::encode(&mac_key));
    println!("   IV:             {}", hex::encode(&iv));
    println!();

    println!("=== Examples Complete ===");
}
