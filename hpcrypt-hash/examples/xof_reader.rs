//! XOF Reader - Streaming API for Extendable-Output Functions
//!
//! Comprehensive examples of XofReader usage with SHAKE128 and SHAKE256

use hpcrypt_hash::sha3::{Shake128, Shake256};

fn main() {
    println!("=== XOF Reader Examples ===\n");

    basic_streaming();
    println!();

    incremental_reading();
    println!();

    reader_forking();
    println!();

    key_material_generation();
    println!();

    all_xof_types();
    println!();

    large_output_streaming();
}

fn basic_streaming() {
    println!("1. Basic Streaming Output");
    println!("   ---------------------");

    let mut shake = Shake128::new();
    shake.update(b"streaming example");
    let mut reader = shake.finalize_xof();

    // Read multiple chunks
    for i in 0..5 {
        let chunk: [u8; 16] = reader.read_array();
        println!("   Chunk {}: {}", i + 1, hex::encode(&chunk[..8]));
    }
}

fn incremental_reading() {
    println!("2. Incremental Reading");
    println!("   ------------------");

    let input = b"test input";

    // Read all at once
    let mut shake1 = Shake256::new();
    shake1.update(input);
    let mut reader1 = shake1.finalize_xof();
    let mut all_at_once = vec![0u8; 200];
    reader1.read(&mut all_at_once);

    // Read incrementally in various chunk sizes
    let mut shake2 = Shake256::new();
    shake2.update(input);
    let mut reader2 = shake2.finalize_xof();
    let mut incremental = vec![0u8; 200];

    reader2.read(&mut incremental[0..10]); // 10 bytes
    reader2.read(&mut incremental[10..50]); // 40 bytes
    reader2.read(&mut incremental[50..100]); // 50 bytes
    reader2.read(&mut incremental[100..200]); // 100 bytes

    println!("   All-at-once:  {}...", hex::encode(&all_at_once[..16]));
    println!("   Incremental:  {}...", hex::encode(&incremental[..16]));
    println!("   Match: {}", all_at_once == incremental);
}

fn reader_forking() {
    println!("3. Reader Forking and Branching");
    println!("   ---------------------------");

    let mut shake = Shake128::new();
    shake.update(b"fork example");
    let mut reader = shake.finalize_xof();

    // Read some initial data
    let initial: [u8; 32] = reader.read_array();
    println!("   Initial: {}", hex::encode(&initial[..8]));

    // Fork the reader at this point
    let mut fork1 = reader.fork();
    let mut fork2 = reader.fork();

    // All three should produce identical output
    let out1: [u8; 24] = reader.read_array();
    let out2: [u8; 24] = fork1.read_array();
    let out3: [u8; 24] = fork2.read_array();

    println!("   Original: {}", hex::encode(&out1[..8]));
    println!("   Fork 1:   {}", hex::encode(&out2[..8]));
    println!("   Fork 2:   {}", hex::encode(&out3[..8]));
    println!("   All match: {}", out1 == out2 && out2 == out3);
}

fn key_material_generation() {
    println!("4. Key Material Generation");
    println!("   ----------------------");

    // Use SHAKE256 to derive multiple keys from a master secret
    let master_secret = b"high-entropy-master-key";
    let context = b"application-v1.0";

    let mut shake = Shake256::new();
    shake.update(master_secret);
    shake.update(context);
    let mut reader = shake.finalize_xof();

    // Derive various key materials
    let aes256_key: [u8; 32] = reader.read_array();
    let hmac_key: [u8; 64] = reader.read_array();
    let iv: [u8; 16] = reader.read_array();
    let salt: [u8; 32] = reader.read_array();

    println!("   AES-256 key: {}", hex::encode(&aes256_key[..16]));
    println!("   HMAC key:    {}", hex::encode(&hmac_key[..16]));
    println!("   IV:          {}", hex::encode(&iv));
    println!("   Salt:        {}", hex::encode(&salt[..16]));
}

fn all_xof_types() {
    println!("5. SHAKE128 vs SHAKE256");
    println!("   -------------------");

    let input = b"test data";

    // SHAKE128 (128-bit security)
    let mut shake128 = Shake128::new();
    shake128.update(input);
    let mut reader128 = shake128.finalize_xof();
    let out128: [u8; 32] = reader128.read_array();
    println!("   SHAKE128: {}", hex::encode(&out128[..16]));

    // SHAKE256 (256-bit security)
    let mut shake256 = Shake256::new();
    shake256.update(input);
    let mut reader256 = shake256.finalize_xof();
    let out256: [u8; 32] = reader256.read_array();
    println!("   SHAKE256: {}", hex::encode(&out256[..16]));
    println!("   Different security levels produce different outputs");
}

fn large_output_streaming() {
    println!("6. Large Output Streaming");
    println!("   ---------------------");

    let mut shake = Shake128::new();
    shake.update(b"large output example");
    let mut reader = shake.finalize_xof();

    // Stream large amounts of data efficiently
    let mut total_bytes = 0;
    let chunk_size = 1024;

    for _ in 0..10 {
        let mut chunk = vec![0u8; chunk_size];
        reader.read(&mut chunk);
        total_bytes += chunk_size;
    }

    println!("   Streamed {} KB total", total_bytes / 1024);
    println!("   Memory efficient: reads one chunk at a time");
}
