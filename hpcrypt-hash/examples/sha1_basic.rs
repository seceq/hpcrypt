//! Basic SHA-1 usage examples
//!
//! **WARNING**: SHA-1 is cryptographically broken and should not be used for
//! security-critical applications. It is provided here for compatibility with
//! legacy protocols.
//!
//! Run with: cargo run --example sha1_basic

use hpcrypt_hash::sha1::{sha1, Sha1};

fn main() {
    println!("=== SHA-1 Basic Examples ===\n");
    println!("WARNING: SHA-1 is broken! Use SHA-256 or better for new applications.\n");

    // Example 1: Simple one-shot hashing
    println!("1. One-shot hashing:");
    let message = b"Hello, World!";
    let hash = sha1(message);
    println!("   Input: {:?}", String::from_utf8_lossy(message));
    println!("   SHA-1: {}", hex_encode(&hash));
    println!();

    // Example 2: Empty string
    println!("2. Empty string:");
    let hash = sha1(b"");
    println!("   SHA-1(\"\") = {}", hex_encode(&hash));
    println!("   Expected:    da39a3ee5e6b4b0d3255bfef95601890afd80709");
    println!();

    // Example 3: Standard test vector "abc"
    println!("3. Standard test vector:");
    let hash = sha1(b"abc");
    println!("   SHA-1(\"abc\") = {}", hex_encode(&hash));
    println!("   Expected:       a9993e364706816aba3e25717850c26c9cd0d89d");
    println!();

    // Example 4: Incremental hashing
    println!("4. Incremental hashing:");
    let mut hasher = Sha1::new();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let hash = hasher.finalize();
    println!("   SHA-1(\"Hello, \" + \"World!\") = {}", hex_encode(&hash));
    println!();

    // Example 5: Comparing incremental vs one-shot
    println!("5. Incremental vs one-shot:");
    let mut hasher = Sha1::new();
    hasher.update(b"The quick brown ");
    hasher.update(b"fox jumps over ");
    hasher.update(b"the lazy dog");
    let hash_incremental = hasher.finalize();

    let hash_oneshot = sha1(b"The quick brown fox jumps over the lazy dog");

    println!("   Incremental: {}", hex_encode(&hash_incremental));
    println!("   One-shot:    {}", hex_encode(&hash_oneshot));
    println!("   Match: {}", hash_incremental == hash_oneshot);
    println!();

    // Example 6: Hashing binary data
    println!("6. Hashing binary data:");
    let binary_data = [0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC];
    let hash = sha1(&binary_data);
    println!("   Binary input: {:02x?}", &binary_data);
    println!("   SHA-1: {}", hex_encode(&hash));
    println!();

    // Example 7: Large data
    println!("7. Large data (1 MB):");
    let large_data = vec![b'A'; 1_000_000];
    let hash = sha1(&large_data);
    println!("   SHA-1(1 million 'A's) = {}", hex_encode(&hash));
    println!();

    // Example 8: Different message sizes
    println!("8. Different message sizes:");
    for size in [0, 1, 10, 55, 56, 64, 100, 128] {
        let message = vec![b'X'; size];
        let hash = sha1(&message);
        println!("   {} bytes: {}...", size, hex_encode(&hash[..8]));
    }
}

/// Helper function to encode bytes as hexadecimal string
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}
