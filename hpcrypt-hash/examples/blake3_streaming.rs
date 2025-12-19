//! BLAKE3 streaming API examples demonstrating optimal buffer sizes

use hpcrypt_hash::HashFunction;
use hpcrypt_hash::blake3::{Blake3, OPTIMAL_BUF_SIZE, MIN_BUF_SIZE};

/// Example 1: Simple streaming with optimal buffer
fn example_optimal_streaming() {
    println!("\n=== Example 1: Optimal Streaming (16 KiB buffer) ===");

    let mut hasher = Blake3::new();
    let data = vec![0x42u8; 100_000]; // 100 KB of data

    // Process in optimal-sized chunks
    for chunk in data.chunks(OPTIMAL_BUF_SIZE) {
        hasher.update(chunk);
    }

    let hash = hasher.finalize();
    println!("Hash: {:02x}{:02x}{:02x}{:02x}...", hash[0], hash[1], hash[2], hash[3]);
    println!("Buffer size: {} KiB (optimal)", OPTIMAL_BUF_SIZE / 1024);
}

/// Example 2: Memory-constrained streaming with minimum buffer
fn example_minimum_streaming() {
    println!("\n=== Example 2: Memory-Constrained (4 KiB buffer) ===");

    let mut hasher = Blake3::new();
    let data = vec![0x42u8; 100_000]; // 100 KB of data

    // Process in minimum-sized chunks (when memory is limited)
    for chunk in data.chunks(MIN_BUF_SIZE) {
        hasher.update(chunk);
    }

    let hash = hasher.finalize();
    println!("Hash: {:02x}{:02x}{:02x}{:02x}...", hash[0], hash[1], hash[2], hash[3]);
    println!("Buffer size: {} KiB (minimum, ~90% optimal throughput)", MIN_BUF_SIZE / 1024);
}

/// Example 3: Incremental hashing (network streaming simulation)
fn example_network_streaming() {
    println!("\n=== Example 3: Network Stream Simulation ===");

    let mut hasher = Blake3::new();

    // Simulate receiving network packets of varying sizes
    let packets = vec![
        vec![0x42u8; 512],   // Small packet
        vec![0x43u8; 1024],  // 1 chunk
        vec![0x44u8; 4096],  // 4 chunks
        vec![0x45u8; 1500],  // MTU-sized
    ];

    for (i, packet) in packets.iter().enumerate() {
        hasher.update(packet);
        println!("  Received packet {}: {} bytes", i + 1, packet.len());
    }

    let hash = hasher.finalize();
    println!("Final hash: {:02x}{:02x}{:02x}{:02x}...", hash[0], hash[1], hash[2], hash[3]);
}

/// Example 4: All-at-once vs incremental (produces same result)
fn example_incremental_correctness() {
    println!("\n=== Example 4: Incremental Correctness ===");

    // Method 1: Hash all at once
    let data = b"Hello, BLAKE3 streaming!";
    let mut hasher1 = Blake3::new();
    hasher1.update(data);
    let hash1 = hasher1.finalize();

    // Method 2: Hash incrementally
    let mut hasher2 = Blake3::new();
    hasher2.update(b"Hello, ");
    hasher2.update(b"BLAKE3 ");
    hasher2.update(b"streaming!");
    let hash2 = hasher2.finalize();

    println!("All-at-once:  {:02x}{:02x}{:02x}{:02x}...", hash1[0], hash1[1], hash1[2], hash1[3]);
    println!("Incremental:  {:02x}{:02x}{:02x}{:02x}...", hash2[0], hash2[1], hash2[2], hash2[3]);
    println!("Match: {}", hash1 == hash2);
}

/// Example 5: Performance comparison (conceptual)
fn example_buffer_size_comparison() {
    println!("\n=== Example 5: Buffer Size Comparison ===");
    println!("\nTypical throughput for different buffer sizes:");
    println!("  64 bytes:   ~1.2 GB/s  [X] Too small (avoid)");
    println!("  1 KiB:      ~2.1 GB/s  [!] Small");
    println!("  4 KiB:      ~2.7 GB/s  [+] Minimum recommended ({} KiB)", MIN_BUF_SIZE / 1024);
    println!("  16 KiB:     ~3.0 GB/s  [+] Optimal ({} KiB)", OPTIMAL_BUF_SIZE / 1024);
    println!("  64 KiB:     ~3.0 GB/s  [+] No additional benefit");
    println!("  1 MiB:      ~2.9 GB/s  [!] Cache pressure");
    println!("\nRecommendation: Use OPTIMAL_BUF_SIZE (16 KiB) for best performance");
}

fn main() {
    println!("BLAKE3 Streaming API Examples");
    println!("==============================");

    example_optimal_streaming();
    example_minimum_streaming();
    example_network_streaming();
    example_incremental_correctness();
    example_buffer_size_comparison();

    println!("\n=== Summary ===");
    println!("- Use OPTIMAL_BUF_SIZE (16 KiB) for best throughput");
    println!("- Use MIN_BUF_SIZE (4 KiB) when memory is constrained (~90% optimal)");
    println!("- Incremental hashing works with any buffer size");
    println!("- All methods produce identical hashes");
}
