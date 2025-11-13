/// PGO Profiling Workload for SHA-1
///
/// This program exercises SHA-1 with representative workloads to generate
/// profile data for Profile-Guided Optimization (PGO).
///
/// The workload includes:
/// - Various data sizes (64 bytes to 1MB)
/// - Incremental updates
/// - Different update patterns
/// - Edge cases (empty, single block, multi-block)
use hpcrypt::hash::sha1::{sha1, Sha1};

fn main() {
    println!("Running SHA-1 PGO profiling workload...");

    // Warm up
    for _ in 0..1000 {
        let _ = sha1(b"warmup");
    }

    // Small data (64 bytes) - common in message authentication
    println!("Profiling 64-byte data...");
    let data_64 = vec![0xA5u8; 64];
    for _ in 0..100_000 {
        let _ = sha1(&data_64);
    }

    // Medium data (256 bytes) - common for short messages
    println!("Profiling 256-byte data...");
    let data_256 = vec![0xB3u8; 256];
    for _ in 0..50_000 {
        let _ = sha1(&data_256);
    }

    // Medium data (1KB) - common workload
    println!("Profiling 1KB data...");
    let data_1kb = vec![0xC7u8; 1024];
    for _ in 0..50_000 {
        let _ = sha1(&data_1kb);
    }

    // Medium-large data (4KB) - page size
    println!("Profiling 4KB data...");
    let data_4kb = vec![0xD1u8; 4096];
    for _ in 0..25_000 {
        let _ = sha1(&data_4kb);
    }

    // Large data (16KB) - typical file chunk
    println!("Profiling 16KB data...");
    let data_16kb = vec![0xE9u8; 16384];
    for _ in 0..10_000 {
        let _ = sha1(&data_16kb);
    }

    // Very large data (1MB) - large file
    println!("Profiling 1MB data...");
    let data_1mb = vec![0xF2u8; 1024 * 1024];
    for _ in 0..1_000 {
        let _ = sha1(&data_1mb);
    }

    // Incremental updates - common pattern
    println!("Profiling incremental updates...");
    for _ in 0..10_000 {
        let mut hasher = Sha1::new();
        hasher.update(b"first chunk ");
        hasher.update(b"second chunk ");
        hasher.update(b"third chunk ");
        hasher.update(b"fourth chunk");
        let _ = hasher.finalize();
    }

    // Variable-size incremental updates
    println!("Profiling variable incremental updates...");
    let chunks = vec![
        vec![0u8; 13],  // Odd size
        vec![1u8; 64],  // Block boundary
        vec![2u8; 127], // Just under 2 blocks
        vec![3u8; 200], // Over 3 blocks
    ];
    for _ in 0..10_000 {
        let mut hasher = Sha1::new();
        for chunk in &chunks {
            hasher.update(chunk);
        }
        let _ = hasher.finalize();
    }

    // Edge cases
    println!("Profiling edge cases...");

    // Empty
    for _ in 0..10_000 {
        let _ = sha1(b"");
    }

    // Single byte
    for _ in 0..10_000 {
        let _ = sha1(b"x");
    }

    // Just under block boundary (55 bytes - needs padding in same block)
    let data_55 = vec![0xAAu8; 55];
    for _ in 0..10_000 {
        let _ = sha1(&data_55);
    }

    // Just over block boundary (56 bytes - needs extra block for padding)
    let data_56 = vec![0xBBu8; 56];
    for _ in 0..10_000 {
        let _ = sha1(&data_56);
    }

    // Exactly one block (64 bytes)
    for _ in 0..10_000 {
        let _ = sha1(&data_64);
    }

    // Just over one block (65 bytes)
    let data_65 = vec![0xCCu8; 65];
    for _ in 0..10_000 {
        let _ = sha1(&data_65);
    }

    // Many small updates (stress buffer management)
    println!("Profiling many small updates...");
    for _ in 0..5_000 {
        let mut hasher = Sha1::new();
        for _ in 0..100 {
            hasher.update(b"x");
        }
        let _ = hasher.finalize();
    }

    // Large chunks (stress block processing)
    println!("Profiling large chunk processing...");
    let large_chunk = vec![0xDDu8; 10_000];
    for _ in 0..5_000 {
        let _ = sha1(&large_chunk);
    }

    println!("PGO profiling workload complete!");
    println!("Profile data has been generated for optimization.");
}
