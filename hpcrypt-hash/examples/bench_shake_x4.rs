//! Benchmark comparing sequential SHAKE vs 4-way batched SHAKE

use std::time::Instant;
use hpcrypt_hash::{Shake256, shake_batched::Shake256x4};

fn main() {
    let iterations = 10000;
    let seed = [0u8; 64];

    // Build 4 different seeds
    let mut seeds: [[u8; 66]; 4] = [[0u8; 66]; 4];
    for i in 0..4 {
        seeds[i][..64].copy_from_slice(&seed);
        seeds[i][64] = i as u8;
        seeds[i][65] = 0;
    }

    // Warm up
    for _ in 0..100 {
        let mut state = Shake256::new();
        state.update(&seeds[0]);
        let mut reader = state.finalize_xof();
        let mut out = [0u8; 256];
        reader.read(&mut out);
    }

    // Benchmark 4x sequential SHAKE-256
    let start = Instant::now();
    for _ in 0..iterations {
        for i in 0..4 {
            let mut state = Shake256::new();
            state.update(&seeds[i]);
            let mut reader = state.finalize_xof();
            let mut out = [0u8; 256];
            reader.read(&mut out);
        }
    }
    let sequential_time = start.elapsed();

    // Benchmark Shake256x4 batched
    let start = Instant::now();
    for _ in 0..iterations {
        let inputs: [&[u8]; 4] = [&seeds[0], &seeds[1], &seeds[2], &seeds[3]];
        let _outputs: [[u8; 256]; 4] = Shake256x4::hash_x4(&inputs);
    }
    let batched_time = start.elapsed();

    println!("=== SHAKE-256 (256 bytes output) x {} iterations ===", iterations);
    println!();
    println!("4x Sequential SHAKE-256:  {:?}", sequential_time);
    println!("Shake256x4 batched:       {:?}", batched_time);
    println!();
    println!("Per 4-batch (sequential): {:?}", sequential_time / iterations as u32);
    println!("Per 4-batch (batched):    {:?}", batched_time / iterations as u32);
    println!();

    let speedup = sequential_time.as_nanos() as f64 / batched_time.as_nanos() as f64;
    if speedup > 1.0 {
        println!("Batched is {:.2}x FASTER than sequential", speedup);
    } else {
        println!("Sequential is {:.2}x FASTER than batched", 1.0 / speedup);
    }
}
