//! WOTS+ optimization benchmarks.
//!
//! Tests chain interleaving vs sequential chain computation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Sha256, Digest};

const CHAIN_LEN: usize = 67; // Typical WOTS+ parameter (w=16)
const NUM_CHAINS: usize = 32; // Number of parallel chains

// Baseline: Sequential chain computation (current implementation)
fn wots_chains_sequential(num_chains: usize, chain_len: usize, seed: &[u8; 32], output: &mut Vec<Vec<u8>>) {
    for chain_idx in 0..num_chains {
        let mut current = seed.to_vec();

        for step in 0..chain_len {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(&[chain_idx as u8]);
            hasher.update(&[step as u8]);
            current = hasher.finalize().to_vec();
        }

        output[chain_idx] = current;
    }
}

// Optimized: Interleaved chain computation for better cache locality
fn wots_chains_interleaved(num_chains: usize, chain_len: usize, seed: &[u8; 32], output: &mut Vec<Vec<u8>>) {
    // Initialize all chains
    let mut chains: Vec<Vec<u8>> = (0..num_chains)
        .map(|_| seed.to_vec())
        .collect();

    // Compute all chains one step at a time (interleaved)
    for step in 0..chain_len {
        for chain_idx in 0..num_chains {
            let mut hasher = Sha256::new();
            hasher.update(&chains[chain_idx]);
            hasher.update(&[chain_idx as u8]);
            hasher.update(&[step as u8]);
            chains[chain_idx] = hasher.finalize().to_vec();
        }
    }

    // Copy results
    for (i, chain) in chains.into_iter().enumerate() {
        output[i] = chain;
    }
}

// Alternative: Block-based interleaving (compute N chains at a time)
fn wots_chains_blocked(num_chains: usize, chain_len: usize, seed: &[u8; 32], output: &mut Vec<Vec<u8>>) {
    const BLOCK_SIZE: usize = 4;

    for block_start in (0..num_chains).step_by(BLOCK_SIZE) {
        let block_end = (block_start + BLOCK_SIZE).min(num_chains);

        // Initialize block chains
        let mut block_chains: Vec<Vec<u8>> = (block_start..block_end)
            .map(|_| seed.to_vec())
            .collect();

        // Compute block chains
        for step in 0..chain_len {
            for (local_idx, chain_idx) in (block_start..block_end).enumerate() {
                let mut hasher = Sha256::new();
                hasher.update(&block_chains[local_idx]);
                hasher.update(&[chain_idx as u8]);
                hasher.update(&[step as u8]);
                block_chains[local_idx] = hasher.finalize().to_vec();
            }
        }

        // Copy results
        for (local_idx, chain_idx) in (block_start..block_end).enumerate() {
            output[chain_idx] = block_chains[local_idx].clone();
        }
    }
}

fn bench_wots_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_chains");

    for &num_chains in &[16, 32, 64] {
        let seed = [0x42u8; 32];
        let mut output = vec![vec![0u8; 32]; num_chains];

        group.bench_with_input(
            criterion::BenchmarkId::new("sequential", num_chains),
            &num_chains,
            |b, _| {
                b.iter(|| {
                    wots_chains_sequential(
                        black_box(num_chains),
                        black_box(CHAIN_LEN),
                        black_box(&seed),
                        black_box(&mut output)
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_wots_interleaved(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_chains");

    for &num_chains in &[16, 32, 64] {
        let seed = [0x42u8; 32];
        let mut output = vec![vec![0u8; 32]; num_chains];

        group.bench_with_input(
            criterion::BenchmarkId::new("interleaved", num_chains),
            &num_chains,
            |b, _| {
                b.iter(|| {
                    wots_chains_interleaved(
                        black_box(num_chains),
                        black_box(CHAIN_LEN),
                        black_box(&seed),
                        black_box(&mut output)
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_wots_blocked(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_chains");

    for &num_chains in &[16, 32, 64] {
        let seed = [0x42u8; 32];
        let mut output = vec![vec![0u8; 32]; num_chains];

        group.bench_with_input(
            criterion::BenchmarkId::new("blocked", num_chains),
            &num_chains,
            |b, _| {
                b.iter(|| {
                    wots_chains_blocked(
                        black_box(num_chains),
                        black_box(CHAIN_LEN),
                        black_box(&seed),
                        black_box(&mut output)
                    );
                });
            },
        );
    }

    group.finish();
}

// More realistic: Full WOTS+ signature generation simulation
fn wots_signature_sequential(message: &[u8; 32], seed: &[u8; 32]) -> Vec<Vec<u8>> {
    const LEN: usize = 67;
    let mut signature = vec![vec![0u8; 32]; LEN];

    // Simulate base-w encoding
    let mut message_lengths = vec![15u8; LEN]; // Simulated base-w values
    for i in 0..32 {
        message_lengths[i] = (message[i] % 16) as u8;
    }

    // Generate signature chains
    for i in 0..LEN {
        let mut current = seed.to_vec();
        let chain_len = message_lengths[i] as usize;

        for step in 0..chain_len {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(&[i as u8]);
            hasher.update(&[step as u8]);
            current = hasher.finalize().to_vec();
        }

        signature[i] = current;
    }

    signature
}

fn bench_wots_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_signature");

    let message = [0x42u8; 32];
    let seed = [0x24u8; 32];

    group.bench_function("full_sequential", |b| {
        b.iter(|| {
            let sig = wots_signature_sequential(black_box(&message), black_box(&seed));
            black_box(sig);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_wots_sequential,
    bench_wots_interleaved,
    bench_wots_blocked,
    bench_wots_full
);
criterion_main!(benches);
