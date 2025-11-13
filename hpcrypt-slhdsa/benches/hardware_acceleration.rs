//! Hardware acceleration benchmarks for SLH-DSA.
//!
//! Tests various hardware-accelerated approaches:
//! 1. SHA-NI (hardware SHA instructions)
//! 2. Parallel hashing operations
//! 3. Batch processing with SIMD-friendly patterns

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sha2::{Digest, Sha256};

// Test different input sizes that might benefit from hardware acceleration
const SIZES: &[usize] = &[32, 64, 128, 256, 512, 1024, 4096];

/// Baseline: Single hash operation (current implementation)
fn hash_single(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Hardware-accelerated: Batch multiple independent hashes
/// This allows the CPU to potentially pipeline operations
fn hash_batch_independent(inputs: &[&[u8]]) -> Vec<[u8; 32]> {
    inputs
        .iter()
        .map(|input| {
            let mut hasher = Sha256::new();
            hasher.update(input);
            hasher.finalize().into()
        })
        .collect()
}

/// Parallel-friendly: Process multiple hashes with explicit unrolling
/// Helps compiler/CPU identify independent operations
fn hash_batch_unrolled_4(inputs: &[&[u8]]) -> Vec<[u8; 32]> {
    let mut results = Vec::with_capacity(inputs.len());

    let chunks = inputs.chunks_exact(4);
    let remainder = chunks.remainder();

    // Process 4 at a time (unrolled for better pipelining)
    for chunk in chunks {
        let mut h0 = Sha256::new();
        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();
        let mut h3 = Sha256::new();

        h0.update(chunk[0]);
        h1.update(chunk[1]);
        h2.update(chunk[2]);
        h3.update(chunk[3]);

        results.push(h0.finalize().into());
        results.push(h1.finalize().into());
        results.push(h2.finalize().into());
        results.push(h3.finalize().into());
    }

    // Handle remainder
    for input in remainder {
        let mut hasher = Sha256::new();
        hasher.update(input);
        results.push(hasher.finalize().into());
    }

    results
}

/// Parallel-friendly: Process multiple hashes with 8-way unrolling
fn hash_batch_unrolled_8(inputs: &[&[u8]]) -> Vec<[u8; 32]> {
    let mut results = Vec::with_capacity(inputs.len());

    let chunks = inputs.chunks_exact(8);
    let remainder = chunks.remainder();

    // Process 8 at a time for better instruction-level parallelism
    for chunk in chunks {
        let mut h0 = Sha256::new();
        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();
        let mut h3 = Sha256::new();
        let mut h4 = Sha256::new();
        let mut h5 = Sha256::new();
        let mut h6 = Sha256::new();
        let mut h7 = Sha256::new();

        h0.update(chunk[0]);
        h1.update(chunk[1]);
        h2.update(chunk[2]);
        h3.update(chunk[3]);
        h4.update(chunk[4]);
        h5.update(chunk[5]);
        h6.update(chunk[6]);
        h7.update(chunk[7]);

        results.push(h0.finalize().into());
        results.push(h1.finalize().into());
        results.push(h2.finalize().into());
        results.push(h3.finalize().into());
        results.push(h4.finalize().into());
        results.push(h5.finalize().into());
        results.push(h6.finalize().into());
        results.push(h7.finalize().into());
    }

    // Handle remainder
    for input in remainder {
        let mut hasher = Sha256::new();
        hasher.update(input);
        results.push(hasher.finalize().into());
    }

    results
}

/// Optimized for WOTS chains: Hash with address mixing
/// This is more realistic for actual SLH-DSA usage
fn hash_chain_step(current: &[u8; 32], chain_idx: u32, step: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(current);
    hasher.update(&chain_idx.to_be_bytes());
    hasher.update(&step.to_be_bytes());
    hasher.finalize().into()
}

/// Batch chain steps with unrolling
fn hash_chain_batch_unrolled(
    starts: &[[u8; 32]],
    chain_indices: &[u32],
    step: u32,
) -> Vec<[u8; 32]> {
    let mut results = Vec::with_capacity(starts.len());

    let chunks = starts.len() / 4;
    let remainder = starts.len() % 4;

    for i in 0..chunks {
        let base = i * 4;

        let mut h0 = Sha256::new();
        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();
        let mut h3 = Sha256::new();

        h0.update(&starts[base]);
        h0.update(&chain_indices[base].to_be_bytes());
        h0.update(&step.to_be_bytes());

        h1.update(&starts[base + 1]);
        h1.update(&chain_indices[base + 1].to_be_bytes());
        h1.update(&step.to_be_bytes());

        h2.update(&starts[base + 2]);
        h2.update(&chain_indices[base + 2].to_be_bytes());
        h2.update(&step.to_be_bytes());

        h3.update(&starts[base + 3]);
        h3.update(&chain_indices[base + 3].to_be_bytes());
        h3.update(&step.to_be_bytes());

        results.push(h0.finalize().into());
        results.push(h1.finalize().into());
        results.push(h2.finalize().into());
        results.push(h3.finalize().into());
    }

    // Handle remainder
    for i in 0..remainder {
        let idx = chunks * 4 + i;
        results.push(hash_chain_step(&starts[idx], chain_indices[idx], step));
    }

    results
}

fn bench_single_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_single");

    for &size in SIZES {
        let input = vec![0x42u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let result = hash_single(black_box(&input));
                black_box(result);
            });
        });
    }

    group.finish();
}

fn bench_batch_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_batch");

    // Test batches of different sizes
    for &batch_size in &[4, 8, 16, 32, 64] {
        let inputs: Vec<Vec<u8>> = (0..batch_size).map(|i| vec![i as u8; 32]).collect();
        let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        // Sequential (baseline)
        group.bench_with_input(
            BenchmarkId::new("sequential", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    let results = hash_batch_independent(black_box(&input_refs));
                    black_box(results);
                });
            },
        );

        // Unrolled 4-way
        group.bench_with_input(
            BenchmarkId::new("unrolled_4", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    let results = hash_batch_unrolled_4(black_box(&input_refs));
                    black_box(results);
                });
            },
        );

        // Unrolled 8-way
        group.bench_with_input(
            BenchmarkId::new("unrolled_8", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    let results = hash_batch_unrolled_8(black_box(&input_refs));
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

fn bench_chain_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_chains");

    for &num_chains in &[16, 32, 64] {
        let starts: Vec<[u8; 32]> = (0..num_chains)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr
            })
            .collect();

        let indices: Vec<u32> = (0..num_chains).collect();

        group.throughput(Throughput::Elements(num_chains as u64));

        // Sequential
        group.bench_with_input(
            BenchmarkId::new("sequential", num_chains),
            &num_chains,
            |b, _| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(num_chains as usize);
                    for i in 0..(num_chains as usize) {
                        results.push(hash_chain_step(
                            black_box(&starts[i]),
                            black_box(indices[i]),
                            black_box(0),
                        ));
                    }
                    black_box(results);
                });
            },
        );

        // Unrolled batch
        group.bench_with_input(
            BenchmarkId::new("unrolled", num_chains),
            &num_chains,
            |b, _| {
                b.iter(|| {
                    let results = hash_chain_batch_unrolled(
                        black_box(&starts),
                        black_box(&indices),
                        black_box(0),
                    );
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark realistic WOTS signature generation with different approaches
fn bench_wots_realistic(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_realistic");

    const CHAIN_LEN: u32 = 67;
    const NUM_CHAINS: usize = 67;

    let seed = [0x42u8; 32];

    // Sequential (current approach)
    group.bench_function("sequential", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(NUM_CHAINS);
            for chain_idx in 0..NUM_CHAINS {
                let mut current = seed;
                for step in 0..CHAIN_LEN {
                    current = hash_chain_step(
                        black_box(&current),
                        black_box(chain_idx as u32),
                        black_box(step),
                    );
                }
                results.push(current);
            }
            black_box(results);
        });
    });

    // Unrolled: Process 4 chains at a time, but still sequential within chain
    group.bench_function("unrolled_outer", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(NUM_CHAINS);

            let chunks = NUM_CHAINS / 4;
            for chunk_idx in 0..chunks {
                let base = chunk_idx * 4;

                let mut c0 = seed;
                let mut c1 = seed;
                let mut c2 = seed;
                let mut c3 = seed;

                for step in 0..CHAIN_LEN {
                    c0 = hash_chain_step(&c0, base as u32, step);
                    c1 = hash_chain_step(&c1, (base + 1) as u32, step);
                    c2 = hash_chain_step(&c2, (base + 2) as u32, step);
                    c3 = hash_chain_step(&c3, (base + 3) as u32, step);
                }

                results.push(c0);
                results.push(c1);
                results.push(c2);
                results.push(c3);
            }

            // Handle remainder
            for chain_idx in (chunks * 4)..NUM_CHAINS {
                let mut current = seed;
                for step in 0..CHAIN_LEN {
                    current = hash_chain_step(&current, chain_idx as u32, step);
                }
                results.push(current);
            }

            black_box(results);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_hash,
    bench_batch_hashing,
    bench_chain_hashing,
    bench_wots_realistic,
);
criterion_main!(benches);
