//! FORS optimization benchmarks.
//!
//! Tests batch leaf generation vs sequential.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};

// Baseline: Sequential leaf generation (current implementation)
fn fors_leaves_sequential(count: usize, seed: &[u8; 32], leaves: &mut [Vec<u8>]) {
    for i in 0..count {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&(i as u32).to_be_bytes());
        let result = hasher.finalize();
        leaves[i].clear();
        leaves[i].extend_from_slice(&result);
    }
}

// Optimized: Batch generation with better cache locality
fn fors_leaves_batched(count: usize, seed: &[u8; 32], leaves: &mut [Vec<u8>]) {
    const BATCH_SIZE: usize = 4;

    for batch_start in (0..count).step_by(BATCH_SIZE) {
        let batch_end = (batch_start + BATCH_SIZE).min(count);

        // Generate batch of leaves
        for i in batch_start..batch_end {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(&(i as u32).to_be_bytes());
            let result = hasher.finalize();
            leaves[i].clear();
            leaves[i].extend_from_slice(&result);
        }
    }
}

fn bench_fors_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("fors_leaves");

    for count in [16, 32, 64].iter() {
        let seed = [0x42u8; 32];
        let mut leaves = vec![vec![0u8; 32]; *count];

        group.bench_with_input(
            criterion::BenchmarkId::new("sequential", count),
            count,
            |b, _| {
                b.iter(|| {
                    fors_leaves_sequential(
                        black_box(*count),
                        black_box(&seed),
                        black_box(&mut leaves),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_fors_batched(c: &mut Criterion) {
    let mut group = c.benchmark_group("fors_leaves");

    for count in [16, 32, 64].iter() {
        let seed = [0x42u8; 32];
        let mut leaves = vec![vec![0u8; 32]; *count];

        group.bench_with_input(
            criterion::BenchmarkId::new("batched", count),
            count,
            |b, _| {
                b.iter(|| {
                    fors_leaves_batched(
                        black_box(*count),
                        black_box(&seed),
                        black_box(&mut leaves),
                    );
                });
            },
        );
    }

    group.finish();
}

// More realistic: Full treehash with batch vs sequential
fn treehash_sequential(leaf_count: usize, seed: &[u8; 32]) -> Vec<u8> {
    let mut stack: Vec<(Vec<u8>, usize)> = Vec::with_capacity(10);

    for i in 0..leaf_count {
        // Generate leaf
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&(i as u32).to_be_bytes());
        let mut node = hasher.finalize().to_vec();
        let mut node_height = 0;

        // Merge with stack
        while !stack.is_empty() {
            let (_top_node, top_height) = stack.last().unwrap();
            if *top_height != node_height {
                break;
            }

            let (top_node, _) = stack.pop().unwrap();

            // Hash together
            let mut hasher = Sha256::new();
            hasher.update(&top_node);
            hasher.update(&node);
            node = hasher.finalize().to_vec();
            node_height += 1;
        }

        stack.push((node, node_height));
    }

    stack.pop().unwrap().0
}

fn bench_treehash_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("treehash");
    let seed = [0x42u8; 32];

    for height in [4, 6, 8].iter() {
        let leaf_count = 1 << height;

        group.bench_with_input(
            criterion::BenchmarkId::new("sequential", height),
            height,
            |b, _| {
                b.iter(|| {
                    let root = treehash_sequential(black_box(leaf_count), black_box(&seed));
                    black_box(root);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_fors_sequential,
    bench_fors_batched,
    bench_treehash_sequential
);
criterion_main!(benches);
