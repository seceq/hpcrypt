//! Micro-benchmarks for hash operation optimizations.
//!
//! This benchmark suite tests specific optimization techniques for hash operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

// Simulate hash operations without pooling (baseline)
mod baseline {
    use sha2::{Sha256, Digest};

    pub fn hash_multiple_without_pool(data: &[&[u8]], outputs: &mut [Vec<u8>]) {
        for (input, output) in data.iter().zip(outputs.iter_mut()) {
            let mut hasher = Sha256::new();  // Create new each time
            hasher.update(input);
            let result = hasher.finalize();
            output.clear();
            output.extend_from_slice(&result);
        }
    }
}

// Simulate hash operations with context pooling
mod optimized {
    use sha2::{Sha256, Digest};

    pub struct HashContextPool {
        // Simple pool - just reuse one context
        context: Option<Sha256>,
    }

    impl HashContextPool {
        pub fn new() -> Self {
            Self { context: None }
        }

        pub fn hash(&mut self, input: &[u8], output: &mut Vec<u8>) {
            let mut hasher = self.context.take().unwrap_or_else(|| Sha256::new());

            hasher.update(input);
            let result = hasher.finalize();
            output.clear();
            output.extend_from_slice(&result);

            // Reset and return to pool
            self.context = Some(Sha256::new());
        }
    }

    pub fn hash_multiple_with_pool(data: &[&[u8]], outputs: &mut [Vec<u8>]) {
        let mut pool = HashContextPool::new();
        for (input, output) in data.iter().zip(outputs.iter_mut()) {
            pool.hash(input, output);
        }
    }
}

fn bench_hash_without_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_context");

    for count in [10, 50, 100].iter() {
        let data: Vec<Vec<u8>> = (0..*count).map(|i| vec![i as u8; 32]).collect();
        let data_refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let mut outputs = vec![vec![0u8; 32]; *count];

        group.bench_with_input(
            BenchmarkId::new("without_pool", count),
            count,
            |b, _| {
                b.iter(|| {
                    baseline::hash_multiple_without_pool(
                        black_box(&data_refs),
                        black_box(&mut outputs),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_hash_with_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_context");

    for count in [10, 50, 100].iter() {
        let data: Vec<Vec<u8>> = (0..*count).map(|i| vec![i as u8; 32]).collect();
        let data_refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let mut outputs = vec![vec![0u8; 32]; *count];

        group.bench_with_input(
            BenchmarkId::new("with_pool", count),
            count,
            |b, _| {
                b.iter(|| {
                    optimized::hash_multiple_with_pool(
                        black_box(&data_refs),
                        black_box(&mut outputs),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_wots_chain_baseline(c: &mut Criterion) {
    use sha2::{Sha256, Digest};

    let mut group = c.benchmark_group("wots_chain");

    let w = 16;
    let mut buffer = vec![0u8; 32];
    let seed = [0x42u8; 32];

    group.bench_function("baseline", |b| {
        b.iter(|| {
            buffer.copy_from_slice(&seed);
            for _step in 0..w {
                let mut hasher = Sha256::new();
                hasher.update(&buffer);
                let result = hasher.finalize();
                buffer.copy_from_slice(&result);
                black_box(&buffer);
            }
        });
    });

    group.finish();
}

fn bench_wots_chain_pooled(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_chain");

    let w = 16;
    let mut buffer = vec![0u8; 32];
    let seed = [0x42u8; 32];

    group.bench_function("pooled", |b| {
        let mut pool = optimized::HashContextPool::new();
        let mut temp = vec![0u8; 32];
        b.iter(|| {
            buffer.copy_from_slice(&seed);
            for _step in 0..w {
                pool.hash(&buffer, &mut temp);
                buffer.copy_from_slice(&temp);
                black_box(&buffer);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_without_pool,
    bench_hash_with_pool,
    bench_wots_chain_baseline,
    bench_wots_chain_pooled
);
criterion_main!(benches);
