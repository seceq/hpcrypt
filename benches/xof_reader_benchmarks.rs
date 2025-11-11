//! XOF Reader performance benchmarks
//!
//! Measures throughput and efficiency of XofReader for various use cases

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hpcrypt_hash::sha3::{Shake128, Shake256};

// Helper to generate test data
fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

// Benchmark XOF Reader vs one-shot finalize
fn bench_xof_vs_oneshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("xof_vs_oneshot");
    let input = generate_data(1024);

    for output_size in [256, 1024, 4096] {
        group.throughput(Throughput::Bytes(output_size as u64));

        group.bench_with_input(
            BenchmarkId::new("oneshot", output_size),
            &output_size,
            |b, &size| {
                b.iter(|| {
                    let mut shake = Shake128::new();
                    shake.update(black_box(&input));
                    let mut output = vec![0u8; size];
                    shake.finalize(black_box(&mut output));
                    black_box(output)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("xof_reader", output_size),
            &output_size,
            |b, &size| {
                b.iter(|| {
                    let mut shake = Shake128::new();
                    shake.update(black_box(&input));
                    let mut reader = shake.finalize_xof();
                    let mut output = vec![0u8; size];
                    reader.read(black_box(&mut output));
                    black_box(output)
                });
            },
        );
    }

    group.finish();
}

// Benchmark incremental reading
fn bench_incremental_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental_reads");
    let input = generate_data(1024);
    let total_output = 1024;

    group.throughput(Throughput::Bytes(total_output as u64));

    // All at once
    group.bench_function("all_at_once", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let mut output = vec![0u8; total_output];
            reader.read(black_box(&mut output));
            black_box(output)
        });
    });

    // 16-byte chunks
    group.bench_function("chunks_16b", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let mut output = vec![0u8; total_output];
            for chunk in output.chunks_mut(16) {
                reader.read(black_box(chunk));
            }
            black_box(output)
        });
    });

    // 64-byte chunks
    group.bench_function("chunks_64b", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let mut output = vec![0u8; total_output];
            for chunk in output.chunks_mut(64) {
                reader.read(black_box(chunk));
            }
            black_box(output)
        });
    });

    // 256-byte chunks
    group.bench_function("chunks_256b", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let mut output = vec![0u8; total_output];
            for chunk in output.chunks_mut(256) {
                reader.read(black_box(chunk));
            }
            black_box(output)
        });
    });

    group.finish();
}

// Benchmark different XOF types
fn bench_xof_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("xof_types");
    let input = generate_data(1024);
    let output_size = 1024;

    group.throughput(Throughput::Bytes(output_size as u64));

    group.bench_function("SHAKE128", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let mut output = vec![0u8; output_size];
            reader.read(black_box(&mut output));
            black_box(output)
        });
    });

    group.bench_function("SHAKE256", |b| {
        b.iter(|| {
            let mut shake = Shake256::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let mut output = vec![0u8; output_size];
            reader.read(black_box(&mut output));
            black_box(output)
        });
    });

    group.finish();
}

// Benchmark variable output sizes
fn bench_output_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("output_sizes");
    let input = generate_data(1024);

    for size in [64, 256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let mut shake = Shake128::new();
                shake.update(black_box(&input));
                let mut reader = shake.finalize_xof();
                let mut output = vec![0u8; size];
                reader.read(black_box(&mut output));
                black_box(output)
            });
        });
    }

    group.finish();
}

// Benchmark reader forking
fn bench_fork(c: &mut Criterion) {
    let mut group = c.benchmark_group("fork");
    let input = generate_data(1024);

    group.bench_function("fork_and_read", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();

            // Read some data
            let mut initial = [0u8; 64];
            reader.read(black_box(&mut initial));

            // Fork
            let mut fork = reader.fork();

            // Read from fork
            let mut output = [0u8; 128];
            fork.read(black_box(&mut output));

            black_box((initial, output))
        });
    });

    group.bench_function("no_fork_baseline", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();

            let mut initial = [0u8; 64];
            reader.read(black_box(&mut initial));

            let mut output = [0u8; 128];
            reader.read(black_box(&mut output));

            black_box((initial, output))
        });
    });

    group.finish();
}

// Benchmark read_array vs read
fn bench_read_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_methods");
    let input = generate_data(1024);

    group.bench_function("read_array_32", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let output: [u8; 32] = reader.read_array();
            black_box(output)
        });
    });

    group.bench_function("read_slice_32", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&input));
            let mut reader = shake.finalize_xof();
            let mut output = [0u8; 32];
            reader.read(black_box(&mut output));
            black_box(output)
        });
    });

    group.finish();
}

// Benchmark large stream processing
fn bench_large_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_stream");
    let input = generate_data(1024);

    for total_kb in [1, 10, 100] {
        let total_bytes = total_kb * 1024;
        group.throughput(Throughput::Bytes(total_bytes as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", total_kb)),
            &total_bytes,
            |b, &size| {
                b.iter(|| {
                    let mut shake = Shake128::new();
                    shake.update(black_box(&input));
                    let mut reader = shake.finalize_xof();

                    let mut buffer = [0u8; 1024];
                    let mut remaining = size;

                    while remaining > 0 {
                        let to_read = remaining.min(1024);
                        reader.read(black_box(&mut buffer[..to_read]));
                        remaining -= to_read;
                    }

                    black_box(())
                });
            },
        );
    }

    group.finish();
}

// Benchmark key derivation use case
fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    let master_key = generate_data(32);
    let context = b"application-context";

    group.bench_function("derive_4_keys", |b| {
        b.iter(|| {
            let mut shake = Shake256::new();
            shake.update(black_box(&master_key));
            shake.update(black_box(context));
            let mut reader = shake.finalize_xof();

            let key1: [u8; 32] = reader.read_array();
            let key2: [u8; 32] = reader.read_array();
            let key3: [u8; 16] = reader.read_array();
            let key4: [u8; 32] = reader.read_array();

            black_box((key1, key2, key3, key4))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_xof_vs_oneshot,
    bench_incremental_reads,
    bench_xof_types,
    bench_output_sizes,
    bench_fork,
    bench_read_methods,
    bench_large_stream,
    bench_key_derivation,
);
criterion_main!(benches);
