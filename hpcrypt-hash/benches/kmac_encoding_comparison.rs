//! Benchmark: Stack Allocation Optimization for KMAC Encoding Functions
//!
//! Compares baseline (Vec allocation) vs optimized (stack allocation) encoding.
//!
//! Baseline approach:
//!   fn left_encode(value: usize) -> Vec<u8> { ... }  // Heap allocation
//!
//! Optimized approach:
//!   fn left_encode_fast(value: usize) -> EncodedValue { ... }  // Stack + LUT
//!
//! Optimizations tested:
//! 1. Stack allocation ([u8; 9] instead of Vec<u8>)
//! 2. Lookup tables (O(1) for values 0-255)
//! 3. Pre-sized Vec allocation (eliminate realloc in encode_string/bytepad)
//!
//! Expected improvement: 15-25%

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// Baseline encoding functions (Vec-based)
mod baseline {
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate alloc;

    pub fn left_encode(value: usize) -> Vec<u8> {
        if value == 0 {
            return vec![1, 0];
        }
        let mut n = value;
        let mut num_bytes = 0;
        while n > 0 {
            num_bytes += 1;
            n >>= 8;
        }
        let mut result = vec![num_bytes as u8];
        for i in (0..num_bytes).rev() {
            result.push(((value >> (i * 8)) & 0xFF) as u8);
        }
        result
    }

    pub fn right_encode(value: usize) -> Vec<u8> {
        if value == 0 {
            return vec![0, 1];
        }
        let mut n = value;
        let mut num_bytes = 0;
        while n > 0 {
            num_bytes += 1;
            n >>= 8;
        }
        let mut result = Vec::new();
        for i in (0..num_bytes).rev() {
            result.push(((value >> (i * 8)) & 0xFF) as u8);
        }
        result.push(num_bytes as u8);
        result
    }

    pub fn encode_string(s: &[u8]) -> Vec<u8> {
        let mut result = left_encode(s.len() * 8);
        result.extend_from_slice(s);
        result
    }

    pub fn bytepad(input: &[u8], rate: usize) -> Vec<u8> {
        let mut result = left_encode(rate);
        result.extend_from_slice(input);
        while result.len() % rate != 0 {
            result.push(0);
        }
        result
    }
}

use hpcrypt_hash::kmac_optimized_encoding as optimized;

// ===== Individual Encoding Function Benchmarks =====

fn bench_left_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("left_encode");

    let test_values = vec![
        0,      // Special case
        5,      // Small value (1 byte)
        255,    // Max 1-byte value
        256,    // Min 2-byte value
        1024,   // Common: 1KB
        65535,  // Max 2-byte value
        16384,  // Common: 16KB
        1048576, // Common: 1MB
    ];

    for &value in &test_values {
        group.throughput(Throughput::Elements(1));

        // Baseline
        group.bench_with_input(
            BenchmarkId::new("Baseline", value),
            &value,
            |b, &v| {
                b.iter(|| black_box(baseline::left_encode(black_box(v))));
            },
        );

        // Optimized (stack + LUT)
        group.bench_with_input(
            BenchmarkId::new("Optimized", value),
            &value,
            |b, &v| {
                b.iter(|| black_box(optimized::left_encode_fast(black_box(v))));
            },
        );
    }

    group.finish();
}

fn bench_right_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("right_encode");

    let test_values = vec![0, 16, 32, 64, 128, 256, 512, 1024, 2048];

    for &value in &test_values {
        group.throughput(Throughput::Elements(1));

        // Baseline
        group.bench_with_input(
            BenchmarkId::new("Baseline", value),
            &value,
            |b, &v| {
                b.iter(|| black_box(baseline::right_encode(black_box(v))));
            },
        );

        // Optimized
        group.bench_with_input(
            BenchmarkId::new("Optimized", value),
            &value,
            |b, &v| {
                b.iter(|| black_box(optimized::right_encode_fast(black_box(v))));
            },
        );
    }

    group.finish();
}

// ===== Higher-Level Function Benchmarks =====

fn bench_encode_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_string");

    let test_cases = vec![
        ("Empty", vec![]),
        ("KMAC", b"KMAC".to_vec()),
        ("CustomString_32B", vec![b'A'; 32]),
        ("Key_64B", vec![b'K'; 64]),
        ("Message_128B", vec![b'M'; 128]),
    ];

    for (name, data) in test_cases {
        group.throughput(Throughput::Bytes(data.len() as u64));

        // Baseline
        group.bench_with_input(
            BenchmarkId::new("Baseline", name),
            &data,
            |b, d| {
                b.iter(|| black_box(baseline::encode_string(black_box(d))));
            },
        );

        // Optimized
        group.bench_with_input(
            BenchmarkId::new("Optimized", name),
            &data,
            |b, d| {
                b.iter(|| black_box(optimized::encode_string_optimized(black_box(d))));
            },
        );
    }

    group.finish();
}

fn bench_bytepad(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytepad");

    let test_cases = vec![
        ("Key_32B_Rate168", vec![b'K'; 32], 168),   // KMAC128 key
        ("Key_64B_Rate168", vec![b'K'; 64], 168),   // KMAC128 key
        ("Key_32B_Rate136", vec![b'K'; 32], 136),   // KMAC256 key
        ("Prefix_16B_Rate168", vec![b'P'; 16], 168), // cSHAKE prefix
    ];

    for (name, data, rate) in test_cases {
        group.throughput(Throughput::Bytes(data.len() as u64));

        // Baseline
        group.bench_with_input(
            BenchmarkId::new("Baseline", name),
            &(&data, rate),
            |b, (d, r)| {
                b.iter(|| black_box(baseline::bytepad(black_box(d), black_box(*r))));
            },
        );

        // Optimized
        group.bench_with_input(
            BenchmarkId::new("Optimized", name),
            &(&data, rate),
            |b, (d, r)| {
                b.iter(|| black_box(optimized::bytepad_optimized(black_box(d), black_box(*r))));
            },
        );
    }

    group.finish();
}

// ===== End-to-End KMAC Initialization Benchmark =====

fn bench_kmac_init_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("KMAC_Initialization");

    let key = vec![b'K'; 64];
    let customization = b"benchmark";

    group.throughput(Throughput::Elements(1));

    // Baseline: Simulate KMAC init with baseline encoding
    group.bench_function("Baseline_Init", |b| {
        b.iter(|| {
            // encode_string(key)
            let encoded_key = baseline::encode_string(black_box(&key));
            // bytepad(encoded_key, 168)
            let padded_key = baseline::bytepad(black_box(&encoded_key), black_box(168));
            // encode_string("KMAC")
            let fname = baseline::encode_string(black_box(b"KMAC"));
            // encode_string(customization)
            let custom = baseline::encode_string(black_box(customization));
            black_box((padded_key, fname, custom))
        });
    });

    // Optimized: Simulate KMAC init with optimized encoding
    group.bench_function("Optimized_Init", |b| {
        b.iter(|| {
            // encode_string(key)
            let encoded_key = optimized::encode_string_optimized(black_box(&key));
            // bytepad(encoded_key, 168)
            let padded_key = optimized::bytepad_optimized(black_box(&encoded_key), black_box(168));
            // encode_string("KMAC")
            let fname = optimized::encode_string_optimized(black_box(b"KMAC"));
            // encode_string(customization)
            let custom = optimized::encode_string_optimized(black_box(customization));
            black_box((padded_key, fname, custom))
        });
    });

    group.finish();
}

// ===== Lookup Table Hit Rate Test =====

fn bench_lut_hit_rate(c: &mut Criterion) {
    let mut group = c.benchmark_group("LUT_Hit_Rate");

    // Test LUT effectiveness on real-world value distributions
    let common_values: Vec<usize> = (0..256).collect(); // All LUT values
    let large_values: Vec<usize> = (256..512).collect(); // No LUT

    group.throughput(Throughput::Elements(common_values.len() as u64));

    // Common values (LUT hits)
    group.bench_function("Common_Values_LUT", |b| {
        b.iter(|| {
            for &v in &common_values {
                black_box(optimized::left_encode_fast(black_box(v)));
            }
        });
    });

    // Common values (baseline)
    group.bench_function("Common_Values_Baseline", |b| {
        b.iter(|| {
            for &v in &common_values {
                black_box(baseline::left_encode(black_box(v)));
            }
        });
    });

    group.throughput(Throughput::Elements(large_values.len() as u64));

    // Large values (LUT misses)
    group.bench_function("Large_Values_Stack", |b| {
        b.iter(|| {
            for &v in &large_values {
                black_box(optimized::left_encode_fast(black_box(v)));
            }
        });
    });

    // Large values (baseline)
    group.bench_function("Large_Values_Baseline", |b| {
        b.iter(|| {
            for &v in &large_values {
                black_box(baseline::left_encode(black_box(v)));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_left_encode,
    bench_right_encode,
    bench_encode_string,
    bench_bytepad,
    bench_kmac_init_overhead,
    bench_lut_hit_rate
);
criterion_main!(benches);
