// Ed25519 Optimization Benchmarks
//
// This benchmark suite measures the performance of each optimization
// technique to validate gains before applying changes to production code.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use hpcrypt_curves::ed25519::{Ed25519, EdwardsPoint, Scalar, base_point, scalar_mul_base_fast};
use hpcrypt_curves::ed25519_wnaf::wnaf_scalar_mul;
use hpcrypt_curves::ed25519_sliding::sliding_window_scalar_mul;
use hpcrypt_curves::field25519::FieldElement;

// ============================================================================
// Baseline Benchmarks
// ============================================================================

fn bench_baseline_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_baseline");

    let a = FieldElement::from_bytes(&[1u8; 32]);
    let b = FieldElement::from_bytes(&[2u8; 32]);

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a.add(&b)));
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a.mul(&b)));
    });

    group.bench_function("square", |bencher| {
        bencher.iter(|| black_box(a.square()));
    });

    group.bench_function("invert", |bencher| {
        bencher.iter(|| black_box(a.invert()));
    });

    group.finish();
}

fn bench_baseline_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_baseline");

    let p1 = base_point();
    let p2 = p1.double();

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(p1.add(&p2)));
    });

    group.bench_function("double", |bencher| {
        bencher.iter(|| black_box(p1.double()));
    });

    group.bench_function("encode", |bencher| {
        bencher.iter(|| black_box(p1.encode()));
    });

    group.bench_function("decode", |bencher| {
        let encoded = p1.encode();
        bencher.iter(|| black_box(EdwardsPoint::decode(&encoded)));
    });

    group.finish();
}

fn bench_lazy_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_lazy");

    let p1 = base_point();

    // Single doubling benchmark
    group.bench_function("double_lazy", |bencher| {
        bencher.iter(|| black_box(p1.double_lazy()));
    });

    // Multiple doublings to amplify performance differences
    group.bench_function("double_lazy_chain_16x", |bencher| {
        bencher.iter(|| {
            let mut r = p1;
            for _ in 0..16 {
                r = r.double_lazy();
            }
            black_box(r)
        });
    });

    group.finish();
}

fn bench_doubling_chain_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("doubling_chain");

    let p1 = base_point();

    // Normal doubling chain (16x)
    group.bench_function("normal_16x", |bencher| {
        bencher.iter(|| {
            let mut r = p1;
            for _ in 0..16 {
                r = r.double();
            }
            black_box(r)
        });
    });

    // Lazy doubling chain (16x)
    group.bench_function("lazy_16x", |bencher| {
        bencher.iter(|| {
            let mut r = p1;
            for _ in 0..16 {
                r = r.double_lazy();
            }
            black_box(r)
        });
    });

    group.finish();
}

fn bench_baseline_scalar_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_baseline");

    let a = Scalar::from_bytes([1u8; 32]);
    let b = Scalar::from_bytes([2u8; 32]);

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a.add(&b)));
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a.mul(&b)));
    });

    // Test scalar reduction from hash
    let hash = [0x42u8; 64];
    group.bench_function("from_hash", |bencher| {
        bencher.iter(|| black_box(Scalar::from_hash(&hash)));
    });

    group.finish();
}

fn bench_baseline_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_mul_baseline");

    let point = base_point();
    let scalar = [0x42u8; 32];

    group.bench_function("variable_base", |bencher| {
        bencher.iter(|| black_box(point.scalar_mul(&scalar)));
    });

    group.bench_function("fixed_base", |bencher| {
        bencher.iter(|| black_box(scalar_mul_base_fast(&scalar)));
    });

    group.finish();
}

fn bench_baseline_signature_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_baseline");

    let private_key = [0x42u8; 32];
    let message = b"Benchmark message for Ed25519";

    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(Ed25519::public_key(&private_key)));
    });

    let public_key = Ed25519::public_key(&private_key);

    group.bench_function("sign", |bencher| {
        bencher.iter(|| black_box(Ed25519::sign(&private_key, message)));
    });

    let signature = Ed25519::sign(&private_key, message);

    group.bench_function("verify", |bencher| {
        bencher.iter(|| black_box(Ed25519::verify(&public_key, message, &signature)));
    });

    group.finish();
}

fn bench_baseline_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verify_baseline");
    group.sample_size(10); // Reduce sample size for slower operations

    // Generate test data for different batch sizes
    for n in [4, 8, 16, 32, 64].iter() {
        let mut public_keys = Vec::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..*n {
            let private_key = [(i as u8); 32];
            let message = format!("Message {}", i);
            let public_key = Ed25519::public_key(&private_key);
            let signature = Ed25519::sign(&private_key, message.as_bytes());

            public_keys.push(public_key);
            messages.push(message);
            signatures.push(signature);
        }

        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_bytes()).collect();

        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |bencher, _| {
            bencher.iter(|| {
                black_box(Ed25519::verify_batch(&public_keys, &message_refs, &signatures))
            });
        });
    }

    group.finish();
}

// ============================================================================
// Batch Inversion Benchmarks (for Montgomery's trick comparison)
// ============================================================================

fn bench_batch_inversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_inversion");

    for n in [4, 8, 16, 32, 64].iter() {
        let elements: Vec<FieldElement> = (0..*n)
            .map(|i| FieldElement::from_bytes(&[(i + 1) as u8; 32]))
            .collect();

        group.throughput(Throughput::Elements(*n as u64));

        // Baseline: individual inversions
        group.bench_with_input(BenchmarkId::new("individual", n), n, |bencher, _| {
            bencher.iter(|| {
                let results: Vec<FieldElement> = elements.iter()
                    .map(|e| e.invert())
                    .collect();
                black_box(results)
            });
        });

        // Montgomery's trick: batch inversion
        group.bench_with_input(BenchmarkId::new("montgomery_batch", n), n, |bencher, _| {
            bencher.iter(|| {
                let results = FieldElement::batch_invert(&elements);
                black_box(results)
            });
        });
    }

    group.finish();
}

// ============================================================================
// Table Lookup Benchmarks (constant-time vs non-constant-time)
// ============================================================================

fn bench_table_lookups(c: &mut Criterion) {
    let mut group = c.benchmark_group("table_lookup");

    // Create a lookup table
    let base = base_point();
    let mut table = [base; 16];
    for i in 1..16 {
        table[i] = table[i - 1].add(&base);
    }

    // Benchmark current (non-constant-time) lookup
    group.bench_function("non_constant_time", |bencher| {
        bencher.iter(|| {
            let index = 7; // Fixed index for benchmark
            black_box(table[index])
        });
    });

    // TODO: Constant-time lookup will be benchmarked here

    group.finish();
}

// ============================================================================
// Coordinate System Benchmarks (Extended vs Niels)
// ============================================================================

fn bench_coordinate_systems(c: &mut Criterion) {
    let mut group = c.benchmark_group("coordinate_systems");

    let p1 = base_point();
    let p2 = p1.double();

    // Baseline: Extended + Extended addition
    group.bench_function("extended_add", |bencher| {
        bencher.iter(|| black_box(p1.add(&p2)));
    });

    // TODO: Niels coordinate addition will be benchmarked here

    group.finish();
}

// ============================================================================
// Scalar Multiplication Method Comparisons
// ============================================================================

fn bench_scalar_multiplication_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_mul_methods");

    let point = base_point();
    let scalar = [0x42u8; 32];

    // Current: 4-bit windowing
    group.bench_function("4bit_windowing", |bencher| {
        bencher.iter(|| black_box(point.scalar_mul(&scalar)));
    });

    // Simple NAF (width-2, current implementation)
    group.bench_function("simple_naf_width2", |bencher| {
        bencher.iter(|| black_box(point.scalar_mul_naf(&scalar)));
    });

    // w-NAF width-4 with precomputed odd multiples
    group.bench_function("wnaf_width4", |bencher| {
        bencher.iter(|| black_box(wnaf_scalar_mul(&point, &scalar, 4)));
    });

    // w-NAF width-5: fewer additions, more memory (16 odd multiples)
    group.bench_function("wnaf_width5", |bencher| {
        bencher.iter(|| black_box(wnaf_scalar_mul(&point, &scalar, 5)));
    });

    // Sliding window width-4: adaptive window sizing
    group.bench_function("sliding_width4", |bencher| {
        bencher.iter(|| black_box(sliding_window_scalar_mul(&point, &scalar, 4)));
    });

    // Sliding window width-5: adaptive with wider max window
    group.bench_function("sliding_width5", |bencher| {
        bencher.iter(|| black_box(sliding_window_scalar_mul(&point, &scalar, 5)));
    });

    group.finish();
}

// ============================================================================
// Double-Scalar Multiplication (for verification)
// ============================================================================

fn bench_double_scalar_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("double_scalar");

    let base = base_point();
    let public_key = base.scalar_mul(&[0x42u8; 32]);
    let s_scalar = [0x12u8; 32];
    let k_scalar = [0x34u8; 32];

    // Current method: compute separately then add
    group.bench_function("current", |bencher| {
        bencher.iter(|| {
            let sb = scalar_mul_base_fast(&s_scalar);
            let ka = public_key.scalar_mul(&k_scalar);
            black_box(sb.add(&ka))
        });
    });

    // TODO: Optimized separate method will be benchmarked here
    // TODO: Joint sparse form will be benchmarked here

    group.finish();
}

// ============================================================================
// Multiscalar Multiplication Benchmarks
// ============================================================================

fn bench_multiscalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiscalar");
    group.sample_size(10);

    for n in [4, 8, 16, 32, 64].iter() {
        let points: Vec<EdwardsPoint> = (0..*n)
            .map(|i| base_point().scalar_mul(&[(i + 1) as u8; 32]))
            .collect();

        let scalars: Vec<[u8; 32]> = (0..*n)
            .map(|i| [i as u8; 32])
            .collect();

        group.throughput(Throughput::Elements(*n as u64));

        // Baseline: individual scalar multiplications
        group.bench_with_input(BenchmarkId::new("individual", n), n, |bencher, _| {
            bencher.iter(|| {
                let mut result = EdwardsPoint::identity();
                for i in 0..*n {
                    let term = points[i].scalar_mul(&scalars[i]);
                    result = result.add(&term);
                }
                black_box(result)
            });
        });

        // Pippenger's algorithm: bucket method MSM
        group.bench_with_input(BenchmarkId::new("pippenger", n), n, |bencher, _| {
            bencher.iter(|| {
                let result = Ed25519::pippenger_msm(&scalars, &points);
                black_box(result)
            });
        });
    }

    group.finish();
}

// ============================================================================
// Benchmark Groups
// ============================================================================

criterion_group!(
    baseline_benches,
    bench_baseline_field_operations,
    bench_baseline_point_operations,
    bench_lazy_point_operations,
    bench_doubling_chain_comparison,
    bench_baseline_scalar_operations,
    bench_baseline_scalar_multiplication,
    bench_baseline_signature_operations,
    bench_baseline_batch_verification,
);

criterion_group!(
    optimization_benches,
    bench_batch_inversion,
    bench_table_lookups,
    bench_coordinate_systems,
    bench_scalar_multiplication_methods,
    bench_double_scalar_methods,
    bench_multiscalar_multiplication,
);

criterion_main!(baseline_benches, optimization_benches);
