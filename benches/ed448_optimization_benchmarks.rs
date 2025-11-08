// Ed448 Optimization Benchmarks
//
// This benchmark suite measures the performance of each Ed448 optimization
// technique to validate gains before applying changes.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use hpcrypt_curves::ed448::{FieldElement, Scalar, Point, sign, verify, public_key};
use hpcrypt_curves::ed448::sliding::sliding_window_scalar_mul;

// ============================================================================
// Baseline Field Operation Benchmarks
// ============================================================================

fn bench_baseline_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_field_baseline");

    let a = FieldElement::from_limbs([1, 2, 3, 4, 5, 6, 7, 8]);
    let b = FieldElement::from_limbs([8, 7, 6, 5, 4, 3, 2, 1]);

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a + b));
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(a - b));
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a * b));
    });

    group.bench_function("square", |bencher| {
        bencher.iter(|| black_box(a.square()));
    });

    group.bench_function("weak_reduce", |bencher| {
        bencher.iter(|| black_box(a.weak_reduce()));
    });

    group.bench_function("strong_reduce", |bencher| {
        bencher.iter(|| black_box(a.strong_reduce()));
    });

    group.bench_function("invert", |bencher| {
        bencher.iter(|| black_box(a.invert()));
    });

    group.finish();
}

// ============================================================================
// Field Multiplication Method Benchmarks
// ============================================================================

fn bench_field_multiplication_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_field_mul_methods");

    let a = FieldElement::from_limbs([1, 2, 3, 4, 5, 6, 7, 8]);
    let b = FieldElement::from_limbs([8, 7, 6, 5, 4, 3, 2, 1]);

    // Current: schoolbook multiplication
    group.bench_function("schoolbook", |bencher| {
        bencher.iter(|| black_box(a * b));
    });

    // TODO: Karatsuba multiplication will be benchmarked here
    // TODO: Fused Karatsuba-Solinas will be benchmarked here

    group.finish();
}

// ============================================================================
// Field Inversion Method Benchmarks
// ============================================================================

fn bench_field_inversion_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_field_inversion");
    group.sample_size(10); // Inversion is slow

    let a = FieldElement::from_limbs([1, 2, 3, 4, 5, 6, 7, 8]);

    // Current: likely Fermat's little theorem
    group.bench_function("current", |bencher| {
        bencher.iter(|| black_box(a.invert()));
    });

    // TODO: Optimized 460-operation chain will be benchmarked here

    group.finish();
}

// ============================================================================
// Tight/Loose Representation Benchmarks
// ============================================================================

fn bench_tight_loose_representation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_tight_loose");

    let a = FieldElement::from_limbs([1, 2, 3, 4, 5, 6, 7, 8]);
    let b = FieldElement::from_limbs([8, 7, 6, 5, 4, 3, 2, 1]);

    // Current: always reduce after operations
    group.bench_function("always_reduce", |bencher| {
        bencher.iter(|| {
            let r1 = a + b;
            let r2 = r1 + a;
            let r3 = r2 + b;
            black_box(r3)
        });
    });

    // TODO: Tight/loose with deferred reduction will be benchmarked here

    group.finish();
}

// ============================================================================
// Point Operation Benchmarks
// ============================================================================

fn bench_baseline_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_point_baseline");

    // Create test points
    let scalar1 = Scalar::from_bytes(&[1u8; 57]);
    let scalar2 = Scalar::from_bytes(&[2u8; 57]);

    let p1 = Point::generator().scalar_mul(&scalar1);
    let p2 = Point::generator().scalar_mul(&scalar2);

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(p1.add(&p2)));
    });

    group.bench_function("double", |bencher| {
        bencher.iter(|| black_box(p1.double()));
    });

    group.finish();
}

// ============================================================================
// Coordinate System Benchmarks
// ============================================================================

fn bench_coordinate_systems(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_coordinates");

    let scalar1 = Scalar::from_bytes(&[1u8; 57]);
    let scalar2 = Scalar::from_bytes(&[2u8; 57]);

    let p1 = Point::generator().scalar_mul(&scalar1);
    let p2 = Point::generator().scalar_mul(&scalar2);

    // Current: Extended coordinates only
    group.bench_function("extended_add", |bencher| {
        bencher.iter(|| black_box(p1.add(&p2)));
    });

    group.bench_function("extended_double", |bencher| {
        bencher.iter(|| black_box(p1.double()));
    });

    // TODO: Twisted Edwards doubling (3S+4M) will be benchmarked here
    // TODO: Niels addition (6M) will be benchmarked here

    group.finish();
}

// ============================================================================
// Scalar Multiplication Benchmarks
// ============================================================================

fn bench_scalar_multiplication_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_scalar_mul");
    group.sample_size(10);

    let point = Point::generator();
    let scalar = Scalar::from_bytes(&[0x42u8; 57]);

    // Baseline: 1-bit double-and-add (simple method)
    group.bench_function("1bit_simple", |bencher| {
        bencher.iter(|| black_box(point.scalar_mul_simple(&scalar)));
    });

    // Optimized: 4-bit windowing method (current scalar_mul)
    group.bench_function("4bit_windowing", |bencher| {
        bencher.iter(|| black_box(point.scalar_mul(&scalar)));
    });

    // NAF method: Non-Adjacent Form (signed digits)
    // Expected: 25-33% speedup over 1-bit method
    group.bench_function("naf", |bencher| {
        bencher.iter(|| black_box(point.scalar_mul_naf(&scalar)));
    });

    // Sliding window width-4: adaptive window sizing
    // Expected: 20-30% speedup over 4-bit windowing based on Ed25519 results
    group.bench_function("sliding_width4", |bencher| {
        bencher.iter(|| black_box(sliding_window_scalar_mul(&point, &scalar, 4)));
    });

    // Sliding window width-5: adaptive with wider max window
    // Expected: Similar or slightly less than width-4 (memory tradeoff)
    group.bench_function("sliding_width5", |bencher| {
        bencher.iter(|| black_box(sliding_window_scalar_mul(&point, &scalar, 5)));
    });

    group.finish();
}

// ============================================================================
// Fixed-Base Scalar Multiplication Benchmarks
// ============================================================================

fn bench_fixed_base_scalar_multiplication(c: &mut Criterion) {
    use hpcrypt_curves::ed448::scalar_mul_base_comb;

    let mut group = c.benchmark_group("ed448_fixed_base");
    group.sample_size(10);

    let scalar_bytes = [0x42u8; 57];
    let scalar = Scalar::from_bytes(&scalar_bytes);

    // CRITICAL: Pre-initialize the Comb table before benchmarking
    // This ensures we measure only the scalar multiplication, not table generation
    let _ = scalar_mul_base_comb(&scalar_bytes);

    // Baseline: Regular variable-base scalar multiplication (4-bit windowing)
    group.bench_function("variable_base_4bit", |bencher| {
        let base = Point::generator();
        bencher.iter(|| black_box(base.scalar_mul(&scalar)));
    });

    // Optimized: Fixed-base Comb method with precomputation
    // Table is already initialized above, so this measures only scalar_mul performance
    group.bench_function("fixed_base_comb", |bencher| {
        bencher.iter(|| black_box(scalar_mul_base_comb(&scalar_bytes)));
    });

    group.finish();
}

// ============================================================================
// Signature Operation Benchmarks
// ============================================================================

fn bench_baseline_signature_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_signature_baseline");
    group.sample_size(10);

    let private_key = [0x42u8; 57];
    let message = b"Benchmark message for Ed448-Goldilocks";

    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(public_key(&private_key)));
    });

    let pub_key = public_key(&private_key);

    group.bench_function("sign", |bencher| {
        bencher.iter(|| black_box(sign(&private_key, message)));
    });

    let signature = sign(&private_key, message);

    group.bench_function("verify", |bencher| {
        bencher.iter(|| black_box(verify(&pub_key, message, &signature)));
    });

    group.finish();
}

// ============================================================================
// Batch Inversion Benchmarks
// ============================================================================

fn bench_batch_inversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_batch_inversion");
    group.sample_size(10);

    for n in [4, 8, 16, 32].iter() {
        let elements: Vec<FieldElement> = (0..*n)
            .map(|i| FieldElement::from_limbs([
                (i + 1) as u64,
                (i + 2) as u64,
                (i + 3) as u64,
                (i + 4) as u64,
                (i + 5) as u64,
                (i + 6) as u64,
                (i + 7) as u64,
                (i + 8) as u64
            ]))
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
// Multiscalar Multiplication Benchmarks
// ============================================================================

fn bench_multiscalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed448_multiscalar");
    group.sample_size(10);

    for n in [4, 8, 16, 32].iter() {
        let points: Vec<Point> = (0..*n)
            .map(|i| {
                let scalar = Scalar::from_bytes(&[(i + 1) as u8; 57]);
                Point::generator().scalar_mul(&scalar)
            })
            .collect();

        let scalars: Vec<Scalar> = (0..*n)
            .map(|i| Scalar::from_bytes(&[i as u8; 57]))
            .collect();

        let scalar_bytes: Vec<[u8; 57]> = (0..*n)
            .map(|i| [i as u8; 57])
            .collect();

        group.throughput(Throughput::Elements(*n as u64));

        // Baseline: naive summation (individual multiplications)
        group.bench_with_input(BenchmarkId::new("naive", n), n, |bencher, _| {
            bencher.iter(|| {
                let mut result = Point::identity();
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
                let result = Point::pippenger_msm(&scalar_bytes, &points);
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
    bench_baseline_signature_operations,
);

criterion_group!(
    optimization_benches,
    bench_field_multiplication_methods,
    bench_field_inversion_methods,
    bench_tight_loose_representation,
    bench_coordinate_systems,
    bench_scalar_multiplication_methods,
    bench_fixed_base_scalar_multiplication,
    bench_batch_inversion,
    bench_multiscalar_multiplication,
);

criterion_main!(baseline_benches, optimization_benches);
