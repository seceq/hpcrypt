use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_curves::secp256k1::point_montgomery::MontgomeryPoint;
use hpcrypt_curves::secp256k1::{Point, Scalar};

/// Benchmark point doubling: Standard vs Montgomery
fn bench_point_double(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_point_double");

    // Standard point doubling
    let g_std = Point::generator();
    group.bench_function("standard", |b| {
        b.iter(|| {
            let result = black_box(&g_std).double();
            black_box(result)
        })
    });

    // Montgomery point doubling
    let g_mont = MontgomeryPoint::generator();
    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let result = black_box(&g_mont).double();
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark point addition: Standard vs Montgomery
fn bench_point_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_point_add");

    // Prepare test points
    let g_std = Point::generator();
    let p_std = g_std.double();

    let g_mont = MontgomeryPoint::generator();
    let p_mont = g_mont.double();

    // Standard point addition
    group.bench_function("standard", |b| {
        b.iter(|| {
            let result = black_box(&g_std).add(black_box(&p_std));
            black_box(result)
        })
    });

    // Montgomery point addition
    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let result = black_box(&g_mont).add(black_box(&p_mont));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark chained operations (10 doubles)
fn bench_chained_doubles(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_chained_10_doubles");

    // Standard
    let g_std = Point::generator();
    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut p = black_box(g_std);
            for _ in 0..10 {
                p = p.double();
            }
            black_box(p)
        })
    });

    // Montgomery
    let g_mont = MontgomeryPoint::generator();
    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let mut p = black_box(g_mont);
            for _ in 0..10 {
                p = p.double();
            }
            black_box(p)
        })
    });

    group.finish();
}

/// Benchmark chained operations (10 additions)
fn bench_chained_additions(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_chained_10_additions");

    // Standard
    let g_std = Point::generator();
    let h_std = g_std.double();
    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut p = black_box(g_std);
            for _ in 0..10 {
                p = p.add(&h_std);
            }
            black_box(p)
        })
    });

    // Montgomery
    let g_mont = MontgomeryPoint::generator();
    let h_mont = g_mont.double();
    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let mut p = black_box(g_mont);
            for _ in 0..10 {
                p = p.add(&h_mont);
            }
            black_box(p)
        })
    });

    group.finish();
}

/// Benchmark scalar multiplication (constant-time)
fn bench_scalar_mul_constant_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_scalar_mul_constant_time");

    // Test scalar
    let scalar_val = Scalar::from_u64(123456789);
    let scalar_bytes = scalar_val.to_bytes();

    // Standard
    let g_std = Point::generator();
    group.bench_function("standard", |b| {
        b.iter(|| {
            let result = black_box(&g_std).scalar_mul_constant_time(black_box(&scalar_bytes));
            black_box(result)
        })
    });

    // Montgomery
    let g_mont = MontgomeryPoint::generator();
    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let result = black_box(&g_mont).scalar_mul_constant_time(black_box(&scalar_bytes));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark generator scalar multiplication
fn bench_scalar_mul_generator(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_scalar_mul_generator");

    // Test scalar
    let scalar_val = Scalar::from_u64(987654321);
    let scalar_bytes = scalar_val.to_bytes();

    // Standard
    group.bench_function("standard", |b| {
        b.iter(|| {
            let result = Point::scalar_mul_generator(black_box(&scalar_bytes));
            black_box(result)
        })
    });

    // Montgomery
    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let result = MontgomeryPoint::scalar_mul_generator(black_box(&scalar_bytes));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark Shamir's trick (ECDSA verification simulation)
fn bench_scalar_mul_shamir(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_scalar_mul_shamir");

    // Test scalars
    let u1 = Scalar::from_u64(111111);
    let u2 = Scalar::from_u64(222222);
    let u1_bytes = u1.to_bytes();
    let u2_bytes = u2.to_bytes();

    // Test point (public key)
    let g_std = Point::generator();
    let pubkey_std = g_std.scalar_mul_constant_time(&[0x42; 32]);

    let g_mont = MontgomeryPoint::generator();
    let pubkey_mont = g_mont.scalar_mul_constant_time(&[0x42; 32]);

    // Standard
    group.bench_function("standard", |b| {
        b.iter(|| {
            let result = Point::scalar_mul_shamir(
                black_box(&u1_bytes),
                black_box(&u2_bytes),
                black_box(&pubkey_std),
            );
            black_box(result)
        })
    });

    // Montgomery
    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let result = MontgomeryPoint::scalar_mul_shamir(
                black_box(&u1_bytes),
                black_box(&u2_bytes),
                black_box(&pubkey_mont),
            );
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark conversion overhead
fn bench_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_conversion");

    let g_std = Point::generator();
    let g_mont = MontgomeryPoint::generator();

    // Standard -> Montgomery
    group.bench_function("standard_to_montgomery", |b| {
        b.iter(|| {
            let result = MontgomeryPoint::from_standard(black_box(&g_std));
            black_box(result)
        })
    });

    // Montgomery -> Standard
    group.bench_function("montgomery_to_standard", |b| {
        b.iter(|| {
            let result = black_box(&g_mont).to_standard();
            black_box(result)
        })
    });

    // Roundtrip
    group.bench_function("roundtrip", |b| {
        b.iter(|| {
            let mont = MontgomeryPoint::from_standard(black_box(&g_std));
            let result = mont.to_standard();
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark point doubling with varying sizes
fn bench_double_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_double_batch");

    for size in [10, 50, 100, 256].iter() {
        // Standard
        group.bench_with_input(BenchmarkId::new("standard", size), size, |b, &size| {
            let g = Point::generator();
            b.iter(|| {
                let mut p = black_box(g);
                for _ in 0..size {
                    p = p.double();
                }
                black_box(p)
            })
        });

        // Montgomery
        group.bench_with_input(BenchmarkId::new("montgomery", size), size, |b, &size| {
            let g = MontgomeryPoint::generator();
            b.iter(|| {
                let mut p = black_box(g);
                for _ in 0..size {
                    p = p.double();
                }
                black_box(p)
            })
        });
    }

    group.finish();
}

/// Benchmark ECDSA verification simulation (full operation)
fn bench_ecdsa_verification_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_ecdsa_verification_simulation");

    // Simulate ECDSA verification: R' = u1*G + u2*Q
    let u1 = Scalar::from_u64(0x1234567890ABCDEF);
    let u2 = Scalar::from_u64(0xFEDCBA0987654321);
    let u1_bytes = u1.to_bytes();
    let u2_bytes = u2.to_bytes();

    // Public key (simulated)
    let pubkey_scalar = [0x42u8; 32];

    // Standard
    let g_std = Point::generator();
    let pubkey_std = g_std.scalar_mul_constant_time(&pubkey_scalar);

    group.bench_function("standard", |b| {
        b.iter(|| {
            let result = Point::scalar_mul_shamir(
                black_box(&u1_bytes),
                black_box(&u2_bytes),
                black_box(&pubkey_std),
            );
            black_box(result)
        })
    });

    // Montgomery
    let g_mont = MontgomeryPoint::generator();
    let pubkey_mont = g_mont.scalar_mul_constant_time(&pubkey_scalar);

    group.bench_function("montgomery", |b| {
        b.iter(|| {
            let result = MontgomeryPoint::scalar_mul_shamir(
                black_box(&u1_bytes),
                black_box(&u2_bytes),
                black_box(&pubkey_mont),
            );
            black_box(result)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_point_double,
    bench_point_add,
    bench_chained_doubles,
    bench_chained_additions,
    bench_scalar_mul_constant_time,
    bench_scalar_mul_generator,
    bench_scalar_mul_shamir,
    bench_conversion,
    bench_double_batch,
    bench_ecdsa_verification_simulation,
);

criterion_main!(benches);
