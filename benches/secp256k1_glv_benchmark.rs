use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_curves::secp256k1::{Point, Scalar};
use hpcrypt_curves::secp256k1::point_montgomery::MontgomeryPoint;

fn bench_scalar_mul_glv(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_scalar_mul");

    let g = Point::generator();
    let p = g.double().add(&g); // Arbitrary point

    // Montgomery point for GLV + Montgomery benchmarks
    let g_mont = MontgomeryPoint::generator();
    let p_mont = g_mont.double().add(&g_mont);

    // Test with a typical scalar
    let scalar = Scalar::from_bytes(&[
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]);
    let scalar_bytes = scalar.to_bytes();

    // Standard GLV (baseline)
    group.bench_function("standard_glv", |b| {
        b.iter(|| {
            black_box(&p).scalar_mul(black_box(&scalar_bytes))
        })
    });

    // GLV + Montgomery (new optimized implementation)
    group.bench_function("glv_montgomery", |b| {
        b.iter(|| {
            black_box(&p_mont).scalar_mul_glv(black_box(&scalar_bytes))
        })
    });

    // Constant-time Montgomery ladder (for comparison)
    group.bench_function("constant_time_montgomery", |b| {
        b.iter(|| {
            black_box(&p).scalar_mul_constant_time(black_box(&scalar_bytes))
        })
    });

    // Generator with precomputed table (fastest for generator)
    group.bench_function("generator_precomputed", |b| {
        b.iter(|| {
            Point::scalar_mul_generator(black_box(&scalar_bytes))
        })
    });

    group.finish();
}

fn bench_ecdsa_operations(c: &mut Criterion) {
    use hpcrypt_signatures::ecdsa_secp256k1::SigningKey;

    let mut group = c.benchmark_group("secp256k1_ecdsa");

    // Generate a key pair
    let signing_key = SigningKey::generate().expect("Failed to generate key");
    let verifying_key = signing_key.verifying_key();

    let message = b"Hello, GLV optimization!";
    let signature = signing_key.sign(message);

    group.bench_function("sign", |b| {
        b.iter(|| {
            black_box(&signing_key).sign(black_box(message))
        })
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(&verifying_key).verify(black_box(message), black_box(&signature))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_scalar_mul_glv,
    bench_ecdsa_operations
);
criterion_main!(benches);
