use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_curves::p256::FieldElement;

fn bench_field_mul(c: &mut Criterion) {
    let a = FieldElement::from_u64(12345);
    let b = FieldElement::from_u64(67890);

    c.bench_function("p256_field_mul", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).mul(black_box(&b));
            black_box(result);
        });
    });
}

fn bench_field_square(c: &mut Criterion) {
    let a = FieldElement::from_u64(12345);

    c.bench_function("p256_field_square", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).square();
            black_box(result);
        });
    });
}

fn bench_field_add(c: &mut Criterion) {
    let a = FieldElement::from_u64(12345);
    let b = FieldElement::from_u64(67890);

    c.bench_function("p256_field_add", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).add(black_box(&b));
            black_box(result);
        });
    });
}

fn bench_field_invert(c: &mut Criterion) {
    let a = FieldElement::from_u64(12345);

    c.bench_function("p256_field_invert_fermat", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).invert();
            black_box(result);
        });
    });

    c.bench_function("p256_field_invert_gcd", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).invert_gcd();
            black_box(result);
        });
    });
}

fn bench_field_sqrt(c: &mut Criterion) {
    // Use a value that has a square root
    let a = FieldElement::from_u64(4);

    c.bench_function("p256_field_sqrt", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).sqrt();
            black_box(result);
        });
    });
}

fn bench_montgomery_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_montgomery");

    let a = FieldElement::from_u64(12345);
    let b = FieldElement::from_u64(67890);

    // Benchmark standard multiplication (baseline)
    group.bench_function("standard_mul", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).mul(black_box(&b));
            black_box(result);
        });
    });

    // Benchmark Montgomery multiplication (with conversion overhead)
    group.bench_function("montgomery_mul_with_conversion", |bencher| {
        bencher.iter(|| {
            let a_mont = black_box(&a).to_montgomery();
            let b_mont = black_box(&b).to_montgomery();
            let c_mont = a_mont.montgomery_mul(&b_mont);
            let result = c_mont.from_montgomery();
            black_box(result);
        });
    });

    // Benchmark pure Montgomery multiplication (inputs already in Montgomery form)
    let a_mont = a.to_montgomery();
    let b_mont = b.to_montgomery();

    group.bench_function("montgomery_mul_pure", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a_mont).montgomery_mul(black_box(&b_mont));
            black_box(result);
        });
    });

    // Benchmark standard squaring (baseline)
    group.bench_function("standard_square", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).square();
            black_box(result);
        });
    });

    // Benchmark Montgomery squaring (with conversion overhead)
    group.bench_function("montgomery_square_with_conversion", |bencher| {
        bencher.iter(|| {
            let a_mont = black_box(&a).to_montgomery();
            let c_mont = a_mont.montgomery_square();
            let result = c_mont.from_montgomery();
            black_box(result);
        });
    });

    // Benchmark pure Montgomery squaring (input already in Montgomery form)
    group.bench_function("montgomery_square_pure", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a_mont).montgomery_square();
            black_box(result);
        });
    });

    // Benchmark conversion to Montgomery form
    group.bench_function("to_montgomery", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).to_montgomery();
            black_box(result);
        });
    });

    // Benchmark conversion from Montgomery form
    group.bench_function("from_montgomery", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a_mont).from_montgomery();
            black_box(result);
        });
    });

    // Benchmark sequence: 3 multiplications (amortizes conversion cost)
    let c = FieldElement::from_u64(11111);

    group.bench_function("standard_3_muls", |bencher| {
        bencher.iter(|| {
            let ab = black_box(&a).mul(black_box(&b));
            let abc = ab.mul(black_box(&c));
            let result = abc.square();
            black_box(result);
        });
    });

    group.bench_function("montgomery_3_muls", |bencher| {
        bencher.iter(|| {
            let a_m = black_box(&a).to_montgomery();
            let b_m = black_box(&b).to_montgomery();
            let c_m = black_box(&c).to_montgomery();
            let ab_m = a_m.montgomery_mul(&b_m);
            let abc_m = ab_m.montgomery_mul(&c_m);
            let result_m = abc_m.montgomery_square();
            let result = result_m.from_montgomery();
            black_box(result);
        });
    });

    // Benchmark large value multiplication
    let large_a = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000000,
    ]);
    let large_b = FieldElement::from_limbs([
        0xAAAAAAAAAAAAAAAA,
        0x0000000055555555,
        0x5555555555555555,
        0x55555555AAAAAAAA,
    ]);

    group.bench_function("standard_mul_large", |bencher| {
        bencher.iter(|| {
            let result = black_box(&large_a).mul(black_box(&large_b));
            black_box(result);
        });
    });

    let large_a_mont = large_a.to_montgomery();
    let large_b_mont = large_b.to_montgomery();

    group.bench_function("montgomery_mul_large_pure", |bencher| {
        bencher.iter(|| {
            let result = black_box(&large_a_mont).montgomery_mul(black_box(&large_b_mont));
            black_box(result);
        });
    });

    group.finish();
}

fn bench_reduction_edge_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_reduction_edge_cases");

    // Test case: (p-1)^2
    let p_minus_1 = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFE,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]);

    group.bench_function("p_minus_1_squared", |bencher| {
        bencher.iter(|| {
            let result = black_box(&p_minus_1).mul(black_box(&p_minus_1));
            black_box(result);
        });
    });

    // Test case: (p-3)^2 (our critical test case)
    let p_minus_3 = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFC,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]);

    group.bench_function("p_minus_3_squared", |bencher| {
        bencher.iter(|| {
            let result = black_box(&p_minus_3).mul(black_box(&p_minus_3));
            black_box(result);
        });
    });

    // Test case: large value multiplication
    let large_a = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000000,
    ]);
    let large_b = FieldElement::from_limbs([
        0xAAAAAAAAAAAAAAAA,
        0x0000000055555555,
        0x5555555555555555,
        0x55555555AAAAAAAA,
    ]);

    group.bench_function("large_values", |bencher| {
        bencher.iter(|| {
            let result = black_box(&large_a).mul(black_box(&large_b));
            black_box(result);
        });
    });

    group.finish();
}

fn bench_point_operations(c: &mut Criterion) {
    use hpcrypt_curves::p256::Point;

    let g = Point::generator();

    c.bench_function("p256_point_double", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g).double();
            black_box(result);
        });
    });

    let p = Point::generator();
    let q = p.double();

    c.bench_function("p256_point_add", |bencher| {
        bencher.iter(|| {
            let result = black_box(&p).add(black_box(&q));
            black_box(result);
        });
    });
}

fn bench_scalar_multiplication(c: &mut Criterion) {
    use hpcrypt_curves::p256::Point;

    let g = Point::generator();

    // Test scalar (random-looking value)
    let scalar = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ];

    // Montgomery-optimized wNAF (now the default)
    c.bench_function("p256_scalar_mul_variable_time", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g).scalar_mul(black_box(&scalar));
            black_box(result);
        });
    });

    // Standard wNAF for comparison
    c.bench_function("p256_scalar_mul_standard_wnaf", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g).scalar_mul_standard(black_box(&scalar));
            black_box(result);
        });
    });

    c.bench_function("p256_scalar_mul_constant_time", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g).scalar_mul_constant_time(black_box(&scalar));
            black_box(result);
        });
    });
}

fn bench_ecdsa_operations(c: &mut Criterion) {
    use hpcrypt_signatures::ecdsa::SigningKey;

    // Generate a test keypair
    let secret = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    let signing_key = SigningKey::from_bytes(&secret).expect("valid key");
    let verifying_key = signing_key.verifying_key();

    let message = b"The quick brown fox jumps over the lazy dog";

    // Benchmark signing
    c.bench_function("p256_ecdsa_sign", |bencher| {
        bencher.iter(|| {
            let signature = black_box(&signing_key).sign(black_box(message));
            black_box(signature);
        });
    });

    // Pre-sign a message for verification benchmarks
    let signature = signing_key.sign(message);

    // Benchmark verification
    c.bench_function("p256_ecdsa_verify", |bencher| {
        bencher.iter(|| {
            let result = black_box(&verifying_key).verify(black_box(message), black_box(&signature));
            black_box(result);
        });
    });

    // Benchmark key generation (computing public key from private)
    c.bench_function("p256_ecdsa_keygen", |bencher| {
        bencher.iter(|| {
            let vk = black_box(&signing_key).verifying_key();
            black_box(vk);
        });
    });
}

fn bench_scalar_arithmetic(c: &mut Criterion) {
    use hpcrypt_curves::p256::Scalar;

    let a = Scalar::from_u64(123456789);
    let b = Scalar::from_u64(987654321);

    c.bench_function("p256_scalar_mul", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).mul(black_box(&b));
            black_box(result);
        });
    });

    c.bench_function("p256_scalar_add", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).add(black_box(&b));
            black_box(result);
        });
    });

    c.bench_function("p256_scalar_invert", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).invert();
            black_box(result);
        });
    });
}

fn bench_generator_multiplication(c: &mut Criterion) {
    use hpcrypt_curves::p256::precomputed::{
        scalar_mul_generator, scalar_mul_generator_compressed,
        scalar_mul_generator_wide, scalar_mul_generator_balanced
    };

    let scalar = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    c.bench_function("p256_generator_mul_6bit_172kb_default", |bencher| {
        bencher.iter(|| {
            let result = scalar_mul_generator(black_box(&scalar));
            black_box(result);
        });
    });

    c.bench_function("p256_generator_mul_5bit_104kb", |bencher| {
        bencher.iter(|| {
            let result = scalar_mul_generator_wide(black_box(&scalar));
            black_box(result);
        });
    });

    c.bench_function("p256_generator_mul_4bit_64kb", |bencher| {
        bencher.iter(|| {
            let result = scalar_mul_generator_balanced(black_box(&scalar));
            black_box(result);
        });
    });

    c.bench_function("p256_generator_mul_compressed_32kb", |bencher| {
        bencher.iter(|| {
            let result = scalar_mul_generator_compressed(black_box(&scalar));
            black_box(result);
        });
    });
}

fn bench_montgomery_point_operations(c: &mut Criterion) {
    use hpcrypt_curves::p256::{Point, PointMontgomery};

    let g = Point::generator();
    let g2 = g.double();

    // Benchmark: Standard point doubling
    c.bench_function("p256_point_double_standard", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g).double();
            black_box(result);
        });
    });

    // Benchmark: Montgomery point doubling (with conversion overhead)
    c.bench_function("p256_point_double_montgomery_with_conversion", |bencher| {
        bencher.iter(|| {
            let g_mont = PointMontgomery::from_point(black_box(&g));
            let result_mont = g_mont.double();
            let result = result_mont.to_point();
            black_box(result);
        });
    });

    // Benchmark: Montgomery point doubling (pure, no conversion)
    let g_mont = PointMontgomery::from_point(&g);
    c.bench_function("p256_point_double_montgomery_pure", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g_mont).double();
            black_box(result);
        });
    });

    // Benchmark: Standard point addition
    c.bench_function("p256_point_add_standard", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g).add(black_box(&g2));
            black_box(result);
        });
    });

    // Benchmark: Montgomery point addition (with conversion overhead)
    c.bench_function("p256_point_add_montgomery_with_conversion", |bencher| {
        bencher.iter(|| {
            let g_mont = PointMontgomery::from_point(black_box(&g));
            let g2_mont = PointMontgomery::from_point(black_box(&g2));
            let result_mont = g_mont.add(&g2_mont);
            let result = result_mont.to_point();
            black_box(result);
        });
    });

    // Benchmark: Montgomery point addition (pure, no conversion)
    let g2_mont = PointMontgomery::from_point(&g2);
    c.bench_function("p256_point_add_montgomery_pure", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g_mont).add(black_box(&g2_mont));
            black_box(result);
        });
    });

    // Benchmark: Standard mixed addition
    let g2_affine = g2.to_affine().expect("valid point");
    c.bench_function("p256_point_add_affine_standard", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g).add_affine(black_box(&g2_affine));
            black_box(result);
        });
    });

    // Benchmark: Montgomery mixed addition (pure, no conversion)
    c.bench_function("p256_point_add_affine_montgomery_pure", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g_mont).add_affine(black_box(&g2_affine));
            black_box(result);
        });
    });

    // Benchmark: Conversion costs
    c.bench_function("p256_point_to_montgomery", |bencher| {
        bencher.iter(|| {
            let result = PointMontgomery::from_point(black_box(&g));
            black_box(result);
        });
    });

    c.bench_function("p256_point_from_montgomery", |bencher| {
        bencher.iter(|| {
            let result = black_box(&g_mont).to_point();
            black_box(result);
        });
    });

    // Benchmark: Complex sequence (10 doubles + 10 adds)
    c.bench_function("p256_point_sequence_standard", |bencher| {
        bencher.iter(|| {
            let mut result = black_box(&g).clone();
            for _ in 0..10 {
                result = result.double();
                result = result.add(&g2);
            }
            black_box(result);
        });
    });

    c.bench_function("p256_point_sequence_montgomery", |bencher| {
        bencher.iter(|| {
            let mut result_mont = PointMontgomery::from_point(black_box(&g));
            let g2_mont = PointMontgomery::from_point(&g2);
            for _ in 0..10 {
                result_mont = result_mont.double();
                result_mont = result_mont.add(&g2_mont);
            }
            let result = result_mont.to_point();
            black_box(result);
        });
    });
}

criterion_group!(
    benches,
    bench_field_mul,
    bench_field_square,
    bench_field_add,
    bench_field_invert,
    bench_field_sqrt,
    bench_montgomery_arithmetic,
    bench_reduction_edge_cases,
    bench_point_operations,
    bench_scalar_multiplication,
    bench_ecdsa_operations,
    bench_scalar_arithmetic,
    bench_generator_multiplication,
    bench_montgomery_point_operations,
);
criterion_main!(benches);
