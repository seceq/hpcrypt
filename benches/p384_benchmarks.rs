use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_curves::p384::{Point, Scalar, FieldElement};
use hpcrypt_signatures::ecdsa_p384::{SigningKey, Signature};

fn field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_field");

    let a = FieldElement::from_bytes(&[0x42u8; 48]).unwrap();
    let b = FieldElement::from_bytes(&[0x43u8; 48]).unwrap();

    group.bench_function("add", |bench| {
        bench.iter(|| {
            black_box(a.add(&b))
        })
    });

    group.bench_function("mul", |bench| {
        bench.iter(|| {
            black_box(a.mul(&b))
        })
    });

    group.bench_function("square", |bench| {
        bench.iter(|| {
            black_box(a.square())
        })
    });

    group.bench_function("invert", |bench| {
        bench.iter(|| {
            black_box(a.invert())
        })
    });

    group.finish();
}

fn scalar_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_scalar");

    let a = Scalar::from_bytes(&[0x42u8; 48]);
    let b = Scalar::from_bytes(&[0x43u8; 48]);

    group.bench_function("add", |bench| {
        bench.iter(|| {
            black_box(a.add(&b))
        })
    });

    group.bench_function("mul", |bench| {
        bench.iter(|| {
            black_box(a.mul(&b))
        })
    });

    group.bench_function("invert", |bench| {
        bench.iter(|| {
            black_box(a.invert())
        })
    });

    group.finish();
}

fn point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_point");

    let g = Point::generator();
    let p1 = g.scalar_mul(&[0x42u8; 48]);
    let p2 = g.scalar_mul(&[0x43u8; 48]);

    group.bench_function("add", |bench| {
        bench.iter(|| {
            black_box(p1.add(&p2))
        })
    });

    group.bench_function("double", |bench| {
        bench.iter(|| {
            black_box(p1.double())
        })
    });

    group.bench_function("to_affine", |bench| {
        bench.iter(|| {
            black_box(p1.to_affine())
        })
    });

    group.finish();
}

fn scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_scalar_mul");

    let g = Point::generator();
    let scalar = [0x42u8; 48];

    group.bench_function("generator_variable_time", |bench| {
        bench.iter(|| {
            black_box(g.scalar_mul(&scalar))
        })
    });

    group.bench_function("generator_constant_time", |bench| {
        bench.iter(|| {
            black_box(g.scalar_mul_constant_time(&scalar))
        })
    });

    // Arbitrary point multiplication
    let p = g.scalar_mul(&[0x43u8; 48]);

    group.bench_function("arbitrary_point_variable_time", |bench| {
        bench.iter(|| {
            black_box(p.scalar_mul(&scalar))
        })
    });

    group.bench_function("arbitrary_point_constant_time", |bench| {
        bench.iter(|| {
            black_box(p.scalar_mul_constant_time(&scalar))
        })
    });

    group.finish();
}

fn ecdsa_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_ecdsa");

    let signing_key = SigningKey::from_bytes(&[0x42u8; 48]).unwrap();
    let verifying_key = signing_key.verifying_key();
    let message = b"Hello, world! This is a test message for ECDSA benchmarking.";
    let signature = signing_key.sign(message);

    group.bench_function("sign", |bench| {
        bench.iter(|| {
            black_box(signing_key.sign(message))
        })
    });

    group.bench_function("verify", |bench| {
        bench.iter(|| {
            black_box(verifying_key.verify(message, &signature))
        })
    });

    group.bench_function("keygen", |bench| {
        bench.iter(|| {
            let sk = SigningKey::from_bytes(&[0x42u8; 48]).unwrap();
            black_box(sk.verifying_key())
        })
    });

    group.finish();
}

fn batch_verification(c: &mut Criterion) {
    use hpcrypt_signatures::ecdsa_p384::VerifyingKey;

    let mut group = c.benchmark_group("p384_batch_verify");

    // Create test data
    let keys: Vec<_> = (0..100).map(|i| {
        let mut secret = [0x42u8; 48];
        secret[0] = i as u8;
        SigningKey::from_bytes(&secret).unwrap()
    }).collect();

    let messages: Vec<Vec<u8>> = (0..100).map(|i| {
        format!("Test message {}", i).into_bytes()
    }).collect();

    let signatures: Vec<_> = keys.iter().zip(&messages).map(|(key, msg)| {
        key.sign(msg)
    }).collect();

    let verifying_keys: Vec<_> = keys.iter().map(|k| k.verifying_key()).collect();

    // Benchmark different batch sizes
    for size in [1, 10, 50, 100] {
        let items: Vec<(&[u8], &Signature, &VerifyingKey)> = messages[..size]
            .iter()
            .zip(&signatures[..size])
            .zip(&verifying_keys[..size])
            .map(|((msg, sig), vk)| (msg.as_slice(), sig, vk))
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bench, _| {
            bench.iter(|| {
                black_box(VerifyingKey::batch_verify(&items))
            })
        });
    }

    group.finish();
}

fn montgomery_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_montgomery");

    let a = FieldElement::from_u64(12345);
    let b = FieldElement::from_u64(67890);

    // Benchmark standard multiplication (baseline)
    group.bench_function("standard_mul", |bench| {
        bench.iter(|| {
            let result = black_box(&a).mul(black_box(&b));
            black_box(result);
        });
    });

    // Benchmark Montgomery multiplication (with conversion overhead)
    group.bench_function("montgomery_mul_with_conversion", |bench| {
        bench.iter(|| {
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

    group.bench_function("montgomery_mul_pure", |bench| {
        bench.iter(|| {
            let result = black_box(&a_mont).montgomery_mul(black_box(&b_mont));
            black_box(result);
        });
    });

    // Benchmark standard squaring (baseline)
    group.bench_function("standard_square", |bench| {
        bench.iter(|| {
            let result = black_box(&a).square();
            black_box(result);
        });
    });

    // Benchmark Montgomery squaring (with conversion overhead)
    group.bench_function("montgomery_square_with_conversion", |bench| {
        bench.iter(|| {
            let a_mont = black_box(&a).to_montgomery();
            let c_mont = a_mont.montgomery_square();
            let result = c_mont.from_montgomery();
            black_box(result);
        });
    });

    // Benchmark pure Montgomery squaring (input already in Montgomery form)
    group.bench_function("montgomery_square_pure", |bench| {
        bench.iter(|| {
            let result = black_box(&a_mont).montgomery_square();
            black_box(result);
        });
    });

    // Benchmark conversion to Montgomery form
    group.bench_function("to_montgomery", |bench| {
        bench.iter(|| {
            let result = black_box(&a).to_montgomery();
            black_box(result);
        });
    });

    // Benchmark conversion from Montgomery form
    group.bench_function("from_montgomery", |bench| {
        bench.iter(|| {
            let result = black_box(&a_mont).from_montgomery();
            black_box(result);
        });
    });

    // Benchmark sequence: 3 multiplications (amortizes conversion cost)
    let c = FieldElement::from_u64(11111);

    group.bench_function("standard_3_muls", |bench| {
        bench.iter(|| {
            let ab = black_box(&a).mul(black_box(&b));
            let abc = ab.mul(black_box(&c));
            let result = abc.square();
            black_box(result);
        });
    });

    group.bench_function("montgomery_3_muls", |bench| {
        bench.iter(|| {
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

    // Benchmark large value multiplication (with 6 limbs for P-384)
    let large_a = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000000,
        0xAAAAAAAAAAAAAAAA,
        0x5555555555555555,
    ]);
    let large_b = FieldElement::from_limbs([
        0xAAAAAAAAAAAAAAAA,
        0x0000000055555555,
        0x5555555555555555,
        0x55555555AAAAAAAA,
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
    ]);

    group.bench_function("standard_mul_large", |bench| {
        bench.iter(|| {
            let result = black_box(&large_a).mul(black_box(&large_b));
            black_box(result);
        });
    });

    let large_a_mont = large_a.to_montgomery();
    let large_b_mont = large_b.to_montgomery();

    group.bench_function("montgomery_mul_large_pure", |bench| {
        bench.iter(|| {
            let result = black_box(&large_a_mont).montgomery_mul(black_box(&large_b_mont));
            black_box(result);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    field_operations,
    scalar_operations,
    point_operations,
    scalar_multiplication,
    ecdsa_operations,
    batch_verification,
    montgomery_arithmetic,
);
criterion_main!(benches);
