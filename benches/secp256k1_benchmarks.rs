use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_curves::secp256k1::{Point, Scalar, FieldElement};
use hpcrypt_signatures::ecdsa_secp256k1::{SigningKey, Signature};

fn field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_field");

    let a = FieldElement::from_bytes(&[0x42u8; 32]);
    let b = FieldElement::from_bytes(&[0x43u8; 32]);

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
    let mut group = c.benchmark_group("secp256k1_scalar");

    let a = Scalar::from_bytes(&[0x42u8; 32]);
    let b = Scalar::from_bytes(&[0x43u8; 32]);

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
    let mut group = c.benchmark_group("secp256k1_point");

    let g = Point::generator();
    let p1 = g.scalar_mul(&[0x42u8; 32]);
    let p2 = g.scalar_mul(&[0x43u8; 32]);

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
    let mut group = c.benchmark_group("secp256k1_scalar_mul");

    let g = Point::generator();
    let scalar = [0x42u8; 32];

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
    let p = g.scalar_mul(&[0x43u8; 32]);

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
    let mut group = c.benchmark_group("secp256k1_ecdsa");

    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]).unwrap();
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
            let sk = SigningKey::from_bytes(&[0x42u8; 32]).unwrap();
            black_box(sk.verifying_key())
        })
    });

    group.finish();
}

fn batch_verification(c: &mut Criterion) {
    use hpcrypt_signatures::ecdsa_secp256k1::VerifyingKey;

    let mut group = c.benchmark_group("secp256k1_batch_verify");

    // Create test data
    let keys: Vec<_> = (0..100).map(|i| {
        let mut secret = [0x42u8; 32];
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

fn glv_operations(c: &mut Criterion) {
    use hpcrypt_curves::secp256k1::glv;

    let mut group = c.benchmark_group("secp256k1_glv");

    let g = Point::generator();
    let scalar_01 = [0x01u8; 32];
    let scalar_42 = [0x42u8; 32];

    // Compare standard vs GLV scalar multiplication
    group.bench_function("variable_time_scalar_mul", |bench| {
        bench.iter(|| {
            black_box(g.scalar_mul(&scalar_42))
        })
    });

    group.bench_function("constant_time_scalar_mul", |bench| {
        bench.iter(|| {
            black_box(g.scalar_mul_constant_time(&scalar_42))
        })
    });

    group.bench_function("glv_scalar_mul", |bench| {
        bench.iter(|| {
            black_box(glv::scalar_mul_glv(&g, &scalar_42))
        })
    });

    // Benchmark decomposition
    group.bench_function("scalar_decomposition", |bench| {
        let k = Scalar::from_bytes(&scalar_42);
        bench.iter(|| {
            black_box(glv::decompose_scalar(&k))
        })
    });

    // Benchmark endomorphism
    group.bench_function("endomorphism", |bench| {
        bench.iter(|| {
            black_box(glv::endomorphism(&g))
        })
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
    glv_operations,
);
criterion_main!(benches);
