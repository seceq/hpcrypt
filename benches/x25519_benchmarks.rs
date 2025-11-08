use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_curves::X25519;
use hpcrypt_curves::field25519::FieldElement;

fn bench_x25519_public_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519 Key Generation");

    let private_key = [1u8; 32];

    group.bench_function("public_key", |b| {
        b.iter(|| {
            let public_key = black_box(X25519::public_key(&private_key));
            black_box(public_key)
        });
    });

    group.finish();
}

fn bench_x25519_shared_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519 Key Exchange");

    let alice_private = [1u8; 32];
    let bob_private = [2u8; 32];
    let bob_public = X25519::public_key(&bob_private);

    group.bench_function("shared_secret", |b| {
        b.iter(|| {
            let shared = black_box(X25519::shared_secret(&alice_private, &bob_public).unwrap());
            black_box(shared)
        });
    });

    group.finish();
}

fn bench_x25519_full_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519 Full Exchange");

    let alice_private = [1u8; 32];
    let bob_private = [2u8; 32];

    group.bench_function("full_key_exchange", |b| {
        b.iter(|| {
            // Alice generates public key
            let alice_public = black_box(X25519::public_key(&alice_private));

            // Bob generates public key
            let bob_public = black_box(X25519::public_key(&bob_private));

            // Both compute shared secret
            let alice_shared = black_box(X25519::shared_secret(&alice_private, &bob_public).unwrap());
            let bob_shared = black_box(X25519::shared_secret(&bob_private, &alice_public).unwrap());

            black_box((alice_shared, bob_shared))
        });
    });

    group.finish();
}

// Field operations benchmarks (supporting X25519)
fn bench_field25519_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Field25519 Operations");

    let a = FieldElement::from_bytes(&[1u8; 32]);
    let b = FieldElement::from_bytes(&[2u8; 32]);

    group.bench_function("add", |b_iter| {
        b_iter.iter(|| {
            let result = black_box(a.add(&b));
            black_box(result)
        });
    });

    group.bench_function("sub", |b_iter| {
        b_iter.iter(|| {
            let result = black_box(a.sub(&b));
            black_box(result)
        });
    });

    group.bench_function("mul", |b_iter| {
        b_iter.iter(|| {
            let result = black_box(a.mul(&b));
            black_box(result)
        });
    });

    group.bench_function("square", |b_iter| {
        b_iter.iter(|| {
            let result = black_box(a.square());
            black_box(result)
        });
    });

    group.bench_function("invert", |b_iter| {
        b_iter.iter(|| {
            let result = black_box(a.invert());
            black_box(result)
        });
    });

    group.finish();
}

// Benchmark different input sizes for pattern analysis
fn bench_x25519_input_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519 Input Patterns");

    let test_cases = vec![
        ("all_zeros", [0u8; 32]),
        ("all_ones", [0xFFu8; 32]),
        ("alternating", {
            let mut arr = [0u8; 32];
            for i in 0..32 {
                arr[i] = if i % 2 == 0 { 0xAA } else { 0x55 };
            }
            arr
        }),
        ("sequential", {
            let mut arr = [0u8; 32];
            for i in 0..32 {
                arr[i] = i as u8;
            }
            arr
        }),
    ];

    for (name, private_key) in test_cases {
        let public_key = X25519::public_key(&[1u8; 32]);

        group.bench_with_input(
            BenchmarkId::new("pattern", name),
            &private_key,
            |b, pk| {
                b.iter(|| {
                    let shared = black_box(X25519::shared_secret(pk, &public_key).unwrap());
                    black_box(shared)
                });
            },
        );
    }

    group.finish();
}

// Benchmark comparison with constant data
fn bench_x25519_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519 Batch Operations");

    let private_keys: Vec<[u8; 32]> = (0..10)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = i;
            key
        })
        .collect();

    let public_keys: Vec<[u8; 32]> = private_keys
        .iter()
        .map(|pk| X25519::public_key(pk))
        .collect();

    for batch_size in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("key_exchange", format!("{}_exchanges", batch_size)),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for i in 0..size {
                        let shared = black_box(
                            X25519::shared_secret(&private_keys[i], &public_keys[(i + 1) % size]).unwrap()
                        );
                        black_box(shared);
                    }
                });
            },
        );
    }

    group.finish();
}

// Montgomery ladder operations (constant-time scalar multiplication)
fn bench_x25519_montgomery_ladder(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519 Montgomery Ladder");

    let scalar = [1u8; 32];
    let point = [2u8; 32];

    group.bench_function("scalar_multiplication", |b| {
        b.iter(|| {
            let result = black_box(X25519::shared_secret(&scalar, &point).unwrap());
            black_box(result)
        });
    });

    group.finish();
}

// Encoding/decoding benchmarks
fn bench_x25519_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519 Encoding");

    let private_key = [1u8; 32];
    let public_key = X25519::public_key(&private_key);

    group.bench_function("public_key_to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(public_key);
            black_box(bytes)
        });
    });

    group.bench_function("clamping", |b| {
        let mut key = [0xFFu8; 32];
        b.iter(|| {
            // X25519 clamping: clear bits 0, 1, 2 and 255, set bit 254
            key[0] &= 248;
            key[31] &= 127;
            key[31] |= 64;
            black_box(key)
        });
    });

    group.finish();
}

criterion_group!(
    x25519_benches,
    bench_x25519_public_key,
    bench_x25519_shared_secret,
    bench_x25519_full_exchange,
    bench_field25519_operations,
    bench_x25519_input_patterns,
    bench_x25519_batch,
    bench_x25519_montgomery_ladder,
    bench_x25519_encoding,
);

criterion_main!(x25519_benches);
