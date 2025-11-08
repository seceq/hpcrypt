//! Benchmarks for Ed25519 signatures
//!
//! Measures performance of key operations:
//! - Key generation
//! - Signing
//! - Single signature verification
//! - Batch signature verification
//! - Scalar multiplication (with and without precomputed tables)

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use hpcrypt_curves::ed25519::Ed25519;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("ed25519_keygen", |b| {
        let sk = [0x42; 32];
        b.iter(|| {
            black_box(Ed25519::public_key(black_box(&sk)))
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    let sk = [0x42; 32];
    let message = b"Hello, world! This is a test message for Ed25519 signing.";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(Ed25519::sign(black_box(&sk), black_box(message)))
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let sk = [0x42; 32];
    let pk = Ed25519::public_key(&sk);
    let message = b"Hello, world! This is a test message for Ed25519 signing.";
    let signature = Ed25519::sign(&sk, message);

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            black_box(Ed25519::verify(
                black_box(&pk),
                black_box(message),
                black_box(&signature)
            ))
        });
    });
}

fn bench_verify_variable_message_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_verify_message_size");

    let sk = [0x42; 32];
    let pk = Ed25519::public_key(&sk);

    for size in [32, 64, 128, 256, 512, 1024, 2048, 4096].iter() {
        let message = vec![0x42u8; *size];
        let signature = Ed25519::sign(&sk, &message);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(Ed25519::verify(
                    black_box(&pk),
                    black_box(&message),
                    black_box(&signature)
                ))
            });
        });
    }

    group.finish();
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_batch_verify");

    for batch_size in [2, 4, 8, 16, 32, 64].iter() {
        let mut public_keys = Vec::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..*batch_size {
            let mut sk = [0u8; 32];
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;

            let pk = Ed25519::public_key(&sk);
            let message = format!("Message number {}", i);
            let sig = Ed25519::sign(&sk, message.as_bytes());

            public_keys.push(pk);
            messages.push(message);
            signatures.push(sig);
        }

        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_bytes()).collect();

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(batch_size), batch_size, |b, _| {
            b.iter(|| {
                black_box(Ed25519::verify_batch(
                    black_box(&public_keys),
                    black_box(&message_refs),
                    black_box(&signatures)
                ))
            });
        });
    }

    group.finish();
}

fn bench_scalar_mul(c: &mut Criterion) {
    use hpcrypt_curves::ed25519::{base_point, scalar_mul_base_fast};

    let scalar = [0x42; 32];

    c.bench_function("ed25519_scalar_mul_regular", |b| {
        let base = base_point();
        b.iter(|| {
            black_box(base.scalar_mul(black_box(&scalar)))
        });
    });

    c.bench_function("ed25519_scalar_mul_precomputed", |b| {
        b.iter(|| {
            black_box(scalar_mul_base_fast(black_box(&scalar)))
        });
    });
}

fn bench_point_operations(c: &mut Criterion) {
    use hpcrypt_curves::ed25519::base_point;

    let g = base_point();
    let two_g = g.double();

    c.bench_function("ed25519_point_add", |b| {
        b.iter(|| {
            black_box(g.add(black_box(&two_g)))
        });
    });

    c.bench_function("ed25519_point_double", |b| {
        b.iter(|| {
            black_box(g.double())
        });
    });
}

fn bench_scalar_operations(c: &mut Criterion) {
    use hpcrypt_curves::ed25519::Scalar;

    let a_bytes = [0x12; 32];
    let b_bytes = [0x34; 32];

    let a = Scalar::from_bytes(a_bytes);
    let b = Scalar::from_bytes(b_bytes);

    c.bench_function("ed25519_scalar_mul", |b_bench| {
        b_bench.iter(|| {
            black_box(a.mul(black_box(&b)))
        });
    });

    c.bench_function("ed25519_scalar_add", |b_bench| {
        b_bench.iter(|| {
            black_box(a.add(black_box(&b)))
        });
    });
}

fn bench_encoding_decoding(c: &mut Criterion) {
    use hpcrypt_curves::ed25519::base_point;

    let point = base_point();
    let encoded = point.encode();

    c.bench_function("ed25519_point_encode", |b| {
        b.iter(|| {
            black_box(point.encode())
        });
    });

    c.bench_function("ed25519_point_decode", |b| {
        b.iter(|| {
            black_box(hpcrypt_curves::ed25519::EdwardsPoint::decode(black_box(&encoded)))
        });
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_verify_variable_message_size,
    bench_batch_verify,
    bench_scalar_mul,
    bench_point_operations,
    bench_scalar_operations,
    bench_encoding_decoding,
);

criterion_main!(benches);
