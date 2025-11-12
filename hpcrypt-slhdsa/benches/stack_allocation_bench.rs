//! Benchmark for stack allocation optimization in sign/verify functions
//!
//! This benchmark measures the impact of replacing heap allocations with
//! stack-allocated arrays for temporary buffers in signing and verification.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_slhdsa::{Sha2_128s, Sha2_128f, Sha2_192s, Sha2_256s, KeyPair};
use rand::rngs::OsRng;

fn bench_sign_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_stack_allocation");

    // SHA2-128s (N=16, small buffers)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for stack allocation benchmark";

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-128f (N=16, larger FORS)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
        let message = b"Test message for stack allocation benchmark";

        group.bench_function("sha2_128f_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-192s (N=24)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for stack allocation benchmark";

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-256s (N=32, largest buffers)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_256s>::generate(&mut rng);
        let message = b"Test message for stack allocation benchmark";

        group.bench_function("sha2_256s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    group.finish();
}

fn bench_verify_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_stack_allocation");

    // SHA2-128s
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for stack allocation benchmark";
        let signature = hpcrypt_slhdsa::sign(&keypair.secret_key, message);

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let valid = hpcrypt_slhdsa::verify(&keypair.public_key, black_box(message), black_box(&signature));
                black_box(valid)
            })
        });
    }

    // SHA2-192s
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for stack allocation benchmark";
        let signature = hpcrypt_slhdsa::sign(&keypair.secret_key, message);

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let valid = hpcrypt_slhdsa::verify(&keypair.public_key, black_box(message), black_box(&signature));
                black_box(valid)
            })
        });
    }

    group.finish();
}

fn bench_allocation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocation_overhead");

    // Measure heap allocation cost for small buffers (N=16)
    group.bench_function("heap_alloc_16_bytes", |b| {
        b.iter(|| {
            let buf = vec![0u8; 16];
            black_box(buf)
        })
    });

    // Measure heap allocation cost for medium buffers (N=24)
    group.bench_function("heap_alloc_24_bytes", |b| {
        b.iter(|| {
            let buf = vec![0u8; 24];
            black_box(buf)
        })
    });

    // Measure heap allocation cost for large buffers (N=32)
    group.bench_function("heap_alloc_32_bytes", |b| {
        b.iter(|| {
            let buf = vec![0u8; 32];
            black_box(buf)
        })
    });

    // Measure heap allocation cost for FORS digest (SHA2-128s: 34+8=42 bytes)
    group.bench_function("heap_alloc_42_bytes_digest", |b| {
        b.iter(|| {
            let buf = vec![0u8; 42];
            black_box(buf)
        })
    });

    // Stack allocation (should be nearly free)
    group.bench_function("stack_alloc_32_bytes", |b| {
        b.iter(|| {
            let buf = [0u8; 32];
            black_box(buf)
        })
    });

    // Multiple allocations (simulating sign function: opt_rand + digest)
    group.bench_function("heap_alloc_multi_16_42", |b| {
        b.iter(|| {
            let buf1 = vec![0u8; 16];
            let buf2 = vec![0u8; 42];
            black_box((buf1, buf2))
        })
    });

    // Stack version
    group.bench_function("stack_alloc_multi_16_42", |b| {
        b.iter(|| {
            let buf1 = [0u8; 16];
            let buf2 = [0u8; 42];
            black_box((buf1, buf2))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sign_baseline,
    bench_verify_baseline,
    bench_allocation_overhead
);
criterion_main!(benches);
