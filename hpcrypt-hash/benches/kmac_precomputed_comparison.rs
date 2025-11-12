use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_hash::kmac::{Kmac128, Kmac256};
use hpcrypt_hash::kmac_precomputed::{PrecomputedKmac128, PrecomputedKmac256};

fn bench_kmac128_single_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_single_message");

    let key = b"my secret key for authentication";
    let message = b"hello world";
    let customization = b"";

    group.bench_function("regular", |b| {
        b.iter(|| {
            Kmac128::mac(
                black_box(key),
                black_box(message),
                black_box(customization),
                black_box(32),
            )
        })
    });

    group.bench_function("precomputed", |b| {
        let precomputed = PrecomputedKmac128::new(key, customization);
        b.iter(|| precomputed.mac(black_box(message), black_box(32)))
    });

    group.finish();
}

fn bench_kmac256_single_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256_single_message");

    let key = b"my secret key for authentication";
    let message = b"hello world";
    let customization = b"";

    group.bench_function("regular", |b| {
        b.iter(|| {
            Kmac256::mac(
                black_box(key),
                black_box(message),
                black_box(customization),
                black_box(64),
            )
        })
    });

    group.bench_function("precomputed", |b| {
        let precomputed = PrecomputedKmac256::new(key, customization);
        b.iter(|| precomputed.mac(black_box(message), black_box(64)))
    });

    group.finish();
}

fn bench_kmac128_multiple_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_multiple_messages");

    let key = b"shared key for all messages";
    let customization = b"app context";
    let messages = [
        b"message 1" as &[u8],
        b"message 2",
        b"message 3",
        b"message 4",
        b"message 5",
        b"message 6",
        b"message 7",
        b"message 8",
        b"message 9",
        b"message 10",
    ];

    for count in [1, 5, 10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::new("regular", count), count, |b, &count| {
            b.iter(|| {
                for i in 0..count {
                    let msg = messages[i % messages.len()];
                    black_box(Kmac128::mac(
                        black_box(key),
                        black_box(msg),
                        black_box(customization),
                        black_box(32),
                    ));
                }
            })
        });

        group.bench_with_input(
            BenchmarkId::new("precomputed", count),
            count,
            |b, &count| {
                let precomputed = PrecomputedKmac128::new(key, customization);
                b.iter(|| {
                    for i in 0..count {
                        let msg = messages[i % messages.len()];
                        black_box(precomputed.mac(black_box(msg), black_box(32)));
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_kmac256_multiple_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256_multiple_messages");

    let key = b"shared key for all messages";
    let customization = b"app context";
    let messages = [
        b"message 1" as &[u8],
        b"message 2",
        b"message 3",
        b"message 4",
        b"message 5",
        b"message 6",
        b"message 7",
        b"message 8",
        b"message 9",
        b"message 10",
    ];

    for count in [1, 5, 10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::new("regular", count), count, |b, &count| {
            b.iter(|| {
                for i in 0..count {
                    let msg = messages[i % messages.len()];
                    black_box(Kmac256::mac(
                        black_box(key),
                        black_box(msg),
                        black_box(customization),
                        black_box(64),
                    ));
                }
            })
        });

        group.bench_with_input(
            BenchmarkId::new("precomputed", count),
            count,
            |b, &count| {
                let precomputed = PrecomputedKmac256::new(key, customization);
                b.iter(|| {
                    for i in 0..count {
                        let msg = messages[i % messages.len()];
                        black_box(precomputed.mac(black_box(msg), black_box(64)));
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_kmac128_varying_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_varying_message_sizes");

    let key = b"authentication key";
    let customization = b"";

    for size in [16, 64, 256, 1024, 4096].iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(
            BenchmarkId::new("regular", size),
            size,
            |b, _size| {
                b.iter(|| {
                    Kmac128::mac(
                        black_box(key),
                        black_box(&message),
                        black_box(customization),
                        black_box(32),
                    )
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("precomputed", size),
            size,
            |b, _size| {
                let precomputed = PrecomputedKmac128::new(key, customization);
                b.iter(|| precomputed.mac(black_box(&message), black_box(32)))
            },
        );
    }

    group.finish();
}

fn bench_kmac256_varying_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256_varying_message_sizes");

    let key = b"authentication key";
    let customization = b"";

    for size in [16, 64, 256, 1024, 4096].iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(
            BenchmarkId::new("regular", size),
            size,
            |b, _size| {
                b.iter(|| {
                    Kmac256::mac(
                        black_box(key),
                        black_box(&message),
                        black_box(customization),
                        black_box(64),
                    )
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("precomputed", size),
            size,
            |b, _size| {
                let precomputed = PrecomputedKmac256::new(key, customization);
                b.iter(|| precomputed.mac(black_box(&message), black_box(64)))
            },
        );
    }

    group.finish();
}

fn bench_initialization_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("initialization_overhead");

    let key = b"test key";
    let customization = b"";

    group.bench_function("kmac128_init", |b| {
        b.iter(|| {
            black_box(Kmac128::new(black_box(key), black_box(customization)));
        })
    });

    group.bench_function("kmac256_init", |b| {
        b.iter(|| {
            black_box(Kmac256::new(black_box(key), black_box(customization)));
        })
    });

    group.bench_function("precomputed_kmac128_init", |b| {
        b.iter(|| {
            black_box(PrecomputedKmac128::new(black_box(key), black_box(customization)));
        })
    });

    group.bench_function("precomputed_kmac256_init", |b| {
        b.iter(|| {
            black_box(PrecomputedKmac256::new(black_box(key), black_box(customization)));
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kmac128_single_message,
    bench_kmac256_single_message,
    bench_kmac128_multiple_messages,
    bench_kmac256_multiple_messages,
    bench_kmac128_varying_message_sizes,
    bench_kmac256_varying_message_sizes,
    bench_initialization_overhead
);
criterion_main!(benches);
