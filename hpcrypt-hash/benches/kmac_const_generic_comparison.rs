use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_hash::kmac::{Kmac128, Kmac256};
use hpcrypt_hash::kmac_const_generic::{Kmac128Generic, Kmac256Generic};

// ===== KMAC128 Benchmarks =====

fn bench_kmac128_oneshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_oneshot");

    let key = b"test key for benchmarking purposes";
    let customization = b"test customization";

    for msg_size in [16, 64, 256, 1024, 4096].iter() {
        let message = vec![0x42u8; *msg_size];

        group.bench_with_input(
            BenchmarkId::new("baseline", msg_size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mac = Kmac128::mac(
                        black_box(key),
                        black_box(msg),
                        black_box(customization),
                        black_box(32),
                    );
                    black_box(mac)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("const_generic", msg_size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mac = Kmac128Generic::mac(
                        black_box(key),
                        black_box(msg),
                        black_box(customization),
                        black_box(32),
                    );
                    black_box(mac)
                })
            },
        );
    }

    group.finish();
}

fn bench_kmac128_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_incremental");

    let key = b"test key";
    let customization = b"";
    let message = vec![0x42u8; 1024];

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), black_box(customization));
            for chunk in message.chunks(64) {
                kmac.update(black_box(chunk));
            }
            let mac = kmac.finalize(black_box(32));
            black_box(mac)
        })
    });

    group.bench_function("const_generic", |b| {
        b.iter(|| {
            let mut kmac = Kmac128Generic::new(black_box(key), black_box(customization));
            for chunk in message.chunks(64) {
                kmac.update(black_box(chunk));
            }
            let mac = kmac.finalize(black_box(32));
            black_box(mac)
        })
    });

    group.finish();
}

fn bench_kmac128_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_small_messages");

    let key = b"k";
    let customization = b"";

    for size in [1, 4, 8, 16, 32].iter() {
        let message = vec![0x55u8; *size];

        group.bench_with_input(
            BenchmarkId::new("baseline", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mac = Kmac128::mac(black_box(key), black_box(msg), black_box(customization), black_box(16));
                    black_box(mac)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("const_generic", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mac = Kmac128Generic::mac(black_box(key), black_box(msg), black_box(customization), black_box(16));
                    black_box(mac)
                })
            },
        );
    }

    group.finish();
}

// ===== KMAC256 Benchmarks =====

fn bench_kmac256_oneshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256_oneshot");

    let key = b"test key for benchmarking purposes";
    let customization = b"test customization";

    for msg_size in [16, 64, 256, 1024, 4096].iter() {
        let message = vec![0x42u8; *msg_size];

        group.bench_with_input(
            BenchmarkId::new("baseline", msg_size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mac = Kmac256::mac(
                        black_box(key),
                        black_box(msg),
                        black_box(customization),
                        black_box(64),
                    );
                    black_box(mac)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("const_generic", msg_size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mac = Kmac256Generic::mac(
                        black_box(key),
                        black_box(msg),
                        black_box(customization),
                        black_box(64),
                    );
                    black_box(mac)
                })
            },
        );
    }

    group.finish();
}

fn bench_kmac256_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256_incremental");

    let key = b"test key";
    let customization = b"";
    let message = vec![0x42u8; 1024];

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut kmac = Kmac256::new(black_box(key), black_box(customization));
            for chunk in message.chunks(64) {
                kmac.update(black_box(chunk));
            }
            let mac = kmac.finalize(black_box(64));
            black_box(mac)
        })
    });

    group.bench_function("const_generic", |b| {
        b.iter(|| {
            let mut kmac = Kmac256Generic::new(black_box(key), black_box(customization));
            for chunk in message.chunks(64) {
                kmac.update(black_box(chunk));
            }
            let mac = kmac.finalize(black_box(64));
            black_box(mac)
        })
    });

    group.finish();
}

// ===== Initialization Overhead =====

fn bench_initialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_initialization");

    let key = b"test key";
    let customization = b"test custom";

    group.bench_function("kmac128_baseline", |b| {
        b.iter(|| {
            let kmac = Kmac128::new(black_box(key), black_box(customization));
            black_box(kmac)
        })
    });

    group.bench_function("kmac128_const_generic", |b| {
        b.iter(|| {
            let kmac = Kmac128Generic::new(black_box(key), black_box(customization));
            black_box(kmac)
        })
    });

    group.bench_function("kmac256_baseline", |b| {
        b.iter(|| {
            let kmac = Kmac256::new(black_box(key), black_box(customization));
            black_box(kmac)
        })
    });

    group.bench_function("kmac256_const_generic", |b| {
        b.iter(|| {
            let kmac = Kmac256Generic::new(black_box(key), black_box(customization));
            black_box(kmac)
        })
    });

    group.finish();
}

// ===== Variable Output Length =====

fn bench_variable_output_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_variable_output");

    let key = b"key";
    let message = b"message";
    let customization = b"";

    for output_len in [16, 32, 64, 128, 256].iter() {
        group.bench_with_input(
            BenchmarkId::new("kmac128_baseline", output_len),
            output_len,
            |b, &len| {
                b.iter(|| {
                    let mac = Kmac128::mac(black_box(key), black_box(message), black_box(customization), black_box(len));
                    black_box(mac)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("kmac128_const_generic", output_len),
            output_len,
            |b, &len| {
                b.iter(|| {
                    let mac = Kmac128Generic::mac(black_box(key), black_box(message), black_box(customization), black_box(len));
                    black_box(mac)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_kmac128_oneshot,
    bench_kmac128_incremental,
    bench_kmac128_small_messages,
    bench_kmac256_oneshot,
    bench_kmac256_incremental,
    bench_initialization,
    bench_variable_output_length
);
criterion_main!(benches);
