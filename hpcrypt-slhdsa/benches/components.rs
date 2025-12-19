//! Component benchmarks for SLH-DSA internal operations.
//!
//! Measures the performance of individual components: WOTS+, FORS, Merkle trees.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_slhdsa::Sha2_128s;
use hpcrypt_rng::OsRng;
use rand::RngCore;

// We need to access internal modules for component benchmarking
// This is a test/benchmark scenario, so we'll work with what's exposed

fn bench_wots_operations(c: &mut Criterion) {
    // Note: Since WOTS+ operations are internal, we benchmark them indirectly
    // through key generation which heavily uses WOTS+
    let mut group = c.benchmark_group("wots_pk_generation");
    let mut rng = OsRng;

    // Generate test keys to measure WOTS+ PK generation overhead
    let mut sk_seed = vec![0u8; 16];
    let mut pk_seed = vec![0u8; 16];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut pk_seed);

    group.bench_function("single_wots_pk_gen_overhead", |b| {
        b.iter(|| {
            // This indirectly measures WOTS+ performance through keygen
            use hpcrypt_slhdsa::KeyPair;
            let keypair = KeyPair::<Sha2_128s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.finish();
}

fn bench_hash_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_operations");
    let mut rng = OsRng;

    // Benchmark hash throughput by measuring signing operations
    // which are hash-intensive
    use hpcrypt_slhdsa::{sign, KeyPair};
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    for msg_size in [32, 64, 128, 256, 512, 1024].iter() {
        let message = vec![0u8; *msg_size];
        group.bench_with_input(
            BenchmarkId::new("hash_throughput_via_sign", msg_size),
            msg_size,
            |b, _| {
                b.iter(|| {
                    let sig = sign(black_box(&keypair.secret_key), black_box(&message));
                    black_box(sig);
                });
            },
        );
    }

    group.finish();
}

fn bench_fors_operations(c: &mut Criterion) {
    // FORS performance is measured indirectly through signing
    let mut group = c.benchmark_group("fors_signing");
    let mut rng = OsRng;

    use hpcrypt_slhdsa::{sign, KeyPair};

    // Different parameter sets have different FORS parameters (k, a)
    // SHA2-128s: k=14, a=12
    // SHA2-128f: k=33, a=6

    let keypair_128s = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"FORS benchmark message";

    group.bench_function("fors_in_sha2_128s", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_128s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    use hpcrypt_slhdsa::Sha2_128f;
    let keypair_128f = KeyPair::<Sha2_128f>::generate(&mut rng);

    group.bench_function("fors_in_sha2_128f", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_128f.secret_key), black_box(message));
            black_box(sig);
        });
    });

    group.finish();
}

fn bench_merkle_tree_heights(c: &mut Criterion) {
    // Merkle tree performance varies with height
    // We can measure this through different parameter sets
    let mut group = c.benchmark_group("merkle_via_parameters");
    let mut rng = OsRng;

    use hpcrypt_slhdsa::{sign, KeyPair, Sha2_128f, Sha2_192s, Sha2_256s};

    // Different tree heights:
    // 128s: h'=63, d=7 (height per layer = 9)
    // 128f: h'=66, d=22 (height per layer = 3)

    let message = b"Merkle tree benchmark";

    let keypair_128s = KeyPair::<Sha2_128s>::generate(&mut rng);
    group.bench_function("sha2_128s_h9_layers", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_128s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_128f = KeyPair::<Sha2_128f>::generate(&mut rng);
    group.bench_function("sha2_128f_h3_layers", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_128f.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_192s = KeyPair::<Sha2_192s>::generate(&mut rng);
    group.bench_function("sha2_192s_h8_layers", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_192s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_256s = KeyPair::<Sha2_256s>::generate(&mut rng);
    group.bench_function("sha2_256s_h8_layers", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_256s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    group.finish();
}

fn bench_address_operations(c: &mut Criterion) {
    // Address updates are frequent operations
    // Measure through repeated key generation which does many address updates
    let mut group = c.benchmark_group("address_updates_via_keygen");
    let mut rng = OsRng;

    use hpcrypt_slhdsa::KeyPair;

    group.bench_function("keygen_address_overhead", |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_128s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.finish();
}

fn bench_base_w_encoding(c: &mut Criterion) {
    // Base-w encoding is used in WOTS+
    // Measure through signing which uses WOTS+ encoding
    let mut group = c.benchmark_group("base_w_via_signing");
    let mut rng = OsRng;

    use hpcrypt_slhdsa::{sign, KeyPair, Sha2_128s, Sha2_256s};

    // w=16 parameter sets
    let keypair_128s = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Base-w encoding benchmark";

    group.bench_function("w16_encoding_sha2_128s", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_128s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    // w=256 parameter sets (if we had them, but 128f also uses w=16)
    let keypair_256s = KeyPair::<Sha2_256s>::generate(&mut rng);

    group.bench_function("w16_encoding_sha2_256s", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_256s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    group.finish();
}

fn bench_memory_allocation_patterns(c: &mut Criterion) {
    // Measure allocation overhead through operations
    let mut group = c.benchmark_group("allocation_patterns");
    let mut rng = OsRng;

    use hpcrypt_slhdsa::{sign, KeyPair};

    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Small message (minimal allocation)
    let small_msg = b"small";
    group.bench_function("small_message_allocations", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(small_msg));
            black_box(sig);
        });
    });

    // Large message (more allocation in hashing)
    let large_msg = vec![0u8; 4096];
    group.bench_function("large_message_allocations", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(&large_msg));
            black_box(sig);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_wots_operations,
    bench_hash_functions,
    bench_fors_operations,
    bench_merkle_tree_heights,
    bench_address_operations,
    bench_base_w_encoding,
    bench_memory_allocation_patterns
);
criterion_main!(benches);
