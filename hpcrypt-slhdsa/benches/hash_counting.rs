//! Hash counting benchmark - measures exactly how many hash operations
//! are performed during signing to understand the performance profile.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{sign, KeyPair, Sha2_128f, Sha2_128s, Sha2_192s, Sha2_256s};
use hpcrypt_rng::OsRng;
use std::sync::atomic::{AtomicUsize, Ordering};

// Global counters for hash operations
static T_LEAF_COUNT: AtomicUsize = AtomicUsize::new(0);
static T_NODE_COUNT: AtomicUsize = AtomicUsize::new(0);
static F_COUNT: AtomicUsize = AtomicUsize::new(0);
static H_COUNT: AtomicUsize = AtomicUsize::new(0);
static PRF_COUNT: AtomicUsize = AtomicUsize::new(0);
static PRF_MSG_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn reset_counters() {
    T_LEAF_COUNT.store(0, Ordering::SeqCst);
    T_NODE_COUNT.store(0, Ordering::SeqCst);
    F_COUNT.store(0, Ordering::SeqCst);
    H_COUNT.store(0, Ordering::SeqCst);
    PRF_COUNT.store(0, Ordering::SeqCst);
    PRF_MSG_COUNT.store(0, Ordering::SeqCst);
}

pub fn print_hash_counts(label: &str) {
    let t_leaf = T_LEAF_COUNT.load(Ordering::SeqCst);
    let t_node = T_NODE_COUNT.load(Ordering::SeqCst);
    let f = F_COUNT.load(Ordering::SeqCst);
    let h = H_COUNT.load(Ordering::SeqCst);
    let prf = PRF_COUNT.load(Ordering::SeqCst);
    let prf_msg = PRF_MSG_COUNT.load(Ordering::SeqCst);

    let total = t_leaf + t_node + f + h + prf + prf_msg;

    println!("\n{}", label);
    println!("==========================================");
    println!("T_leaf (tree leaf hashing):     {:>8}", t_leaf);
    println!("T_node (tree node hashing):     {:>8}", t_node);
    println!("F (chain function):             {:>8}", f);
    println!("H (message hash):               {:>8}", h);
    println!("PRF (pseudorandom function):    {:>8}", prf);
    println!("PRF_msg (message PRF):          {:>8}", prf_msg);
    println!("------------------------------------------");
    println!("TOTAL hash operations:          {:>8}", total);
    println!("==========================================\n");
}

fn analyze_sha2_128s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for hash counting analysis";

    // Do one signature to count hashes
    reset_counters();
    let _sig = sign::<Sha2_128s>(&keypair.secret_key, message);
    print_hash_counts("SHA2-128s Hash Operation Count");

    // Benchmark
    c.bench_function("hash_count_sha2_128s", |b| {
        b.iter(|| {
            let sig = sign::<Sha2_128s>(&keypair.secret_key, black_box(message));
            black_box(sig);
        });
    });
}

fn analyze_sha2_128f(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
    let message = b"Benchmark message for hash counting analysis";

    reset_counters();
    let _sig = sign::<Sha2_128f>(&keypair.secret_key, message);
    print_hash_counts("SHA2-128f Hash Operation Count");

    c.bench_function("hash_count_sha2_128f", |b| {
        b.iter(|| {
            let sig = sign::<Sha2_128f>(&keypair.secret_key, black_box(message));
            black_box(sig);
        });
    });
}

fn analyze_sha2_192s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
    let message = b"Benchmark message for hash counting analysis";

    reset_counters();
    let _sig = sign::<Sha2_192s>(&keypair.secret_key, message);
    print_hash_counts("SHA2-192s Hash Operation Count");
}

fn analyze_sha2_256s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_256s>::generate(&mut rng);
    let message = b"Benchmark message for hash counting analysis";

    reset_counters();
    let _sig = sign::<Sha2_256s>(&keypair.secret_key, message);
    print_hash_counts("SHA2-256s Hash Operation Count");
}

criterion_group!(
    benches,
    analyze_sha2_128s,
    analyze_sha2_128f,
    analyze_sha2_192s,
    analyze_sha2_256s,
);
criterion_main!(benches);
