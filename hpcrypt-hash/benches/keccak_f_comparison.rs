use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_hash::kmac_optimized_keccak::*;

fn init_state() -> [u64; 25] {
    let mut state = [0u64; 25];
    for i in 0..25 {
        state[i] = i as u64 * 0x0123456789ABCDEF;
    }
    state
}

fn bench_single_permutation(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f_single");

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut state = init_state();
            keccak_f_baseline(black_box(&mut state));
            black_box(state)
        })
    });

    group.bench_function("unrolled", |b| {
        b.iter(|| {
            let mut state = init_state();
            keccak_f_unrolled(black_box(&mut state));
            black_box(state)
        })
    });

    group.finish();
}

fn bench_multiple_permutations(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f_multiple");

    for count in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::new("baseline", count), count, |b, &count| {
            b.iter(|| {
                let mut state = init_state();
                for _ in 0..count {
                    keccak_f_baseline(black_box(&mut state));
                }
                black_box(state)
            })
        });

        group.bench_with_input(BenchmarkId::new("unrolled", count), count, |b, &count| {
            b.iter(|| {
                let mut state = init_state();
                for _ in 0..count {
                    keccak_f_unrolled(black_box(&mut state));
                }
                black_box(state)
            })
        });
    }

    group.finish();
}

fn bench_zero_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f_zero_state");

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut state = [0u64; 25];
            keccak_f_baseline(black_box(&mut state));
            black_box(state)
        })
    });

    group.bench_function("unrolled", |b| {
        b.iter(|| {
            let mut state = [0u64; 25];
            keccak_f_unrolled(black_box(&mut state));
            black_box(state)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_permutation,
    bench_multiple_permutations,
    bench_zero_state
);
criterion_main!(benches);
