use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_hash::kmac_step_level_keccak::*;

fn init_state() -> [u64; 25] {
    let mut state = [0u64; 25];
    for i in 0..25 {
        state[i] = i as u64 * 0x0123456789ABCDEF;
    }
    state
}

fn bench_single_permutation(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f_step_level_single");

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut state = init_state();
            keccak_f_baseline(black_box(&mut state));
            black_box(state)
        })
    });

    group.bench_function("step_unrolled", |b| {
        b.iter(|| {
            let mut state = init_state();
            keccak_f_step_unrolled(black_box(&mut state));
            black_box(state)
        })
    });

    group.finish();
}

fn bench_multiple_permutations(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f_step_level_multiple");

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

        group.bench_with_input(BenchmarkId::new("step_unrolled", count), count, |b, &count| {
            b.iter(|| {
                let mut state = init_state();
                for _ in 0..count {
                    keccak_f_step_unrolled(black_box(&mut state));
                }
                black_box(state)
            })
        });
    }

    group.finish();
}

fn bench_zero_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f_step_level_zero_state");

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut state = [0u64; 25];
            keccak_f_baseline(black_box(&mut state));
            black_box(state)
        })
    });

    group.bench_function("step_unrolled", |b| {
        b.iter(|| {
            let mut state = [0u64; 25];
            keccak_f_step_unrolled(black_box(&mut state));
            black_box(state)
        })
    });

    group.finish();
}

fn bench_random_states(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_f_step_level_random");

    // Benchmark with different "random" states to test various data patterns
    let states = vec![
        [0x0123456789ABCDEFu64; 25],
        [0xFEDCBA9876543210u64; 25],
        [0x5555555555555555u64; 25],
        [0xAAAAAAAAAAAAAAAAu64; 25],
    ];

    for (idx, initial_state) in states.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("baseline", idx),
            initial_state,
            |b, &state| {
                b.iter(|| {
                    let mut s = state;
                    keccak_f_baseline(black_box(&mut s));
                    black_box(s)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("step_unrolled", idx),
            initial_state,
            |b, &state| {
                b.iter(|| {
                    let mut s = state;
                    keccak_f_step_unrolled(black_box(&mut s));
                    black_box(s)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_single_permutation,
    bench_multiple_permutations,
    bench_zero_state,
    bench_random_states
);
criterion_main!(benches);
