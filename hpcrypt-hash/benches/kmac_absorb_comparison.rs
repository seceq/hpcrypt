use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_hash::kmac_optimized_absorb::*;

fn init_state() -> [u64; 25] {
    let mut state = [0u64; 25];
    for i in 0..25 {
        state[i] = i as u64 * 0x0123456789ABCDEF;
    }
    state
}

fn init_block_168() -> [u8; 168] {
    let mut block = [0u8; 168];
    for i in 0..168 {
        block[i] = (i % 256) as u8;
    }
    block
}

fn init_block_136() -> [u8; 136] {
    let mut block = [0u8; 136];
    for i in 0..136 {
        block[i] = (i % 256) as u8;
    }
    block
}

fn bench_absorb_168(c: &mut Criterion) {
    let mut group = c.benchmark_group("absorb_block_168_single");

    let block = init_block_168();

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut state = init_state();
            absorb_block_baseline(black_box(&mut state), black_box(&block));
            black_box(state)
        })
    });

    group.bench_function("unrolled", |b| {
        b.iter(|| {
            let mut state = init_state();
            absorb_block_unrolled_168(black_box(&mut state), black_box(&block));
            black_box(state)
        })
    });

    group.finish();
}

fn bench_absorb_136(c: &mut Criterion) {
    let mut group = c.benchmark_group("absorb_block_136_single");

    let block = init_block_136();

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut state = init_state();
            absorb_block_baseline(black_box(&mut state), black_box(&block));
            black_box(state)
        })
    });

    group.bench_function("unrolled", |b| {
        b.iter(|| {
            let mut state = init_state();
            absorb_block_unrolled_136(black_box(&mut state), black_box(&block));
            black_box(state)
        })
    });

    group.finish();
}

fn bench_absorb_168_multi(c: &mut Criterion) {
    let mut group = c.benchmark_group("absorb_block_168_multi");

    let block = init_block_168();

    for count in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::new("baseline", count), count, |b, &count| {
            b.iter(|| {
                let mut state = init_state();
                for _ in 0..count {
                    absorb_block_baseline(black_box(&mut state), black_box(&block));
                }
                black_box(state)
            })
        });

        group.bench_with_input(BenchmarkId::new("unrolled", count), count, |b, &count| {
            b.iter(|| {
                let mut state = init_state();
                for _ in 0..count {
                    absorb_block_unrolled_168(black_box(&mut state), black_box(&block));
                }
                black_box(state)
            })
        });
    }

    group.finish();
}

fn bench_absorb_136_multi(c: &mut Criterion) {
    let mut group = c.benchmark_group("absorb_block_136_multi");

    let block = init_block_136();

    for count in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::new("baseline", count), count, |b, &count| {
            b.iter(|| {
                let mut state = init_state();
                for _ in 0..count {
                    absorb_block_baseline(black_box(&mut state), black_box(&block));
                }
                black_box(state)
            })
        });

        group.bench_with_input(BenchmarkId::new("unrolled", count), count, |b, &count| {
            b.iter(|| {
                let mut state = init_state();
                for _ in 0..count {
                    absorb_block_unrolled_136(black_box(&mut state), black_box(&block));
                }
                black_box(state)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_absorb_168,
    bench_absorb_136,
    bench_absorb_168_multi,
    bench_absorb_136_multi
);
criterion_main!(benches);
