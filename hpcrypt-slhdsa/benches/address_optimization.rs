//! Benchmark for Address.to_bytes() optimization
//!
//! This benchmark tests different approaches to optimizing the critical
//! Address.to_bytes() function which is called ~40,000 times per signature.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_slhdsa::address::Address;

/// Baseline implementation (current): Manual copy_from_slice for each word
#[inline(always)]
fn to_bytes_baseline(addr: &Address) -> [u8; 32] {
    let mut addr_copy = *addr;
    addr_copy.to_bytes()
}

/// Optimized v1: Use unsafe pointer operations (zero-cost on little-endian)
#[inline(always)]
fn to_bytes_unsafe_ptr(addr: &Address) -> [u8; 32] {
    let words = unsafe {
        core::slice::from_raw_parts(
            addr as *const Address as *const u32,
            8
        )
    };

    let mut bytes = [0u8; 32];
    for (i, &word) in words.iter().enumerate() {
        let word_bytes = word.to_be_bytes();
        unsafe {
            core::ptr::copy_nonoverlapping(
                word_bytes.as_ptr(),
                bytes.as_mut_ptr().add(i * 4),
                4
            );
        }
    }
    bytes
}

/// Optimized v2: Use transmute on big-endian, optimized copy on little-endian
#[inline(always)]
fn to_bytes_transmute(addr: &Address) -> [u8; 32] {
    let words = unsafe {
        core::slice::from_raw_parts(
            addr as *const Address as *const u32,
            8
        )
    };

    #[cfg(target_endian = "big")]
    {
        unsafe { core::mem::transmute::<[u32; 8], [u8; 32]>(*words) }
    }

    #[cfg(target_endian = "little")]
    {
        let mut bytes = [0u8; 32];

        // Unroll manually for better performance
        macro_rules! convert_word {
            ($idx:expr) => {
                {
                    let word_be = words[$idx].to_be();
                    let word_bytes = word_be.to_le_bytes();
                    bytes[$idx * 4] = word_bytes[0];
                    bytes[$idx * 4 + 1] = word_bytes[1];
                    bytes[$idx * 4 + 2] = word_bytes[2];
                    bytes[$idx * 4 + 3] = word_bytes[3];
                }
            };
        }

        convert_word!(0);
        convert_word!(1);
        convert_word!(2);
        convert_word!(3);
        convert_word!(4);
        convert_word!(5);
        convert_word!(6);
        convert_word!(7);

        bytes
    }
}

/// Optimized v3: Direct byte manipulation with loop unrolling macro
#[inline(always)]
fn to_bytes_macro_unrolled(addr: &Address) -> [u8; 32] {
    let words = unsafe {
        core::slice::from_raw_parts(
            addr as *const Address as *const u32,
            8
        )
    };

    let mut bytes = [0u8; 32];

    macro_rules! unroll_to_be {
        ($($idx:expr),*) => {
            $(
                {
                    let be_bytes = words[$idx].to_be_bytes();
                    bytes[$idx * 4] = be_bytes[0];
                    bytes[$idx * 4 + 1] = be_bytes[1];
                    bytes[$idx * 4 + 2] = be_bytes[2];
                    bytes[$idx * 4 + 3] = be_bytes[3];
                }
            )*
        };
    }

    unroll_to_be!(0, 1, 2, 3, 4, 5, 6, 7);

    bytes
}

/// Optimized v4: Using array operations and const evaluation
#[inline(always)]
fn to_bytes_array_ops(addr: &Address) -> [u8; 32] {
    let words = unsafe {
        core::slice::from_raw_parts(
            addr as *const Address as *const u32,
            8
        )
    };

    // Convert all words to big-endian
    let words_be = [
        words[0].to_be(),
        words[1].to_be(),
        words[2].to_be(),
        words[3].to_be(),
        words[4].to_be(),
        words[5].to_be(),
        words[6].to_be(),
        words[7].to_be(),
    ];

    // Safe transmute via union
    unsafe { core::mem::transmute::<[u32; 8], [u8; 32]>(words_be) }
}

fn bench_to_bytes_single_call(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_to_bytes_single");

    let mut addr = Address::new();
    addr.set_layer(3);
    addr.set_tree(0x123456789ABCDEF0);
    addr.set_type(1);
    addr.set_keypair(42);
    addr.set_chain(10);
    addr.set_hash(5);

    group.bench_function("baseline", |b| {
        b.iter(|| {
            black_box(to_bytes_baseline(black_box(&addr)))
        })
    });

    group.bench_function("unsafe_ptr", |b| {
        b.iter(|| {
            black_box(to_bytes_unsafe_ptr(black_box(&addr)))
        })
    });

    group.bench_function("transmute", |b| {
        b.iter(|| {
            black_box(to_bytes_transmute(black_box(&addr)))
        })
    });

    group.bench_function("macro_unrolled", |b| {
        b.iter(|| {
            black_box(to_bytes_macro_unrolled(black_box(&addr)))
        })
    });

    group.bench_function("array_ops", |b| {
        b.iter(|| {
            black_box(to_bytes_array_ops(black_box(&addr)))
        })
    });

    group.finish();
}

fn bench_to_bytes_hot_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_to_bytes_hot_loop");

    let mut addr = Address::new();
    addr.set_layer(3);
    addr.set_tree(0x123456789ABCDEF0);
    addr.set_type(1);

    // Simulate hot loop in WOTS signing (1000 iterations)
    for iterations in [100, 1000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("baseline", iterations),
            &iterations,
            |b, &iters| {
                b.iter(|| {
                    for i in 0..iters {
                        addr.set_hash(i as u32);
                        black_box(to_bytes_baseline(black_box(&addr)));
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("unsafe_ptr", iterations),
            &iterations,
            |b, &iters| {
                b.iter(|| {
                    for i in 0..iters {
                        addr.set_hash(i as u32);
                        black_box(to_bytes_unsafe_ptr(black_box(&addr)));
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("transmute", iterations),
            &iterations,
            |b, &iters| {
                b.iter(|| {
                    for i in 0..iters {
                        addr.set_hash(i as u32);
                        black_box(to_bytes_transmute(black_box(&addr)));
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("macro_unrolled", iterations),
            &iterations,
            |b, &iters| {
                b.iter(|| {
                    for i in 0..iters {
                        addr.set_hash(i as u32);
                        black_box(to_bytes_macro_unrolled(black_box(&addr)));
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("array_ops", iterations),
            &iterations,
            |b, &iters| {
                b.iter(|| {
                    for i in 0..iters {
                        addr.set_hash(i as u32);
                        black_box(to_bytes_array_ops(black_box(&addr)));
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_to_bytes_realistic_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_to_bytes_realistic");

    // Simulate realistic usage pattern: multiple field updates + serialization
    group.bench_function("baseline_realistic", |b| {
        b.iter(|| {
            let mut addr = Address::new();
            for layer in 0..7 {
                addr.set_layer(layer);
                for tree_idx in 0..10 {
                    addr.set_tree(tree_idx);
                    for i in 0..67 {  // WOTS_LEN for SHA2-128s
                        addr.set_chain(i);
                        for j in 0..15 {  // Chain length
                            addr.set_hash(j);
                            black_box(to_bytes_baseline(black_box(&addr)));
                        }
                    }
                }
            }
        })
    });

    group.bench_function("array_ops_realistic", |b| {
        b.iter(|| {
            let mut addr = Address::new();
            for layer in 0..7 {
                addr.set_layer(layer);
                for tree_idx in 0..10 {
                    addr.set_tree(tree_idx);
                    for i in 0..67 {
                        addr.set_chain(i);
                        for j in 0..15 {
                            addr.set_hash(j);
                            black_box(to_bytes_array_ops(black_box(&addr)));
                        }
                    }
                }
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_to_bytes_single_call,
    bench_to_bytes_hot_loop,
    bench_to_bytes_realistic_usage
);
criterion_main!(benches);
