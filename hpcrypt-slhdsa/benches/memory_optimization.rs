//! Memory optimization benchmarks.
//!
//! Tests:
//! 1. Memory alignment (cache line boundaries)
//! 2. Stack vs heap allocation
//! 3. Struct-of-Arrays vs Array-of-Structs

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sha2::{Sha256, Digest};

// ============================================================================
// Test 1: Memory Alignment
// ============================================================================

/// Unaligned structure (default)
struct UnalignedHashState {
    input: [u8; 32],
    output: [u8; 32],
    counter: u64,
}

/// Cache-line aligned structure (64 bytes)
#[repr(align(64))]
struct AlignedHashState {
    input: [u8; 32],
    output: [u8; 32],
    counter: u64,
}

fn bench_alignment(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_alignment");

    // Unaligned access pattern
    group.bench_function("unaligned", |b| {
        let mut states: Vec<UnalignedHashState> = (0..64)
            .map(|i| UnalignedHashState {
                input: [i as u8; 32],
                output: [0u8; 32],
                counter: i,
            })
            .collect();

        b.iter(|| {
            for state in states.iter_mut() {
                let mut hasher = Sha256::new();
                hasher.update(black_box(&state.input));
                state.output.copy_from_slice(&hasher.finalize());
                state.counter += 1;
            }
            black_box(&mut states);
        });
    });

    // Aligned access pattern
    group.bench_function("aligned", |b| {
        let mut states: Vec<AlignedHashState> = (0..64)
            .map(|i| AlignedHashState {
                input: [i as u8; 32],
                output: [0u8; 32],
                counter: i,
            })
            .collect();

        b.iter(|| {
            for state in states.iter_mut() {
                let mut hasher = Sha256::new();
                hasher.update(black_box(&state.input));
                state.output.copy_from_slice(&hasher.finalize());
                state.counter += 1;
            }
            black_box(&mut states);
        });
    });

    group.finish();
}

// ============================================================================
// Test 2: Stack vs Heap Allocation
// ============================================================================

fn hash_with_heap_buffer(input: &[u8]) -> [u8; 32] {
    let mut buffer = vec![0u8; 32]; // Heap allocation
    let mut hasher = Sha256::new();
    hasher.update(input);
    buffer.copy_from_slice(&hasher.finalize());
    buffer.try_into().unwrap()
}

fn hash_with_stack_buffer(input: &[u8]) -> [u8; 32] {
    let mut buffer = [0u8; 32]; // Stack allocation
    let mut hasher = Sha256::new();
    hasher.update(input);
    buffer.copy_from_slice(&hasher.finalize());
    buffer
}

fn bench_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocation_strategy");

    let input = [0x42u8; 32];

    // Heap allocation
    group.bench_function("heap", |b| {
        b.iter(|| {
            let result = hash_with_heap_buffer(black_box(&input));
            black_box(result);
        });
    });

    // Stack allocation
    group.bench_function("stack", |b| {
        b.iter(|| {
            let result = hash_with_stack_buffer(black_box(&input));
            black_box(result);
        });
    });

    // Multiple operations (more realistic)
    group.bench_function("heap_multiple", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let result = hash_with_heap_buffer(black_box(&input));
                black_box(result);
            }
        });
    });

    group.bench_function("stack_multiple", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let result = hash_with_stack_buffer(black_box(&input));
                black_box(result);
            }
        });
    });

    group.finish();
}

// ============================================================================
// Test 3: Struct-of-Arrays vs Array-of-Structs
// ============================================================================

/// Array-of-Structs (AoS) - current approach
struct HashOperation {
    input: [u8; 32],
    output: [u8; 32],
    index: u32,
}

/// Struct-of-Arrays (SoA) - optimized for cache
struct HashOperations {
    inputs: Vec<[u8; 32]>,
    outputs: Vec<[u8; 32]>,
    indices: Vec<u32>,
}

fn process_aos(ops: &mut [HashOperation]) {
    for op in ops.iter_mut() {
        let mut hasher = Sha256::new();
        hasher.update(&op.input);
        hasher.update(&op.index.to_be_bytes());
        op.output.copy_from_slice(&hasher.finalize());
    }
}

fn process_soa(ops: &mut HashOperations) {
    for i in 0..ops.inputs.len() {
        let mut hasher = Sha256::new();
        hasher.update(&ops.inputs[i]);
        hasher.update(&ops.indices[i].to_be_bytes());
        ops.outputs[i].copy_from_slice(&hasher.finalize());
    }
}

fn bench_data_layout(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_layout");

    for &count in &[16, 64, 256] {
        // Array-of-Structs
        let mut aos: Vec<HashOperation> = (0..count)
            .map(|i| HashOperation {
                input: [i as u8; 32],
                output: [0u8; 32],
                index: i as u32,
            })
            .collect();

        group.bench_with_input(BenchmarkId::new("AoS", count), &count, |b, _| {
            b.iter(|| {
                process_aos(black_box(&mut aos));
            });
        });

        // Struct-of-Arrays
        let mut soa = HashOperations {
            inputs: (0..count).map(|i| [i as u8; 32]).collect(),
            outputs: vec![[0u8; 32]; count as usize],
            indices: (0..count).map(|i| i as u32).collect(),
        };

        group.bench_with_input(BenchmarkId::new("SoA", count), &count, |b, _| {
            b.iter(|| {
                process_soa(black_box(&mut soa));
            });
        });
    }

    group.finish();
}

// ============================================================================
// Test 4: WOTS Chain with Different Memory Strategies
// ============================================================================

/// Stack-based WOTS chain (fixed size)
fn wots_chain_stack(seed: &[u8; 32], chain_len: usize) -> [u8; 32] {
    let mut current = *seed;

    for step in 0..chain_len {
        let mut hasher = Sha256::new();
        hasher.update(&current);
        hasher.update(&(step as u32).to_be_bytes());
        current = hasher.finalize().into();
    }

    current
}

/// Heap-based WOTS chain (Vec)
fn wots_chain_heap(seed: &[u8; 32], chain_len: usize) -> Vec<u8> {
    let mut current = seed.to_vec();

    for step in 0..chain_len {
        let mut hasher = Sha256::new();
        hasher.update(&current);
        hasher.update(&(step as u32).to_be_bytes());
        current = hasher.finalize().to_vec();
    }

    current
}

fn bench_wots_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_memory_strategy");

    let seed = [0x42u8; 32];

    for &chain_len in &[10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("stack", chain_len),
            &chain_len,
            |b, &len| {
                b.iter(|| {
                    let result = wots_chain_stack(black_box(&seed), black_box(len));
                    black_box(result);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("heap", chain_len),
            &chain_len,
            |b, &len| {
                b.iter(|| {
                    let result = wots_chain_heap(black_box(&seed), black_box(len));
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Test 5: Inline vs Non-Inline Functions
// ============================================================================

fn hash_no_inline(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[inline(always)]
fn hash_always_inline(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[inline]
fn hash_inline(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn bench_inlining(c: &mut Criterion) {
    let mut group = c.benchmark_group("inlining");

    let input = [0x42u8; 32];

    group.bench_function("no_inline", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let result = hash_no_inline(black_box(&input));
                black_box(result);
            }
        });
    });

    group.bench_function("inline", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let result = hash_inline(black_box(&input));
                black_box(result);
            }
        });
    });

    group.bench_function("always_inline", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let result = hash_always_inline(black_box(&input));
                black_box(result);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_alignment,
    bench_allocation,
    bench_data_layout,
    bench_wots_memory,
    bench_inlining,
);
criterion_main!(benches);
