//! Compiler auto-vectorization benchmarks for SLH-DSA components.
//!
//! Tests vectorization optimizations based on hpenc/COMPILER_VECTORIZATION_GUIDE.md:
//! 1. WOTS+ hash chain computations (batch processing)
//! 2. Merkle tree node hashing (parallel leaf generation)
//! 3. FORS tree computations (batch tree processing)
//!
//! Key principles applied:
//! - Fixed-size vector types (Vec8, Vec16, Vec32)
//! - Function boundaries as optimization hints (#[inline(always)])
//! - Pass by value (Copy trait) to eliminate aliasing
//! - Simple, predictable loops
//! - Sequential memory access patterns

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::address::Address;
use hpcrypt_slhdsa::hash::sha2::Sha2HashFunction;
use hpcrypt_slhdsa::hash::traits::HashFunction;
use hpcrypt_slhdsa::params::{ParameterSet, Sha2_128s};
use hpcrypt_slhdsa::vectorized;

// ============================================================================
// VECTORIZED TYPES (following hpenc guide)
// ============================================================================

/// Fixed-size 16-byte vector optimized for SIMD auto-vectorization.
/// Maps to SSE2 (2×128-bit) or AVX2 (1×256-bit) registers.
#[derive(Clone, Copy, Debug)]
#[repr(align(16))]
struct Vec16 {
    elements: [u8; 16],
}

impl Vec16 {
    #[inline(always)]
    fn zero() -> Self {
        Self { elements: [0u8; 16] }
    }

    #[inline(always)]
    fn from_slice(data: &[u8]) -> Self {
        let mut elements = [0u8; 16];
        elements.copy_from_slice(data);
        Self { elements }
    }

    #[inline(always)]
    fn as_slice(&self) -> &[u8] {
        &self.elements
    }
}

/// Fixed-size 32-byte vector for larger hash outputs.
#[derive(Clone, Copy, Debug)]
#[repr(align(32))]
struct Vec32 {
    elements: [u8; 32],
}

impl Vec32 {
    #[inline(always)]
    fn zero() -> Self {
        Self { elements: [0u8; 32] }
    }

    #[inline(always)]
    fn from_slice(data: &[u8]) -> Self {
        let mut elements = [0u8; 32];
        elements.copy_from_slice(data);
        Self { elements }
    }

    #[inline(always)]
    fn as_slice(&self) -> &[u8] {
        &self.elements
    }
}

// ============================================================================
// 1. WOTS+ HASH CHAIN VECTORIZATION
// ============================================================================

/// Baseline: Sequential WOTS+ chain computation (current implementation).
fn wots_chain_baseline<H: HashFunction>(
    input: &[u8],
    start: usize,
    steps: usize,
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    output[..input.len()].copy_from_slice(input);
    let mut temp = vec![0u8; H::N];

    for i in start..(start + steps) {
        addr.set_hash(i as u32);
        let addr_bytes = addr.to_bytes();
        hash.f(pk_seed, &addr_bytes, output, &mut temp);
        output[..H::N].copy_from_slice(&temp);
    }
}

/// Optimized: Batch 4 chains with fixed-size buffers (vectorization-friendly).
///
/// Key optimizations:
/// - Process 4 chains simultaneously
/// - Fixed-size [u8; 16] arrays enable stack allocation
/// - Function boundary helps compiler recognize vectorization opportunity
#[inline(always)]
fn wots_chain_batch4_vec16(
    inputs: &[[u8; 16]; 4],
    starts: &[usize; 4],
    steps: &[usize; 4],
    pk_seed: &[u8],
    addrs: &mut [Address; 4],
    hash: &Sha2HashFunction<16>,
    outputs: &mut [[u8; 16]; 4],
) {
    // Initialize outputs
    for i in 0..4 {
        outputs[i].copy_from_slice(&inputs[i]);
    }

    // Find max steps to process
    let max_steps = *steps.iter().max().unwrap();

    // Process all chains in lockstep (interleaved for cache locality)
    for step in 0..max_steps {
        // Manually unrolled for vectorization (4 chains)
        for idx in 0..4 {
            if step >= starts[idx] && step < starts[idx] + steps[idx] {
                addrs[idx].set_hash((starts[idx] + step) as u32);
                let addr_bytes = addrs[idx].to_bytes();
                let mut temp = [0u8; 16];
                hash.f(pk_seed, &addr_bytes, &outputs[idx], &mut temp);
                outputs[idx].copy_from_slice(&temp);
            }
        }
    }
}

/// Optimized: Batch 8 chains (for larger WOTS_LEN parameters).
#[inline(always)]
fn wots_chain_batch8_vec16(
    inputs: &[[u8; 16]; 8],
    starts: &[usize; 8],
    steps: &[usize; 8],
    pk_seed: &[u8],
    addrs: &mut [Address; 8],
    hash: &Sha2HashFunction<16>,
    outputs: &mut [[u8; 16]; 8],
) {
    // Initialize outputs
    for i in 0..8 {
        outputs[i].copy_from_slice(&inputs[i]);
    }

    let max_steps = *steps.iter().max().unwrap();

    for step in 0..max_steps {
        // Manually unrolled for vectorization (8 chains)
        for idx in 0..8 {
            if step >= starts[idx] && step < starts[idx] + steps[idx] {
                addrs[idx].set_hash((starts[idx] + step) as u32);
                let addr_bytes = addrs[idx].to_bytes();
                let mut temp = [0u8; 16];
                hash.f(pk_seed, &addr_bytes, &outputs[idx], &mut temp);
                outputs[idx].copy_from_slice(&temp);
            }
        }
    }
}

// ============================================================================
// 2. MERKLE TREE VECTORIZATION
// ============================================================================

/// Baseline: Sequential Merkle tree leaf generation.
fn merkle_leaves_baseline<H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    start_idx: usize,
    count: usize,
    addr: &mut Address,
    hash: &H,
    outputs: &mut [Vec<u8>],
) {
    for i in 0..count {
        let leaf_idx = start_idx + i;
        addr.set_tree_index(leaf_idx as u32);
        let addr_bytes = addr.to_bytes();

        let mut output = vec![0u8; H::N];
        hash.prf(sk_seed, &addr_bytes, &mut output);

        let mut leaf = vec![0u8; H::N];
        hash.t_leaf(pk_seed, &addr_bytes, &output, &mut leaf);

        outputs[i] = leaf;
    }
}

/// Optimized: Batch 8 leaf generation with fixed-size buffers.
///
/// Vectorization-friendly pattern:
/// - Process 8 leaves simultaneously
/// - Fixed-size arrays for intermediate results
/// - Unrolled operations for predictable memory access
#[inline(always)]
fn merkle_leaves_batch8_vec16(
    sk_seed: &[u8; 16],
    pk_seed: &[u8; 16],
    start_idx: usize,
    addrs: &mut [Address; 8],
    hash: &Sha2HashFunction<16>,
    outputs: &mut [[u8; 16]; 8],
) {
    // Temporary buffers for PRF outputs (stack-allocated)
    let mut prf_outputs = [[0u8; 16]; 8];

    // Step 1: Generate PRF values (can be vectorized)
    for idx in 0..8 {
        addrs[idx].set_tree_index((start_idx + idx) as u32);
        let addr_bytes = addrs[idx].to_bytes();
        hash.prf(sk_seed, &addr_bytes, &mut prf_outputs[idx]);
    }

    // Step 2: Apply T_leaf (can be vectorized)
    for idx in 0..8 {
        let addr_bytes = addrs[idx].to_bytes();
        hash.t_leaf(pk_seed, &addr_bytes, &prf_outputs[idx], &mut outputs[idx]);
    }
}

/// Optimized: Batch 16 leaf generation (maximum SIMD utilization).
#[inline(always)]
fn merkle_leaves_batch16_vec16(
    sk_seed: &[u8; 16],
    pk_seed: &[u8; 16],
    start_idx: usize,
    addrs: &mut [Address; 16],
    hash: &Sha2HashFunction<16>,
    outputs: &mut [[u8; 16]; 16],
) {
    let mut prf_outputs = [[0u8; 16]; 16];

    // Generate all PRF values
    for idx in 0..16 {
        addrs[idx].set_tree_index((start_idx + idx) as u32);
        let addr_bytes = addrs[idx].to_bytes();
        hash.prf(sk_seed, &addr_bytes, &mut prf_outputs[idx]);
    }

    // Apply T_leaf to all
    for idx in 0..16 {
        let addr_bytes = addrs[idx].to_bytes();
        hash.t_leaf(pk_seed, &addr_bytes, &prf_outputs[idx], &mut outputs[idx]);
    }
}

// ============================================================================
// 3. FORS TREE VECTORIZATION
// ============================================================================

/// Baseline: Sequential FORS tree root computation.
fn fors_trees_baseline<P: ParameterSet, H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    indices: &[usize],
    addr: &mut Address,
    hash: &H,
    roots: &mut Vec<Vec<u8>>,
) {
    for (tree_idx, &leaf_idx) in indices.iter().enumerate() {
        // Generate SK element
        addr.set_tree_index((tree_idx * (1 << P::A) + leaf_idx) as u32);
        let addr_bytes = addr.to_bytes();

        let mut sk_element = vec![0u8; P::N];
        hash.prf(sk_seed, &addr_bytes, &mut sk_element);

        // Apply T_leaf to get root (simplified - full implementation would compute tree)
        let mut root = vec![0u8; P::N];
        hash.t_leaf(pk_seed, &addr_bytes, &sk_element, &mut root);

        roots.push(root);
    }
}

/// Optimized: Batch 4 FORS trees with fixed-size buffers.
#[inline(always)]
fn fors_trees_batch4_vec16(
    sk_seed: &[u8; 16],
    pk_seed: &[u8; 16],
    tree_indices: &[usize; 4],
    leaf_indices: &[usize; 4],
    addrs: &mut [Address; 4],
    hash: &Sha2HashFunction<16>,
    roots: &mut [[u8; 16]; 4],
) {
    let mut sk_elements = [[0u8; 16]; 4];

    // Step 1: Generate SK elements
    for idx in 0..4 {
        let global_idx = (tree_indices[idx] * 64 + leaf_indices[idx]) as u32; // Assuming A=6
        addrs[idx].set_tree_index(global_idx);
        let addr_bytes = addrs[idx].to_bytes();
        hash.prf(sk_seed, &addr_bytes, &mut sk_elements[idx]);
    }

    // Step 2: Apply T_leaf to get roots
    for idx in 0..4 {
        let addr_bytes = addrs[idx].to_bytes();
        hash.t_leaf(pk_seed, &addr_bytes, &sk_elements[idx], &mut roots[idx]);
    }
}

// ============================================================================
// PHASE 1.1: WOTS PRF AND SAME-LENGTH CHAIN BATCHING BENCHMARKS
// ============================================================================

/// Sequential WOTS PRF generation (baseline).
fn wots_prf_sequential<const N: usize, H: HashFunction>(
    sk_seed: &[u8; N],
    base_addr: &Address,
    chain_indices: &[u32],
    hash: &H,
    outputs: &mut Vec<[u8; N]>,
) {
    use hpcrypt_slhdsa::address::ADDR_TYPE_WOTS_PRF;
    for &chain_idx in chain_indices {
        let mut addr = *base_addr;
        addr.set_type(ADDR_TYPE_WOTS_PRF);
        addr.set_chain(chain_idx);
        let addr_bytes = addr.to_bytes();
        let mut output = [0u8; N];
        hash.prf(sk_seed, &addr_bytes, &mut output);
        outputs.push(output);
    }
}

/// Sequential WOTS chain computation (same length - baseline).
fn wots_chains_sequential_same_length<const N: usize, H: HashFunction>(
    inputs: &[[u8; N]],
    steps: usize,
    pk_seed: &[u8; N],
    base_addr: &Address,
    hash: &H,
    outputs: &mut Vec<[u8; N]>,
) {
    for input in inputs {
        let mut output = *input;
        let mut addr = *base_addr;
        for step in 0..steps {
            addr.set_hash(step as u32);
            let addr_bytes = addr.to_bytes();
            let mut temp = [0u8; N];
            hash.f(pk_seed, &addr_bytes, &output, &mut temp);
            output = temp;
        }
        outputs.push(output);
    }
}

// ============================================================================
// BENCHMARKS
// ============================================================================

fn bench_wots_prf_batching(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_prf_vectorization");
    group.sample_size(100);

    let hash = Sha2HashFunction::<16>::new();
    let sk_seed = [0x42u8; 16];
    let base_addr = Address::new();

    // Baseline: 8 PRF calls sequentially
    group.bench_function("baseline_8prf", |b| {
        let chain_indices = [0u32, 1, 2, 3, 4, 5, 6, 7];
        let mut outputs = Vec::with_capacity(8);
        b.iter(|| {
            outputs.clear();
            wots_prf_sequential(
                black_box(&sk_seed),
                black_box(&base_addr),
                black_box(&chain_indices),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    // Vectorized: Batch 8 PRF calls
    group.bench_function("vectorized_batch8", |b| {
        let chain_indices = [0u32, 1, 2, 3, 4, 5, 6, 7];
        let mut outputs = [[0u8; 16]; 8];
        b.iter(|| {
            vectorized::wots_prf_batch8(
                black_box(&sk_seed),
                black_box(&base_addr),
                black_box(&chain_indices),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    // Vectorized: Batch 4 PRF calls
    group.bench_function("vectorized_batch4", |b| {
        let chain_indices = [0u32, 1, 2, 3];
        let mut outputs = [[0u8; 16]; 4];
        b.iter(|| {
            vectorized::wots_prf_batch4(
                black_box(&sk_seed),
                black_box(&base_addr),
                black_box(&chain_indices),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    group.finish();
}

fn bench_wots_chains_same_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_chains_same_length_vectorization");
    group.sample_size(100);

    let hash = Sha2HashFunction::<16>::new();
    let pk_seed = [0x42u8; 16];
    let base_addr = Address::new();
    let steps = 15; // W-1 = 15 for W=16 (typical WOTS+ parameter)

    // Baseline: 4 chains sequentially (same length)
    group.bench_function("baseline_4chains", |b| {
        let inputs = [[0x11u8; 16]; 4];
        let mut outputs = Vec::with_capacity(4);
        b.iter(|| {
            outputs.clear();
            wots_chains_sequential_same_length(
                black_box(&inputs),
                black_box(steps),
                black_box(&pk_seed),
                black_box(&base_addr),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    // Vectorized: Batch 4 chains (same length)
    group.bench_function("vectorized_batch4", |b| {
        let inputs = [[0x11u8; 16]; 4];
        let mut addrs = [base_addr; 4];
        let mut outputs = [[0u8; 16]; 4];
        b.iter(|| {
            vectorized::wots_chains_batch4_same_length(
                black_box(&inputs),
                black_box(steps),
                black_box(&pk_seed),
                black_box(&mut addrs),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    // Vectorized: Batch 8 chains (same length)
    group.bench_function("vectorized_batch8", |b| {
        let inputs = [[0x11u8; 16]; 8];
        let mut addrs = [base_addr; 8];
        let mut outputs = [[0u8; 16]; 8];
        b.iter(|| {
            vectorized::wots_chains_batch8_same_length(
                black_box(&inputs),
                black_box(steps),
                black_box(&pk_seed),
                black_box(&mut addrs),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    group.finish();
}

fn bench_wots_chains(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_vectorization");
    group.sample_size(100);

    let hash = Sha2HashFunction::<16>::new();
    let pk_seed = [0x42u8; 16];
    let input = [0x11u8; 16];
    let steps = 15; // Typical WOTS+ chain length

    // Baseline: Single chain
    group.bench_function("baseline_single", |b| {
        let mut addr = Address::new();
        let mut output = vec![0u8; 16];
        b.iter(|| {
            wots_chain_baseline(
                black_box(&input),
                black_box(0),
                black_box(steps),
                black_box(&pk_seed),
                black_box(&mut addr),
                black_box(&hash),
                black_box(&mut output),
            );
        });
    });

    // Vectorized: Batch 4 chains
    group.bench_function("vectorized_batch4", |b| {
        let inputs = [[0x11u8; 16]; 4];
        let starts = [0usize; 4];
        let steps_arr = [steps; 4];
        let mut addrs = [Address::new(); 4];
        let mut outputs = [[0u8; 16]; 4];

        b.iter(|| {
            wots_chain_batch4_vec16(
                black_box(&inputs),
                black_box(&starts),
                black_box(&steps_arr),
                black_box(&pk_seed),
                black_box(&mut addrs),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    // Vectorized: Batch 8 chains
    group.bench_function("vectorized_batch8", |b| {
        let inputs = [[0x11u8; 16]; 8];
        let starts = [0usize; 8];
        let steps_arr = [steps; 8];
        let mut addrs = [Address::new(); 8];
        let mut outputs = [[0u8; 16]; 8];

        b.iter(|| {
            wots_chain_batch8_vec16(
                black_box(&inputs),
                black_box(&starts),
                black_box(&steps_arr),
                black_box(&pk_seed),
                black_box(&mut addrs),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    group.finish();
}

fn bench_merkle_leaves(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_vectorization");
    group.sample_size(100);

    let hash = Sha2HashFunction::<16>::new();
    let sk_seed = [0x12u8; 16];
    let pk_seed = [0x34u8; 16];

    // Baseline: 8 leaves sequentially
    group.bench_function("baseline_8leaves", |b| {
        let mut addr = Address::new();
        let mut outputs = vec![vec![0u8; 16]; 8];
        b.iter(|| {
            merkle_leaves_baseline(
                black_box(&sk_seed),
                black_box(&pk_seed),
                black_box(0),
                black_box(8),
                black_box(&mut addr),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    // Vectorized: Batch 8 leaves
    group.bench_function("vectorized_batch8", |b| {
        let mut addrs = [Address::new(); 8];
        let mut outputs = [[0u8; 16]; 8];
        b.iter(|| {
            merkle_leaves_batch8_vec16(
                black_box(&sk_seed),
                black_box(&pk_seed),
                black_box(0),
                black_box(&mut addrs),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    // Vectorized: Batch 16 leaves
    group.bench_function("vectorized_batch16", |b| {
        let mut addrs = [Address::new(); 16];
        let mut outputs = [[0u8; 16]; 16];
        b.iter(|| {
            merkle_leaves_batch16_vec16(
                black_box(&sk_seed),
                black_box(&pk_seed),
                black_box(0),
                black_box(&mut addrs),
                black_box(&hash),
                black_box(&mut outputs),
            );
        });
    });

    group.finish();
}

fn bench_fors_trees(c: &mut Criterion) {
    let mut group = c.benchmark_group("fors_vectorization");
    group.sample_size(100);

    let hash = Sha2HashFunction::<16>::new();
    let sk_seed = [0x12u8; 16];
    let pk_seed = [0x34u8; 16];
    let indices = [5, 10, 15, 20]; // Leaf indices for 4 trees

    // Baseline: 4 trees sequentially
    group.bench_function("baseline_4trees", |b| {
        let mut addr = Address::new();
        let mut roots = Vec::new();
        b.iter(|| {
            roots.clear();
            fors_trees_baseline::<Sha2_128s, _>(
                black_box(&sk_seed),
                black_box(&pk_seed),
                black_box(&indices),
                black_box(&mut addr),
                black_box(&hash),
                black_box(&mut roots),
            );
        });
    });

    // Vectorized: Batch 4 trees
    group.bench_function("vectorized_batch4", |b| {
        let tree_indices = [0, 1, 2, 3];
        let leaf_indices = [5, 10, 15, 20];
        let mut addrs = [Address::new(); 4];
        let mut roots = [[0u8; 16]; 4];

        b.iter(|| {
            fors_trees_batch4_vec16(
                black_box(&sk_seed),
                black_box(&pk_seed),
                black_box(&tree_indices),
                black_box(&leaf_indices),
                black_box(&mut addrs),
                black_box(&hash),
                black_box(&mut roots),
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_wots_prf_batching,
    bench_wots_chains_same_length,
    bench_wots_chains,
    bench_merkle_leaves,
    bench_fors_trees
);
criterion_main!(benches);
