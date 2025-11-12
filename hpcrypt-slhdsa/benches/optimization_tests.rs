//! Systematic benchmarks for testing individual optimization techniques.
//!
//! Each benchmark compares baseline vs optimized implementation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{Sha2_128s, KeyPair, sign, verify};
use rand::rngs::OsRng;

// ============================================================================
// BASELINE: Current implementation benchmarks
// ============================================================================

fn baseline_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline");
    let mut rng = OsRng;

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_128s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.finish();
}

fn baseline_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline");
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for baseline signing test";

    group.bench_function("sign", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(message));
            black_box(sig);
        });
    });

    group.finish();
}

fn baseline_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline");
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for baseline verify test";
    let signature = sign(&keypair.secret_key, message);

    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature)
            );
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// TEST 1: Stack Allocation vs Heap Allocation
// ============================================================================

fn test_allocation_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocation_test");

    // Simulate heap allocation (current approach)
    group.bench_function("heap_alloc_vec", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let buffer = vec![0u8; 32];
                black_box(&buffer);
            }
        });
    });

    // Simulate stack allocation (optimized approach)
    group.bench_function("stack_alloc_array", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let buffer = [0u8; 32];
                black_box(&buffer);
            }
        });
    });

    // Test with larger buffers
    group.bench_function("heap_alloc_vec_large", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let buffer = vec![0u8; 256];
                black_box(&buffer);
            }
        });
    });

    group.bench_function("stack_alloc_array_large", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let buffer = [0u8; 256];
                black_box(&buffer);
            }
        });
    });

    group.finish();
}

// ============================================================================
// TEST 2: Base-W Encoding with Lookup Tables
// ============================================================================

// Current implementation (from utils.rs)
fn base_w_checksum_current(high: usize, low: usize) -> usize {
    (15 - high) + (15 - low)
}

// Optimized with lookup table
const W16_CHECKSUM_TABLE: [usize; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

fn base_w_checksum_optimized(high: usize, low: usize) -> usize {
    W16_CHECKSUM_TABLE[high] + W16_CHECKSUM_TABLE[low]
}

fn test_base_w_lookup_tables(c: &mut Criterion) {
    let mut group = c.benchmark_group("base_w_encoding");

    // Test data: simulate encoding a message
    let msg = vec![0xABu8; 100];

    group.bench_function("checksum_current", |b| {
        b.iter(|| {
            let mut csum = 0usize;
            for &byte in msg.iter() {
                let high = (byte >> 4) as usize;
                let low = (byte & 0x0F) as usize;
                csum += base_w_checksum_current(high, low);
            }
            black_box(csum);
        });
    });

    group.bench_function("checksum_lookup_table", |b| {
        b.iter(|| {
            let mut csum = 0usize;
            for &byte in msg.iter() {
                let high = (byte >> 4) as usize;
                let low = (byte & 0x0F) as usize;
                csum += base_w_checksum_optimized(high, low);
            }
            black_box(csum);
        });
    });

    group.finish();
}

// ============================================================================
// TEST 3: Address Structure Operations
// ============================================================================

fn test_address_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_ops");

    use hpcrypt_slhdsa::address::Address;

    // Test address updates (current approach with mutable borrow)
    group.bench_function("address_update_borrow", |b| {
        b.iter(|| {
            let mut addr = Address::new();
            for i in 0..1000 {
                addr.set_chain(i);
                addr.set_hash(i * 2);
                let bytes = addr.to_bytes();
                black_box(bytes);
            }
        });
    });

    // Test address updates with copy
    group.bench_function("address_update_copy", |b| {
        b.iter(|| {
            let mut addr = Address::new();
            for i in 0..1000 {
                addr.set_chain(i);
                addr.set_hash(i * 2);
                let mut addr_copy = addr; // Copy is cheap (32 bytes)
                let bytes = addr_copy.to_bytes();
                black_box(bytes);
            }
        });
    });

    group.finish();
}

// ============================================================================
// TEST 4: Function Inlining Impact
// ============================================================================

// Non-inlined version
#[inline(never)]
fn extract_bits_no_inline(input: &[u8], bit_offset: usize, num_bits: usize) -> usize {
    let byte_offset = bit_offset / 8;
    let bit_in_byte = bit_offset % 8;
    let mut result = 0usize;
    let mut bits_remaining = num_bits;
    let mut current_byte = byte_offset;
    let mut shift = bit_in_byte;

    while bits_remaining > 0 && current_byte < input.len() {
        let bits_from_this_byte = (8 - shift).min(bits_remaining);
        let mask = (1u8 << bits_from_this_byte) - 1;
        let bits = (input[current_byte] >> shift) & mask;

        result |= (bits as usize) << (num_bits - bits_remaining);
        bits_remaining -= bits_from_this_byte;
        current_byte += 1;
        shift = 0;
    }

    result
}

// Inlined version
#[inline(always)]
fn extract_bits_inline(input: &[u8], bit_offset: usize, num_bits: usize) -> usize {
    let byte_offset = bit_offset / 8;
    let bit_in_byte = bit_offset % 8;
    let mut result = 0usize;
    let mut bits_remaining = num_bits;
    let mut current_byte = byte_offset;
    let mut shift = bit_in_byte;

    while bits_remaining > 0 && current_byte < input.len() {
        let bits_from_this_byte = (8 - shift).min(bits_remaining);
        let mask = (1u8 << bits_from_this_byte) - 1;
        let bits = (input[current_byte] >> shift) & mask;

        result |= (bits as usize) << (num_bits - bits_remaining);
        bits_remaining -= bits_from_this_byte;
        current_byte += 1;
        shift = 0;
    }

    result
}

fn test_inlining_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("inlining");

    let data = vec![0xABu8; 32];

    group.bench_function("extract_bits_no_inline", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0..100 {
                sum += extract_bits_no_inline(black_box(&data), i % 20, 6);
            }
            black_box(sum);
        });
    });

    group.bench_function("extract_bits_inline", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0..100 {
                sum += extract_bits_inline(black_box(&data), i % 20, 6);
            }
            black_box(sum);
        });
    });

    group.finish();
}

// ============================================================================
// TEST 5: Vec Capacity Pre-allocation
// ============================================================================

fn test_vec_preallocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_capacity");

    // Without pre-allocation (grows as needed)
    group.bench_function("vec_no_prealloc", |b| {
        b.iter(|| {
            let mut vec = Vec::new();
            for i in 0..1000 {
                vec.push(i as u8);
            }
            black_box(vec);
        });
    });

    // With exact pre-allocation
    group.bench_function("vec_exact_prealloc", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(1000);
            for i in 0..1000 {
                vec.push(i as u8);
            }
            black_box(vec);
        });
    });

    // Test with extend_from_slice (no prealloc)
    group.bench_function("vec_extend_no_prealloc", |b| {
        b.iter(|| {
            let mut vec = Vec::new();
            for _ in 0..10 {
                let chunk = [0u8; 100];
                vec.extend_from_slice(&chunk);
            }
            black_box(vec);
        });
    });

    // Test with extend_from_slice (with prealloc)
    group.bench_function("vec_extend_prealloc", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(1000);
            for _ in 0..10 {
                let chunk = [0u8; 100];
                vec.extend_from_slice(&chunk);
            }
            black_box(vec);
        });
    });

    group.finish();
}

// ============================================================================
// TEST 6: Const Generics Specialization
// ============================================================================

// Generic version (runtime dispatch)
fn process_buffer_generic(buffer: &[u8], n: usize) -> usize {
    match n {
        16 => buffer.iter().take(16).map(|&x| x as usize).sum(),
        24 => buffer.iter().take(24).map(|&x| x as usize).sum(),
        32 => buffer.iter().take(32).map(|&x| x as usize).sum(),
        _ => 0,
    }
}

// Const generic version (compile-time specialization)
fn process_buffer_const<const N: usize>(buffer: &[u8]) -> usize {
    buffer.iter().take(N).map(|&x| x as usize).sum()
}

fn test_const_generics(c: &mut Criterion) {
    let mut group = c.benchmark_group("const_generics");

    let buffer = vec![0xABu8; 64];

    group.bench_function("runtime_dispatch_n16", |b| {
        b.iter(|| {
            let result = process_buffer_generic(black_box(&buffer), 16);
            black_box(result);
        });
    });

    group.bench_function("const_generic_n16", |b| {
        b.iter(|| {
            let result = process_buffer_const::<16>(black_box(&buffer));
            black_box(result);
        });
    });

    group.bench_function("runtime_dispatch_n32", |b| {
        b.iter(|| {
            let result = process_buffer_generic(black_box(&buffer), 32);
            black_box(result);
        });
    });

    group.bench_function("const_generic_n32", |b| {
        b.iter(|| {
            let result = process_buffer_const::<32>(black_box(&buffer));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    baseline,
    baseline_keygen,
    baseline_sign,
    baseline_verify
);

criterion_group!(
    optimization_tests,
    test_allocation_patterns,
    test_base_w_lookup_tables,
    test_address_operations,
    test_inlining_impact,
    test_vec_preallocation,
    test_const_generics
);

criterion_main!(baseline, optimization_tests);
