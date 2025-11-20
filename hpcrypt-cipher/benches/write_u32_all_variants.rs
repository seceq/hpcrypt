use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

/// Variant 1: copy_from_slice (current safe implementation)
#[inline(always)]
fn write_u32_le_copy_from_slice(dst: &mut [u8], value: u32) {
    dst[..4].copy_from_slice(&value.to_le_bytes());
}

/// Variant 2: Manual array indexing
#[inline(always)]
fn write_u32_le_manual_index(dst: &mut [u8], value: u32) {
    let bytes = value.to_le_bytes();
    dst[0] = bytes[0];
    dst[1] = bytes[1];
    dst[2] = bytes[2];
    dst[3] = bytes[3];
}

/// Variant 3: Split array assignment
#[inline(always)]
fn write_u32_le_split_array(dst: &mut [u8], value: u32) {
    dst[..4].copy_from_slice(&value.to_le_bytes());
}

/// Variant 4: Direct byte manipulation (no intermediate array)
#[inline(always)]
fn write_u32_le_direct_bytes(dst: &mut [u8], value: u32) {
    dst[0] = (value & 0xff) as u8;
    dst[1] = ((value >> 8) & 0xff) as u8;
    dst[2] = ((value >> 16) & 0xff) as u8;
    dst[3] = ((value >> 24) & 0xff) as u8;
}

/// Variant 5: Using iterator and enumerate
#[inline(always)]
fn write_u32_le_iterator(dst: &mut [u8], value: u32) {
    for (i, &byte) in value.to_le_bytes().iter().enumerate() {
        dst[i] = byte;
    }
}

/// Unsafe version (baseline)
#[inline(always)]
fn write_u32_le_unsafe(dst: &mut [u8], value: u32) {
    unsafe {
        (dst.as_mut_ptr() as *mut u32).write_unaligned(value.to_le());
    }
}

fn serialize_chacha20_state_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_chacha20_state_variants");
    group.throughput(Throughput::Bytes(64));

    let state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];
    let buffer = [0u8; 64];

    group.bench_function("unsafe_baseline", |b| {
        b.iter(|| {
            let mut buf = buffer;
            write_u32_le_unsafe(black_box(&mut buf[0..]), state[0]);
            write_u32_le_unsafe(black_box(&mut buf[4..]), state[1]);
            write_u32_le_unsafe(black_box(&mut buf[8..]), state[2]);
            write_u32_le_unsafe(black_box(&mut buf[12..]), state[3]);
            write_u32_le_unsafe(black_box(&mut buf[16..]), state[4]);
            write_u32_le_unsafe(black_box(&mut buf[20..]), state[5]);
            write_u32_le_unsafe(black_box(&mut buf[24..]), state[6]);
            write_u32_le_unsafe(black_box(&mut buf[28..]), state[7]);
            write_u32_le_unsafe(black_box(&mut buf[32..]), state[8]);
            write_u32_le_unsafe(black_box(&mut buf[36..]), state[9]);
            write_u32_le_unsafe(black_box(&mut buf[40..]), state[10]);
            write_u32_le_unsafe(black_box(&mut buf[44..]), state[11]);
            write_u32_le_unsafe(black_box(&mut buf[48..]), state[12]);
            write_u32_le_unsafe(black_box(&mut buf[52..]), state[13]);
            write_u32_le_unsafe(black_box(&mut buf[56..]), state[14]);
            write_u32_le_unsafe(black_box(&mut buf[60..]), state[15]);
            black_box(buf)
        });
    });

    group.bench_function("copy_from_slice", |b| {
        b.iter(|| {
            let mut buf = buffer;
            write_u32_le_copy_from_slice(black_box(&mut buf[0..]), state[0]);
            write_u32_le_copy_from_slice(black_box(&mut buf[4..]), state[1]);
            write_u32_le_copy_from_slice(black_box(&mut buf[8..]), state[2]);
            write_u32_le_copy_from_slice(black_box(&mut buf[12..]), state[3]);
            write_u32_le_copy_from_slice(black_box(&mut buf[16..]), state[4]);
            write_u32_le_copy_from_slice(black_box(&mut buf[20..]), state[5]);
            write_u32_le_copy_from_slice(black_box(&mut buf[24..]), state[6]);
            write_u32_le_copy_from_slice(black_box(&mut buf[28..]), state[7]);
            write_u32_le_copy_from_slice(black_box(&mut buf[32..]), state[8]);
            write_u32_le_copy_from_slice(black_box(&mut buf[36..]), state[9]);
            write_u32_le_copy_from_slice(black_box(&mut buf[40..]), state[10]);
            write_u32_le_copy_from_slice(black_box(&mut buf[44..]), state[11]);
            write_u32_le_copy_from_slice(black_box(&mut buf[48..]), state[12]);
            write_u32_le_copy_from_slice(black_box(&mut buf[52..]), state[13]);
            write_u32_le_copy_from_slice(black_box(&mut buf[56..]), state[14]);
            write_u32_le_copy_from_slice(black_box(&mut buf[60..]), state[15]);
            black_box(buf)
        });
    });

    group.bench_function("manual_index", |b| {
        b.iter(|| {
            let mut buf = buffer;
            write_u32_le_manual_index(black_box(&mut buf[0..]), state[0]);
            write_u32_le_manual_index(black_box(&mut buf[4..]), state[1]);
            write_u32_le_manual_index(black_box(&mut buf[8..]), state[2]);
            write_u32_le_manual_index(black_box(&mut buf[12..]), state[3]);
            write_u32_le_manual_index(black_box(&mut buf[16..]), state[4]);
            write_u32_le_manual_index(black_box(&mut buf[20..]), state[5]);
            write_u32_le_manual_index(black_box(&mut buf[24..]), state[6]);
            write_u32_le_manual_index(black_box(&mut buf[28..]), state[7]);
            write_u32_le_manual_index(black_box(&mut buf[32..]), state[8]);
            write_u32_le_manual_index(black_box(&mut buf[36..]), state[9]);
            write_u32_le_manual_index(black_box(&mut buf[40..]), state[10]);
            write_u32_le_manual_index(black_box(&mut buf[44..]), state[11]);
            write_u32_le_manual_index(black_box(&mut buf[48..]), state[12]);
            write_u32_le_manual_index(black_box(&mut buf[52..]), state[13]);
            write_u32_le_manual_index(black_box(&mut buf[56..]), state[14]);
            write_u32_le_manual_index(black_box(&mut buf[60..]), state[15]);
            black_box(buf)
        });
    });

    group.bench_function("direct_bytes", |b| {
        b.iter(|| {
            let mut buf = buffer;
            write_u32_le_direct_bytes(black_box(&mut buf[0..]), state[0]);
            write_u32_le_direct_bytes(black_box(&mut buf[4..]), state[1]);
            write_u32_le_direct_bytes(black_box(&mut buf[8..]), state[2]);
            write_u32_le_direct_bytes(black_box(&mut buf[12..]), state[3]);
            write_u32_le_direct_bytes(black_box(&mut buf[16..]), state[4]);
            write_u32_le_direct_bytes(black_box(&mut buf[20..]), state[5]);
            write_u32_le_direct_bytes(black_box(&mut buf[24..]), state[6]);
            write_u32_le_direct_bytes(black_box(&mut buf[28..]), state[7]);
            write_u32_le_direct_bytes(black_box(&mut buf[32..]), state[8]);
            write_u32_le_direct_bytes(black_box(&mut buf[36..]), state[9]);
            write_u32_le_direct_bytes(black_box(&mut buf[40..]), state[10]);
            write_u32_le_direct_bytes(black_box(&mut buf[44..]), state[11]);
            write_u32_le_direct_bytes(black_box(&mut buf[48..]), state[12]);
            write_u32_le_direct_bytes(black_box(&mut buf[52..]), state[13]);
            write_u32_le_direct_bytes(black_box(&mut buf[56..]), state[14]);
            write_u32_le_direct_bytes(black_box(&mut buf[60..]), state[15]);
            black_box(buf)
        });
    });

    group.bench_function("iterator", |b| {
        b.iter(|| {
            let mut buf = buffer;
            write_u32_le_iterator(black_box(&mut buf[0..]), state[0]);
            write_u32_le_iterator(black_box(&mut buf[4..]), state[1]);
            write_u32_le_iterator(black_box(&mut buf[8..]), state[2]);
            write_u32_le_iterator(black_box(&mut buf[12..]), state[3]);
            write_u32_le_iterator(black_box(&mut buf[16..]), state[4]);
            write_u32_le_iterator(black_box(&mut buf[20..]), state[5]);
            write_u32_le_iterator(black_box(&mut buf[24..]), state[6]);
            write_u32_le_iterator(black_box(&mut buf[28..]), state[7]);
            write_u32_le_iterator(black_box(&mut buf[32..]), state[8]);
            write_u32_le_iterator(black_box(&mut buf[36..]), state[9]);
            write_u32_le_iterator(black_box(&mut buf[40..]), state[10]);
            write_u32_le_iterator(black_box(&mut buf[44..]), state[11]);
            write_u32_le_iterator(black_box(&mut buf[48..]), state[12]);
            write_u32_le_iterator(black_box(&mut buf[52..]), state[13]);
            write_u32_le_iterator(black_box(&mut buf[56..]), state[14]);
            write_u32_le_iterator(black_box(&mut buf[60..]), state[15]);
            black_box(buf)
        });
    });

    group.finish();
}

criterion_group!(benches, serialize_chacha20_state_benchmark);
criterion_main!(benches);
