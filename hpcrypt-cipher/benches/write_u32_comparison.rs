use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

/// Safe implementation using copy_from_slice
#[inline(always)]
fn write_u32_le_safe(dst: &mut [u8], value: u32) {
    dst[..4].copy_from_slice(&value.to_le_bytes());
}

/// Unsafe implementation using pointer cast
#[inline(always)]
fn write_u32_le_unsafe(dst: &mut [u8], value: u32) {
    debug_assert!(dst.len() >= 4);
    unsafe {
        (dst.as_mut_ptr() as *mut u32).write_unaligned(value.to_le());
    }
}

fn write_u32_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_u32_le");

    // Benchmark writing a single u32 value repeatedly
    let iterations = 1000;
    group.throughput(Throughput::Elements(iterations as u64));

    let mut buffer = vec![0u8; iterations * 4];
    let values: Vec<u32> = (0..iterations).map(|i| i as u32).collect();

    group.bench_function("safe", |b| {
        b.iter(|| {
            for (i, &value) in values.iter().enumerate() {
                write_u32_le_safe(black_box(&mut buffer[i * 4..]), black_box(value));
            }
        });
    });

    group.bench_function("unsafe", |b| {
        b.iter(|| {
            for (i, &value) in values.iter().enumerate() {
                write_u32_le_unsafe(black_box(&mut buffer[i * 4..]), black_box(value));
            }
        });
    });

    group.finish();
}

/// Benchmark serializing a full ChaCha20 state (16 u32 words = 64 bytes)
fn serialize_state_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_chacha20_state");
    group.throughput(Throughput::Bytes(64));

    let state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];
    let mut buffer = [0u8; 64];

    group.bench_function("safe", |b| {
        b.iter(|| {
            let mut buf = buffer;
            write_u32_le_safe(black_box(&mut buf[0..]), state[0]);
            write_u32_le_safe(black_box(&mut buf[4..]), state[1]);
            write_u32_le_safe(black_box(&mut buf[8..]), state[2]);
            write_u32_le_safe(black_box(&mut buf[12..]), state[3]);
            write_u32_le_safe(black_box(&mut buf[16..]), state[4]);
            write_u32_le_safe(black_box(&mut buf[20..]), state[5]);
            write_u32_le_safe(black_box(&mut buf[24..]), state[6]);
            write_u32_le_safe(black_box(&mut buf[28..]), state[7]);
            write_u32_le_safe(black_box(&mut buf[32..]), state[8]);
            write_u32_le_safe(black_box(&mut buf[36..]), state[9]);
            write_u32_le_safe(black_box(&mut buf[40..]), state[10]);
            write_u32_le_safe(black_box(&mut buf[44..]), state[11]);
            write_u32_le_safe(black_box(&mut buf[48..]), state[12]);
            write_u32_le_safe(black_box(&mut buf[52..]), state[13]);
            write_u32_le_safe(black_box(&mut buf[56..]), state[14]);
            write_u32_le_safe(black_box(&mut buf[60..]), state[15]);
            black_box(buf)
        });
    });

    group.bench_function("unsafe", |b| {
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

    group.finish();
}

criterion_group!(benches, write_u32_benchmark, serialize_state_benchmark);
criterion_main!(benches);
