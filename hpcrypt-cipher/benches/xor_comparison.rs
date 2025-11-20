use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

/// Current unsafe implementation - word-wise XOR using raw pointers
#[inline]
fn xor_unsafe_word_wise(data: &mut [u8], keystream: &[u8]) {
    debug_assert_eq!(data.len(), keystream.len());

    let len = data.len();
    let mut offset = 0;

    // Process 64-bit words first (8 bytes at a time)
    if len >= 8 {
        let u64_processable = (len / 8) * 8;
        let data_ptr = data.as_mut_ptr() as *mut u64;
        let key_ptr = keystream.as_ptr() as *const u64;
        let num_words = u64_processable / 8;

        unsafe {
            for i in 0..num_words {
                let data_word = data_ptr.add(i).read_unaligned();
                let key_word = key_ptr.add(i).read_unaligned();
                data_ptr.add(i).write_unaligned(data_word ^ key_word);
            }
        }
        offset = u64_processable;
    }

    // Process remaining 32-bit words (4 bytes at a time)
    if len - offset >= 4 {
        let remaining = len - offset;
        let u32_processable = (remaining / 4) * 4;
        let data_ptr = data[offset..].as_mut_ptr() as *mut u32;
        let key_ptr = keystream[offset..].as_ptr() as *const u32;
        let num_words = u32_processable / 4;

        unsafe {
            for i in 0..num_words {
                let data_word = data_ptr.add(i).read_unaligned();
                let key_word = key_ptr.add(i).read_unaligned();
                data_ptr.add(i).write_unaligned(data_word ^ key_word);
            }
        }
        offset += u32_processable;
    }

    // Process any remaining bytes
    for i in offset..len {
        data[i] ^= keystream[i];
    }
}

/// Safe alternative 1: Using chunks_exact_mut with u64
#[inline]
fn xor_safe_chunks_u64(data: &mut [u8], keystream: &[u8]) {
    debug_assert_eq!(data.len(), keystream.len());

    let len = data.len();

    // Process 8-byte chunks
    let (data_chunks, data_remainder) = data.split_at_mut(len - (len % 8));
    let (key_chunks, key_remainder) = keystream.split_at(len - (len % 8));

    for (data_chunk, key_chunk) in data_chunks.chunks_exact_mut(8).zip(key_chunks.chunks_exact(8)) {
        let data_word = u64::from_le_bytes(data_chunk.try_into().unwrap());
        let key_word = u64::from_le_bytes(key_chunk.try_into().unwrap());
        data_chunk.copy_from_slice(&(data_word ^ key_word).to_le_bytes());
    }

    // Process remainder byte-by-byte
    for (d, k) in data_remainder.iter_mut().zip(key_remainder.iter()) {
        *d ^= k;
    }
}

/// Safe alternative 2: Using array_chunks (nightly feature) simulation
#[inline]
fn xor_safe_chunks_nested(data: &mut [u8], keystream: &[u8]) {
    debug_assert_eq!(data.len(), keystream.len());

    let mut i = 0;
    let len = data.len();

    // Process 8 bytes at a time
    while i + 8 <= len {
        let data_bytes: [u8; 8] = data[i..i+8].try_into().unwrap();
        let key_bytes: [u8; 8] = keystream[i..i+8].try_into().unwrap();

        let data_word = u64::from_le_bytes(data_bytes);
        let key_word = u64::from_le_bytes(key_bytes);

        data[i..i+8].copy_from_slice(&(data_word ^ key_word).to_le_bytes());
        i += 8;
    }

    // Process 4 bytes at a time
    while i + 4 <= len {
        let data_bytes: [u8; 4] = data[i..i+4].try_into().unwrap();
        let key_bytes: [u8; 4] = keystream[i..i+4].try_into().unwrap();

        let data_word = u32::from_le_bytes(data_bytes);
        let key_word = u32::from_le_bytes(key_bytes);

        data[i..i+4].copy_from_slice(&(data_word ^ key_word).to_le_bytes());
        i += 4;
    }

    // Process remaining bytes
    while i < len {
        data[i] ^= keystream[i];
        i += 1;
    }
}

/// Safe alternative 3: Direct byte iteration (baseline)
#[inline]
fn xor_safe_bytewise(data: &mut [u8], keystream: &[u8]) {
    for (d, k) in data.iter_mut().zip(keystream.iter()) {
        *d ^= k;
    }
}

/// Safe alternative 4: Using split_at_mut for word processing
#[inline]
fn xor_safe_split_at(data: &mut [u8], keystream: &[u8]) {
    debug_assert_eq!(data.len(), keystream.len());

    let len = data.len();
    let mut offset = 0;

    // Process u64 chunks
    while offset + 8 <= len {
        let data_slice = &mut data[offset..offset+8];
        let key_slice = &keystream[offset..offset+8];

        let data_word = u64::from_le_bytes(data_slice.try_into().unwrap());
        let key_word = u64::from_le_bytes(key_slice.try_into().unwrap());
        data_slice.copy_from_slice(&(data_word ^ key_word).to_le_bytes());

        offset += 8;
    }

    // Process u32 chunks
    while offset + 4 <= len {
        let data_slice = &mut data[offset..offset+4];
        let key_slice = &keystream[offset..offset+4];

        let data_word = u32::from_le_bytes(data_slice.try_into().unwrap());
        let key_word = u32::from_le_bytes(key_slice.try_into().unwrap());
        data_slice.copy_from_slice(&(data_word ^ key_word).to_le_bytes());

        offset += 4;
    }

    // Process remaining bytes
    for i in offset..len {
        data[i] ^= keystream[i];
    }
}

fn xor_benchmark(c: &mut Criterion) {
    // Test different buffer sizes
    let sizes = [64, 256, 1024, 4096];

    for &size in &sizes {
        let mut group = c.benchmark_group(format!("xor_{}_bytes", size));
        group.throughput(Throughput::Bytes(size as u64));

        let keystream = vec![0x42u8; size];
        let original_data = vec![0xAAu8; size];

        group.bench_function("unsafe_word_wise", |b| {
            b.iter(|| {
                let mut data = original_data.clone();
                xor_unsafe_word_wise(black_box(&mut data), black_box(&keystream));
                data
            });
        });

        group.bench_function("safe_chunks_u64", |b| {
            b.iter(|| {
                let mut data = original_data.clone();
                xor_safe_chunks_u64(black_box(&mut data), black_box(&keystream));
                data
            });
        });

        group.bench_function("safe_chunks_nested", |b| {
            b.iter(|| {
                let mut data = original_data.clone();
                xor_safe_chunks_nested(black_box(&mut data), black_box(&keystream));
                data
            });
        });

        group.bench_function("safe_split_at", |b| {
            b.iter(|| {
                let mut data = original_data.clone();
                xor_safe_split_at(black_box(&mut data), black_box(&keystream));
                data
            });
        });

        group.bench_function("safe_bytewise", |b| {
            b.iter(|| {
                let mut data = original_data.clone();
                xor_safe_bytewise(black_box(&mut data), black_box(&keystream));
                data
            });
        });

        group.finish();
    }
}

criterion_group!(benches, xor_benchmark);
criterion_main!(benches);
