use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hpcrypt_cipher::ChaCha20;

fn chacha20_encryption_benchmark(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    // Benchmark different data sizes
    let sizes = [64, 256, 1024, 4096, 16384];

    for &size in &sizes {
        let mut group = c.benchmark_group(format!("chacha20_{}_bytes", size));
        group.throughput(Throughput::Bytes(size as u64));

        let data = vec![0u8; size];

        group.bench_function("encrypt", |b| {
            b.iter(|| {
                let mut cipher = ChaCha20::new(&key, &nonce, 0);
                let mut data_copy = data.clone();
                cipher.encrypt(black_box(&mut data_copy));
                data_copy
            });
        });

        group.finish();
    }
}

criterion_group!(benches, chacha20_encryption_benchmark);
criterion_main!(benches);
