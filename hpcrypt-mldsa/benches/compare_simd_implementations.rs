// Benchmark to compare C intrinsics vs hand-written assembly implementations
//
// Run with:
// - cargo bench --bench compare_simd_implementations --features avx2,simd-c
// - cargo bench --bench compare_simd_implementations --features avx2,simd-asm
// - cargo bench --bench compare_simd_implementations --features avx2,simd-both

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::params::MlDsa65;
use hpcrypt_mldsa::sign::sign;
use hpcrypt_mldsa::verify::verify;

fn benchmark_signing(c: &mut Criterion) {
    let (_pk, sk) = keygen::<MlDsa65>();
    let message = b"Benchmark message for ML-DSA signing";

    let implementation_name = if cfg!(feature = "simd-asm") {
        "Assembly"
    } else {
        "C_intrinsics"
    };

    c.bench_function(&format!("signing/{}", implementation_name), |b| {
        b.iter(|| {
            let sig = sign(&sk, black_box(message));
            black_box(sig);
        });
    });
}

fn benchmark_verification(c: &mut Criterion) {
    let (pk, sk) = keygen::<MlDsa65>();
    let message = b"Benchmark message for ML-DSA verification";
    let sig = sign(&sk, message).expect("Signing failed");

    let implementation_name = if cfg!(feature = "simd-asm") {
        "Assembly"
    } else {
        "C_intrinsics"
    };

    c.bench_function(&format!("verification/{}", implementation_name), |b| {
        b.iter(|| {
            let valid = verify(&pk, black_box(message), black_box(&sig));
            black_box(valid);
        });
    });
}

fn benchmark_keygen(c: &mut Criterion) {
    let implementation_name = if cfg!(feature = "simd-asm") {
        "Assembly"
    } else {
        "C_intrinsics"
    };

    c.bench_function(&format!("keygen/{}", implementation_name), |b| {
        b.iter(|| {
            let (pk, sk) = keygen::<MlDsa65>();
            black_box((pk, sk));
        });
    });
}

criterion_group!(
    benches,
    benchmark_signing,
    benchmark_verification,
    benchmark_keygen
);
criterion_main!(benches);
