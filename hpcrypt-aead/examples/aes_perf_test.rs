// Quick AES performance comparison
use hpcrypt_aead::aes::Aes;
use hpcrypt_aead::aes_optimized::AesOptimized;
use std::time::Instant;

fn benchmark_impl<F>(name: &str, mut f: F) -> u128
where
    F: FnMut(),
{
    // Warmup
    for _ in 0..10000 {
        f();
    }

    // Measure
    let iterations = 100_000;
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total_ns = start.elapsed().as_nanos();
    let avg_ns = total_ns / iterations;

    println!("{}: {} ns/op", name, avg_ns);
    avg_ns
}

fn main() {
    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let plaintext = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];

    println!("\n=== AES-128 Performance Comparison ===\n");

    let baseline_aes = Aes::new_128(&key);
    let baseline_time = benchmark_impl("Baseline (aes.rs)", || {
        let _ = baseline_aes.encrypt_block(&plaintext);
    });

    let optimized_aes = AesOptimized::new_128(&key);
    let optimized_time = benchmark_impl("Optimized (aes_optimized.rs)", || {
        let _ = optimized_aes.encrypt_block(&plaintext);
    });

    println!("\n=== Results ===");
    println!("Baseline:   {} ns", baseline_time);
    println!("Optimized:  {} ns", optimized_time);

    let speedup = baseline_time as f64 / optimized_time as f64;
    let improvement_pct =
        ((baseline_time as f64 - optimized_time as f64) / baseline_time as f64) * 100.0;

    println!("Speedup:    {:.3}x", speedup);
    println!("Improvement: {:.1}%", improvement_pct);

    if improvement_pct >= 20.0 {
        println!(
            "\n SUCCESS: Achieved {}% improvement (target: 20-45%)",
            improvement_pct as i32
        );
    } else if improvement_pct >= 15.0 {
        println!(
            "\n  PARTIAL: Achieved {}% improvement (target: 20-45%)",
            improvement_pct as i32
        );
    } else {
        println!(
            "\n BELOW TARGET: Only {}% improvement (target: 20-45%)",
            improvement_pct as i32
        );
    }
}
