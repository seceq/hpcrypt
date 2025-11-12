// Micro-benchmark: Cost of reduction in NTT butterfly
//
// Measures the cost of Montgomery reduction vs just doing the multiply

use std::time::Instant;

const Q: i32 = 8380417;
const QINV: i64 = -58728449; // -(q^-1 mod 2^32)

#[inline(always)]
fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i128 * QINV as i128) & 0xFFFFFFFF;
    let u = ((a as i128 - t * Q as i128) >> 32) as i64;
    u as i32
}

fn main() {
    println!("================================================================================");
    println!("NTT Butterfly Reduction Cost Analysis");
    println!("================================================================================");
    println!();

    let iterations = 10_000_000;

    // Test data
    let mut a_vals = Vec::new();
    let mut zeta_vals = Vec::new();
    for i in 0..256 {
        a_vals.push(((i * 12345) % Q) as i32);
        zeta_vals.push(((i * 67890) % Q) as i32);
    }

    println!("Testing {} iterations (warm up CPU)", iterations);
    println!();

    // Benchmark 1: Just the multiply (no reduction)
    let start = Instant::now();
    let mut sum: i64 = 0;
    for j in 0..iterations {
        for i in 0..256 {
            let product = (a_vals[i] as i64).wrapping_mul(zeta_vals[(i + j as usize) % 256] as i64);
            sum = sum.wrapping_add(product);
        }
    }
    let multiply_time = start.elapsed();
    let multiply_ns = multiply_time.as_nanos() / (iterations * 256);

    println!("1. Multiply only:              {} ns/op", multiply_ns);
    if sum == 0x123456789ABCDEF { println!("impossible {}", sum); }

    // Benchmark 2: Multiply + Montgomery reduction
    let start = Instant::now();
    let mut sum: i64 = 0;
    for j in 0..iterations {
        for i in 0..256 {
            let product = (a_vals[i] as i64).wrapping_mul(zeta_vals[(i + j as usize) % 256] as i64);
            let reduced = montgomery_reduce(product);
            sum = sum.wrapping_add(reduced as i64);
        }
    }
    let montgomery_time = start.elapsed();
    let montgomery_ns = montgomery_time.as_nanos() / (iterations * 256);

    println!("2. Multiply + Montgomery:      {} ns/op", montgomery_ns);
    if sum == 0x123456789ABCDEF { println!("impossible {}", sum); }

    // Benchmark 3: Multiply + simple modulo (for comparison)
    let start = Instant::now();
    let mut sum: i64 = 0;
    for j in 0..iterations {
        for i in 0..256 {
            let product = (a_vals[i] as i64).wrapping_mul(zeta_vals[(i + j as usize) % 256] as i64);
            let reduced = (product % Q as i64) as i32;
            sum = sum.wrapping_add(reduced as i64);
        }
    }
    let modulo_time = start.elapsed();
    let modulo_ns = modulo_time.as_nanos() / (iterations * 256);

    println!("3. Multiply + simple modulo:   {} ns/op", modulo_ns);
    if sum == 0x123456789ABCDEF { println!("impossible {}", sum); }

    println!();
    println!("================================================================================");
    println!("Analysis:");
    println!("================================================================================");
    println!();

    let reduction_cost = montgomery_ns - multiply_ns;
    let modulo_cost = modulo_ns - multiply_ns;

    println!("Montgomery reduction cost:  {} ns ({:.1}% of multiply+reduce)",
             reduction_cost,
             (reduction_cost as f64 / montgomery_ns as f64) * 100.0);

    println!("Simple modulo cost:         {} ns ({:.1}% of multiply+mod)",
             modulo_cost,
             (modulo_cost as f64 / modulo_ns as f64) * 100.0);

    println!();
    println!("Montgomery vs modulo: {:.1}× faster", modulo_ns as f64 / montgomery_ns as f64);

    println!();
    println!("Impact on NTT:");
    println!("- NTT has 256 coeffs × 8 layers = 2048 operations");
    println!("- Current NTT time: ~540 ns (with AVX2)");
    println!("- Reduction cost per NTT: {} × 2048 = {} ns", reduction_cost, reduction_cost * 2048);
    println!("- Reduction % of NTT: {:.1}%", (reduction_cost * 2048) as f64 / 540.0);

    println!();
    println!("If we could eliminate reduction entirely:");
    println!("- NTT speedup: {:.1}%", ((reduction_cost * 2048) as f64 / 540.0));
    println!("- Overall signing impact: {:.2}%", ((reduction_cost * 2048) as f64 / 540.0) * 0.054);

    println!();
    println!("Conclusion:");
    if (reduction_cost * 2048) as f64 / 540.0 < 10.0 {
        println!("✓ Reduction cost is <10% of NTT time");
        println!("✓ Eliminating it would give <0.5% overall improvement");
        println!("✓ Not worth the complexity of switching away from Montgomery");
    } else {
        println!("! Reduction cost is significant");
        println!("! Might be worth exploring lazy reduction");
    }

    println!();
    println!("================================================================================");
}
