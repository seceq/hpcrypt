//! Benchmark: Precomputed ZETAS vs On-the-Fly W Computation
//!
//! Compares the performance of:
//! 1. Array lookup (current approach)
//! 2. On-the-fly computation using modular exponentiation

use std::time::Instant;

const Q: i32 = 8380417;
const ZETA: i32 = 1753; // Primitive 512-th root of unity

// Precomputed zetas (first 16 values from actual ZETAS array)
const ZETAS: [i32; 256] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

/// Modular exponentiation: (base^exp) mod Q
/// This is the "on-the-fly" approach - compute zeta from scratch
#[inline(always)]
fn mod_pow(mut base: i64, mut exp: u32, modulus: i64) -> i32 {
    let mut result: i64 = 1;
    base %= modulus;

    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp >>= 1;
    }

    result as i32
}

/// Bit-reverse for computing correct exponent
#[inline(always)]
fn bit_reverse(mut x: usize, bits: u32) -> u32 {
    let mut result = 0u32;
    for _ in 0..bits {
        result = (result << 1) | ((x & 1) as u32);
        x >>= 1;
    }
    result
}

/// On-the-fly computation of zeta value
#[inline(always)]
fn compute_zeta_onthefly(k: usize) -> i32 {
    let exp = bit_reverse(k, 8);
    mod_pow(ZETA as i64, exp, Q as i64)
}

/// Alternative: Iterative computation (faster but still overhead)
/// Build up powers incrementally
#[inline(always)]
#[allow(dead_code)]
fn compute_zeta_iterative(_k: usize, prev: i32) -> i32 {
    // This would need state tracking across calls
    // Simplified version - still requires modular multiplication
    ((prev as i64 * ZETA as i64) % Q as i64) as i32
}

fn main() {
    const ITERATIONS: usize = 100_000;

    println!("=== Twiddle Factor (W) Computation Benchmark ===\n");
    println!("Comparing array lookup vs on-the-fly computation");
    println!("Iterations: {}\n", ITERATIONS);

    // Benchmark 1: Array lookup (current approach)
    let mut sum1 = 0i64;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for k in 0..256 {
            let zeta = ZETAS[k];
            sum1 = sum1.wrapping_add(zeta as i64);
        }
    }
    let elapsed1 = start.elapsed();
    let ns_per_lookup = elapsed1.as_nanos() / (ITERATIONS as u128 * 256);

    println!("1. Array Lookup (current):");
    println!("   Total: {:?}", elapsed1);
    println!("   Per lookup: {} ns", ns_per_lookup);
    println!("   Checksum: {}", sum1);

    // Benchmark 2: On-the-fly modular exponentiation
    let mut sum2 = 0i64;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for k in 0..256 {
            let zeta = compute_zeta_onthefly(k);
            sum2 = sum2.wrapping_add(zeta as i64);
        }
    }
    let elapsed2 = start.elapsed();
    let ns_per_compute = elapsed2.as_nanos() / (ITERATIONS as u128 * 256);

    println!("\n2. On-the-Fly Computation (modular exponentiation):");
    println!("   Total: {:?}", elapsed2);
    println!("   Per computation: {} ns", ns_per_compute);
    println!("   Checksum: {}", sum2);

    // Benchmark 3: Simple modular multiplication (lower bound for iterative)
    let mut sum3 = 0i64;
    let mut prev = ZETA;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for _k in 0..256 {
            prev = ((prev as i64 * ZETA as i64) % Q as i64) as i32;
            sum3 = sum3.wrapping_add(prev as i64);
        }
    }
    let elapsed3 = start.elapsed();
    let ns_per_iter = elapsed3.as_nanos() / (ITERATIONS as u128 * 256);

    println!("\n3. Iterative Multiplication (best-case on-the-fly):");
    println!("   Total: {:?}", elapsed3);
    println!("   Per iteration: {} ns", ns_per_iter);
    println!("   Checksum: {}", sum3);

    // Analysis
    println!("\n=== Analysis ===");
    println!("Slowdown factors:");
    println!(
        "  Modular exponentiation: {:.1}x slower",
        ns_per_compute as f64 / ns_per_lookup as f64
    );
    println!(
        "  Iterative multiplication: {:.1}x slower",
        ns_per_iter as f64 / ns_per_lookup as f64
    );

    println!("\nImpact on NTT (256 zeta lookups per NTT):");
    let ntt_overhead_exp = (ns_per_compute - ns_per_lookup) * 256;
    let ntt_overhead_iter = (ns_per_iter - ns_per_lookup) * 256;
    println!(
        "  Modular exp overhead: {} ns ({:.2} µs)",
        ntt_overhead_exp,
        ntt_overhead_exp as f64 / 1000.0
    );
    println!(
        "  Iterative overhead: {} ns ({:.2} µs)",
        ntt_overhead_iter,
        ntt_overhead_iter as f64 / 1000.0
    );

    println!("\nImpact on ML-DSA signing (assuming ~2 NTTs per signature):");
    let sign_overhead_exp = ntt_overhead_exp * 2;
    let sign_overhead_iter = ntt_overhead_iter * 2;
    println!(
        "  Modular exp overhead: {:.2} µs",
        sign_overhead_exp as f64 / 1000.0
    );
    println!(
        "  Iterative overhead: {:.2} µs",
        sign_overhead_iter as f64 / 1000.0
    );

    println!("\n=== Conclusion ===");
    if ns_per_compute > ns_per_lookup * 10 {
        println!(" On-the-fly computation is >10x slower - NOT recommended");
    } else if ns_per_compute > ns_per_lookup * 2 {
        println!("  On-the-fly computation is 2-10x slower - questionable");
    } else {
        println!(" On-the-fly computation is competitive");
    }

    println!("\nMemory trade-off:");
    println!("  Saved: 2 KB (ZETAS + ZETAS_SHOUP arrays)");
    println!(
        "  Cost: {:.1}x slower performance",
        ns_per_compute as f64 / ns_per_lookup as f64
    );
}
