//! Direct comparison: Karatsuba vs Schoolbook for P-256
//!
//! This benchmark implements both methods inline to compare them directly.

use std::time::Instant;

const ITERATIONS: usize = 100_000;

// Simple 4-limb representation for testing
#[derive(Clone, Copy)]
struct TestValue {
    limbs: [u64; 4],
}

impl TestValue {
    fn new(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }
}

// Schoolbook multiplication (16 multiplications)
fn schoolbook_mul(a: &TestValue, b: &TestValue) -> [u64; 8] {
    let mut result = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let product = (a.limbs[i] as u128) * (b.limbs[j] as u128);
            let sum = (result[i + j] as u128) + product + carry;
            result[i + j] = sum as u64;
            carry = sum >> 64;
        }
        result[i + 4] = carry as u64;
    }

    result
}

// Karatsuba multiplication (12 multiplications)
fn karatsuba_mul(a: &TestValue, b: &TestValue) -> [u64; 8] {
    // 2x2 schoolbook helper
    fn mul_2x2(a: &[u64; 2], b: &[u64; 2]) -> [u64; 4] {
        let mut result = [0u64; 4];

        let p00 = (a[0] as u128) * (b[0] as u128);
        result[0] = p00 as u64;
        let mut carry = p00 >> 64;

        let p01 = (a[0] as u128) * (b[1] as u128);
        let p10 = (a[1] as u128) * (b[0] as u128);
        let sum1 = p01 + p10 + carry;
        result[1] = sum1 as u64;
        carry = sum1 >> 64;

        let p11 = (a[1] as u128) * (b[1] as u128);
        let sum2 = p11 + carry;
        result[2] = sum2 as u64;
        result[3] = (sum2 >> 64) as u64;

        result
    }

    let a_lo = [a.limbs[0], a.limbs[1]];
    let a_hi = [a.limbs[2], a.limbs[3]];
    let b_lo = [b.limbs[0], b.limbs[1]];
    let b_hi = [b.limbs[2], b.limbs[3]];

    let z0 = mul_2x2(&a_lo, &b_lo);
    let z2 = mul_2x2(&a_hi, &b_hi);

    let a_sum_0 = (a_lo[0] as u128) + (a_hi[0] as u128);
    let a_sum_1 = (a_lo[1] as u128) + (a_hi[1] as u128) + (a_sum_0 >> 64);
    let a_sum = [a_sum_0 as u64, a_sum_1 as u64];
    let a_sum_carry = a_sum_1 >> 64;

    let b_sum_0 = (b_lo[0] as u128) + (b_hi[0] as u128);
    let b_sum_1 = (b_lo[1] as u128) + (b_hi[1] as u128) + (b_sum_0 >> 64);
    let b_sum = [b_sum_0 as u64, b_sum_1 as u64];
    let b_sum_carry = b_sum_1 >> 64;

    let mut z_mid = mul_2x2(&a_sum, &b_sum);

    if a_sum_carry != 0 {
        let add = (z_mid[2] as u128) + (b_sum[0] as u128);
        z_mid[2] = add as u64;
        let add = (z_mid[3] as u128) + (b_sum[1] as u128) + (add >> 64);
        z_mid[3] = add as u64;
    }

    if b_sum_carry != 0 {
        let add = (z_mid[2] as u128) + (a_sum[0] as u128);
        z_mid[2] = add as u64;
        let add = (z_mid[3] as u128) + (a_sum[1] as u128) + (add >> 64);
        z_mid[3] = add as u64;
    }

    let mut z1 = [0u64; 5];
    z1[0] = z_mid[0];
    z1[1] = z_mid[1];
    z1[2] = z_mid[2];
    z1[3] = z_mid[3];
    z1[4] = if a_sum_carry != 0 && b_sum_carry != 0 {
        1
    } else {
        0
    };

    // z1 -= z0
    let sub0 = (z1[0] as u128).wrapping_sub(z0[0] as u128);
    z1[0] = sub0 as u64;
    let borrow = if sub0 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    let sub1 = (z1[1] as u128).wrapping_sub((z0[1] as u128) + borrow);
    z1[1] = sub1 as u64;
    let borrow = if sub1 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    let sub2 = (z1[2] as u128).wrapping_sub((z0[2] as u128) + borrow);
    z1[2] = sub2 as u64;
    let borrow = if sub2 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    let sub3 = (z1[3] as u128).wrapping_sub((z0[3] as u128) + borrow);
    z1[3] = sub3 as u64;
    let borrow = if sub3 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    z1[4] = z1[4].wrapping_sub(borrow as u64);

    // z1 -= z2
    let sub0 = (z1[0] as u128).wrapping_sub(z2[0] as u128);
    z1[0] = sub0 as u64;
    let borrow = if sub0 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    let sub1 = (z1[1] as u128).wrapping_sub((z2[1] as u128) + borrow);
    z1[1] = sub1 as u64;
    let borrow = if sub1 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    let sub2 = (z1[2] as u128).wrapping_sub((z2[2] as u128) + borrow);
    z1[2] = sub2 as u64;
    let borrow = if sub2 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    let sub3 = (z1[3] as u128).wrapping_sub((z2[3] as u128) + borrow);
    z1[3] = sub3 as u64;
    let borrow = if sub3 > 0xFFFFFFFFFFFFFFFF { 1 } else { 0 };

    z1[4] = z1[4].wrapping_sub(borrow as u64);

    // Combine
    let mut result = [0u64; 8];

    result[0] = z0[0];
    result[1] = z0[1];
    result[2] = z0[2];
    result[3] = z0[3];

    let add = (result[2] as u128) + (z1[0] as u128);
    result[2] = add as u64;

    let add = (result[3] as u128) + (z1[1] as u128) + (add >> 64);
    result[3] = add as u64;

    let add = (result[4] as u128) + (z1[2] as u128) + (add >> 64);
    result[4] = add as u64;

    let add = (result[5] as u128) + (z1[3] as u128) + (add >> 64);
    result[5] = add as u64;

    let add = (result[6] as u128) + (z1[4] as u128) + (add >> 64);
    result[6] = add as u64;

    result[7] = (add >> 64) as u64;

    let add = (result[4] as u128) + (z2[0] as u128);
    result[4] = add as u64;

    let add = (result[5] as u128) + (z2[1] as u128) + (add >> 64);
    result[5] = add as u64;

    let add = (result[6] as u128) + (z2[2] as u128) + (add >> 64);
    result[6] = add as u64;

    let add = (result[7] as u128) + (z2[3] as u128) + (add >> 64);
    result[7] = add as u64;

    result
}

fn main() {
    println!("P-256 Multiplication: Karatsuba vs Schoolbook");
    println!("Iterations: {}", ITERATIONS);
    println!("{}", "=".repeat(70));
    println!();

    let a = TestValue::new([
        0x123456789ABCDEF0,
        0xFEDCBA9876543210,
        0x0123456789ABCDEF,
        0x0FEDCBA987654321,
    ]);

    let b = TestValue::new([
        0xDEADBEEFCAFEBABE,
        0xBABECAFEDEADBEEF,
        0xCAFEBABEDEADBEEF,
        0x0DEADBEEFCAFEBAB,
    ]);

    let c = TestValue::new([
        0x1111111111111111,
        0x2222222222222222,
        0x3333333333333333,
        0x4444444444444444,
    ]);

    let d = TestValue::new([
        0x5555555555555555,
        0x6666666666666666,
        0x7777777777777777,
        0x8888888888888888,
    ]);

    let test_pairs = vec![(a, b), (b, c), (c, d), (d, a)];

    // Verify both give same results
    println!("CORRECTNESS CHECK:");
    println!("{}", "-".repeat(70));
    for (x, y) in &test_pairs {
        let result_sb = schoolbook_mul(x, y);
        let result_kt = karatsuba_mul(x, y);
        assert_eq!(result_sb, result_kt, "Results must match!");
    }
    println!("   Both methods produce identical results");
    println!();

    // Benchmark Schoolbook
    println!("1. SCHOOLBOOK (16 multiplications):");
    println!("{}", "-".repeat(70));

    for (x, y) in &test_pairs {
        let _ = schoolbook_mul(x, y);
    }

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for (x, y) in &test_pairs {
            let _ = schoolbook_mul(x, y);
        }
    }
    let duration_sb = start.elapsed();

    let total = ITERATIONS * test_pairs.len();
    let ns_per_sb = duration_sb.as_nanos() as f64 / total as f64;

    println!("  Time per multiplication: {:.2} ns", ns_per_sb);
    println!(
        "  Throughput: {:.2} million ops/sec",
        1000.0 / (ns_per_sb / 1000.0)
    );
    println!();

    // Benchmark Karatsuba
    println!("2. KARATSUBA (12 multiplications):");
    println!("{}", "-".repeat(70));

    for (x, y) in &test_pairs {
        let _ = karatsuba_mul(x, y);
    }

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for (x, y) in &test_pairs {
            let _ = karatsuba_mul(x, y);
        }
    }
    let duration_kt = start.elapsed();

    let ns_per_kt = duration_kt.as_nanos() as f64 / total as f64;

    println!("  Time per multiplication: {:.2} ns", ns_per_kt);
    println!(
        "  Throughput: {:.2} million ops/sec",
        1000.0 / (ns_per_kt / 1000.0)
    );
    println!();

    // Comparison
    println!("{}", "=".repeat(70));
    println!("PERFORMANCE COMPARISON:");
    println!("{}", "=".repeat(70));
    println!();
    println!("  Schoolbook: {:.2} ns", ns_per_sb);
    println!("  Karatsuba:  {:.2} ns", ns_per_kt);
    println!();

    let speedup = ns_per_sb / ns_per_kt;
    let improvement = ((ns_per_sb - ns_per_kt) / ns_per_sb) * 100.0;

    if speedup > 1.0 {
        println!(
            "   Karatsuba is {:.2}x faster ({:.1}% improvement)",
            speedup, improvement
        );
    } else {
        println!(
            "    Schoolbook is {:.2}x faster ({:.1}% slower)",
            1.0 / speedup,
            -improvement
        );
    }

    println!();
    println!(
        "  Time saved per multiplication: {:.2} ns",
        ns_per_sb - ns_per_kt
    );
    println!(
        "  Time saved per 1000 multiplications: {:.2} μs",
        (ns_per_sb - ns_per_kt) / 1000.0
    );
    println!();
    println!("{}", "=".repeat(70));
}
