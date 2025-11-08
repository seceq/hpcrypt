// Debug the NIST P-256 reduction for (p-3)^2
//
// We'll manually compute what the schoolbook multiplication gives us
// and what the reduction should produce

fn main() {
    println!("=== Manual Computation of (p-3)^2 ===\n");

    // P-256 modulus
    let _p = [
        0xFFFFFFFFFFFFFFFF_u64,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ];

    println!("p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFF FFFFFFFFFFFFFFFF");

    // p-3
    let _p_minus_3 = [
        0xFFFFFFFFFFFFFFFC_u64,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];

    println!("p-3 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFC");

    // Expected result: (p-3)^2 mod p = 9
    // Let's verify: (p-3)^2 = p^2 - 6p + 9
    // mod p: p^2 ≡ 0, -6p ≡ 0, so result is 9

    println!("\nExpected: (p-3)^2 mod p = 9");

    // What does (p-3)^2 look like before reduction?
    // (p-3)^2 = p^2 - 6p + 9
    //         = (FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)^2
    //           - 6 * (FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)
    //           + 9

    // Let's focus on what simple_reduce might be computing wrong
    // The problem is likely in the S-term construction or carry propagation

    println!("\n=== Analyzing the actual wrong result ===");
    println!("Got:      0xFFFFFFFC00000006FFFFFFFFFFFFFFFF00000004FFFFFFFF000000000000000A");
    println!("Expected: 0x0000000000000000000000000000000000000000000000000000000000000009");

    // The wrong result is very large - it looks like reduction failed
    // Let's see if there's a pattern

    // If we had 9 but failed to reduce properly, what could we get?
    // Actually, let's think about what 9 + k*p would look like for small k

    println!("\n=== What is 9 + k*p for small k? ===");

    // 9 + 1*p = 9 + p
    println!("9 + 1*p would be around p + 9, which is larger than what we got");

    // Let's compute what the result actually is in decimal
    // 0xFFFFFFFC00000006FFFFFFFFFFFFFFFF00000004FFFFFFFF000000000000000A

    // This looks like it might be related to incomplete reduction
    // The high limbs are near max values

    println!("\n=== Hypothesis ===");
    println!("The result 0xFFFFFFFC... is much larger than p.");
    println!("This suggests simple_reduce is not properly reducing the final result.");
    println!("The reduction loops (lines 384-402) may not be running enough iterations,");
    println!("or the negativity check (line 386) might be incorrect.");

    // Let's also check (p-1)^2 result
    println!("\n=== What about (p-1)^2? ===");
    println!("Expected: (p-1)^2 mod p = 1");
    println!("The pattern suggests the reduction is consistently failing for large inputs.");
}
