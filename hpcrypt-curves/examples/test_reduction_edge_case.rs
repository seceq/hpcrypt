// Test to understand the reduction bug
//
// The issue is in simple_reduce's final reduction loops
// Specifically line 386: if result.limbs[3] > 0xFFFFFFFF00000001

use hpcrypt_curves::p256::field::FieldElement;

fn main() {
    println!("=== Understanding the Reduction Bug ===\n");

    // The P-256 modulus for reference
    println!("P-256 modulus: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    println!("  limbs[3] = 0xFFFFFFFF00000001");
    println!("  limbs[2] = 0x0000000000000000");
    println!("  limbs[1] = 0x00000000FFFFFFFF");
    println!("  limbs[0] = 0xFFFFFFFFFFFFFFFF\n");

    // When we compute (p-3)^2, after the S-term arithmetic and carry propagation,
    // we likely get a value that's negative (in signed arithmetic sense)
    // represented as a large unsigned number

    // The bug is on line 386 of field_ops.rs:
    //     if result.limbs[3] > 0xFFFFFFFF00000001
    //
    // This check tries to detect negative numbers (in two's complement)
    // But it's insufficient!

    println!("=== Why the check fails ===");
    println!("The check: result.limbs[3] > 0xFFFFFFFF00000001");
    println!();
    println!("Case 1: result.limbs[3] = 0xFFFFFFFFFFFFFFFF (all bits set)");
    println!("  Is 0xFFFFFFFFFFFFFFFF > 0xFFFFFFFF00000001? YES");
    println!("  This SHOULD trigger the 'add p' path. Good!");
    println!();
    println!("Case 2: result.limbs[3] = 0xFFFFFFFF00000001 (exactly p's high limb)");
    println!("  Is 0xFFFFFFFF00000001 > 0xFFFFFFFF00000001? NO");
    println!("  So it won't add p. But this could still be negative overall!");
    println!();

    // Let's test what (p-3)^2 actually produces
    let p_minus_3 = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFC,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]);

    let result = p_minus_3.mul(&p_minus_3);
    let bytes = result.to_bytes();

    println!("=== Actual (p-3)^2 result ===");
    print!("Got: 0x");
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();
    println!("Expected: 9\n");

    // This result is clearly wrong - it's way larger than p
    // The issue is that the reduction didn't work

    println!("=== Hypothesis ===");
    println!("After S-term arithmetic and initial carry propagation in simple_reduce,");
    println!("the result might be in a form that:");
    println!("1. Has limbs[3] = 0xFFFFFFFFFFFFFFFF (passes negativity check)");
    println!("2. Represents a negative value that needs p added to it");
    println!("3. But the loop only runs 16 times, which might not be enough");
    println!();
    println!("OR:");
    println!("1. After carry handling, limbs[3] might be 0xFFFFFFFC or similar");
    println!("2. Which is less than 0xFFFFFFFF00000001");
    println!("3. So the negativity check doesn't trigger");
    println!("4. But the value is still not properly reduced\n");

    // The real fix: we need a better way to detect if the result needs more reduction
    // Instead of checking just limbs[3], we should check if result >= p
}
