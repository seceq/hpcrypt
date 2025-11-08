use hpcrypt_curves::p256::FieldElement;

fn main() {
    println!("Testing (p-3)^2 mod p with debug output");
    println!();

    // p in hex (for reference)
    println!("p = 0xFFFFFFFF00000001_0000000000000000_FFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF");
    println!();

    // p - 3
    let p_minus_3 = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFC, // limb 0
        0xFFFFFFFFFFFFFFFF, // limb 1
        0x0000000000000000, // limb 2
        0xFFFFFFFF00000001, // limb 3
    ]);

    println!("p - 3 = {:?}", p_minus_3);
    println!();

    // Square it
    let result = p_minus_3.square();

    println!("(p-3)^2 = {:?}", result);
    println!();

    // Expected: 9
    let expected = FieldElement::from_u64(9);
    println!("Expected = {:?}", expected);
    println!();

    // Check if result > p by looking at high limb
    // p[3] = 0xFFFFFFFF00000001
    // result[3] appears to be 0xFFFFFFFC00000000 based on the output format

    if result == expected {
        println!("✅ CORRECT!");
    } else {
        println!("❌ WRONG!");
        println!();

        // Try to compare with modulus manually
        println!("Note: The result should have been reduced modulo p.");
        println!("The NIST reduction must have failed to properly reduce this value.");
    }
}
