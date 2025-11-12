use hpcrypt_curves::p256::FieldElement;

fn main() {
    println!("Testing (p-3)^2 mod p");
    println!();

    // p - 3
    let p_minus_3 = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFC,  // limb 0
        0xFFFFFFFFFFFFFFFF,  // limb 1
        0x0000000000000000,  // limb 2
        0xFFFFFFFF00000001,  // limb 3
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

    if result == expected {
        println!("✅ CORRECT!");
    } else {
        println!("❌ WRONG!");

        // Show result in a different format
        println!("Result: {:?}", result);
        println!("Expected: {:?}", expected);
    }
}
