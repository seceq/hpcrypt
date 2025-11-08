// Test if gte_modulus works correctly

use hpcrypt_curves::p256::field::FieldElement;

fn main() {
    println!("=== Testing gte_modulus ===\n");

    // Test with p exactly
    let p = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]);

    // This should be >= p
    let bytes = p.to_bytes();
    print!("p: 0x");
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();

    // Test with p-1
    let p_minus_1 = FieldElement::from_limbs([
        0xFFFFFFFFFFFFFFFE,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]);

    let bytes = p_minus_1.to_bytes();
    print!("p-1: 0x");
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();

    println!("\nNote: These values are created via from_limbs without reduction,");
    println!("so they might not be in canonical form [0, p).");
}
