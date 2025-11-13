// Test (p-3)^2 reduction to find the bug
//
// Expected: (p-3)^2 = p^2 - 6p + 9 ≡ 9 (mod p)
// Actual: Getting a wrong value

use hpcrypt_curves::p256::field::FieldElement;

fn main() {
    println!("=== Testing (p-3)^2 mod p ===\n");

    // p-3 for P-256
    let p_minus_3 = FieldElement::from_limbs([
        0xfffffffffffffffc,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ]);

    println!("Input: p-3 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc");

    // Test with different multiplications
    println!("\n1. Using square():");
    let squared = p_minus_3.square();
    let bytes = squared.to_bytes();
    print!("   Result: 0x");
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();
    println!("   Equals 9: {}", squared == FieldElement::from_u64(9));

    println!("\n2. Using mul(&self):");
    let multiplied = p_minus_3.mul(&p_minus_3);
    let bytes = multiplied.to_bytes();
    print!("   Result: 0x");
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();
    println!("   Equals 9: {}", multiplied == FieldElement::from_u64(9));

    println!("\n3. Results match: {}", squared == multiplied);

    // Let's try smaller test cases that might reveal the pattern
    println!("\n=== Testing (p-1)^2 ===");
    let p_minus_1 = FieldElement::from_limbs([
        0xfffffffffffffffe,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ]);
    let p_minus_1_squared = p_minus_1.mul(&p_minus_1);
    println!("Expected: 1 (since (p-1)^2 = p^2 - 2p + 1 ≡ 1 mod p)");
    println!("Equals 1: {}", p_minus_1_squared == FieldElement::one());

    println!("\n=== Testing (p-2)^2 ===");
    let p_minus_2 = FieldElement::from_limbs([
        0xfffffffffffffffd,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ]);
    let p_minus_2_squared = p_minus_2.mul(&p_minus_2);
    println!("Expected: 4 (since (p-2)^2 = p^2 - 4p + 4 ≡ 4 mod p)");
    println!(
        "Equals 4: {}",
        p_minus_2_squared == FieldElement::from_u64(4)
    );

    // Try multiplying p-3 by small numbers
    println!("\n=== Testing (p-3) * 2 ===");
    let two = FieldElement::from_u64(2);
    let p_minus_3_times_2 = p_minus_3.mul(&two);
    println!("Expected: p-6 = 2p - 6 ≡ -6 ≡ p-6 (mod p)");
    let p_minus_6 = FieldElement::from_limbs([
        0xfffffffffffffff9,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ]);
    println!("Equals p-6: {}", p_minus_3_times_2 == p_minus_6);
    let bytes = p_minus_3_times_2.to_bytes();
    print!("   Actual: 0x");
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();

    // Try 3 * 3 for comparison
    println!("\n=== Testing 3 * 3 ===");
    let three = FieldElement::from_u64(3);
    let three_squared = three.mul(&three);
    println!("Expected: 9");
    println!("Equals 9: {}", three_squared == FieldElement::from_u64(9));
}
