// Quick test for secp256k1 Montgomery implementation

use hpcrypt_curves::secp256k1::field_montgomery_native::MontgomeryFieldElement;

fn main() {
    println!("Testing secp256k1 Native Montgomery Implementation");
    println!("==================================================\n");

    // Test 1: Basic multiplication
    println!("Test 1: 1 * 1 = 1");
    let one = MontgomeryFieldElement::one();
    let result = one.mul(&one);
    assert_eq!(result, one, "1 * 1 should equal 1");
    println!("✓ PASS\n");

    // Test 2: Addition
    println!("Test 2: 1 + 1 = 2, then 2 - 1 = 1");
    let two = one.add(&one);
    let back_to_one = two.sub(&one);
    assert_eq!(back_to_one, one, "2 - 1 should equal 1");
    println!("✓ PASS\n");

    // Test 3: Zero is additive identity
    println!("Test 3: 1 + 0 = 1");
    let zero = MontgomeryFieldElement::zero();
    let result = one.add(&zero);
    assert_eq!(result, one, "1 + 0 should equal 1");
    println!("✓ PASS\n");

    // Test 4: Squaring
    println!("Test 4: 2² = 4");
    let four = two.square();
    let expected_four = two.add(&two); // 2 + 2 = 4
    assert_eq!(four, expected_four, "2² should equal 4");
    println!("✓ PASS\n");

    // Test 5: Multiplication commutativity
    println!("Test 5: a * b = b * a");
    let a = one.add(&one).add(&one); // 3
    let b = one.add(&one); // 2
    let ab = a.mul(&b);
    let ba = b.mul(&a);
    assert_eq!(ab, ba, "a * b should equal b * a");
    println!("✓ PASS\n");

    println!("==================================================");
    println!("All secp256k1 Montgomery tests PASSED! ✓");
}
