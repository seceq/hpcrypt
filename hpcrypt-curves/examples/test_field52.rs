// Standalone test for field52
use hpcrypt_curves::secp256k1::FieldElement52;

fn main() {
    println!("Testing FieldElement52...\n");

    // Test 1: Zero and One
    let zero = FieldElement52::ZERO;
    let one = FieldElement52::ONE;
    println!("✓ Zero and One constants created");

    // Test 2: from_u64
    let seven = FieldElement52::from_u64(7);
    let nine = FieldElement52::from_u64(9);
    println!("✓ from_u64 works");

    // Test 3: Addition
    let sum = seven.add(&nine);
    let expected = FieldElement52::from_u64(16);
    assert_eq!(sum, expected);
    println!("✓ Addition: 7 + 9 = 16");

    // Test 4: Subtraction
    let diff = nine.sub(&seven);
    let expected = FieldElement52::from_u64(2);
    assert_eq!(diff, expected);
    println!("✓ Subtraction: 9 - 7 = 2");

    // Test 5: Multiplication
    let product = seven.mul(&nine);
    let expected = FieldElement52::from_u64(63);
    assert_eq!(product, expected);
    println!("✓ Multiplication: 7 * 9 = 63");

    // Test 6: Squaring
    let squared = seven.square();
    let expected = FieldElement52::from_u64(49);
    assert_eq!(squared, expected);
    println!("✓ Squaring: 7^2 = 49");

    // Test 7: Doubling
    let doubled = seven.double();
    let expected = FieldElement52::from_u64(14);
    assert_eq!(doubled, expected);
    println!("✓ Doubling: 2*7 = 14");

    // Test 8: mul3
    let tripled = seven.mul3();
    let expected = FieldElement52::from_u64(21);
    assert_eq!(tripled, expected);
    println!("✓ mul3: 3*7 = 21");

    // Test 9: Negation
    let neg_seven = seven.neg();
    let sum = seven.add(&neg_seven);
    assert_eq!(sum, zero);
    println!("✓ Negation: 7 + (-7) = 0");

    // Test 10: Inversion
    let inv_seven = seven.invert().unwrap();
    let product = seven.mul(&inv_seven);
    assert_eq!(product, one);
    println!("✓ Inversion: 7 * 7^-1 = 1");

    // Test 11: Lazy addition
    let a = FieldElement52::from_u64(1);
    let mut sum = a;
    for _ in 0..100 {
        sum = sum.add_lazy(&a);
    }
    let normalized = sum.normalized();
    let expected = FieldElement52::from_u64(101);
    assert_eq!(normalized, expected);
    println!("✓ Lazy addition: 100 lazy adds + normalize = 101");

    // Test 12: Bytes roundtrip
    let original = FieldElement52::from_u64(0x123456789ABCDEF0);
    let bytes = original.to_bytes();
    let recovered = FieldElement52::from_bytes(&bytes);
    assert_eq!(original, recovered);
    println!("✓ Bytes roundtrip successful");

    println!("\n✅ All tests passed!");
}
