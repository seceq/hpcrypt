// Comprehensive test comparing both field implementations
use hpcrypt_curves::secp256k1::{FieldElement, FieldElement52};

fn main() {
    println!("=== Testing Both secp256k1 Field Implementations ===\n");

    // Test values
    let test_cases = vec![
        (7u64, 9u64),
        (123, 456),
        (12345, 67890),
        (0xFFFF, 0x10000),
        (0xFFFFFFFF, 2),
        (123456789, 987654321),
    ];

    println!("Testing multiplication consistency between 64-bit and 52-bit implementations:\n");

    for (a_val, b_val) in &test_cases {
        let a_64 = FieldElement::from_u64(*a_val);
        let b_64 = FieldElement::from_u64(*b_val);
        let product_64 = a_64.mul(&b_64);

        let a_52 = FieldElement52::from_u64(*a_val);
        let b_52 = FieldElement52::from_u64(*b_val);
        let product_52 = a_52.mul(&b_52);

        // Convert both to bytes and compare
        let bytes_64 = product_64.to_bytes();
        let bytes_52 = product_52.to_bytes();

        if bytes_64 == bytes_52 {
            println!("✓ {} × {} matches", a_val, b_val);
        } else {
            println!("✗ {} × {} MISMATCH!", a_val, b_val);
            println!("  64-bit: {:02x?}", &bytes_64[..8]);
            println!("  52-bit: {:02x?}", &bytes_52[..8]);
        }
    }

    println!("\nTesting squaring consistency:\n");

    let square_tests = vec![2u64, 7, 13, 42, 100, 12345, 0xFFFF];
    for val in &square_tests {
        let a_64 = FieldElement::from_u64(*val);
        let squared_64 = a_64.square();

        let a_52 = FieldElement52::from_u64(*val);
        let squared_52 = a_52.square();

        let bytes_64 = squared_64.to_bytes();
        let bytes_52 = squared_52.to_bytes();

        if bytes_64 == bytes_52 {
            println!("✓ {}² matches", val);
        } else {
            println!("✗ {}² MISMATCH!", val);
        }
    }

    println!("\nTesting addition consistency:\n");

    for (a_val, b_val) in &test_cases[..3] {
        let a_64 = FieldElement::from_u64(*a_val);
        let b_64 = FieldElement::from_u64(*b_val);
        let sum_64 = a_64.add(&b_64);

        let a_52 = FieldElement52::from_u64(*a_val);
        let b_52 = FieldElement52::from_u64(*b_val);
        let sum_52 = a_52.add(&b_52);

        let bytes_64 = sum_64.to_bytes();
        let bytes_52 = sum_52.to_bytes();

        if bytes_64 == bytes_52 {
            println!("✓ {} + {} matches", a_val, b_val);
        } else {
            println!("✗ {} + {} MISMATCH!", a_val, b_val);
        }
    }

    println!("\nTesting Karatsuba correctness (64-bit):\n");

    // Test that 64-bit Karatsuba produces correct results
    let a = FieldElement::from_u64(123456789);
    let b = FieldElement::from_u64(987654321);
    let product = a.mul(&b);

    // Expected: 123456789 * 987654321 = 121932631112635269 (mod p)
    let expected_product = 121932631112635269u64;
    let expected = FieldElement::from_u64(expected_product);

    if product == expected {
        println!("✓ 64-bit Karatsuba: 123456789 × 987654321 = {}", expected_product);
    } else {
        println!("✗ 64-bit Karatsuba INCORRECT!");
    }

    // Test commutativity
    let product_rev = b.mul(&a);
    if product == product_rev {
        println!("✓ 64-bit Karatsuba: Multiplication is commutative");
    } else {
        println!("✗ 64-bit Karatsuba: NOT commutative!");
    }

    println!("\nTesting Karatsuba correctness (52-bit):\n");

    let a_52 = FieldElement52::from_u64(123456789);
    let b_52 = FieldElement52::from_u64(987654321);
    let product_52 = a_52.mul(&b_52);

    let expected_52 = FieldElement52::from_u64(expected_product);

    if product_52 == expected_52 {
        println!("✓ 52-bit Karatsuba: 123456789 × 987654321 = {}", expected_product);
    } else {
        println!("✗ 52-bit Karatsuba INCORRECT!");
    }

    // Test commutativity
    let product_rev_52 = b_52.mul(&a_52);
    if product_52 == product_rev_52 {
        println!("✓ 52-bit Karatsuba: Multiplication is commutative");
    } else {
        println!("✗ 52-bit Karatsuba: NOT commutative!");
    }

    println!("\nTesting lazy reduction (52-bit only):\n");

    let one = FieldElement52::from_u64(1);
    let mut sum = one;

    // Do 100 lazy additions
    for _ in 0..100 {
        sum = sum.add_lazy(&one);
    }

    let normalized = sum.normalized();
    let expected_101 = FieldElement52::from_u64(101);

    if normalized == expected_101 {
        println!("✓ Lazy reduction: 100 lazy adds + normalize = 101");
    } else {
        println!("✗ Lazy reduction FAILED!");
    }

    println!("\nTesting inversion:\n");

    let val_64 = FieldElement::from_u64(42);
    let inv_64 = val_64.invert().unwrap();
    let check_64 = val_64.mul(&inv_64);

    if check_64 == FieldElement::ONE {
        println!("✓ 64-bit: 42 × 42⁻¹ = 1");
    } else {
        println!("✗ 64-bit inversion FAILED!");
    }

    let val_52 = FieldElement52::from_u64(42);
    let inv_52 = val_52.invert().unwrap();
    let check_52 = val_52.mul(&inv_52);

    if check_52 == FieldElement52::ONE {
        println!("✓ 52-bit: 42 × 42⁻¹ = 1");
    } else {
        println!("✗ 52-bit inversion FAILED!");
    }

    println!("\nTesting field properties (both implementations):\n");

    // Test associativity: (a * b) * c = a * (b * c)
    let a_64 = FieldElement::from_u64(7);
    let b_64 = FieldElement::from_u64(11);
    let c_64 = FieldElement::from_u64(13);

    let left_64 = a_64.mul(&b_64).mul(&c_64);
    let right_64 = a_64.mul(&b_64.mul(&c_64));

    if left_64 == right_64 {
        println!("✓ 64-bit: Multiplication is associative");
    } else {
        println!("✗ 64-bit: Multiplication NOT associative!");
    }

    let a_52 = FieldElement52::from_u64(7);
    let b_52 = FieldElement52::from_u64(11);
    let c_52 = FieldElement52::from_u64(13);

    let left_52 = a_52.mul(&b_52).mul(&c_52);
    let right_52 = a_52.mul(&b_52.mul(&c_52));

    if left_52 == right_52 {
        println!("✓ 52-bit: Multiplication is associative");
    } else {
        println!("✗ 52-bit: Multiplication NOT associative!");
    }

    // Test distributivity: a * (b + c) = a * b + a * c
    let left_64 = a_64.mul(&b_64.add(&c_64));
    let right_64 = a_64.mul(&b_64).add(&a_64.mul(&c_64));

    if left_64 == right_64 {
        println!("✓ 64-bit: Multiplication is distributive");
    } else {
        println!("✗ 64-bit: Multiplication NOT distributive!");
    }

    let left_52 = a_52.mul(&b_52.add(&c_52));
    let right_52 = a_52.mul(&b_52).add(&a_52.mul(&c_52));

    if left_52 == right_52 {
        println!("✓ 52-bit: Multiplication is distributive");
    } else {
        println!("✗ 52-bit: Multiplication NOT distributive!");
    }

    println!("\n=== All Tests Complete ===");
}
