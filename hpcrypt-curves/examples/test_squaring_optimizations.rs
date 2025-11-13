// Test correctness of optimized squaring implementations

use hpcrypt_curves::secp256k1::{FieldElement, FieldElement52};

fn main() {
    println!("=== Testing Squaring Optimizations ===\n");

    // Test values
    let test_values = vec![
        2u64,
        7,
        13,
        42,
        100,
        255,
        256,
        1000,
        12345,
        67890,
        0xFFFF,
        0x10000,
        0xFFFFFFFF,
        0x100000000,
        0xFFFFFFFFFFFF,
        0x123456789ABCDEF0,
    ];

    println!("Testing 64-bit squaring optimizations:\n");

    let mut all_pass = true;
    for &val in &test_values {
        let x = FieldElement::from_u64(val);

        let sq_current = x.square();
        let sq_unrolled = x.square_unrolled();
        let sq_mul = x.mul(&x);

        if sq_current != sq_unrolled {
            println!("✗ {}²: unrolled MISMATCH", val);
            all_pass = false;
        } else if sq_current != sq_mul {
            println!("✗ {}²: doesn't match mul(self, self)", val);
            all_pass = false;
        } else {
            println!("✓ {}²: all methods match", val);
        }
    }

    if all_pass {
        println!("\n All 64-bit squaring optimizations CORRECT\n");
    } else {
        println!("\n Some 64-bit squaring optimizations FAILED\n");
    }

    println!("Testing 52-bit squaring optimizations:\n");

    all_pass = true;
    for &val in &test_values {
        let x = FieldElement52::from_u64(val);

        let sq_current = x.square();
        let sq_unrolled = x.square_unrolled();
        let sq_karatsuba = x.square_karatsuba();
        let sq_mul = x.mul(&x);

        let mut methods_match = true;

        if sq_current != sq_unrolled {
            println!("✗ {}²: unrolled MISMATCH", val);
            methods_match = false;
            all_pass = false;
        }

        if sq_current != sq_karatsuba {
            println!("✗ {}²: karatsuba MISMATCH", val);
            methods_match = false;
            all_pass = false;
        }

        if sq_current != sq_mul {
            println!("✗ {}²: doesn't match mul(self, self)", val);
            methods_match = false;
            all_pass = false;
        }

        if methods_match {
            println!("✓ {}²: all methods match", val);
        }
    }

    if all_pass {
        println!("\n All 52-bit squaring optimizations CORRECT\n");
    } else {
        println!("\n Some 52-bit squaring optimizations FAILED\n");
    }

    println!("Testing cross-implementation consistency:\n");

    all_pass = true;
    for &val in &test_values {
        let x_64 = FieldElement::from_u64(val);
        let x_52 = FieldElement52::from_u64(val);

        let sq_64_current = x_64.square();
        let sq_64_unrolled = x_64.square_unrolled();

        let sq_52_current = x_52.square();
        let sq_52_unrolled = x_52.square_unrolled();
        let sq_52_karatsuba = x_52.square_karatsuba();

        // All should produce the same bytes
        let bytes_64_current = sq_64_current.to_bytes();
        let bytes_64_unrolled = sq_64_unrolled.to_bytes();
        let bytes_52_current = sq_52_current.to_bytes();
        let bytes_52_unrolled = sq_52_unrolled.to_bytes();
        let bytes_52_karatsuba = sq_52_karatsuba.to_bytes();

        if bytes_64_current == bytes_52_current
            && bytes_64_current == bytes_52_unrolled
            && bytes_64_current == bytes_52_karatsuba
            && bytes_64_current == bytes_64_unrolled
        {
            println!("✓ {}²: 64-bit and 52-bit implementations match", val);
        } else {
            println!("✗ {}²: 64-bit and 52-bit MISMATCH", val);
            all_pass = false;

            if bytes_64_current != bytes_64_unrolled {
                println!("  64-bit current != unrolled");
            }
            if bytes_64_current != bytes_52_current {
                println!("  64-bit != 52-bit current");
            }
            if bytes_64_current != bytes_52_unrolled {
                println!("  64-bit != 52-bit unrolled");
            }
            if bytes_64_current != bytes_52_karatsuba {
                println!("  64-bit != 52-bit karatsuba");
            }
        }
    }

    if all_pass {
        println!("\n All implementations produce consistent results!\n");
    } else {
        println!("\n Implementations have inconsistencies!\n");
    }

    // Test repeated squaring (exponentiation pattern)
    println!("Testing repeated squaring:\n");

    let base_64 = FieldElement::from_u64(13);
    let base_52 = FieldElement52::from_u64(13);

    let mut x_64_current = base_64;
    let mut x_64_unrolled = base_64;
    let mut x_52_current = base_52;
    let mut x_52_unrolled = base_52;
    let mut x_52_karatsuba = base_52;

    for i in 0..8 {
        x_64_current = x_64_current.square();
        x_64_unrolled = x_64_unrolled.square_unrolled();
        x_52_current = x_52_current.square();
        x_52_unrolled = x_52_unrolled.square_unrolled();
        x_52_karatsuba = x_52_karatsuba.square_karatsuba();

        let bytes_64_current = x_64_current.to_bytes();
        let bytes_64_unrolled = x_64_unrolled.to_bytes();
        let bytes_52_current = x_52_current.to_bytes();
        let bytes_52_unrolled = x_52_unrolled.to_bytes();
        let bytes_52_karatsuba = x_52_karatsuba.to_bytes();

        if bytes_64_current == bytes_64_unrolled
            && bytes_64_current == bytes_52_current
            && bytes_64_current == bytes_52_unrolled
            && bytes_64_current == bytes_52_karatsuba
        {
            println!(
                "✓ Iteration {}: 13^(2^{}) - all methods match",
                i + 1,
                i + 1
            );
        } else {
            println!("✗ Iteration {}: MISMATCH in repeated squaring", i + 1);
        }
    }

    println!("\n=== All Tests Complete ===");
}
