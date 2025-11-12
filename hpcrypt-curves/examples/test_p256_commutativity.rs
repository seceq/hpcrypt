// Debug test for P-256 point addition commutativity issue
//
// Problem: Q+P gives wrong affine x-coordinate compared to P+Q
// Python shows both should be equal (commutativity)

use hpcrypt_curves::p256::field::FieldElement;
use hpcrypt_curves::p256::point::{Point, AffinePoint};

fn print_limbs(name: &str, fe: &FieldElement) {
    let bytes = fe.to_bytes();
    print!("{}: 0x", name);
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();
}

fn print_affine(name: &str, p: &AffinePoint) {
    println!("{}:", name);
    print_limbs("  x", &p.x);
    print_limbs("  y", &p.y);
}

fn main() {
    println!("=== P-256 Point Addition Commutativity Debug ===\n");

    // Test points from the bug report - create via affine coordinates
    let p_affine = AffinePoint {
        x: FieldElement::from_u64(5),
        y: FieldElement::from_u64(7),
    };
    let p = Point::from_affine(&p_affine);

    let q_affine = AffinePoint {
        x: FieldElement::from_u64(2),
        y: FieldElement::from_u64(3),
    };
    let q = Point::from_affine(&q_affine);

    println!("Input points: P(5,7) and Q(2,3)");

    // Compute P+Q
    println!("\nComputing P+Q...");
    let p_plus_q = p.add(&q);
    let p_plus_q_affine = p_plus_q.to_affine().expect("P+Q should not be infinity");
    print_affine("P+Q", &p_plus_q_affine);

    // Compute Q+P
    println!("\nComputing Q+P...");
    let q_plus_p = q.add(&p);
    let q_plus_p_affine = q_plus_p.to_affine().expect("Q+P should not be infinity");
    print_affine("Q+P", &q_plus_p_affine);

    // Compare
    println!("=== Comparison ===");
    println!("Affine X coordinates match: {}", p_plus_q_affine.x == q_plus_p_affine.x);
    println!("Affine Y coordinates match: {}", p_plus_q_affine.y == q_plus_p_affine.y);
    println!();

    // Expected from Python:
    // P+Q affine x: 0x8e38e38daaaaaaab38e38e38e38e38e38e38e38ec71c71c71c71c71c71c71c6c
    println!("Expected affine x (from Python):");
    println!("  0x8e38e38daaaaaaab38e38e38e38e38e38e38e38ec71c71c71c71c71c71c71c6c");
    println!();

    println!("\n=== Debugging ===");

    // Test: Can we invert p-3 correctly?
    println!("=== Testing inversion of p-3 ===");
    let p_minus_3 = FieldElement::from_limbs([
        0xfffffffffffffffc,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ]);
    print_limbs("p-3", &p_minus_3);

    println!("Inverting p-3...");
    let inv_p_minus_3 = p_minus_3.invert();
    print_limbs("(p-3)^-1", &inv_p_minus_3);

    // Verify: (p-3) * (p-3)^-1 should equal 1
    let check = p_minus_3.mul(&inv_p_minus_3);
    print_limbs("(p-3) * (p-3)^-1", &check);
    println!("Equals 1: {}", check == FieldElement::one());
    println!();

    // Test: Compute (p-3)^2 to see if reduction works
    println!("=== Testing (p-3)^2 ===");
    let p_minus_3_squared = p_minus_3.mul(&p_minus_3);
    print_limbs("(p-3)^2 mod p", &p_minus_3_squared);

    // Expected: (p-3)^2 = p^2 - 6p + 9 ≡ 9 (mod p)
    println!("Expected: 9");
    println!("Equals 9: {}", p_minus_3_squared == FieldElement::from_u64(9));
    println!();



    if p_plus_q_affine.x != q_plus_p_affine.x {
        println!("❌ COMMUTATIVITY VIOLATED: P+Q ≠ Q+P");
        std::process::exit(1);
    } else {
        println!("✅ COMMUTATIVITY OK: P+Q = Q+P");
    }
}
