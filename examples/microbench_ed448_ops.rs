use std::time::Instant;
use hpcrypt_curves::ed448::{Point, Scalar};

fn main() {
    println!("=== Ed448 Operation Micro-Benchmarks ===\n");

    let scalar1 = Scalar::from_bytes(&[1u8; 57]);
    let scalar2 = Scalar::from_bytes(&[2u8; 57]);
    let p1 = Point::generator().scalar_mul(&scalar1);
    let p2 = Point::generator().scalar_mul(&scalar2);

    let iterations = 10000;

    // Benchmark point addition
    println!("1. Point Addition");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = p1.add(&p2);
    }
    let elapsed = start.elapsed();
    println!("   {} iterations: {:?}", iterations, elapsed);
    println!("   Per operation: {:?}\n", elapsed / iterations);

    // Benchmark point doubling
    println!("2. Point Doubling");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = p1.double();
    }
    let elapsed = start.elapsed();
    println!("   {} iterations: {:?}", iterations, elapsed);
    println!("   Per operation: {:?}\n", elapsed / iterations);

    // Benchmark field multiplication
    use hpcrypt_curves::ed448::FieldElement;
    let a = FieldElement::from_limbs([1, 2, 3, 4, 5, 6, 7, 8]);
    let b = FieldElement::from_limbs([8, 7, 6, 5, 4, 3, 2, 1]);

    println!("3. Field Multiplication");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = a * b;
    }
    let elapsed = start.elapsed();
    println!("   {} iterations: {:?}", iterations, elapsed);
    println!("   Per operation: {:?}\n", elapsed / iterations);

    // Benchmark field inversion
    println!("4. Field Inversion (expensive!)");
    let iterations_inv = 100;  // Much fewer iterations
    let start = Instant::now();
    for _ in 0..iterations_inv {
        let _ = a.invert();
    }
    let elapsed = start.elapsed();
    println!("   {} iterations: {:?}", iterations_inv, elapsed);
    println!("   Per operation: {:?}\n", elapsed / iterations_inv);
}
