// Test to verify the add_niels bug in Ed448
// Run with: rustc --edition 2021 test_add_niels_bug.rs -L target/debug/deps --extern hpcrypt_curves=target/debug/libhpcrypt_curves.rlib && ./test_add_niels_bug

use hpcrypt_curves::ed448::{Point, Scalar};

fn main() {
    println!("Testing Ed448 add_niels bug...\n");

    // Create base point
    let base = Point::generator();
    let base_niels = base.to_niels();

    // Create point_5b = 5 * base
    let scalar_5 = Scalar::from_u64(5);
    let point_5b = base.scalar_mul(&scalar_5);

    println!("Testing: point_5b + base");
    println!("Expected: 6 * base");
    println!();

    // Method 1: Using regular add
    let result_regular = point_5b.add(&base);
    println!("Method 1 (regular add): point_5b.add(&base)");
    println!("  X: {:?}", result_regular.x);
    println!("  Y: {:?}", result_regular.y);
    println!();

    // Method 2: Using add_niels (BUGGY)
    let result_niels = point_5b.add_niels(&base_niels);
    println!("Method 2 (add_niels): point_5b.add_niels(&base_niels)");
    println!("  X: {:?}", result_niels.x);
    println!("  Y: {:?}", result_niels.y);
    println!();

    // Method 3: Direct computation of 6 * base
    let scalar_6 = Scalar::from_u64(6);
    let point_6b = base.scalar_mul(&scalar_6);
    println!("Method 3 (direct): 6 * base");
    println!("  X: {:?}", point_6b.x);
    println!("  Y: {:?}", point_6b.y);
    println!();

    // Compare
    println!("=== Comparison ===");
    println!("Regular add == Direct computation: {}", result_regular.eq(&point_6b));
    println!("add_niels == Direct computation: {}", result_niels.eq(&point_6b));
    println!("Regular add == add_niels: {}", result_regular.eq(&result_niels));
    println!();

    if result_regular.eq(&point_6b) && !result_niels.eq(&point_6b) {
        println!("BUG CONFIRMED: add_niels produces incorrect results!");
        println!("The bug is likely in the H computation (should be B - A for a=1 curves)");
    } else if result_regular.eq(&result_niels) && result_regular.eq(&point_6b) {
        println!("SUCCESS: add_niels is working correctly!");
    } else {
        println!("UNEXPECTED: Something else is wrong!");
    }
}
