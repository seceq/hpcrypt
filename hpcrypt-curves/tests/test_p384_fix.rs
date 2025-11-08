use hpcrypt_curves::p384::Point;

#[test]
fn test_10g_fix() {
    let g = Point::generator();

    // Method 1: 9*G + G
    let mut nine = [0u8; 48];
    nine[47] = 9;
    let g9 = g.scalar_mul_constant_time(&nine);
    let method1 = g9.add(&g);

    // Method 2: Montgomery ladder
    let mut ten = [0u8; 48];
    ten[47] = 10;
    let method2 = g.scalar_mul_constant_time(&ten);

    // Method 4: 5*G + 5*G
    let mut five = [0u8; 48];
    five[47] = 5;
    let g5 = g.scalar_mul_constant_time(&five);
    let method4 = g5.add(&g5);

    let aff1 = method1.to_affine().unwrap();
    let aff2 = method2.to_affine().unwrap();
    let aff4 = method4.to_affine().unwrap();

    println!("Method 1: {:02x?}...", &aff1.x.to_bytes()[..8]);
    println!("Method 2: {:02x?}...", &aff2.x.to_bytes()[..8]);
    println!("Method 4: {:02x?}...", &aff4.x.to_bytes()[..8]);

    // After fix, all should match
    assert_eq!(aff1.x, aff2.x, "Method 1 and 2 should have same x");
    assert_eq!(aff1.x, aff4.x, "Method 1 and 4 should have same x");
    assert_eq!(aff1.y, aff2.y, "Method 1 and 2 should have same y");
    assert_eq!(aff1.y, aff4.y, "Method 1 and 4 should have same y");
}
