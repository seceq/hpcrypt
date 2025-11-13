// Test that the Fermat inversion fix resolves the P-384 affine conversion bug
use hpcrypt_curves::p384::Point;

#[test]
fn test_10g_multiple_methods_match() {
    let g = Point::generator();

    // Method 1: 9*G + G (was producing correct result)
    let mut nine = [0u8; 48];
    nine[47] = 9;
    let g9 = g.scalar_mul_constant_time(&nine);
    let method1 = g9.add(&g);

    // Method 2: Montgomery ladder (was producing wrong result)
    let mut ten = [0u8; 48];
    ten[47] = 10;
    let method2 = g.scalar_mul_constant_time(&ten);

    // Method 3: 8*G + 2*G (was producing correct result)
    let g2 = g.double();
    let g8 = g2.double().double();
    let method3 = g8.add(&g2);

    // Method 4: 5*G + 5*G (was producing wrong result)
    let mut five = [0u8; 48];
    five[47] = 5;
    let g5 = g.scalar_mul_constant_time(&five);
    let method4 = g5.add(&g5);

    // Get affine coordinates
    let aff1 = method1.to_affine().unwrap();
    let aff2 = method2.to_affine().unwrap();
    let aff3 = method3.to_affine().unwrap();
    let aff4 = method4.to_affine().unwrap();

    // Expected x coordinate for 10*G from Python reference
    let expected_x_bytes: [u8; 48] = [
        0xa6, 0x69, 0xc5, 0x56, 0x3b, 0xd6, 0x7e, 0xec, 0x67, 0x8d, 0x29, 0xd6, 0xef, 0x4f, 0xde,
        0x86, 0x4f, 0x37, 0x2d, 0x90, 0xb7, 0x9b, 0x9e, 0x88, 0x93, 0x1d, 0x5c, 0x29, 0x29, 0x12,
        0x38, 0xcc, 0xed, 0x8e, 0x85, 0xab, 0x50, 0x7b, 0xf9, 0x1a, 0xa9, 0xcb, 0x2d, 0x13, 0x18,
        0x66, 0x58, 0xfb,
    ];

    // After fix, all methods should produce the same (correct) result
    assert_eq!(
        aff1.x.to_bytes().as_ref(),
        &expected_x_bytes,
        "Method 1 (9*G+G) should match Python reference"
    );
    assert_eq!(
        aff2.x.to_bytes().as_ref(),
        &expected_x_bytes,
        "Method 2 (ladder) should match Python reference"
    );
    assert_eq!(
        aff3.x.to_bytes().as_ref(),
        &expected_x_bytes,
        "Method 3 (8*G+2*G) should match Python reference"
    );
    assert_eq!(
        aff4.x.to_bytes().as_ref(),
        &expected_x_bytes,
        "Method 4 (5*G+5*G) should match Python reference"
    );

    // All should be equal to each other
    assert_eq!(aff1.x, aff2.x, "All x-coordinates should match");
    assert_eq!(aff1.x, aff3.x, "All x-coordinates should match");
    assert_eq!(aff1.x, aff4.x, "All x-coordinates should match");
    assert_eq!(aff1.y, aff2.y, "All y-coordinates should match");
    assert_eq!(aff1.y, aff3.y, "All y-coordinates should match");
    assert_eq!(aff1.y, aff4.y, "All y-coordinates should match");
}

#[test]
fn test_all_failing_k_values() {
    // These 43 values were failing with safegcd inversion
    let failing_k_values = [
        10, 19, 24, 25, 28, 32, 36, 38, 39, 64, 76, 80, 88, 90, 102, 119, 120, 125, 130, 131, 145,
        146, 148, 159, 169, 170, 179, 192, 193, 204, 209, 212, 223, 225, 227, 232, 233, 243, 248,
        249, 252, 254, 255,
    ];

    let g = Point::generator();

    for &k in &failing_k_values {
        let mut k_bytes = [0u8; 48];
        k_bytes[47] = k;

        // Compute k*G via Montgomery ladder
        let result_ladder = g.scalar_mul_constant_time(&k_bytes);

        // Compute k*G via repeated addition (slow but reliable)
        let mut result_add = Point::infinity();
        for _ in 0..k {
            result_add = result_add.add(&g);
        }

        // Both methods should produce same affine coordinates
        let aff_ladder = result_ladder.to_affine().unwrap();
        let aff_add = result_add.to_affine().unwrap();

        assert_eq!(
            aff_ladder.x, aff_add.x,
            "k={}: ladder and repeated addition should match (x-coordinate)",
            k
        );
        assert_eq!(
            aff_ladder.y, aff_add.y,
            "k={}: ladder and repeated addition should match (y-coordinate)",
            k
        );
    }
}
