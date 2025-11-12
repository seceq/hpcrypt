// Regression test to ensure field inversions return canonical results
//
// This test was created after discovering that safegcd_invert_vartime_p384()
// was returning non-canonical results (negative or >= modulus), causing
// ~16.8% of affine coordinate conversions to fail.

use hpcrypt_curves::p384::field::FieldElement as P384Field;
use hpcrypt_curves::p256::field::FieldElement as P256Field;
use hpcrypt_curves::p521::field::FieldElement as P521Field;

/// Test that field inversion returns results in canonical form [0, p)
#[test]
fn test_p256_inversion_canonical() {
    // Test with various values
    let test_values = [
        P256Field::from_u64(1),
        P256Field::from_u64(2),
        P256Field::from_u64(3),
        P256Field::from_u64(10),
        P256Field::from_u64(100),
        P256Field::from_u64(12345),
        P256Field::from_u64(u64::MAX),
    ];

    for value in &test_values {
        let inv = value.invert();

        // Check that inv * value = 1
        let product = inv.mul(value);
        assert_eq!(product, P256Field::from_u64(1),
            "Inverse should satisfy inv * value = 1");

        // Check that inv is in canonical form
        // We can verify this by checking that inv < modulus
        // by converting to bytes and checking it's a valid field element
        let inv_bytes = inv.to_bytes();
        let reconstructed = P256Field::from_bytes(&inv_bytes);
        assert!(reconstructed.is_some(),
            "Inverse should be in canonical form [0, p)");
        assert_eq!(reconstructed.unwrap(), inv,
            "Inverse should round-trip through bytes");
    }
}

#[test]
fn test_p384_inversion_canonical() {
    // Test with various values including those that previously failed
    let test_values = [
        P384Field::from_u64(1),
        P384Field::from_u64(2),
        P384Field::from_u64(3),
        P384Field::from_u64(10),
        P384Field::from_u64(100),
        P384Field::from_u64(12345),
        P384Field::from_u64(u64::MAX),
    ];

    for value in &test_values {
        let inv = value.invert();

        // Check that inv * value = 1
        let product = inv.mul(value);
        assert_eq!(product, P384Field::from_u64(1),
            "Inverse should satisfy inv * value = 1");

        // Check that inv is in canonical form
        let inv_bytes = inv.to_bytes();
        let reconstructed = P384Field::from_bytes(&inv_bytes);
        assert!(reconstructed.is_some(),
            "Inverse should be in canonical form [0, p)");
        assert_eq!(reconstructed.unwrap(), inv,
            "Inverse should round-trip through bytes");
    }
}

#[test]
fn test_p521_inversion_canonical() {
    // Test with various values
    let test_values = [
        P521Field::from_u64(1),
        P521Field::from_u64(2),
        P521Field::from_u64(3),
        P521Field::from_u64(10),
        P521Field::from_u64(100),
        P521Field::from_u64(12345),
        P521Field::from_u64(u64::MAX),
    ];

    for value in &test_values {
        let inv = value.invert();

        // Check that inv * value = 1
        let product = inv.mul(value);
        assert_eq!(product, P521Field::from_u64(1),
            "Inverse should satisfy inv * value = 1");

        // Check that inv is in canonical form
        let inv_bytes = inv.to_bytes();
        let reconstructed = P521Field::from_bytes(&inv_bytes);
        assert!(reconstructed.is_some(),
            "Inverse should be in canonical form [0, p)");
        assert_eq!(reconstructed.unwrap(), inv,
            "Inverse should round-trip through bytes");
    }
}

/// Test specific Z-coordinates that were causing failures in P-384
#[test]
fn test_p384_problematic_z_coordinates() {
    use hpcrypt_curves::p384::Point;

    // These scalar multiplications produced Z-coordinates whose inverses
    // were not canonical before the fix
    let problematic_k_values = [10u8, 19, 24, 25, 28, 32, 36, 38, 39];

    let g = Point::generator();

    for &k in &problematic_k_values {
        let mut k_bytes = [0u8; 48];
        k_bytes[47] = k;

        // Compute k*G via Montgomery ladder
        let point = g.scalar_mul_constant_time(&k_bytes);

        // Convert to affine (this internally calls field inversion on Z)
        let affine = point.to_affine();
        assert!(affine.is_some(),
            "Point for k={} should convert to affine", k);

        // Verify the affine point is valid by converting back
        let reconstructed = Point::from_affine(&affine.unwrap());
        assert_eq!(reconstructed, point,
            "Point for k={} should round-trip through affine", k);
    }
}

/// Test that multiple methods of computing the same point produce
/// identical affine coordinates
#[test]
fn test_p384_multiple_computation_methods_consistent() {
    use hpcrypt_curves::p384::Point;

    let g = Point::generator();

    // Test for k=10 (one of the values that failed before the fix)
    let mut ten = [0u8; 48];
    ten[47] = 10;

    // Method 1: Direct scalar multiplication
    let method1 = g.scalar_mul_constant_time(&ten);

    // Method 2: 5*G + 5*G
    let mut five = [0u8; 48];
    five[47] = 5;
    let g5 = g.scalar_mul_constant_time(&five);
    let method2 = g5.add(&g5);

    // Method 3: 9*G + G
    let mut nine = [0u8; 48];
    nine[47] = 9;
    let g9 = g.scalar_mul_constant_time(&nine);
    let method3 = g9.add(&g);

    // All should produce the same affine coordinates
    let aff1 = method1.to_affine().unwrap();
    let aff2 = method2.to_affine().unwrap();
    let aff3 = method3.to_affine().unwrap();

    assert_eq!(aff1.x, aff2.x, "All methods should produce same x-coordinate");
    assert_eq!(aff1.y, aff2.y, "All methods should produce same y-coordinate");
    assert_eq!(aff1.x, aff3.x, "All methods should produce same x-coordinate");
    assert_eq!(aff1.y, aff3.y, "All methods should produce same y-coordinate");
}
