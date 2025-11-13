//! X25519 Diffie-Hellman key exchange
//!
//! Implementation of the X25519 function as specified in RFC 7748.

use crate::ct_utils::{Choice, ConditionallySelectable};
use crate::field25519::FieldElement;
use hpcrypt_core::error::CurveError;

/// X25519 private key (32 bytes)
pub const X25519_PRIVATE_KEY_LEN: usize = 32;

/// X25519 public key (32 bytes)
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// X25519 shared secret (32 bytes)
pub const X25519_SHARED_SECRET_LEN: usize = 32;

/// The X25519 basepoint (u=9)
const BASEPOINT_U: FieldElement = FieldElement::from_limbs([9, 0, 0, 0, 0]);

/// X25519 public API
pub struct X25519;

impl X25519 {
    /// Generate a public key from a private key
    ///
    /// Takes a 32-byte private key and returns the corresponding 32-byte public key.
    /// The private key is clamped according to RFC 7748.
    pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
        let mut clamped = *private_key;
        clamp_scalar(&mut clamped);

        scalar_mult_base(&clamped)
    }

    /// Compute shared secret from private and public keys
    ///
    /// Returns the 32-byte shared secret computed from your private key
    /// and the other party's public key.
    pub fn shared_secret(
        private_key: &[u8; 32],
        public_key: &[u8; 32],
    ) -> Result<[u8; 32], CurveError> {
        let mut clamped = *private_key;
        clamp_scalar(&mut clamped);

        let result = scalar_mult(&clamped, public_key);

        // Check for low-order points (security requirement)
        // An all-zero result indicates the identity point or low-order point
        if is_zero(&result) {
            return Err(CurveError::IdentityPoint);
        }

        Ok(result)
    }
}

/// Clamp scalar according to RFC 7748
///
/// Clear bits 0, 1, 2, 255 and set bit 254
fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248; // Clear bits 0, 1, 2
    scalar[31] &= 127; // Clear bit 255
    scalar[31] |= 64; // Set bit 254
}

/// Scalar multiplication with the base point
fn scalar_mult_base(scalar: &[u8; 32]) -> [u8; 32] {
    let u = BASEPOINT_U;
    montgomery_ladder(scalar, &u)
}

/// Scalar multiplication with arbitrary point
fn scalar_mult(scalar: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    let u = FieldElement::from_bytes(u_bytes);
    montgomery_ladder(scalar, &u)
}

/// Montgomery ladder for constant-time scalar multiplication
///
/// Computes scalar * point using the Montgomery ladder algorithm,
/// which runs in constant time regardless of the scalar value.
///
/// This implementation follows RFC 7748 Section 5 literally.
fn montgomery_ladder(scalar: &[u8; 32], u: &FieldElement) -> [u8; 32] {
    // RFC 7748 Section 5:
    // For X25519, bits = 255
    let x_1 = *u;
    let mut x_2 = FieldElement::ONE;
    let mut z_2 = FieldElement::ZERO;
    let mut x_3 = *u;
    let mut z_3 = FieldElement::ONE;
    let mut swap = 0u8;

    // OPTIMIZATION: Precompute constant a24 = 121665 outside loop
    // X25519: a24 = (A + 2) / 4 = (486662 + 2) / 4 = 121666 (but RFC 7748 uses 121665)
    let a24 = FieldElement::from_limbs([121665, 0, 0, 0, 0]);

    // For t = bits-1 down to 0:
    // For X25519, that's t = 254 down to 0
    for t in (0..255).rev() {
        let byte_idx = t / 8;
        let bit_idx = t % 8;
        let k_t = (scalar[byte_idx] >> bit_idx) & 1;

        // swap ^= k_t
        swap ^= k_t;

        // cswap(swap, x_2, x_3)
        // cswap(swap, z_2, z_3)
        let choice = Choice::from(swap);
        let x_2_new = FieldElement::conditional_select(&x_2, &x_3, choice);
        let x_3_new = FieldElement::conditional_select(&x_3, &x_2, choice);
        let z_2_new = FieldElement::conditional_select(&z_2, &z_3, choice);
        let z_3_new = FieldElement::conditional_select(&z_3, &z_2, choice);
        x_2 = x_2_new;
        x_3 = x_3_new;
        z_2 = z_2_new;
        z_3 = z_3_new;

        // swap = k_t
        swap = k_t;

        // Lazy reduction optimization: use add_unreduced/sub_unreduced in ladder
        // to avoid expensive full reductions on every operation.
        // Only multiplications and final result need full reduction.

        // A = x_2 + z_2
        let a = x_2.add_unreduced(&z_2);
        // AA = A^2
        let aa = a.square();
        // B = x_2 - z_2
        let b = x_2.sub_unreduced(&z_2);
        // BB = B^2
        let bb = b.square();
        // E = AA - BB
        let e = aa.sub_unreduced(&bb);
        // C = x_3 + z_3
        let c = x_3.add_unreduced(&z_3);
        // D = x_3 - z_3
        let d = x_3.sub_unreduced(&z_3);
        // DA = D * A
        let da = d.mul(&a);
        // CB = C * B
        let cb = c.mul(&b);
        // x_3 = (DA + CB)^2
        x_3 = da.add_unreduced(&cb).square();
        // z_3 = x_1 * (DA - CB)^2
        z_3 = x_1.mul(&da.sub_unreduced(&cb).square());
        // x_2 = AA * BB
        x_2 = aa.mul(&bb);
        // z_2 = E * (AA + a24 * E)
        z_2 = e.mul(&aa.add_unreduced(&a24.mul(&e)));
    }

    // OPTIMIZATION: Eliminate final swap
    // X25519 clamping ensures bit 0 is always 0 (scalar[0] &= 248).
    // After processing bit 0, swap = k_t = 0, so the final swap is a no-op.
    // We can directly use (x_2, z_2) without conditional selection.
    //
    // This saves 2 field element conditional selects per scalar multiplication.

    // Return x_2 / z_2
    let z_inv = z_2.invert();
    let result = x_2.mul(&z_inv);

    result.to_bytes()
}

/// Check if a field element is zero
fn is_zero(bytes: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for &b in bytes {
        result |= b;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_element_conversion() {
        // Test that from_bytes and to_bytes work correctly
        let u_coord =
            hex_literal::hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

        let fe = FieldElement::from_bytes(&u_coord);
        let bytes_back = fe.to_bytes();

        // Should round-trip correctly
        assert_eq!(u_coord, bytes_back, "from_bytes/to_bytes should round-trip");
    }

    #[test]
    fn test_simple_multiplication() {
        // Test 2 * 2 = 4
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);
        let four = two.mul(&two);
        let four_bytes = four.to_bytes();
        let expected = [
            4u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(four_bytes, expected, "2 * 2 should equal 4");

        // Test 3 * 5 = 15
        let three = FieldElement::from_limbs([3, 0, 0, 0, 0]);
        let five = FieldElement::from_limbs([5, 0, 0, 0, 0]);
        let fifteen = three.mul(&five);
        let fifteen_bytes = fifteen.to_bytes();
        let expected15 = [
            15u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(fifteen_bytes, expected15, "3 * 5 should equal 15");

        // Test 2^2 = 4 using square
        let two_squared = two.square();
        let squared_bytes = two_squared.to_bytes();
        assert_eq!(squared_bytes, expected, "2^2 should equal 4");

        // Test 3^2 = 9 using square
        let three_squared = three.square();
        let nine_bytes = three_squared.to_bytes();
        let expected9 = [
            9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(nine_bytes, expected9, "3^2 should equal 9");
    }

    #[test]
    fn test_one_inversion() {
        // Test that 1.invert() == 1
        let one = FieldElement::ONE;
        let one_inv = one.invert();
        let one_inv_bytes = one_inv.to_bytes();
        let expected = [
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(one_inv_bytes, expected, "1^{{-1}} should equal 1");

        // And check 1 * 1 = 1
        let product = one.mul(&one_inv);
        let product_bytes = product.to_bytes();
        assert_eq!(product_bytes, expected, "1 * 1^{{-1}} should equal 1");
    }

    #[test]
    fn test_large_number_operations() {
        // Test with a large number close to p
        // Use p - 1 = 2^255 - 20
        let p_minus_1_bytes = [
            236u8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ];
        let p_minus_1 = FieldElement::from_bytes(&p_minus_1_bytes);

        // (p-1) + 1 should equal 0 (mod p)
        let one = FieldElement::ONE;
        let result = p_minus_1.add(&one);
        let result_bytes = result.to_bytes();
        let expected_zero = [0u8; 32];
        assert_eq!(
            result_bytes, expected_zero,
            "(p-1) + 1 should equal 0 mod p"
        );
    }

    #[test]
    fn test_pow2k() {
        // Test that pow2k(k) equals squaring k times
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        // 2^{2^3} = 2^8 = 256
        let result = two.pow2k(3);
        let result_bytes = result.to_bytes();
        let expected = [
            0u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(result_bytes, expected, "2^{{2^3}} should equal 256");

        // Verify manually: 2 -> 4 -> 16 -> 256
        let manual = two.square().square().square();
        let manual_bytes = manual.to_bytes();
        assert_eq!(manual_bytes, expected, "Manual squaring should match pow2k");
    }

    #[test]
    fn test_specific_multiplications() {
        // Test MORE values from pow22501 chain for input=2
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        // Follow exact pow22501 logic
        let t0 = two.square(); // x^2 = 4
        let t1 = t0.square().square(); // x^8 = 256
        let t2 = two.mul(&t1); // x^9 = 512
        let t3 = t0.mul(&t2); // x^11 = 2048
        let t4 = t3.square(); // x^22 = 4194304
        let t5 = t2.mul(&t4); // x^31 = 2147483648

        // Verify t5
        assert_eq!(
            t5.to_bytes()[0..4],
            2147483648u64.to_le_bytes()[0..4],
            "t5 should be 2^31"
        );

        // Continue: t6 = t5.pow2k(5) which is x^31 squared 5 times = x^(31*32) = x^992
        let t6 = t5.pow2k(5);

        // Can't easily verify huge numbers, but check round-trip works
        let t6_bytes = t6.to_bytes();
        let t6_back = FieldElement::from_bytes(&t6_bytes);
        assert_eq!(t6.to_bytes(), t6_back.to_bytes(), "t6 should round-trip");

        // t7 = t6 * t5 = x^992 * x^31 = x^1023
        let t7 = t6.mul(&t5);
        let t7_bytes = t7.to_bytes();
        let t7_back = FieldElement::from_bytes(&t7_bytes);
        assert_eq!(t7_bytes, t7_back.to_bytes(), "t7 should round-trip");
    }

    #[test]
    fn test_many_squares() {
        // Test that doing many squarings doesn't accumulate errors
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        // Compute 2^{2^100} mod p by squaring 100 times
        let result = two.pow2k(100);

        // Now square it again and it should still produce a valid field element
        let result2 = result.square();
        let bytes = result2.to_bytes();

        // Just verify it's not garbage (we can't easily predict what it should be)
        // But we can verify that converting back and forth doesn't change it
        let fe = FieldElement::from_bytes(&bytes);
        let bytes2 = fe.to_bytes();
        assert_eq!(
            bytes, bytes2,
            "to_bytes/from_bytes should round-trip even after many operations"
        );
    }

    #[test]
    fn test_pow22501_intermediate() {
        // Test intermediate values in pow22501 for input = 2
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        // Manually compute first few steps
        let t0 = two.square(); // Should be 4
        let t0_bytes = t0.to_bytes();
        let expected_t0 = [
            4u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(t0_bytes, expected_t0, "t0 = 2^2 = 4");

        let t1 = t0.square().square(); // Should be 4^2 = 16, then 16^2 = 256
        let t1_bytes = t1.to_bytes();
        let expected_t1 = [
            0u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]; // 256 in little-endian
        assert_eq!(t1_bytes, expected_t1, "t1 = (2^2)^2 = 2^8 = 256");
    }

    #[test]
    fn test_simple_mul() {
        // Test 2 * 2 = 4
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);
        let four = two.mul(&two);
        let expected = [
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert_eq!(four.to_bytes(), expected, "2 * 2 should equal 4");
    }

    #[test]
    fn test_powers_of_2() {
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        // Test 2^4 = 16
        let two_4 = two.square().square();
        assert_eq!(two_4.to_bytes()[0], 16, "2^4 should be 16");

        // Test 2^8 = 256
        let two_8 = two_4.square();
        let expected_256 = [
            0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert_eq!(two_8.to_bytes(), expected_256, "2^8 should be 256");

        // Test 2^9 = 2 * 2^8 = 512
        let two_9 = two.mul(&two_8);
        assert_eq!(two_9.to_bytes()[0], 0, "2^9 byte 0");
        assert_eq!(two_9.to_bytes()[1], 2, "2^9 should be 512");

        // Test 2^11 = 2^2 * 2^9 = 2048
        let two_11 = two.square().mul(&two_9);
        let expected_2048 = [
            0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert_eq!(two_11.to_bytes(), expected_2048, "2^11 should be 2048");
    }

    #[test]
    fn test_pow22501_all_steps() {
        // Test EVERY step of pow22501 for input=2
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        let t0 = two.square();
        assert_eq!(&t0.to_bytes()[0..4], &[4, 0, 0, 0], "t0");

        let t1 = t0.square().square();
        assert_eq!(&t1.to_bytes()[0..4], &[0, 1, 0, 0], "t1");

        let t2 = two.mul(&t1);
        assert_eq!(&t2.to_bytes()[0..4], &[0, 2, 0, 0], "t2");

        let t3 = t0.mul(&t2);
        assert_eq!(&t3.to_bytes()[0..4], &[0, 8, 0, 0], "t3");

        let t4 = t3.square();
        assert_eq!(&t4.to_bytes()[0..4], &[0, 0, 64, 0], "t4");

        let t5 = t2.mul(&t4);
        assert_eq!(&t5.to_bytes()[0..4], &[0, 0, 0, 128], "t5");

        let t6 = t5.pow2k(5);
        let expected_t6 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(&t6.to_bytes()[0..16], &expected_t6[..], "t6");

        let t7 = t6.mul(&t5);
        let expected_t7 = [136u8, 232, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let t7_bytes = t7.to_bytes();
        assert_eq!(
            &t7_bytes[0..16],
            &expected_t7[..],
            "t7 - got {:?}",
            &t7_bytes[0..16]
        );

        // Check t7's limbs
        let t7_limbs = t7.limbs();
        // Expected t7 limbs - let's compute what they should be
        // t7 value is [136, 232, 15, 0, ...] in bytes
        // That's 136 + 232*256 + 15*65536 = 136 + 59392 + 983040 = 1042568
        // Which should all fit in limb 0 since it's < 2^51
        // So expected limbs: [1042568, 0, 0, 0, 0]
        let expected_t7_limbs = [1042568i64, 0, 0, 0, 0];
        assert_eq!(
            t7_limbs, expected_t7_limbs,
            "t7 limbs should be [1042568, 0, 0, 0, 0]"
        );

        // Test squaring t7 once
        let t7_squared = t7.square();
        let expected_t7_sq = [64u8, 200, 38, 19, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let t7_sq_bytes = t7_squared.to_bytes();
        assert_eq!(
            &t7_sq_bytes[0..16],
            &expected_t7_sq[..],
            "t7^2 - got {:?}",
            &t7_sq_bytes[0..16]
        );

        // Test t8 step by step - square t7 twice to see if it fails
        let t7_sq_sq = t7_squared.square();
        let _t7_sq_sq_bytes = t7_sq_sq.to_bytes();
        // Don't know the expected value yet, just print it

        // Try just 2 squares total
        let t7_2sq = t7.square().square();
        assert_eq!(
            t7_2sq.to_bytes(),
            t7_sq_sq.to_bytes(),
            "Double square should match"
        );

        // Test squaring t7 incrementally and check limbs
        let mut current = t7;
        for i in 1..=10 {
            current = current.square();
            let limbs = current.limbs();

            // Expected limbs from Python calculation for ALL 10 squares
            let expected = match i {
                1 => [1086948034624i64, 0, 0, 0, 0],
                2 => [1853886388506624i64, 524671874, 0, 0, 0],
                3 => [
                    1076441227722752i64,
                    1904559430732844,
                    560998960986822,
                    122,
                    0,
                ],
                4 => [
                    647583459099808i64,
                    543870741618256,
                    1340511200666851,
                    1504753886484743,
                    1113124285103332,
                ],
                5 => [
                    1389476300342576i64,
                    1081103168511698,
                    698670036238561,
                    1786761589578693,
                    969548901900735,
                ],
                6 => [
                    945787938796331i64,
                    281883122644848,
                    1257523518546423,
                    277074759109911,
                    1229938846834965,
                ],
                7 => [
                    1574390107120866i64,
                    871559649737421,
                    337667584630407,
                    2167283968243958,
                    654586535741251,
                ],
                8 => [
                    323275702184927i64,
                    1186734507640709,
                    718830201372678,
                    484828744966154,
                    85512376563674,
                ],
                9 => [
                    2216317968719237i64,
                    1919012133642788,
                    647610942179171,
                    745562020728013,
                    643149525183618,
                ],
                10 => [
                    842548680036508i64,
                    2043987139278447,
                    1230172140004936,
                    663471947011029,
                    78980750370088,
                ],
                _ => [0i64, 0, 0, 0, 0],
            };
            if limbs != expected {
                panic!(
                    "After {} square(s): got limbs {:?}, expected {:?}",
                    i, limbs, expected
                );
            }
        }

        // If we get here, all intermediate values had valid limbs
        // but the final result is still wrong
        let t8_manual = current;
        let t8_limbs = t8_manual.limbs();

        let t8 = t7.pow2k(10);
        let expected_t8 = [
            156u8, 144, 199, 38, 75, 254, 122, 179, 229, 186, 246, 23, 58, 146, 185, 90,
        ];

        assert_eq!(
            &t8.to_bytes()[0..16],
            &expected_t8[..],
            "t8 - limbs are {:?}",
            t8_limbs
        );

        let t9 = t8.mul(&t7);
        let expected_t9 = [
            213u8, 204, 64, 238, 194, 120, 50, 182, 227, 248, 232, 71, 9, 188, 129, 240,
        ];
        assert_eq!(&t9.to_bytes()[0..16], &expected_t9[..], "t9");

        let t10 = t9.pow2k(20);
        let expected_t10 = [
            173u8, 90, 180, 37, 100, 235, 112, 124, 226, 241, 208, 32, 9, 0, 206, 191,
        ];
        assert_eq!(&t10.to_bytes()[0..16], &expected_t10[..], "t10");

        let t11 = t10.mul(&t9);
        let expected_t11 = [
            175u8, 214, 118, 148, 151, 58, 72, 127, 219, 37, 64, 201, 223, 196, 47, 196,
        ];
        assert_eq!(&t11.to_bytes()[0..16], &expected_t11[..], "t11");

        let t12 = t11.pow2k(10);
        let expected_t12 = [
            231u8, 103, 217, 37, 159, 84, 213, 180, 175, 230, 49, 182, 62, 51, 145, 145,
        ];
        assert_eq!(&t12.to_bytes()[0..16], &expected_t12[..], "t12");

        let t13 = t12.mul(&t7);
        let expected_t13 = [
            71u8, 182, 228, 56, 150, 102, 88, 91, 185, 97, 221, 135, 90, 187, 64, 236,
        ];
        assert_eq!(&t13.to_bytes()[0..16], &expected_t13[..], "t13");
    }

    #[test]
    fn test_mul_associative() {
        // Test (a * b) * c = a * (b * c)
        let a = FieldElement::from_limbs([2, 0, 0, 0, 0]);
        let b = FieldElement::from_limbs([3, 0, 0, 0, 0]);
        let c = FieldElement::from_limbs([5, 0, 0, 0, 0]);

        let left = a.mul(&b).mul(&c); // (2 * 3) * 5 = 6 * 5 = 30
        let right = a.mul(&b.mul(&c)); // 2 * (3 * 5) = 2 * 15 = 30

        assert_eq!(
            left.to_bytes(),
            right.to_bytes(),
            "Multiplication should be associative"
        );

        // Also check the actual value
        assert_eq!(left.to_bytes()[0], 30, "Should equal 30");
    }

    #[test]
    fn test_pow2k_large() {
        // Test pow2k with larger values of k
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);

        // 2^(2^10) = 2^1024
        let result10 = two.pow2k(10);
        // Manually compute by squaring 10 times
        let mut manual = two;
        for _ in 0..10 {
            manual = manual.square();
        }
        assert_eq!(
            result10.to_bytes(),
            manual.to_bytes(),
            "pow2k(10) should match 10 squares"
        );

        // Test even larger
        let result50 = two.pow2k(50);
        let mut manual50 = two;
        for _ in 0..50 {
            manual50 = manual50.square();
        }
        assert_eq!(
            result50.to_bytes(),
            manual50.to_bytes(),
            "pow2k(50) should match 50 squares"
        );
    }

    #[test]
    fn test_pow22501() {
        // Test the pow22501 helper function
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);
        let (t19, t3) = two.pow22501();

        // t19 should be 2^(2^250-1) mod p
        // Expected: [60, 2, 79, 190, 181, 224, 149, 244, 74, 243, 9, 204, 127, 178, 174, 162, 64, 99, 96, 254, 238, 218, 95, 213, 88, 98, 181, 16, 173, 147, 140, 127]
        let expected_t19 = [
            60, 2, 79, 190, 181, 224, 149, 244, 74, 243, 9, 204, 127, 178, 174, 162, 64, 99, 96,
            254, 238, 218, 95, 213, 88, 98, 181, 16, 173, 147, 140, 127,
        ];
        assert_eq!(t19.to_bytes(), expected_t19, "t19 = 2^(2^250-1) mod p");

        // t3 should be 2^11 = 2048
        let expected_t3 = [
            0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert_eq!(t3.to_bytes(), expected_t3, "t3 = 2^11 = 2048");
    }

    #[test]
    fn test_field_inversion() {
        // Test that field inversion is working correctly
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0]);
        let two_inv = two.invert();

        // Expected value of 2^(-1) mod p
        let expected_inv = [
            247, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 63,
        ];
        let two_inv_bytes = two_inv.to_bytes();
        assert_eq!(two_inv_bytes, expected_inv, "2^(-1) should equal (p+1)/2");

        // Verify 2 * inv(2) = 1
        let product = two.mul(&two_inv);
        let product_bytes = product.to_bytes();
        let one_bytes = FieldElement::ONE.to_bytes();
        assert_eq!(product_bytes, one_bytes, "2 * (1/2) should equal 1");
    }

    #[test]
    fn test_scalar_9() {
        // Test scalar multiplication with scalar=9
        // This is a standard X25519 test
        let mut scalar = [0u8; 32];
        scalar[0] = 9; // scalar = 9

        // Basepoint for X25519
        let basepoint = [
            9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let result = X25519::public_key(&scalar);

        // Expected result from x25519-dalek or other reference implementation
        // This is 9 * G where G is the base point
        use x25519_dalek::x25519;
        let expected = x25519(scalar, basepoint);

        assert_eq!(
            result, expected,
            "Scalar multiplication by 9 should match reference"
        );
    }

    #[test]
    fn test_clamp_scalar() {
        let mut scalar = [0xFFu8; 32];
        clamp_scalar(&mut scalar);

        assert_eq!(scalar[0] & 0x07, 0); // Bits 0,1,2 cleared
        assert_eq!(scalar[31] & 0x80, 0); // Bit 255 cleared
        assert_eq!(scalar[31] & 0x40, 0x40); // Bit 254 set
    }

    #[test]
    fn test_x25519_basic() {
        // Test that key generation works
        let private_key = [1u8; 32];
        let public_key = X25519::public_key(&private_key);

        // Public key should not be all zeros
        assert!(!is_zero(&public_key));
    }

    #[test]
    fn test_x25519_shared_secret() {
        let alice_private = [2u8; 32];
        let bob_private = [3u8; 32];

        let alice_public = X25519::public_key(&alice_private);
        let bob_public = X25519::public_key(&bob_private);

        // Both parties should compute the same shared secret
        let alice_shared = X25519::shared_secret(&alice_private, &bob_public).unwrap();
        let bob_shared = X25519::shared_secret(&bob_private, &alice_public).unwrap();

        // Verify they're equal (symmetric key agreement)
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_x25519_rfc7748_vector1() {
        // RFC 7748 Test Vector 1
        let scalar =
            hex_literal::hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u_coord =
            hex_literal::hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

        let mut clamped = scalar;
        clamp_scalar(&mut clamped);
        let result = scalar_mult(&clamped, &u_coord);

        let expected =
            hex_literal::hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        assert_eq!(result, expected);
    }

    #[test]
    fn test_x25519_rfc7748_iteration() {
        // RFC 7748 Iteration test (1 iteration for speed)
        let mut k = [0u8; 32];
        k[0] = 9; // Start with 0x09000000... (little-endian)

        let u = k;

        // Clamp the scalar as per X25519 specification
        clamp_scalar(&mut k);
        k = scalar_mult(&k, &u);

        // After 1 iteration
        let expected_1 =
            hex_literal::hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        assert_eq!(k, expected_1);
    }

    #[test]
    fn test_compare_with_reference() {
        // Compare our implementation against x25519-dalek
        use x25519_dalek::x25519;

        // Test the RFC 7748 test vector using reference implementation
        let scalar =
            hex_literal::hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u_coord =
            hex_literal::hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

        // Use the low-level x25519 function from dalek (it applies clamping internally)
        let expected = x25519(scalar, u_coord);

        // Our implementation
        let mut clamped = scalar;
        clamp_scalar(&mut clamped);
        let result = scalar_mult(&clamped, &u_coord);

        assert_eq!(
            result, expected,
            "Our X25519 doesn't match reference implementation"
        );
    }

    #[test]
    fn test_iteration_with_dalek() {
        use x25519_dalek::x25519;

        // Test the iteration vector with dalek to see what we should get
        let mut k = [0u8; 32];
        k[0] = 9;
        let u = k;

        let dalek_result = x25519(k, u);

        // Our implementation - need to clamp like dalek does
        let mut k_clamped = k;
        clamp_scalar(&mut k_clamped);
        let our_result = scalar_mult(&k_clamped, &u);

        assert_eq!(
            our_result, dalek_result,
            "Iteration test: Our result doesn't match dalek"
        );
    }
}
