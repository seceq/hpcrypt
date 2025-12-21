//! X448 Diffie-Hellman key exchange
//!
//! Implementation of the X448 function as specified in RFC 7748.
//!
//! X448 uses the Montgomery form of Curve448 (also known as Curve448-Goldilocks)
//! for ECDH key exchange. It provides approximately 224 bits of security.

use crate::ct_utils::{Choice, ConditionallySelectable};
use crate::ed448::field::FieldElement;
use hpcrypt_core::error::CurveError;

/// X448 private key (56 bytes)
pub const X448_PRIVATE_KEY_LEN: usize = 56;

/// X448 public key (56 bytes)
pub const X448_PUBLIC_KEY_LEN: usize = 56;

/// X448 shared secret (56 bytes)
pub const X448_SHARED_SECRET_LEN: usize = 56;

/// The X448 basepoint (u=5)
const BASEPOINT_U: [u64; 8] = [5, 0, 0, 0, 0, 0, 0, 0];

/// X448 public API
pub struct X448;

impl X448 {
    /// Generate a public key from a private key
    ///
    /// Takes a 56-byte private key and returns the corresponding 56-byte public key.
    /// The private key is clamped according to RFC 7748.
    pub fn public_key(private_key: &[u8; 56]) -> [u8; 56] {
        let mut clamped = *private_key;
        clamp_scalar(&mut clamped);

        scalar_mult_base(&clamped)
    }

    /// Compute shared secret from private and public keys
    ///
    /// Returns the 56-byte shared secret computed from your private key
    /// and the other party's public key.
    pub fn shared_secret(
        private_key: &[u8; 56],
        public_key: &[u8; 56],
    ) -> Result<[u8; 56], CurveError> {
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

/// Clamp scalar according to RFC 7748 Section 5
///
/// For X448:
/// - Clear bits 0, 1 (ensure scalar is multiple of 4)
/// - Set bit 447 (ensure scalar has form 2^447 + ...)
fn clamp_scalar(scalar: &mut [u8; 56]) {
    scalar[0] &= 0xFC; // Clear bits 0, 1
    scalar[55] |= 0x80; // Set bit 447
}

/// Scalar multiplication with the base point
fn scalar_mult_base(scalar: &[u8; 56]) -> [u8; 56] {
    let u = FieldElement::from_limbs(BASEPOINT_U);
    montgomery_ladder(scalar, &u)
}

/// Scalar multiplication with arbitrary point
fn scalar_mult(scalar: &[u8; 56], u_bytes: &[u8; 56]) -> [u8; 56] {
    // Convert 56-byte X448 coordinate to 57-byte field element format
    let u_57 = bytes_56_to_57(u_bytes);
    let u = FieldElement::from_bytes(&u_57);
    montgomery_ladder(scalar, &u)
}

/// Convert 56-byte X448 format to 57-byte field element format
fn bytes_56_to_57(bytes_56: &[u8; 56]) -> [u8; 57] {
    let mut bytes_57 = [0u8; 57];
    bytes_57[..56].copy_from_slice(bytes_56);
    bytes_57
}

/// Convert 57-byte field element format to 56-byte X448 format
fn bytes_57_to_56(bytes_57: &[u8; 57]) -> [u8; 56] {
    let mut bytes_56 = [0u8; 56];
    bytes_56.copy_from_slice(&bytes_57[..56]);
    bytes_56
}

/// Montgomery ladder for constant-time scalar multiplication
///
/// Computes scalar * point using the Montgomery ladder algorithm,
/// which runs in constant time regardless of the scalar value.
///
/// This implementation follows RFC 7748 Section 5.
fn montgomery_ladder(scalar: &[u8; 56], u: &FieldElement) -> [u8; 56] {
    // RFC 7748 Section 5:
    // For X448, bits = 448
    let x_1 = *u;
    let mut x_2 = FieldElement::one();
    let mut z_2 = FieldElement::zero();
    let mut x_3 = *u;
    let mut z_3 = FieldElement::one();
    let mut swap = 0u8;

    // OPTIMIZATION: Precompute constant a24 = 39081 outside loop
    // X448/Curve448: a24 = (A + 2) / 4 = (156326 + 2) / 4 = 39082 (but RFC 7748 uses 39081)
    let a24 = FieldElement::from_limbs([39081, 0, 0, 0, 0, 0, 0, 0]);

    // For t = bits-1 down to 0:
    // For X448, that's t = 447 down to 0
    for t in (0..448).rev() {
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

        // Montgomery ladder step (RFC 7748, Section 5)
        // A = x_2 + z_2
        let a = x_2 + z_2;
        // AA = A^2
        let aa = a.square();
        // B = x_2 - z_2
        let b = x_2 - z_2;
        // BB = B^2
        let bb = b.square();
        // E = AA - BB
        let e = aa - bb;
        // C = x_3 + z_3
        let c = x_3 + z_3;
        // D = x_3 - z_3
        let d = x_3 - z_3;
        // DA = D * A
        let da = d * a;
        // CB = C * B
        let cb = c * b;
        // x_3 = (DA + CB)^2
        x_3 = (da + cb).square();
        // z_3 = x_1 * (DA - CB)^2
        z_3 = x_1 * (da - cb).square();
        // x_2 = AA * BB
        x_2 = aa * bb;
        // z_2 = E * (AA + a24 * E)
        z_2 = e * (aa + (a24 * e));
    }

    // OPTIMIZATION: Eliminate final swap
    // X448 clamping ensures bits 0,1 are always 0 (scalar[0] &= 0xFC).
    // After processing bit 0, swap = k_t = 0, so the final swap is a no-op.
    // We can directly use (x_2, z_2) without conditional selection.
    //
    // This saves 2 field element conditional selects per scalar multiplication.

    // Return x_2 / z_2
    let z_2_inv = z_2.invert();
    let result = x_2 * z_2_inv;
    let bytes_57 = result.to_bytes();
    bytes_57_to_56(&bytes_57)
}

/// Check if a byte array is all zeros
fn is_zero(bytes: &[u8; 56]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_generation() {
        // Test that we can generate a public key
        let private_key = [1u8; 56];
        let public_key = X448::public_key(&private_key);

        // Public key should not be all zeros
        assert!(!is_zero(&public_key));
    }

    #[test]
    fn test_ladder_single_iteration() {
        // Test a single Montgomery ladder iteration with known inputs
        // This tests the core field arithmetic in the ladder context

        // Initial values for first iteration (after cswap when k_t=1)
        let u = 2u64.pow(24); // 2^192 = 2^(168+24) in limb 3
        let x_1 = FieldElement::from_limbs([0, 0, 0, u, 0, 0, 0, 0]); // 2^192
        let x_2 = x_1; // After cswap
        let z_2 = FieldElement::one();
        let x_3 = FieldElement::one();
        let z_3 = FieldElement::zero();
        let a24 = FieldElement::from_limbs([39081, 0, 0, 0, 0, 0, 0, 0]);

        // One ladder step
        let a = x_2.add(&z_2);
        let aa = a.square();
        let b = x_2.sub(&z_2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x_3.add(&z_3);
        let d = x_3.sub(&z_3);
        let da = d * a;
        let cb = c * b;
        let _new_x_3 = da.add(&cb).square();
        let _new_z_3 = x_1 * da.sub(&cb).square();
        let new_x_2 = aa * bb;
        let new_z_2 = e * aa.add(&(a24 * e));

        // Just check that we got something non-zero
        assert!(!bool::from(new_x_2.is_zero()), "x_2 should not be zero after one iteration");
        assert!(!bool::from(new_z_2.is_zero()), "z_2 should not be zero after one iteration");

        // Detailed check: verify A = x_2 + z_2 = 2^192 + 1
        let expected_a = FieldElement::from_limbs([1, 0, 0, 1 << 24, 0, 0, 0, 0]);
        assert_eq!(
            a.strong_reduce(),
            expected_a.strong_reduce(),
            "A = x_2 + z_2 should equal 2^192 + 1"
        );

        // Check AA = A^2 = (2^192 + 1)^2 = 2^384 + 2*2^192 + 1 = 2^384 + 2^193 + 1
        // From Python: AA = 39402006196394479212279040100143613805079739270465446667960847607716495133024882190260681587717120351695556059332609
        // 2^384 = limb[6] bit 48
        // 2^193 = limb[3] bit 25
        // Result: limb[0]=1, limb[3]=2^25, limb[6]=2^48
        let expected_aa = FieldElement::from_limbs([1, 0, 0, 1 << 25, 0, 0, 1 << 48, 0]);
        assert_eq!(
            aa.strong_reduce(),
            expected_aa.strong_reduce(),
            "AA = A^2 should equal 2^384 + 2^193 + 1"
        );

        // Check BB first
        // B = 2^192 - 1 (mod p)
        // BB = B^2 = (2^192 - 1)^2 = 2^384 - 2*2^192 + 1 = 2^384 - 2^193 + 1
        // 2^384 = limb[6] bit 48
        // -2^193 = we need to borrow, so this is p - 2^193 in the representation
        // Actually, let me compute this more carefully:
        // 2^384 - 2^193 + 1 mod p should be computed properly

        // First verify B
        // B = 2^192 - 1 should work out to limb[3] having 2^24-1 and lower limbs having all 1s
        // Actually: 2^192 - 1 = 2^192 - 1, but we compute x_2 - z_2 = 2^192 - 1
        // This means limbs 0-2 are all 0xffffffffffffff, and limb 3 = 2^24 - 1 = 0xffffff

        // Let's check what we actually get for BB
        let bb_reduced = bb.strong_reduce();
        // From Python: BB should be 2^384 - 2^193 + 1
        // Let's verify via Python result...

        // E = AA - BB = (2^384 + 2^193 + 1) - (2^384 - 2^193 + 1) = 2*2^193 = 2^194
        // 2^194 = limb[3] bit 26
        let expected_e = FieldElement::from_limbs([0, 0, 0, 1 << 26, 0, 0, 0, 0]);

        // Debug: print BB to understand the issue
        // BB has an error if E has an error and AA is correct
        let expected_bb = aa.sub(&expected_e);
        assert_eq!(
            bb_reduced,
            expected_bb.strong_reduce(),
            "BB = (2^192 - 1)^2 should equal 2^384 - 2^193 + 1.\nGot BB: {:?}\nAA: {:?}\nExpected BB (from AA-E): {:?}",
            bb_reduced.limbs, aa.strong_reduce().limbs, expected_bb.strong_reduce().limbs
        );

        assert_eq!(
            e.strong_reduce(),
            expected_e.strong_reduce(),
            "E = AA - BB should equal 2^194"
        );
    }

    #[test]
    fn test_shared_secret_symmetry() {
        // Alice's keypair
        let alice_private = [1u8; 56];
        let alice_public = X448::public_key(&alice_private);

        // Bob's keypair
        let bob_private = [2u8; 56];
        let bob_public = X448::public_key(&bob_private);

        // Compute shared secrets
        let alice_shared = X448::shared_secret(&alice_private, &bob_public)
            .expect("Alice's shared secret computation failed");
        let bob_shared = X448::shared_secret(&bob_private, &alice_public)
            .expect("Bob's shared secret computation failed");

        // Both should compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_rfc7748_vector1() {
        // RFC 7748 Section 6.2 - Test vector 1
        // Alice's private key
        let alice_private = [
            0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58,
            0x00, 0xd4, 0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65, 0xd4, 0x98, 0xc2, 0x8d,
            0xd9, 0xc9, 0xba, 0xf5, 0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91, 0x00, 0x63,
            0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d, 0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
        ];

        // Bob's public key
        let bob_public = [
            0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5, 0xbc, 0xfc, 0x0b, 0x59, 0x9b, 0x6f,
            0xec, 0xcf, 0x6d, 0xa4, 0x62, 0x71, 0x07, 0xbd, 0xb0, 0xd4, 0xf3, 0x45, 0xb4, 0x30,
            0x27, 0xd8, 0xb9, 0x72, 0xfc, 0x3e, 0x34, 0xfb, 0x42, 0x32, 0xa1, 0x3c, 0xa7, 0x06,
            0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae, 0x07, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x09,
        ];

        // Expected shared secret
        let expected = [
            0x07, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95, 0xec, 0x1c, 0x16, 0xa9, 0x4a, 0x0f,
            0x74, 0xd1, 0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52, 0x28, 0x1d, 0x28, 0x2b,
            0xb6, 0x0c, 0x0b, 0x56, 0xfd, 0x24, 0x64, 0xc3, 0x35, 0x54, 0x39, 0x36, 0x52, 0x1c,
            0x24, 0x40, 0x30, 0x85, 0xd5, 0x9a, 0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d,
        ];

        let shared = X448::shared_secret(&alice_private, &bob_public)
            .expect("Shared secret computation failed");

        assert_eq!(shared, expected, "RFC 7748 test vector 1 failed");
    }

    #[test]
    fn test_scalar_clamping() {
        let mut scalar = [0xFFu8; 56];
        clamp_scalar(&mut scalar);

        // Check bits 0, 1 are clear
        assert_eq!(scalar[0] & 0x03, 0, "Bits 0, 1 should be clear");

        // Check bit 447 is set (byte 55, bit 7)
        assert_eq!(scalar[55] & 0x80, 0x80, "Bit 447 should be set");
    }
}
