//! ECDSA tests

use hpcrypt_signatures::ecdsa_p256::{Signature, VerifyingKey};

#[test]
fn test_ecdsa_p256_edge_cases() {
    // Test vectors from Wycheproof showcase common edge cases

    // Known P-256 public key from Wycheproof
    let wx =
        hex::decode("1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83").unwrap();
    let wy =
        hex::decode("ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9").unwrap();

    let verifying_key = VerifyingKey::from_affine_coords(&wx, &wy).expect("Valid public key");

    // Test 1: All-zero signature (r=0, s=0)
    let zero_sig = Signature::new([0u8; 32], [0u8; 32]);
    let msg = b"test message";
    assert!(
        !verifying_key.verify(msg, &zero_sig),
        "All-zero signature should not verify"
    );

    // Test 2: r=0, s=1
    let mut s_one = [0u8; 32];
    s_one[31] = 1;
    let r_zero_sig = Signature::new([0u8; 32], s_one);
    assert!(
        !verifying_key.verify(msg, &r_zero_sig),
        "Signature with r=0 should not verify"
    );

    // Test 3: r=1, s=0
    let mut r_one = [0u8; 32];
    r_one[31] = 1;
    let s_zero_sig = Signature::new(r_one, [0u8; 32]);
    assert!(
        !verifying_key.verify(msg, &s_zero_sig),
        "Signature with s=0 should not verify"
    );

    // Test 4: High r value (close to curve order n)
    // P-256 order n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    let high_r =
        hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550").unwrap();
    let high_r_arr: [u8; 32] = high_r.try_into().unwrap();
    let high_r_sig = Signature::new(high_r_arr, s_one);
    assert!(
        !verifying_key.verify(msg, &high_r_sig),
        "Signature with r >= n should not verify"
    );
}
