//! Error type tests

use hpcrypt_core::error::*;

#[test]
fn test_curve_error_display() {
    let err = CurveError::NotOnCurve;
    let msg = format!("{}", err);
    assert!(msg.contains("not on the curve"));

    let err = CurveError::InvalidScalar {
        expected: 32,
        actual: 16,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("32 bytes"));
    assert!(msg.contains("16 bytes"));
}

#[test]
fn test_curve_signature_error_display() {
    let err = CurveError::InvalidSignature;
    let msg = format!("{}", err);
    assert!(msg.contains("Signature verification failed"));
}

#[test]
fn test_hash_error_display() {
    let err = HashError::InvalidOutputLength {
        expected: Some(32),
        actual: 16,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("32 bytes"));
    assert!(msg.contains("16 bytes"));
}

#[test]
fn test_error_from_conversions() {
    let curve_err = CurveError::NotOnCurve;
    let general_err: CryptoError = curve_err.into();
    assert!(matches!(general_err, CryptoError::Curve(_)));

    let aead_err = AeadError::AuthenticationFailed;
    let general_err: CryptoError = aead_err.into();
    assert!(matches!(general_err, CryptoError::Aead(_)));
}
