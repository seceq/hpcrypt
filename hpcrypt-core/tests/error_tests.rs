//! Error type tests

use hpcrypt_core::error::*;

#[test]
fn test_curve_error_display() {
    let err = CurveError::InvalidPoint;
    assert_eq!(format!("{}", err), "Invalid point");

    let err = CurveError::InvalidScalar;
    assert_eq!(format!("{}", err), "Invalid scalar");
}

#[test]
fn test_signature_error_display() {
    let err = SignatureError::InvalidSignature;
    assert_eq!(format!("{}", err), "Invalid signature");

    let err = SignatureError::VerificationFailed;
    assert_eq!(format!("{}", err), "Signature verification failed");
}

#[test]
fn test_hash_error_display() {
    let err = HashError::InvalidLength;
    assert_eq!(format!("{}", err), "Invalid length");
}

#[test]
fn test_error_from_conversions() {
    let curve_err = CurveError::InvalidPoint;
    let general_err: Error = curve_err.into();
    assert!(matches!(general_err, Error::Curve(_)));

    let sig_err = SignatureError::InvalidSignature;
    let general_err: Error = sig_err.into();
    assert!(matches!(general_err, Error::Signature(_)));
}

#[test]
#[cfg(feature = "std")]
fn test_error_source() {
    use std::error::Error as StdError;

    let err = Error::Curve(CurveError::InvalidPoint);
    assert!(err.source().is_none());
}
