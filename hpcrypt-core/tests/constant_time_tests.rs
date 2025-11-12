//! Constant-time operations tests

use hpcrypt_core::ct::*;
use hpcrypt_core::ct_utils::CtBool;

#[test]
fn test_ct_eq_same_values() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    assert!(ct_eq(&a, &b));
}

#[test]
fn test_ct_eq_different_values() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 5];
    assert!(!ct_eq(&a, &b));
}

#[test]
fn test_ct_eq_empty_slices() {
    let a: &[u8] = &[];
    let b: &[u8] = &[];
    assert!(ct_eq(a, b));
}

#[test]
fn test_ct_select_true() {
    let a = 42u32;
    let b = 99u32;
    let result = ct_select(a, b, CtBool::TRUE());
    assert_eq!(result, a);
}

#[test]
fn test_ct_select_false() {
    let a = 42u32;
    let b = 99u32;
    let result = ct_select(a, b, CtBool::FALSE());
    assert_eq!(result, b);
}

#[test]
fn test_ct_select_u8() {
    let result_true = ct_select(0xAA_u8, 0x55_u8, CtBool::TRUE());
    assert_eq!(result_true, 0xAA);

    let result_false = ct_select(0xAA_u8, 0x55_u8, CtBool::FALSE());
    assert_eq!(result_false, 0x55);
}

#[test]
fn test_ctbool_from_u8() {
    let zero = CtBool::from_u8(0);
    assert!(!bool::from(zero));

    let one = CtBool::from_u8(1);
    assert!(bool::from(one));

    // Non-zero values should be treated as true
    let two = CtBool::from_u8(2);
    assert!(bool::from(two));
}

#[test]
fn test_ctbool_and() {
    assert!(bool::from(CtBool::TRUE() & CtBool::TRUE()));
    assert!(!bool::from(CtBool::TRUE() & CtBool::FALSE()));
    assert!(!bool::from(CtBool::FALSE() & CtBool::TRUE()));
    assert!(!bool::from(CtBool::FALSE() & CtBool::FALSE()));
}

#[test]
fn test_ctbool_or() {
    assert!(bool::from(CtBool::TRUE() | CtBool::TRUE()));
    assert!(bool::from(CtBool::TRUE() | CtBool::FALSE()));
    assert!(bool::from(CtBool::FALSE() | CtBool::TRUE()));
    assert!(!bool::from(CtBool::FALSE() | CtBool::FALSE()));
}

#[test]
fn test_ctbool_not() {
    assert!(!bool::from(!CtBool::TRUE()));
    assert!(bool::from(!CtBool::FALSE()));
}

#[test]
fn test_ct_copy() {
    let mut dest = [0u8; 4];
    let src = [1u8, 2, 3, 4];

    ct_copy(&mut dest, &src, CtBool::TRUE());
    assert_eq!(dest, src);

    let mut dest2 = [0u8; 4];
    ct_copy(&mut dest2, &src, CtBool::FALSE());
    assert_eq!(dest2, [0u8; 4]); // Should remain unchanged
}

#[test]
fn test_ct_zero() {
    let mut data = [1u8, 2, 3, 4, 5];
    ct_zero(&mut data, CtBool::TRUE());
    assert_eq!(data, [0u8; 5]);

    let mut data2 = [1u8, 2, 3, 4, 5];
    ct_zero(&mut data2, CtBool::FALSE());
    assert_eq!(data2, [1u8, 2, 3, 4, 5]); // Should remain unchanged
}
