//! Constant-time operations tests

use hpcrypt_core::ct::*;
use hpcrypt_core::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

#[test]
fn test_ct_eq_same_values() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    assert!(a.ct_eq(&b).into_bool());
}

#[test]
fn test_ct_eq_different_values() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 5];
    assert!(!a.ct_eq(&b).into_bool());
}

#[test]
fn test_ct_eq_empty_slices() {
    let a: &[u8] = &[];
    let b: &[u8] = &[];
    assert!(ConstantTimeEq::ct_eq(a, b).into_bool());
}

#[test]
fn test_ct_select_true() {
    let a = 42u32;
    let b = 99u32;
    // When choice is TRUE (1), conditional_select returns b
    let result = u32::conditional_select(&a, &b, Choice::TRUE());
    assert_eq!(result, 99);
}

#[test]
fn test_ct_select_false() {
    let a = 42u32;
    let b = 99u32;
    // When choice is FALSE (0), conditional_select returns a
    let result = u32::conditional_select(&a, &b, Choice::FALSE());
    assert_eq!(result, 42);
}

#[test]
fn test_ct_select_u8() {
    // When choice is TRUE (1), returns the second argument (0x55)
    let result_true = u8::conditional_select(&0xAA_u8, &0x55_u8, Choice::TRUE());
    assert_eq!(result_true, 0x55);

    // When choice is FALSE (0), returns the first argument (0xAA)
    let result_false = u8::conditional_select(&0xAA_u8, &0x55_u8, Choice::FALSE());
    assert_eq!(result_false, 0xAA);
}

#[test]
fn test_choice_from_u8() {
    let zero = Choice::from_u8(0);
    assert!(!bool::from(zero));

    let one = Choice::from_u8(1);
    assert!(bool::from(one));
}

#[test]
fn test_choice_and() {
    assert!(bool::from(Choice::TRUE() & Choice::TRUE()));
    assert!(!bool::from(Choice::TRUE() & Choice::FALSE()));
    assert!(!bool::from(Choice::FALSE() & Choice::TRUE()));
    assert!(!bool::from(Choice::FALSE() & Choice::FALSE()));
}

#[test]
fn test_choice_or() {
    assert!(bool::from(Choice::TRUE() | Choice::TRUE()));
    assert!(bool::from(Choice::TRUE() | Choice::FALSE()));
    assert!(bool::from(Choice::FALSE() | Choice::TRUE()));
    assert!(!bool::from(Choice::FALSE() | Choice::FALSE()));
}

#[test]
fn test_choice_not() {
    assert!(!bool::from(!Choice::TRUE()));
    assert!(bool::from(!Choice::FALSE()));
}

#[test]
fn test_ct_copy() {
    use hpcrypt_core::ct::bytes::conditional_copy;

    let mut dest = [0u8; 4];
    let src = [1u8, 2, 3, 4];

    conditional_copy(Choice::TRUE(), &mut dest, &src);
    assert_eq!(dest, src);

    let mut dest2 = [0u8; 4];
    conditional_copy(Choice::FALSE(), &mut dest2, &src);
    assert_eq!(dest2, [0u8; 4]); // Should remain unchanged
}

#[test]
fn test_ct_zero() {
    let mut data = [1u8, 2, 3, 4, 5];
    let zeros = [0u8; 5];
    hpcrypt_core::ct::bytes::conditional_copy(Choice::TRUE(), &mut data, &zeros);
    assert_eq!(data, [0u8; 5]);

    let mut data2 = [1u8, 2, 3, 4, 5];
    hpcrypt_core::ct::bytes::conditional_copy(Choice::FALSE(), &mut data2, &zeros);
    assert_eq!(data2, [1u8, 2, 3, 4, 5]); // Should remain unchanged
}
