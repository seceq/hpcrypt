//! Utility functions for ML-KEM
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;


/// Convert byte to bits (LSB first)
#[inline]
#[allow(dead_code)]
pub fn byte_to_bits(byte: u8) -> [u8; 8] {
    let mut bits = [0u8; 8];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = (byte >> i) & 1;
    }
    bits
}

/// Convert bits to byte (LSB first)
#[inline]
#[allow(dead_code)]
pub fn bits_to_byte(bits: &[u8]) -> u8 {
    debug_assert!(bits.len() == 8);
    let mut byte = 0u8;
    for (i, &bit) in bits.iter().enumerate().take(8) {
        byte |= (bit & 1) << i;
    }
    byte
}

/// Constant-time comparison of two byte slices
///
/// Returns true if slices are equal, false otherwise.
/// Runs in constant time to prevent timing attacks.
#[inline]
pub fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    diff == 0
}

/// Constant-time conditional select
///
/// Returns `a` if `condition` is true, otherwise returns `b`.
/// Runs in constant time.
#[inline]
#[allow(dead_code)]
pub fn ct_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len());

    let mask = if condition { 0xFFu8 } else { 0x00u8 };
    let mut result = vec![0u8; a.len()];

    for i in 0..a.len() {
        result[i] = (a[i] & mask) | (b[i] & !mask);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_to_bits() {
        let bits = byte_to_bits(0b10110100);
        assert_eq!(bits, [0, 0, 1, 0, 1, 1, 0, 1]); // LSB first
    }

    #[test]
    fn test_bits_to_byte() {
        let bits = [0, 0, 1, 0, 1, 1, 0, 1];
        let byte = bits_to_byte(&bits);
        assert_eq!(byte, 0b10110100);
    }

    #[test]
    fn test_byte_to_bits_to_byte_roundtrip() {
        for byte in 0..=255u8 {
            let bits = byte_to_bits(byte);
            let recovered = bits_to_byte(&bits);
            assert_eq!(recovered, byte);
        }
    }

    #[test]
    fn test_ct_compare_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(ct_compare(a, b));
    }

    #[test]
    fn test_ct_compare_not_equal() {
        let a = b"hello world";
        let b = b"hello earth";
        assert!(!ct_compare(a, b));
    }

    #[test]
    fn test_ct_compare_different_length() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!ct_compare(a, b));
    }

    #[test]
    fn test_ct_compare_empty() {
        let a = b"";
        let b = b"";
        assert!(ct_compare(a, b));
    }

    #[test]
    fn test_ct_select_true() {
        let a = b"first";
        let b = b"secnd"; // Same length as "first"
        let result = ct_select(true, a, b);
        assert_eq!(&result, a);
    }

    #[test]
    fn test_ct_select_false() {
        let a = b"first";
        let b = b"secnd";
        let result = ct_select(false, a, b);
        assert_eq!(&result, b);
    }
}
