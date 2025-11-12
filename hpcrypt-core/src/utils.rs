//! Utility functions for cryptographic implementations

/// Convert a u32 to bytes in little-endian order
#[inline(always)]
pub const fn u32_to_le_bytes(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Convert a u32 to bytes in big-endian order
#[inline(always)]
pub const fn u32_to_be_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Convert bytes to u32 in little-endian order
#[inline(always)]
pub const fn u32_from_le_bytes(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

/// Convert bytes to u32 in big-endian order
#[inline(always)]
pub const fn u32_from_be_bytes(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

/// Convert a u64 to bytes in little-endian order
#[inline(always)]
pub const fn u64_to_le_bytes(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Convert a u64 to bytes in big-endian order
#[inline(always)]
pub const fn u64_to_be_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Convert bytes to u64 in little-endian order
#[inline(always)]
pub const fn u64_from_le_bytes(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

/// Convert bytes to u64 in big-endian order
#[inline(always)]
pub const fn u64_from_be_bytes(bytes: [u8; 8]) -> u64 {
    u64::from_be_bytes(bytes)
}

/// Read u32 from slice in little-endian
#[inline]
pub fn read_u32_le(bytes: &[u8]) -> u32 {
    assert!(bytes.len() >= 4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Read u32 from slice in big-endian
#[inline]
pub fn read_u32_be(bytes: &[u8]) -> u32 {
    assert!(bytes.len() >= 4);
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Read u64 from slice in little-endian
#[inline]
pub fn read_u64_le(bytes: &[u8]) -> u64 {
    assert!(bytes.len() >= 8);
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Read u64 from slice in big-endian
#[inline]
pub fn read_u64_be(bytes: &[u8]) -> u64 {
    assert!(bytes.len() >= 8);
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Write u32 to slice in little-endian
#[inline]
pub fn write_u32_le(dst: &mut [u8], value: u32) {
    assert!(dst.len() >= 4);
    let bytes = value.to_le_bytes();
    dst[0] = bytes[0];
    dst[1] = bytes[1];
    dst[2] = bytes[2];
    dst[3] = bytes[3];
}

/// Write u32 to slice in big-endian
#[inline]
pub fn write_u32_be(dst: &mut [u8], value: u32) {
    assert!(dst.len() >= 4);
    let bytes = value.to_be_bytes();
    dst[0] = bytes[0];
    dst[1] = bytes[1];
    dst[2] = bytes[2];
    dst[3] = bytes[3];
}

/// Write u64 to slice in little-endian
#[inline]
pub fn write_u64_le(dst: &mut [u8], value: u64) {
    assert!(dst.len() >= 8);
    let bytes = value.to_le_bytes();
    dst[..8].copy_from_slice(&bytes);
}

/// Write u64 to slice in big-endian
#[inline]
pub fn write_u64_be(dst: &mut [u8], value: u64) {
    assert!(dst.len() >= 8);
    let bytes = value.to_be_bytes();
    dst[..8].copy_from_slice(&bytes);
}

/// Rotate left (wrapping)
#[inline(always)]
pub const fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// Rotate right (wrapping)
#[inline(always)]
pub const fn rotr32(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

/// Rotate left (wrapping) for u64
#[inline(always)]
pub const fn rotl64(x: u64, n: u32) -> u64 {
    x.rotate_left(n)
}

/// Rotate right (wrapping) for u64
#[inline(always)]
pub const fn rotr64(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian_conversions() {
        let value: u32 = 0x12345678;
        let le = u32_to_le_bytes(value);
        let be = u32_to_be_bytes(value);

        assert_eq!(u32_from_le_bytes(le), value);
        assert_eq!(u32_from_be_bytes(be), value);

        let value: u64 = 0x123456789ABCDEF0;
        let le = u64_to_le_bytes(value);
        let be = u64_to_be_bytes(value);

        assert_eq!(u64_from_le_bytes(le), value);
        assert_eq!(u64_from_be_bytes(be), value);
    }

    #[test]
    fn test_rotations() {
        assert_eq!(rotl32(0x12345678, 8), 0x34567812);
        assert_eq!(rotr32(0x12345678, 8), 0x78123456);

        assert_eq!(rotl64(0x123456789ABCDEF0, 8), 0x3456789ABCDEF012);
        assert_eq!(rotr64(0x123456789ABCDEF0, 8), 0xF0123456789ABCDE);
    }
}
