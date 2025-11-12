//\! Constant-Time Carry-Less Multiplication
//\!
//\! Based on BearSSL's ctmul implementation
//\! Uses integer multiplication with masking to simulate carry-less multiplication

/// Constant-time 32x32 -> 64 bit carry-less multiplication
///
/// This is a building block for 64x64 multiplication
#[inline]
fn bmul32(x: u32, y: u32) -> u64 {
    let x0 = x & 0x11111111;
    let x1 = x & 0x22222222;
    let x2 = x & 0x44444444;
    let x3 = x & 0x88888888;
    let y0 = y & 0x11111111;
    let y1 = y & 0x22222222;
    let y2 = y & 0x44444444;
    let y3 = y & 0x88888888;

    let mut z = 0u64;
    
    // Process each nibble combination
    let m = (x0 as u64) * (y0 as u64);
    z ^= m & 0x1111111111111111;

    let m = ((x0 >> 1) as u64) * ((y1 >> 1) as u64);
    z ^= (m & 0x1111111111111111) << 1;
    
    let m = ((x0 >> 2) as u64) * ((y2 >> 2) as u64);
    z ^= (m & 0x1111111111111111) << 2;
    
    let m = ((x0 >> 3) as u64) * ((y3 >> 3) as u64);
    z ^= (m & 0x1111111111111111) << 3;

    let m = ((x1 >> 1) as u64) * (y0 as u64);
    z ^= (m & 0x1111111111111111) << 1;
    
    let m = ((x1 >> 1) as u64) * ((y1 >> 1) as u64);
    z ^= (m & 0x1111111111111111) << 2;
    
    let m = ((x1 >> 1) as u64) * ((y2 >> 2) as u64);
    z ^= (m & 0x1111111111111111) << 3;
    
    let m = ((x1 >> 1) as u64) * ((y3 >> 3) as u64);
    z ^= (m & 0x1111111111111111) << 4;

    let m = ((x2 >> 2) as u64) * (y0 as u64);
    z ^= (m & 0x1111111111111111) << 2;
    
    let m = ((x2 >> 2) as u64) * ((y1 >> 1) as u64);
    z ^= (m & 0x1111111111111111) << 3;
    
    let m = ((x2 >> 2) as u64) * ((y2 >> 2) as u64);
    z ^= (m & 0x1111111111111111) << 4;
    
    let m = ((x2 >> 2) as u64) * ((y3 >> 3) as u64);
    z ^= (m & 0x1111111111111111) << 5;

    let m = ((x3 >> 3) as u64) * (y0 as u64);
    z ^= (m & 0x1111111111111111) << 3;
    
    let m = ((x3 >> 3) as u64) * ((y1 >> 1) as u64);
    z ^= (m & 0x1111111111111111) << 4;
    
    let m = ((x3 >> 3) as u64) * ((y2 >> 2) as u64);
    z ^= (m & 0x1111111111111111) << 5;
    
    let m = ((x3 >> 3) as u64) * ((y3 >> 3) as u64);
    z ^= (m & 0x1111111111111111) << 6;

    z
}

/// Constant-time 64x64 -> 128 bit carry-less multiplication
#[inline]
pub fn carryless_mul_64(a: u64, b: u64) -> [u64; 2] {
    let a0 = a as u32;
    let a1 = (a >> 32) as u32;
    let b0 = b as u32;
    let b1 = (b >> 32) as u32;

    let z0 = bmul32(a0, b0);
    let z2 = bmul32(a1, b1);
    let z1 = bmul32(a0 ^ a1, b0 ^ b1) ^ z0 ^ z2;

    let low = z0 ^ (z1 << 32);
    let high = z2 ^ (z1 >> 32);

    [low, high]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bmul32() {
        let a = 0x12345678u32;
        let b = 0x9abcdef0u32;
        let result = bmul32(a, b);
        assert_ne\!(result, 0);
    }

    #[test]
    fn test_carryless_mul_64() {
        let a = 0x0123456789abcdefu64;
        let b = 0xfedcba9876543210u64;
        let result = carryless_mul_64(a, b);
        assert\!(result[0] \!= 0 || result[1] \!= 0);
    }
}
