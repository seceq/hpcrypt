// Test GB function directly with simple values

fn trunc(x: u64) -> u64 {
    x as u32 as u64
}

fn gb_value(mut a: u64, mut b: u64, mut c: u64, mut d: u64) -> (u64, u64, u64, u64) {
    // Step 1
    a = a.wrapping_add(b).wrapping_add(trunc(a).wrapping_mul(trunc(b)).wrapping_mul(2));
    d = (d ^ a).rotate_right(32);

    // Step 2
    c = c.wrapping_add(d).wrapping_add(trunc(c).wrapping_mul(trunc(d)).wrapping_mul(2));
    b = (b ^ c).rotate_right(24);

    // Step 3
    a = a.wrapping_add(b).wrapping_add(trunc(a).wrapping_mul(trunc(b)).wrapping_mul(2));
    d = (d ^ a).rotate_right(16);

    // Step 4
    c = c.wrapping_add(d).wrapping_add(trunc(c).wrapping_mul(trunc(d)).wrapping_mul(2));
    b = (b ^ c).rotate_right(63);

    (a, b, c, d)
}

fn main() {
    // Test with simple values
    let (a, b, c, d) = gb_value(0, 0, 0, 0);
    println!("GB(0,0,0,0) = ({:016x}, {:016x}, {:016x}, {:016x})", a, b, c, d);

    let (a, b, c, d) = gb_value(1, 2, 3, 4);
    println!("GB(1,2,3,4) = ({:016x}, {:016x}, {:016x}, {:016x})", a, b, c, d);

    // Test with larger values
    let (a, b, c, d) = gb_value(
        0x0123456789abcdef,
        0xfedcba9876543210,
        0x1111111111111111,
        0x2222222222222222
    );
    println!("GB(test) = ({:016x}, {:016x}, {:016x}, {:016x})", a, b, c, d);
}
