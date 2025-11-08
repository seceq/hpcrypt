// Direct test of simple_reduce with (p-3)^2 product
//
// This tests the 512-bit product that results from (p-3) * (p-3)
// Expected result after reduction: 9

fn main() {
    println!("Testing simple_reduce with (p-3)^2 product");
    println!();

    // The 512-bit product of (p-3)^2 as 8 x 64-bit limbs
    // From Python: 0xfffffffe00000002fffffffe0000000100000001fffffffe00000001fffffff800000007fffffff8fffffffffffffffffffffff8000000000000000000000010
    let product_limbs: [u64; 8] = [
        0x0000000000000010,  // limb 0
        0xfffffff800000000,  // limb 1
        0xffffffffffffffff,  // limb 2
        0x00000007fffffff8,  // limb 3
        0x00000001fffffff8,  // limb 4
        0x00000001fffffffe,  // limb 5
        0xfffffffe00000001,  // limb 6
        0xfffffffe00000002,  // limb 7
    ];

    println!("Input (512-bit product):");
    for i in 0..8 {
        println!("  limbs[{}] = 0x{:016x}", i, product_limbs[i]);
    }
    println!();

    // Call simple_reduce directly
    // Note: simple_reduce is private, so we'll need to test via public API
    // For now, just document what we expect

    println!("Expected result: 9");
    println!("  limbs[0] = 0x0000000000000009");
    println!("  limbs[1] = 0x0000000000000000");
    println!("  limbs[2] = 0x0000000000000000");
    println!("  limbs[3] = 0x0000000000000000");
    println!();

    println!("Note: simple_reduce() is private.");
    println!("We need to either:");
    println!("  1. Make it pub(crate) for testing");
    println!("  2. Add a test in the module itself");
    println!("  3. Test via public API (mul/square)");
}
