#!/usr/bin/env python3
"""
Compute exact intermediate values for Barrett reduction at iteration 1203->1204
This will help debug the Rust implementation
"""

def limbs_to_int(limbs):
    """Convert array of u64 limbs to integer"""
    result = 0
    for i, limb in enumerate(limbs):
        result |= (limb << (i * 64))
    return result

def int_to_limbs(value, num_limbs):
    """Convert integer to array of u64 limbs"""
    limbs = []
    for i in range(num_limbs):
        limbs.append((value >> (i * 64)) & 0xFFFFFFFFFFFFFFFF)
    return limbs

# P-256 order
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Barrett constant μ = floor(2^512 / n)
mu = (2**512) // n

print("="*80)
print("P-256 Scalar Barrett Reduction - Iteration 1203->1204 Debug")
print("="*80)

# Step 1: Compute 7^1203 mod n (the correct value before the failing iteration)
base = 7
exp = 1203
val_1203 = pow(base, exp, n)

print(f"\n7^1203 mod n = {hex(val_1203)}")
print("In limbs (little-endian):")
limbs_1203 = int_to_limbs(val_1203, 4)
for i, limb in enumerate(limbs_1203):
    print(f"  limbs[{i}] = 0x{limb:016X}")

# Step 2: Square it (this is what happens in iteration 1204)
val_squared_unreduced = val_1203 * val_1203

print(f"\n(7^1203)^2 (unreduced) = {hex(val_squared_unreduced)}")
print(f"Bit length: {val_squared_unreduced.bit_length()}")
print("\nAs 8 limbs (input to reduce_wide):")
limbs_input = int_to_limbs(val_squared_unreduced, 8)
for i, limb in enumerate(limbs_input):
    print(f"  limbs[{i}] = 0x{limb:016X}")

# Step 3: Perform Barrett reduction step by step
print("\n" + "="*80)
print("Barrett Reduction Steps (HAC Algorithm 14.42)")
print("="*80)

k = 4  # n is 4 limbs
b = 2**64

# Step 1: q1 = floor(x / b^(k-1)) = x >> 192 bits
q1 = val_squared_unreduced >> 192
print(f"\nStep 1: q1 = floor(x / b^3)")
print(f"  q1 = {hex(q1)}")
print(f"  As 5 limbs:")
q1_limbs = int_to_limbs(q1, 5)
for i, limb in enumerate(q1_limbs):
    print(f"    q1[{i}] = 0x{limb:016X}")

# Step 2: q2 = q1 * μ
q2 = q1 * mu
print(f"\nStep 2: q2 = q1 * μ")
print(f"  q2 bit length = {q2.bit_length()}")
print(f"  As 13 limbs:")
q2_limbs = int_to_limbs(q2, 13)
for i, limb in enumerate(q2_limbs):
    print(f"    q2[{i}] = 0x{limb:016X}")

# Step 3: q3 = floor(q2 / b^5) = q2 >> 320 bits
q3 = q2 >> 320
print(f"\nStep 3: q3 = floor(q2 / b^5)")
print(f"  q3 = {hex(q3)}")
print(f"  As 4 limbs:")
q3_limbs = int_to_limbs(q3, 4)
for i, limb in enumerate(q3_limbs):
    print(f"    q3[{i}] = 0x{limb:016X}")

# Step 4: r1 = x mod b^5
r1 = val_squared_unreduced % (b**5)
print(f"\nStep 4: r1 = x mod b^5")
print(f"  r1 = {hex(r1)}")
print(f"  As 5 limbs:")
r1_limbs = int_to_limbs(r1, 5)
for i, limb in enumerate(r1_limbs):
    print(f"    r1[{i}] = 0x{limb:016X}")

# Step 5: r2 = (q3 * n) mod b^5
r2 = (q3 * n) % (b**5)
print(f"\nStep 5: r2 = (q3 * n) mod b^5")
print(f"  q3 * n (full) = {hex(q3 * n)}")
print(f"  r2 = {hex(r2)}")
print(f"  As 5 limbs:")
r2_limbs = int_to_limbs(r2, 5)
for i, limb in enumerate(r2_limbs):
    print(f"    r2[{i}] = 0x{limb:016X}")

# Step 6: r = r1 - r2
r = r1 - r2
print(f"\nStep 6: r = r1 - r2")
print(f"  r (before correction) = {hex(r) if r >= 0 else 'NEGATIVE: ' + hex(r)}")
if r < 0:
    print(f"  r is NEGATIVE, adding b^5...")
    r += b**5
    print(f"  r (after adding b^5) = {hex(r)}")

print(f"  As 5 limbs:")
r_limbs = int_to_limbs(r, 5)
for i, limb in enumerate(r_limbs):
    print(f"    r[{i}] = 0x{limb:016X}")

# Step 7: Extract lower 4 limbs
result_limbs = r_limbs[:4]
print(f"\nStep 7: Extract lower 4 limbs")
for i, limb in enumerate(result_limbs):
    print(f"    result[{i}] = 0x{limb:016X}")

# Step 8: While r >= n, subtract n
result = limbs_to_int(result_limbs)
iterations = 0
print(f"\nStep 8: Final reduction (while r >= n, r -= n)")
print(f"  Initial r = {hex(result)}")
print(f"  r >= n? {result >= n}")

while result >= n:
    result -= n
    iterations += 1
    print(f"  After subtraction {iterations}: r = {hex(result)}")

# Final result
print(f"\n" + "="*80)
print("FINAL RESULT")
print("="*80)
expected_result = pow(val_1203, 2, n)
print(f"Expected (7^2406 mod n): {hex(expected_result)}")
print(f"Computed via Barrett:    {hex(result)}")
print(f"Match: {result == expected_result}")

if result == expected_result:
    print("\n✅ SUCCESS - Barrett reduction worked correctly!")
else:
    print("\n❌ FAILURE - Barrett reduction produced wrong result!")
    print(f"Difference: {hex(abs(result - expected_result))}")

print(f"\nFinal result as 4 limbs:")
final_limbs = int_to_limbs(result, 4)
for i, limb in enumerate(final_limbs):
    print(f"  result[{i}] = 0x{limb:016X}")

print("\n" + "="*80)
print("RUST TEST CODE")
print("="*80)
print("""
// Add this test to verify the Rust implementation matches Python:
#[test]
fn test_barrett_at_1203_to_1204() {
    // Input: (7^1203)^2 unreduced
    let input_limbs = [""")
for limb in limbs_input:
    print(f"        0x{limb:016X}u64,")
print("""    ];

    // Expected output after Barrett reduction
    let expected_limbs = [""")
for limb in final_limbs:
    print(f"        0x{limb:016X}u64,")
print("""    ];

    let result = Scalar::reduce_wide_barrett(&input_limbs);
    let expected = Scalar { limbs: expected_limbs };

    assert_eq!(result, expected,
        "Barrett reduction at 1203->1204 failed");
}
""")
