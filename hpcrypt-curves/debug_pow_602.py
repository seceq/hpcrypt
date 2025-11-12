#!/usr/bin/env python3
"""
Generate complete trace of pow(7, 602) mod n using square-and-multiply algorithm.
This will help identify where the Rust implementation diverges.
"""

def limbs_to_int(limbs):
    """Convert 4-limb representation to integer."""
    result = 0
    for i, limb in enumerate(limbs):
        result |= (limb << (i * 64))
    return result

def int_to_limbs(value, num_limbs=4):
    """Convert integer to limb representation."""
    limbs = []
    for i in range(num_limbs):
        limbs.append((value >> (i * 64)) & 0xFFFFFFFFFFFFFFFF)
    return limbs

def format_limbs(limbs):
    """Format limbs as Rust array."""
    return "[" + ", ".join(f"0x{limb:016X}u64" for limb in limbs) + "]"

# P-256 scalar field order
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Barrett constant
mu = (2**512) // n

def barrett_reduce(x):
    """
    Barrett reduction following HAC Algorithm 14.42.
    Returns both the result and intermediate values for debugging.
    """
    k = 4  # number of limbs in n
    b = 2**64  # base (64-bit limbs)

    # Step 1: q1 = floor(x / b^(k-1)) = floor(x / 2^192)
    q1 = x >> 192

    # Step 2: q2 = q1 * μ
    q2 = q1 * mu

    # Step 3: q3 = floor(q2 / b^(k+1)) = floor(q2 / 2^320)
    q3 = q2 >> 320

    # Step 4: r1 = x mod b^(k+1) = x mod 2^320
    r1 = x & ((1 << 320) - 1)

    # Step 5: r2 = (q3 * n) mod b^(k+1)
    r2 = (q3 * n) & ((1 << 320) - 1)

    # Step 6: r = r1 - r2
    if r1 >= r2:
        r = r1 - r2
    else:
        # Add b^(k+1) when r < 0
        r = r1 + (1 << 320) - r2

    # Step 7-8: Final reduction
    while r >= n:
        r -= n

    return r

def pow_with_trace(base, exponent, modulus):
    """
    Compute base^exponent mod modulus using square-and-multiply.
    Returns list of (iteration, bit, accumulator_before_square, accumulator_after_square,
                     accumulator_after_multiply_if_applicable) tuples.
    """
    trace = []

    # Convert exponent to binary (without '0b' prefix)
    exp_bits = bin(exponent)[2:]

    # Initialize accumulator to base (skip first bit since it's always 1)
    acc = base % modulus

    print(f"Initial accumulator (base): {acc}")
    print(f"Limbs: {format_limbs(int_to_limbs(acc))}")
    print(f"\nExponent {exponent} = 0b{exp_bits}")
    print(f"Processing {len(exp_bits)} bits\n")

    # Process remaining bits
    for i, bit in enumerate(exp_bits[1:], start=1):
        bit_val = int(bit)

        acc_before_square = acc

        # Always square
        acc_squared_unreduced = acc * acc
        acc = barrett_reduce(acc_squared_unreduced)
        acc_after_square = acc

        # Multiply by base if bit is 1
        if bit_val == 1:
            acc_mul_unreduced = acc * base
            acc = barrett_reduce(acc_mul_unreduced)
            acc_after_multiply = acc
        else:
            acc_after_multiply = None

        trace.append({
            'iteration': i,
            'bit': bit_val,
            'acc_before_square': acc_before_square,
            'acc_after_square': acc_after_square,
            'acc_after_multiply': acc_after_multiply,
            'final_acc': acc
        })

        # Print progress for key iterations
        if i in [1, 2, 3, 4, 5, 598, 599, 600, 601, 602] or i == len(exp_bits) - 1:
            print(f"Iteration {i}: bit={bit_val}")
            print(f"  Before square: {format_limbs(int_to_limbs(acc_before_square))}")
            print(f"  After square:  {format_limbs(int_to_limbs(acc_after_square))}")
            if bit_val == 1:
                print(f"  After mul(7):  {format_limbs(int_to_limbs(acc_after_multiply))}")
            print(f"  Final acc:     {format_limbs(int_to_limbs(acc))}")
            print()

    return acc, trace

def main():
    print("=" * 80)
    print("COMPLETE TRACE OF pow(7, 602) mod n")
    print("=" * 80)
    print()

    base = 7
    exponent = 602

    # Generate full trace
    result, trace = pow_with_trace(base, exponent, n)

    print("=" * 80)
    print("FINAL RESULT")
    print("=" * 80)
    print(f"7^602 mod n = {result}")
    print(f"Limbs: {format_limbs(int_to_limbs(result))}")
    print()

    # Also compute using Python's built-in pow for verification
    python_result = pow(7, 602, n)
    print(f"Python pow(7, 602, n) = {python_result}")
    print(f"Limbs: {format_limbs(int_to_limbs(python_result))}")
    print()

    if result == python_result:
        print("✅ Barrett trace matches Python's pow()")
    else:
        print("❌ MISMATCH! This shouldn't happen!")
    print()

    # Generate key intermediate values for Rust tests
    print("=" * 80)
    print("KEY INTERMEDIATE VALUES FOR RUST TESTING")
    print("=" * 80)
    print()

    # Iteration 600
    print("After iteration 600:")
    if len(trace) >= 600:
        val_600 = trace[599]['final_acc']  # 0-indexed
        print(f"  Value: {format_limbs(int_to_limbs(val_600))}")

    # Iteration 601
    print("\nAfter iteration 601:")
    if len(trace) >= 601:
        val_601 = trace[600]['final_acc']
        print(f"  Value: {format_limbs(int_to_limbs(val_601))}")

    # Direct computation of 7^601
    val_601_direct = pow(7, 601, n)
    print(f"\nDirect pow(7, 601):")
    print(f"  Value: {format_limbs(int_to_limbs(val_601_direct))}")

    # 7^601 * 7 (unreduced)
    val_601_times_7_unreduced = val_601_direct * 7
    print(f"\n7^601 * 7 (unreduced 512-bit):")
    limbs_8 = int_to_limbs(val_601_times_7_unreduced, 8)
    print(f"  Value: {format_limbs(limbs_8)}")

    # 7^601 * 7 (reduced)
    val_602_from_601 = barrett_reduce(val_601_times_7_unreduced)
    print(f"\n7^601 * 7 (Barrett reduced):")
    print(f"  Value: {format_limbs(int_to_limbs(val_602_from_601))}")

    # Compare with pow(7, 602)
    val_602_from_pow = pow(7, 602, n)
    print(f"\nDirect pow(7, 602):")
    print(f"  Value: {format_limbs(int_to_limbs(val_602_from_pow))}")

    print()
    if val_602_from_601 == val_602_from_pow:
        print("✅ 7^601 * 7 == pow(7, 602)")
    else:
        print("❌ MISMATCH between 7^601 * 7 and pow(7, 602)")

    print()
    print("=" * 80)
    print("TRACE COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
