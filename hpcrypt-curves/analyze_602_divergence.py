#!/usr/bin/env python3
"""
Analyze the divergence between Rust Barrett and correct value for pow(7, 602)
"""

# Rust produced (with Barrett):
rust_limbs = [
    6124606304464912739,   # 0x54FA9F3E3D2A21E3
    8564167814098791619,   # 0x76CF0B0FA41E5FC3
    15470651310515289061,  # 0xD6B2CB665F31FBE5
    408288973113691289     # 0x05AA88A568268C99
]

# Expected (Python Barrett):
expected_limbs = [
    7009059217459682322,   # 0x61452E39025C9C12
    13399069340294811198,  # 0xB9F30E92DD198E3E
    15470651310515289061,  # 0xD6B2CB665F31FBE5
    408288977408658584     # 0x05AA88A968268C98
]

def limbs_to_int(limbs):
    result = 0
    for i, limb in enumerate(limbs):
        result |= (limb << (i * 64))
    return result

def int_to_hex(value):
    hex_str = hex(value)[2:].upper()
    return '0x' + hex_str.zfill(64)

rust_value = limbs_to_int(rust_limbs)
expected_value = limbs_to_int(expected_limbs)

print("=" * 80)
print("ANALYSIS OF pow(7, 602) DIVERGENCE")
print("=" * 80)
print()

print("Rust Barrett produced:")
print(f"  {int_to_hex(rust_value)}")
print()

print("Expected (Python):")
print(f"  {int_to_hex(expected_value)}")
print()

print("Difference:")
diff = rust_value - expected_value
print(f"  {diff:+d}")
print(f"  {int_to_hex(abs(diff)) if diff >= 0 else '-' + int_to_hex(abs(diff))}")
print()

print("Per-limb analysis:")
print()
for i in range(4):
    rust_limb = rust_limbs[i]
    expected_limb = expected_limbs[i]

    if rust_limb == expected_limb:
        print(f"Limb[{i}]: MATCH")
        print(f"  Value: 0x{rust_limb:016X}")
    else:
        diff_limb = rust_limb - expected_limb
        print(f"Limb[{i}]: MISMATCH")
        print(f"  Rust:     0x{rust_limb:016X} ({rust_limb})")
        print(f"  Expected: 0x{expected_limb:016X} ({expected_limb})")
        print(f"  Diff:     {diff_limb:+d} (0x{abs(diff_limb):016X})")
    print()

# Check if it's off by n (the modulus)
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

print("Checking if difference is related to modulus n...")
print()

if abs(diff) == n:
    print(f"✅ Difference is EXACTLY n!")
elif abs(diff) < n:
    print(f"Difference is less than n (difference = {diff:+d})")
    print(f"Difference / n = {abs(diff) / n:.10f}")
else:
    print(f"Difference is greater than n")
    print(f"Difference / n = {abs(diff) / n:.10f}")

print()

# Check if Rust value + n == expected
if rust_value + n == expected_value:
    print("✅ RUST VALUE + n = EXPECTED VALUE!")
    print("   This suggests Barrett produced a value in range [-n, 0) instead of [0, n)")
elif rust_value - n == expected_value:
    print("✅ RUST VALUE - n = EXPECTED VALUE!")
    print("   This suggests Barrett produced a value in range [n, 2n) instead of [0, n)")
elif (rust_value + 2*n) & ((1 << 256) - 1) == expected_value:
    print("✅ RUST VALUE + 2n (mod 2^256) = EXPECTED VALUE!")
else:
    print("Relationship to n is not simple addition/subtraction")

print()
print("=" * 80)
