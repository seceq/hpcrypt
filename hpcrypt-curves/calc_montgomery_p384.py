#!/usr/bin/env python3
"""
Calculate Montgomery constants for P-384 field arithmetic.

Montgomery arithmetic requires three constants:
1. R = 2^384 (the Montgomery radix)
2. R² mod p (for converting to Montgomery form)
3. p' = -p^(-1) mod R (for Montgomery reduction REDC)

P-384 prime: p = 2^384 - 2^128 - 2^96 + 2^32 - 1
"""

def extended_gcd(a, b):
    """Extended Euclidean algorithm: returns (gcd, x, y) where ax + by = gcd(a,b)"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """Compute modular inverse of a modulo m"""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

# P-384 prime modulus
# p = 2^384 - 2^128 - 2^96 + 2^32 - 1
# In hex: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF

# Verify this matches the limbs representation (little-endian)
# limbs: [0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]
p_from_limbs = (
    0x00000000FFFFFFFF |
    (0xFFFFFFFF00000000 << 64) |
    (0xFFFFFFFFFFFFFFFE << 128) |
    (0xFFFFFFFFFFFFFFFF << 192) |
    (0xFFFFFFFFFFFFFFFF << 256) |
    (0xFFFFFFFFFFFFFFFF << 320)
)

assert p == p_from_limbs, "Modulus mismatch!"
print("✓ P-384 modulus verified")
print(f"p = 0x{p:096X}")
print()

# Montgomery radix R = 2^384 (one bit beyond the 384-bit modulus)
R_bits = 384
R = 2 ** R_bits
print(f"Montgomery radix R = 2^{R_bits}")
print()

# Calculate R mod p
# Since R = 2^384 and p = 2^384 - 2^128 - 2^96 + 2^32 - 1
# R mod p = 2^384 mod p = 2^128 + 2^96 - 2^32 + 1
R_mod_p = R % p
print(f"R mod p = 0x{R_mod_p:096X}")
print()

# Convert to 6 x 64-bit limbs (little-endian)
R_mod_p_limbs = [
    R_mod_p & 0xFFFFFFFFFFFFFFFF,
    (R_mod_p >> 64) & 0xFFFFFFFFFFFFFFFF,
    (R_mod_p >> 128) & 0xFFFFFFFFFFFFFFFF,
    (R_mod_p >> 192) & 0xFFFFFFFFFFFFFFFF,
    (R_mod_p >> 256) & 0xFFFFFFFFFFFFFFFF,
    (R_mod_p >> 320) & 0xFFFFFFFFFFFFFFFF,
]
print("R mod p as limbs (little-endian):")
print(f"  [0x{R_mod_p_limbs[0]:016X}, 0x{R_mod_p_limbs[1]:016X},")
print(f"   0x{R_mod_p_limbs[2]:016X}, 0x{R_mod_p_limbs[3]:016X},")
print(f"   0x{R_mod_p_limbs[4]:016X}, 0x{R_mod_p_limbs[5]:016X}]")
print()

# Calculate R² mod p for converting to Montgomery form
R2_mod_p = (R * R) % p
print(f"R² mod p = 0x{R2_mod_p:096X}")
print()

# Convert to 6 x 64-bit limbs (little-endian)
R2_mod_p_limbs = [
    R2_mod_p & 0xFFFFFFFFFFFFFFFF,
    (R2_mod_p >> 64) & 0xFFFFFFFFFFFFFFFF,
    (R2_mod_p >> 128) & 0xFFFFFFFFFFFFFFFF,
    (R2_mod_p >> 192) & 0xFFFFFFFFFFFFFFFF,
    (R2_mod_p >> 256) & 0xFFFFFFFFFFFFFFFF,
    (R2_mod_p >> 320) & 0xFFFFFFFFFFFFFFFF,
]
print("R² mod p as limbs (little-endian):")
print(f"  [0x{R2_mod_p_limbs[0]:016X}, 0x{R2_mod_p_limbs[1]:016X},")
print(f"   0x{R2_mod_p_limbs[2]:016X}, 0x{R2_mod_p_limbs[3]:016X},")
print(f"   0x{R2_mod_p_limbs[4]:016X}, 0x{R2_mod_p_limbs[5]:016X}]")
print()

# Calculate p' = -p^(-1) mod R for REDC algorithm
# First compute p^(-1) mod R
p_inv = mod_inverse(p, R)
# Then negate: p' = -p^(-1) mod R = R - p^(-1)
p_prime = (R - p_inv) % R

print(f"p' = -p^(-1) mod R = 0x{p_prime:096X}")
print()

# Convert to 6 x 64-bit limbs (little-endian)
p_prime_limbs = [
    p_prime & 0xFFFFFFFFFFFFFFFF,
    (p_prime >> 64) & 0xFFFFFFFFFFFFFFFF,
    (p_prime >> 128) & 0xFFFFFFFFFFFFFFFF,
    (p_prime >> 192) & 0xFFFFFFFFFFFFFFFF,
    (p_prime >> 256) & 0xFFFFFFFFFFFFFFFF,
    (p_prime >> 320) & 0xFFFFFFFFFFFFFFFF,
]
print("p' as limbs (little-endian):")
print(f"  [0x{p_prime_limbs[0]:016X}, 0x{p_prime_limbs[1]:016X},")
print(f"   0x{p_prime_limbs[2]:016X}, 0x{p_prime_limbs[3]:016X},")
print(f"   0x{p_prime_limbs[4]:016X}, 0x{p_prime_limbs[5]:016X}]")
print()

# Verification: p * p' ≡ -1 (mod R)
# This means p * p' + 1 ≡ 0 (mod R)
# Or equivalently: (p * p' + 1) is divisible by R
verification = (p * p_prime + 1) % R
print(f"Verification: (p * p' + 1) mod R = {verification}")
if verification == 0:
    print("✓ p' is correct: p * p' ≡ -1 (mod R)")
else:
    print("✗ ERROR: p' is incorrect!")
print()

# Summary for Rust constants
print("=" * 90)
print("RUST CONSTANTS TO ADD TO p384/constants.rs:")
print("=" * 90)
print()
print("/// Montgomery radix R mod p where R = 2^384")
print("///")
print("/// This constant represents R (the Montgomery radix) reduced modulo p.")
print("/// Used as the Montgomery representation of 1.")
print(f"/// In hex: {R_mod_p:096X}")
print("pub const MONTGOMERY_R: [u64; 6] = [")
print(f"    0x{R_mod_p_limbs[0]:016X},")
print(f"    0x{R_mod_p_limbs[1]:016X},")
print(f"    0x{R_mod_p_limbs[2]:016X},")
print(f"    0x{R_mod_p_limbs[3]:016X},")
print(f"    0x{R_mod_p_limbs[4]:016X},")
print(f"    0x{R_mod_p_limbs[5]:016X},")
print("];")
print()
print("/// Montgomery R² mod p where R = 2^384")
print("///")
print("/// This constant is used to convert from standard representation")
print("/// to Montgomery representation: to_montgomery(a) = a * R² * R^(-1) = a * R")
print(f"/// In hex: {R2_mod_p:096X}")
print("pub const MONTGOMERY_R2: [u64; 6] = [")
print(f"    0x{R2_mod_p_limbs[0]:016X},")
print(f"    0x{R2_mod_p_limbs[1]:016X},")
print(f"    0x{R2_mod_p_limbs[2]:016X},")
print(f"    0x{R2_mod_p_limbs[3]:016X},")
print(f"    0x{R2_mod_p_limbs[4]:016X},")
print(f"    0x{R2_mod_p_limbs[5]:016X},")
print("];")
print()
print("/// Montgomery p' = -p^(-1) mod R where R = 2^384")
print("///")
print("/// This constant is used in the REDC (Montgomery reduction) algorithm.")
print("/// Satisfies: p * p' ≡ -1 (mod R)")
print(f"/// In hex: {p_prime:096X}")
print("pub const MONTGOMERY_P_PRIME: [u64; 6] = [")
print(f"    0x{p_prime_limbs[0]:016X},")
print(f"    0x{p_prime_limbs[1]:016X},")
print(f"    0x{p_prime_limbs[2]:016X},")
print(f"    0x{p_prime_limbs[3]:016X},")
print(f"    0x{p_prime_limbs[4]:016X},")
print(f"    0x{p_prime_limbs[5]:016X},")
print("];")
print()

# Additional useful information
print("=" * 90)
print("MONTGOMERY ARITHMETIC OVERVIEW:")
print("=" * 90)
print()
print("To convert a → ā (Montgomery form):")
print("  ā = a * R mod p = montgomery_mul(a, R²)")
print()
print("To convert ā → a (standard form):")
print("  a = ā * R^(-1) mod p = montgomery_mul(ā, 1)")
print()
print("Montgomery multiplication (REDC):")
print("  montgomery_mul(ā, b̄) = ā * b̄ * R^(-1) mod p")
print("  Returns (c̄) where c̄ = (a * b) * R mod p")
print()
print("=" * 90)
