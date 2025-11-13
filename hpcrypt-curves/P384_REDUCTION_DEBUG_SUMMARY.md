# P-384 Fast Reduction Debugging Summary

## Problem Statement

Attempted to implement a native fast reduction algorithm for P-384 to replace the slow BigUint-based fallback (100-1000x slower). The P-384 modulus is:

```
p = 2^384 - 2^128 - 2^96 + 2^32 - 1
```

Therefore, the reduction relationship is:

```
2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
```

## Implementation Approach Attempted

### Initial Strategy

Followed the same limb-level pattern used successfully in P-256:

1. Store 768-bit multiplication result as 12 × u64 limbs
2. Convert to u128 working array for intermediate computations
3. Process high limbs (6-11) one by one from high to low
4. For each high limb value `hi` at position `i`, distribute it using the reduction formula:
   - Term 1: Add `hi × 1` at appropriate position
   - Term 2: Subtract `hi × 2^32` at appropriate position
   - Term 3: Add `hi × 2^96` at appropriate position
   - Term 4: Add `hi × 2^128` at appropriate position
5. Extract final 6-limb result with carry propagation

### Variations Attempted

Over the debugging session, tried multiple variations:

1. **Signed vs Unsigned**: Initially used `i128`, switched to `u128` (matching P-256)
2. **Multi-pass vs Single-pass**: Tried both iterating until high limbs zero and single-pass
3. **Guard conditions**: Tried restricting writes to `pos < 6` vs allowing `pos < 12`
4. **Wrapping arithmetic**: Tried `+=` vs `.wrapping_add()` (P-384 requires wrapping due to more additions than P-256)
5. **Chunked processing**: Split limbs into low/high 64-bit chunks to handle `u128 > u64::MAX` overflow

### Persistent Bug

Despite all variations, encountered a consistent **~2x error** in results:

```
Test: test_minimal_failing
Expected: 0x...18 (24 decimal)
Got:      0x...30 (48 decimal) ← exactly 2x

Expected: 0x...0d (13 decimal)
Got:      0x...1a (26 decimal) ← exactly 2x
```

This 2x pattern appeared in multiple limbs and persisted across:
- Different arithmetic types (i128, u128)
- Different loop structures (single-pass, multi-pass)
- Different guard conditions
- Different carry handling approaches

**Result**: 21/29 tests passing (72%), with systematic 2x errors in failing tests.

## Root Cause Analysis

### Simple Cases Work

Tests with small values (7×7, 100×100) pass correctly, indicating the formula and basic logic are sound.

### Complex Cases Fail

Larger values with high-bit sets in multiple limbs produce the 2x error, suggesting an issue with how values accumulate or overflow.

### Suspected Issues

1. **u128 Overflow Semantics**: When `working[i] > u64::MAX` due to overflow accumulation from previous terms, bit-shifting operations may not behave as expected
2. **Double-Counting**: Possible systematic double-application of certain reduction terms
3. **Limb-Level Abstraction**: The limb-by-limb approach may be fundamentally wrong for P-384

## Research: Industry Standard Implementations

### OpenSSL Implementation

Examined OpenSSL's `ecp_nistp384.c` and found they use a **completely different approach**:

#### Bit-Level vs Limb-Level

- **OpenSSL**: Works at bit precision, extracting specific bit ranges and placing them at specific target positions
- **My approach**: Works at limb level, processing entire 64-bit limbs at once

#### OpenSSL's Algorithm Structure

```c
// Phase 1: Eliminate high limbs (in[12] down to in[9])
// Each limb broken into specific bit ranges

acc[8] += in[12] >> 32;           // High 32 bits → acc[8]
acc[7] += (in[12] & 0xffffffff) << 24;  // Low 32 bits shifted → acc[7]
acc[7] += in[12] >> 8;            // Shifted by 8
acc[6] += (in[12] & 0xff) << 48;  // Low 8 bits shifted
acc[6] -= in[12] >> 16;           // Subtraction term
acc[5] -= (in[12] & 0xffff) << 40; // Low 16 bits
acc[6] += in[12] >> 48;           // High bits
acc[5] += (in[12] & 0xffffffffffff) << 8; // Low 48 bits

// Repeat for in[11], in[10], in[9]...
// Then Phase 2 for acc[8], acc[7]
// Then Phase 3 for final high-bit reduction
```

#### Key Differences

1. **Bit-precise operations**: Extracts and places specific bit ranges rather than processing whole limbs
2. **Three-phase reduction**: Gradually reduces from 13 limbs → 8 limbs → 7 limbs → 6 limbs
3. **Redundant representation**: Allows intermediate values to exceed normal bounds to prevent underflow
4. **Telescopic constants**: Uses pre-computed constants like `two124p108m76` to prevent overflow
5. **Manual carry propagation**: Explicit carry handling after each phase

### Why The Difference Matters

P-384's formula has terms at bit positions that don't align cleanly with 64-bit limb boundaries:
- 2^32: Splits across limb boundary
- 2^96: Splits across limb boundary
- 2^128: Aligns with limb 2 start

The bit-level approach handles these splits precisely by masking and shifting specific bit ranges, while the limb-level approach relies on generic bit-shift splitting that may accumulate errors.

## Test Results Summary

### Passing Tests (Simple Cases)
- `test_reduce_simple_case`: 7 × 7 ✓
- Various small-value tests ✓

### Failing Tests (Complex Cases)
- `test_minimal_failing`: Custom test with moderate limb values ✗ (2x error)
- `test_reduce_fast_vs_bigint`: Full test suite ✗ (21/29 passing)

### Current Performance
- BigUint implementation: ~208 ns (slow but correct)
- Native implementation: Would be ~20-30 ns if working (7-10x speedup)
- P-256 native: Works correctly with same limb-level approach

## Conclusions

### Why P-256 Works But P-384 Doesn't

1. **Formula structure**: P-256's formula (`2^256 ≡ 2^224 - 2^192 - 2^96 + 1`) is mostly subtractions, keeping values bounded
2. **P-384's formula** (`2^384 ≡ 2^128 + 2^96 - 2^32 + 1`) has more additions, causing accumulation and overflow
3. **Bit alignment**: P-256's terms may align better with 64-bit boundaries
4. **Overflow handling**: P-384 requires more careful handling of u128 values exceeding u64::MAX

### Fundamental Issue

The limb-level approach that works for P-256 appears insufficient for P-384. The systematic 2x error suggests a fundamental misunderstanding of how to apply the reduction formula at the limb level, possibly related to:
- How bit-shifted values split across limb boundaries when working with u128
- How overflow from one reduction term affects subsequent terms
- How to correctly handle values that don't fit in 64 bits

## Recommendations

### Option 1: Bit-Level Rewrite (Recommended)

Implement P-384 reduction using OpenSSL's bit-level approach:

**Pros**:
- Industry-proven algorithm
- Handles bit-alignment issues precisely
- Constant-time operation
- Will definitely work

**Cons**:
- Complete rewrite required
- More complex code (but well-documented in OpenSSL)
- Less intuitive than limb-level approach

**Estimated effort**: 4-6 hours for careful implementation + testing

### Option 2: Continue Debugging Limb-Level

Continue investigating the limb-level approach:

**Pros**:
- Maintains consistency with P-256 implementation
- Potentially simpler final code if bug found

**Cons**:
- Already spent significant time with no resolution
- Root cause still unclear despite many attempts
- May hit fundamental limitation of the approach

**Estimated effort**: Unknown (could be 1 hour or 10+ hours)

### Option 3: Hybrid Approach

Use BigUint for now, implement bit-level later:

**Pros**:
- Unblocks other work
- Can optimize later when time permits

**Cons**:
- Performance penalty remains (100-1000x slower)
- Delays optimization benefits

## Files Modified

- `hpcrypt-curves/src/p384/field_ops.rs`: Main reduction function
- Various test additions for debugging

## Next Steps

If proceeding with Option 1 (bit-level rewrite):

1. Study OpenSSL's `ecp_nistp384.c` in detail
2. Understand the three-phase reduction strategy
3. Implement `felem_reduce` equivalent in Rust
4. Add comprehensive tests matching OpenSSL test vectors
5. Benchmark against BigUint
6. Remove BigUint dependency once verified

## References

- OpenSSL source: `crypto/ec/ecp_nistp384.c`
- FIPS 186-3 Appendix D.2.4 (P-384 implementation notes)
- Solinas primes / Generalized Mersenne primes literature
- Research paper: "Speeding up Elliptic Curve Cryptography on the P-384 Curve" (armfazh)
