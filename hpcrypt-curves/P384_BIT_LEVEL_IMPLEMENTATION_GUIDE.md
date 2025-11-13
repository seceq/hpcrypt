# P-384 Bit-Level Reduction Implementation Guide

**Purpose**: Quick-start guide for implementing OpenSSL-style bit-level reduction
**Estimated effort**: 4-6 hours
**Expected speedup**: 7-10x (from ~208 ns to ~20-30 ns)

## Background

Current P-384 uses BigUint fallback for modular reduction (correct but slow). The limb-level approach that works for P-256 produces a systematic 2x error for P-384. The solution is to implement bit-level precision reduction as used in production implementations like OpenSSL.

See [P384_REDUCTION_DEBUG_SUMMARY.md](P384_REDUCTION_DEBUG_SUMMARY.md) for complete debugging history.

## Algorithm Overview

### The P-384 Prime
```
p = 2^384 - 2^128 - 2^96 + 2^32 - 1
```

### Reduction Relationship
```
2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
```

### Key Insight
Unlike limb-level processing (which operates on entire 64-bit values), bit-level processing extracts and places specific bit ranges using masks and targeted shifts.

## Implementation Steps

### Step 1: Set Up Accumulator Array

```rust
fn nist_p384_reduce_bitlevel(limbs: &[u64; 12]) -> Self {
    // Convert input to 128-bit accumulators
    let mut acc = [0u128; 13];  // 13 positions for intermediate values

    for i in 0..12 {
        acc[i] = limbs[i] as u128;
    }

    // Three-phase reduction follows...
}
```

**Why 13 positions?** OpenSSL uses 13 × 128-bit values as intermediate representation before reducing to final 7 × 64-bit (or 6 × 64-bit for our representation).

### Step 2: Phase 1 - Eliminate High Limbs (acc[12] down to acc[9])

For each high limb, extract specific bit ranges and redistribute according to the reduction formula.

**Example for acc[12]** (following OpenSSL pattern):

```rust
// Process acc[12] - highest limb
if acc[12] != 0 {
    let val = acc[12];

    // Extract and place specific bit ranges
    // These formulas come from applying the reduction relationship
    // 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 at the appropriate bit positions

    acc[8] = acc[8].wrapping_add(val >> 32);           // High 32 bits → acc[8]
    acc[7] = acc[7].wrapping_add((val & 0xffffffff) << 24);  // Low 32 bits, shifted
    acc[7] = acc[7].wrapping_add(val >> 8);            // Shifted by 8
    acc[6] = acc[6].wrapping_add((val & 0xff) << 48);  // Low 8 bits
    acc[6] = acc[6].wrapping_sub(val >> 16);           // Subtraction term
    acc[5] = acc[5].wrapping_sub((val & 0xffff) << 40); // Low 16 bits
    acc[6] = acc[6].wrapping_add(val >> 48);           // High bits
    acc[5] = acc[5].wrapping_add((val & 0xffffffffffff) << 8); // Low 48 bits

    acc[12] = 0;
}
```

**Repeat similar patterns for acc[11], acc[10], acc[9].**

### Step 3: Carry Propagation (Between Phases)

After processing high limbs, propagate carries:

```rust
// Propagate carries through acc[4..8]
for i in 4..8 {
    let carry = acc[i] >> 56;  // Extract high bits (assuming 56-bit limbs)
    acc[i] &= 0x00ffffffffffffff;  // Mask to 56 bits
    acc[i + 1] = acc[i + 1].wrapping_add(carry);
}
```

### Step 4: Phase 2 - Eliminate acc[8] and acc[7]

Process acc[8] and acc[7] similarly to Phase 1, redistributing to lower accumulators.

**Example for acc[8]**:

```rust
if acc[8] != 0 {
    let val = acc[8];

    // Apply reduction formula at this bit position
    // Specific bit extractions and placements
    acc[4] = acc[4].wrapping_add(val >> ...);
    acc[3] = acc[3].wrapping_add((val & ...) << ...);
    // ... continue pattern

    acc[8] = 0;
}
```

### Step 5: Phase 3 - Eliminate High Bits of acc[6]

The final phase handles overflow bits from acc[6]:

```rust
// Extract high bits beyond 384-bit boundary
let temp = acc[6] >> 48;  // Assuming acc[6] represents bits at certain position
acc[6] &= 0x0000ffffffffffff;

if temp != 0 {
    // Redistribute according to reduction formula
    acc[3] = acc[3].wrapping_add(temp >> 40);
    acc[2] = acc[2].wrapping_add((temp & 0xffffffffff) << 16);
    acc[2] = acc[2].wrapping_add(temp >> 16);
    acc[1] = acc[1].wrapping_add((temp & 0xffff) << 40);
    acc[1] = acc[1].wrapping_sub(temp >> 24);
    acc[0] = acc[0].wrapping_sub((temp & 0xffffff) << 32);
    acc[0] = acc[0].wrapping_add(temp);
}
```

### Step 6: Final Carry Propagation and Extraction

```rust
// Final carry propagation from acc[0] through acc[6]
let mut result_limbs = [0u64; 6];
let mut carry = 0u128;

for i in 0..6 {
    let sum = acc[i] + carry;
    result_limbs[i] = sum as u64;
    carry = sum >> 64;
}

let mut result = Self::from_limbs(result_limbs);

// Handle remaining carry (should be small)
while carry > 0 {
    let c = carry.min(u64::MAX as u128) as u64;
    result = result.add(&Self::from_u64(c));
    carry -= c as u128;
}

// Final reduction to ensure result < p
for _ in 0..10 {
    if result.gte_modulus() {
        result = result.sub_modulus_unchecked();
    } else {
        break;
    }
}

result
```

## Implementation Checklist

- [ ] Set up 13 × u128 accumulator array
- [ ] Implement Phase 1: Eliminate acc[12..9]
  - [ ] acc[12] reduction
  - [ ] acc[11] reduction
  - [ ] acc[10] reduction
  - [ ] acc[9] reduction
- [ ] Add carry propagation between phases
- [ ] Implement Phase 2: Eliminate acc[8,7]
  - [ ] acc[8] reduction
  - [ ] acc[7] reduction
- [ ] Implement Phase 3: High bits of acc[6]
- [ ] Final carry propagation
- [ ] Extract to 6-limb result
- [ ] Handle remaining carry
- [ ] Final modular reduction

## Testing Strategy

### Test Progression

1. **Unit test individual phases**:
   ```rust
   #[test]
   fn test_phase1_acc12() {
       // Test acc[12] reduction in isolation
   }
   ```

2. **Compare with BigUint**:
   ```rust
   #[test]
   fn test_bitlevel_vs_bigint() {
       for _ in 0..1000 {
           let a = random_field_element();
           let b = random_field_element();
           let product = a.mul(&b);

           assert_eq!(
               nist_p384_reduce_bitlevel(&product),
               nist_p384_reduce_bigint(&product)
           );
       }
   }
   ```

3. **Known test vectors**:
   - Simple cases: 7×7, 100×100
   - Edge cases: Large values, values with specific bit patterns
   - NIST test vectors if available

4. **Full test suite**: Run all 106 P-384 tests

## Derivation of Bit Operations

The specific bit extractions and placements come from carefully expanding the reduction formula at each bit position.

**General approach**:

1. For limb at position `i` (representing bits `i*64` to `(i+1)*64 - 1`)
2. This is at position `2^(i*64)` beyond the base
3. If `i ≥ 6`, we're beyond 2^384, so apply: `2^(i*64) ≡ 2^(i*64 - 384) * (2^128 + 2^96 - 2^32 + 1)`
4. Expand and determine which bits go to which accumulator positions
5. Use masks to extract specific bit ranges
6. Use shifts to place them at correct positions

**This is complex!** Recommend studying OpenSSL's code to understand the exact patterns.

## Reference Implementation

**OpenSSL source**:
- File: `crypto/ec/ecp_nistp384.c`
- Function: `felem_reduce_ref`
- GitHub: https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_nistp384.c

**Key observations from OpenSSL**:
1. Uses redundant representation (values can exceed normal bounds)
2. Employs "telescopic constants" to prevent underflow
3. Three distinct phases with specific bit operations for each
4. Constant-time implementation (no branches on secret data)

## Performance Expectations

### Before (BigUint)
- ~208 ns per multiplication+reduction
- Works for all values
- Correct but slow

### After (Bit-Level)
- ~20-30 ns per multiplication+reduction
- 7-10x speedup
- Production-grade performance

### Comparison with P-256
| Curve | Method | Performance |
|-------|--------|-------------|
| P-256 | Limb-level | ~20 ns ✅ |
| P-384 | BigUint | ~208 ns ⚠️ |
| P-384 | Bit-level (target) | ~20-30 ns 🎯 |

## Common Pitfalls

### 1. Off-by-One in Bit Positions
Double-check that bit extractions account for limb boundaries correctly.

### 2. Sign Issues with Subtractions
Use `wrapping_sub` to handle underflow in u128 arithmetic.

### 3. Missing Carry Propagation
Ensure carries are propagated between phases.

### 4. Incorrect Masking
Verify mask constants match the intended bit ranges.
- `0xff` = 8 bits
- `0xffff` = 16 bits
- `0xffffffff` = 32 bits
- `0xffffffffffff` = 48 bits

### 5. Final Reduction
Don't forget the final reduction loop to ensure result < p.

## Debugging Tips

1. **Add extensive logging** (compile-time feature):
   ```rust
   #[cfg(feature = "debug-reduction")]
   eprintln!("acc[12] = {:032x}", acc[12]);
   ```

2. **Test with simple inputs first**:
   - Zero values
   - Single-limb values
   - Powers of 2

3. **Compare phase-by-phase** with BigUint:
   - After Phase 1
   - After Phase 2
   - After Phase 3
   - Final result

4. **Use property-based testing**:
   ```rust
   use proptest::prelude::*;

   proptest! {
       #[test]
       fn bitlevel_matches_bigint(a: u64, b: u64) {
           // Test with random inputs
       }
   }
   ```

## Timeline Estimate

- **Hour 1-2**: Implement Phase 1, initial testing
- **Hour 3-4**: Implement Phases 2 & 3, debug
- **Hour 5**: Comprehensive testing, fix edge cases
- **Hour 6**: Performance benchmarking, documentation

## Success Criteria

✅ All 106 P-384 tests pass
✅ Matches BigUint output for 10,000+ random inputs
✅ Performance: 20-30 ns per operation
✅ Constant-time operation verified
✅ No external dependencies (BigUint removed)

## Next Steps After Implementation

1. Benchmark against BigUint
2. Verify constant-time properties
3. Remove `num-bigint` dependency from Cargo.toml
4. Update P384_CURRENT_STATUS.md
5. Consider submitting as contribution to hpcrypt

## Questions?

Refer to:
- [P384_REDUCTION_DEBUG_SUMMARY.md](P384_REDUCTION_DEBUG_SUMMARY.md): Why limb-level failed
- [P384_CURRENT_STATUS.md](P384_CURRENT_STATUS.md): Current implementation state
- OpenSSL source code: Definitive reference implementation

---

**Ready to implement?** Start with Phase 1 (acc[12] reduction) and test thoroughly before proceeding to subsequent phases. Good luck!
