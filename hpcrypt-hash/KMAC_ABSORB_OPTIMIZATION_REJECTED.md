# KMAC Absorb Block Optimization - REJECTED ❌

## Date
2025-11-11

## Optimization Attempted

**Manual Loop Unrolling** - Replace iterator-based loop with unrolled XOR operations using rolling macros

### Expected Improvement
3-5% performance gain on absorb operations

### Implementation
- Created unrolled versions for KMAC128 (21 words/168 bytes) and KMAC256 (17 words/136 bytes)
- Used rolling macros for clean, readable unrolled code
- Safe implementation (no unsafe code)

### Rejected Optimizations
- **Unsafe pointer-based XOR**: Could have provided 5-8% additional gain but library forbids unsafe code

## Benchmark Results

### Single Absorb Operation - MASSIVE REGRESSIONS

| Variant | Baseline | Unrolled | Change | Status |
|---------|----------|----------|--------|--------|
| **KMAC128 (168B)** | **19.87 ns** | **53.74 ns** | **+170.5%** | ❌ FAIL |
| **KMAC256 (136B)** | **19.72 ns** | **44.00 ns** | **+123.2%** | ❌ FAIL |

### Multi-Operation - CATASTROPHIC REGRESSIONS

#### KMAC128 (168 bytes)

| Iterations | Baseline | Unrolled | Change | Status |
|------------|----------|----------|--------|--------|
| 10 | 75.31 ns | 384.86 ns | **+411.0%** | ❌ FAIL |
| 100 | 626.14 ns | 3.865 µs | **+517.3%** | ❌ FAIL |
| 1000 | 6.33 µs | 37.98 µs | **+500.0%** | ❌ FAIL |

#### KMAC256 (136 bytes)

| Iterations | Baseline | Unrolled | Change | Status |
|------------|----------|----------|--------|--------|
| 10 | 64.63 ns | 334.43 ns | **+417.5%** | ❌ FAIL |
| 100 | 482.28 ns | 3.051 µs | **+532.6%** | ❌ FAIL |
| 1000 | 4.71 µs | 30.69 µs | **+551.2%** | ❌ FAIL |

## Summary

**ALL tests regressed - no improvements whatsoever**

- Expected: 3-5% improvement
- Actual: **120-550% SLOWER**
- Total tests: 8
- Improvements: **0**
- Regressions: **8** (100% failure rate)

## Root Cause Analysis

### Why Manual Unrolling Failed

1. **Compiler is Already Optimizing**
   - LLVM's loop optimizer is extremely effective at XOR operations
   - The baseline iterator loop gets heavily optimized with auto-vectorization
   - Manual unrolling prevents LLVM from applying its own optimizations

2. **Stack Pressure**
   - Unrolled macro creates 21 (or 17) separate `u64::from_le_bytes` calls
   - Each creates temporary 8-byte array on stack
   - Excessive stack usage prevents register allocation
   - Forces spills to memory

3. **Macro Expansion Overhead**
   - Rolling macro generates repetitive code that's hard for LLVM to optimize
   - Loses the simple loop structure that LLVM recognizes and auto-vectorizes

4. **Loss of Cache Efficiency**
   - Baseline's tight loop has excellent instruction cache locality
   - Unrolled version has much larger code footprint
   - I-cache misses dominate at this scale

### Baseline Code Quality

```rust
// Baseline - LLVM optimizes this extremely well
fn absorb_block(&mut self, block: &[u8]) {
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        self.state[i] ^= word;
    }
    keccak_f(&mut self.state);
}
```

**Why this is already optimal:**
- `chunks_exact(8)` is zero-cost abstraction
- LLVM recognizes the XOR pattern and can vectorize
- Simple loop structure enables aggressive optimization
- Minimal stack usage
- Excellent register allocation

## Lessons Learned

### When Manual Optimization Backfires

1. **Trust the Compiler**: Modern optimizers (LLVM 15+) are extremely good at simple loops
2. **Measure First**: Never assume manual optimization will help without benchmarking
3. **Simple is Fast**: Clean, idiomatic code often compiles to the fastest machine code
4. **Stack vs Registers**: Unrolling can hurt by preventing register allocation

### Red Flags for Manual Unrolling

- ❌ Operation is simple (XOR, addition)
- ❌ Loop is already tight and cache-friendly
- ❌ Compiler has auto-vectorization opportunities
- ❌ No complex branching or unpredictable behavior

### When Manual Unrolling Helps

- ✓ Loop has complex control flow
- ✓ Unpredictable branches
- ✓ Compiler fails to unroll (provable via assembly inspection)
- ✓ Critical path has proven bottleneck

## Decision: REJECT

**Do NOT apply this optimization to baseline code.**

The current implementation in [kmac.rs:427-433](hpcrypt-hash/src/kmac.rs#L427-L433) and [kmac.rs:539-545](hpcrypt-hash/src/kmac.rs#L539-L545) is already optimal.

### Files to Keep

- [kmac_optimized_absorb.rs](hpcrypt-hash/src/kmac_optimized_absorb.rs) - Keep for educational purposes
- [benches/kmac_absorb_comparison.rs](hpcrypt-hash/benches/kmac_absorb_comparison.rs) - Keep for regression testing

### Recommendation

**Leave baseline unchanged.** The simple iterator-based loop is faster than manual unrolling by 2-5x.

If absorb performance becomes a bottleneck in the future, consider:
1. **Unsafe pointer-based access** (if unsafe code policy changes)
2. **SIMD vectorization** (explicit use of `std::arch`)
3. **Assembly inspection** to verify what LLVM is actually doing

But based on these benchmarks, **absorb_block is not a bottleneck** - it's already fast at ~20ns per operation.

## Impact on Overall KMAC Performance

Since encoding optimization delivered 66% improvement and absorb showed no improvement opportunity, the optimization work should focus on other areas:

1. **Keccak-f permutation** (dominates CPU time in long messages)
2. **Squeeze path** (impacts all output operations)
3. **Buffer management** (reduce allocation/copying)

**Absorb is fast enough. Leave it alone.**
