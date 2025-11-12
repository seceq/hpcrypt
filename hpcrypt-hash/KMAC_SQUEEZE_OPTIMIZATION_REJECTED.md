# KMAC Word-at-a-Time Squeezing Optimization - REJECTED

## Date
2025-11-11

## Optimization Attempted  
Word-at-a-time squeezing for KMAC128/256, migrating the technique that showed 40-50% improvement in SHA-3.

## Benchmark Results - REJECTED

**Average improvement: 3.9%** (Expected: 40-50%)
**Regressions: 5 out of 15 tests (33%)**
**Worst regression: +12.63%**

| Test Case       | Baseline | Optimized | Change    |
|-----------------|----------|-----------|-----------|
| Msg32B_Out16B   | 2.76µs   | 2.41µs    | -12.51%   |
| Msg32B_Out128B  | 2.42µs   | 2.53µs    | **+4.52%** ❌ |
| Msg1024B_Out32B | 4.79µs   | 4.99µs    | **+3.97%** ❌ |
| Msg16384B_Out16B| 39.42µs  | 44.40µs   | **+12.63%** ❌ |
| Msg16384B_Out32B| 44.58µs  | 46.30µs   | **+3.85%** ❌ |
| Msg16384B_Out64B| 39.81µs  | 42.61µs   | **+7.03%** ❌ |

## Why It Failed

1. **KMAC-specific overhead dilutes squeezing benefit**
   - encode_string(), bytepad(), right_encode() add 15-20% overhead
   - Squeezing only represents ~15% of total KMAC cost (vs 25% in SHA-3)

2. **Small outputs regress** 
   - Word-at-a-time macro overhead (division, branching) exceeds benefit for 16-64B outputs
   - Typical MAC outputs are 16-32B

3. **Optimization is workload-dependent**
   - Only helps with large outputs (256B+)
   - Real-world KMAC rarely needs >64B outputs

## Decision: REJECTED

Per directive "reject techniques with regression":
- 33% of tests regressed
- 3.9% average gain far below promised 40-50%
- Optimization doesn't match real-world KMAC usage patterns

## Files Deleted
- `hpcrypt-hash/src/kmac_optimized.rs`
- `hpcrypt-hash/benches/kmac_squeeze_comparison.rs`

## Lesson Learned
Optimizations that work for one algorithm don't always transfer to related algorithms. Always measure in context.
