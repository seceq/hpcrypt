# KMAC128/256 Optimization Analysis
## Comprehensive Research on Rust-Level Optimization Techniques

**Date:** November 11, 2025
**Scope:** Software-only optimizations (no hardware acceleration, no Rayon parallelization)

---

## Executive Summary

This document analyzes optimization opportunities for KMAC128/256 implementation by comparing our current codebase against research papers, academic publications, and production implementations from RustCrypto and tiny-keccak. The analysis is organized by function and algorithmic component.

---

## Current Implementation Analysis

### Our Implementation Structure
- **Location:** `hpcrypt-hash/src/kmac.rs`
- **Architecture:** KMAC wraps CShake, which implements Keccak-f[1600]
- **Key functions:**
  - `keccak_f()` - 24-round permutation (lines 60-103)
  - `encode_string()` - NIST encoding (lines 107-111)
  - `left_encode()` / `right_encode()` - Length encoding (lines 115-158)
  - `bytepad()` - Padding to rate (lines 162-172)
  - `absorb_block()` - State update (lines 280-286, 392-398)
  - `update()` - Incremental absorption (lines 215-246, 330-358)
  - `finalize()` - Squeezing phase (lines 249-277, 361-389)

---

## Optimization Opportunities by Function

### 1. Keccak-f Permutation (lines 60-103)

#### Current State
- Implements 24 rounds with loops
- Theta, Rho/Pi, Chi, Iota steps implemented sequentially
- No explicit unrolling or lane complementing

#### Optimization Techniques from Research

**A. Full Round Unrolling**
- **Source:** tiny-keccak, RustCrypto implementations
- **Technique:** Unroll all 24 rounds at compile time
- **Benefits:** Eliminates loop overhead, enables better instruction scheduling
- **Implementation:** Use macros or const generics with `#[inline(always)]`
- **Expected Impact:** 10-20% improvement
- **Code Pattern:**
  ```rust
  macro_rules! unroll_rounds {
      () => {
          round_0(&mut state);
          round_1(&mut state);
          // ... up to round_23
      }
  }
  ```

**B. Step-Level Unrolling**
- **Source:** RustCrypto's unroll5! and unroll24! macros
- **Technique:** Unroll inner loops in Theta, Chi steps
- **Benefits:** Removes modulo operations, enables register allocation
- **Implementation Status:** Our SHA-3 already has `theta_unrolled` macro
- **Recommendation:** Migrate to KMAC's keccak_f
- **Expected Impact:** 5-10% improvement

**C. Lane Complementing**
- **Source:** IACR 2024/1515 - "Optimized Software Implementation of Keccak"
- **Technique:** Store 6 lanes as complements to reduce NOT operations
- **Details:**
  - Lanes: [1, 2, 8, 12, 17, 20] stored as complements
  - Reduces NOTs from 25 per round to 8 per round
  - Apply complement on load/store, not in Chi step
- **Benefits:** Reduces Chi step instructions by 68%
- **Implementation Complexity:** Medium - requires tracking complemented lanes
- **Expected Impact:** 8-12% improvement
- **Code Pattern:**
  ```rust
  const COMPLEMENTED_LANES: [bool; 25] = [
      false, true, true, false, false,  // row 0
      false, false, false, true, false,  // row 1
      false, false, true, false, false,  // row 2
      false, false, false, false, false, // row 3
      false, true, false, false, false,  // row 4
  ];

  // In Chi step:
  state[x + 5*y] = t[x] ^ ((!t[(x+1)%5]) & t[(x+2)%5]);
  // becomes:
  state[x + 5*y] = t[x] ^ ((t[(x+1)%5] | COMP[(x+1)%5]) & t[(x+2)%5]);
  ```

**D. Instruction Interleaving**
- **Source:** Keccak implementation overview 3.2
- **Technique:** Interleave operations on different variables for pipelining
- **Benefits:** Reduces pipeline stalls on modern CPUs
- **Implementation:** Rearrange assignments in generated code
- **Expected Impact:** 5-8% improvement on in-order CPUs, 2-3% on out-of-order

**E. Rotation Optimization**
- **Source:** ARM Keccak performance analysis (eprint 2023/773)
- **Current:** Uses `u64::rotate_left(n)` which compiles to single instruction
- **Optimization:** Trust LLVM - already optimal on 64-bit platforms
- **Note:** Ensure target features include BMI2 for `rorx` instruction
- **Recommendation:** Add `#[target_feature(enable = "bmi2")]` with runtime detection

### 2. Absorb Block Function (lines 280-286, 392-398)

#### Current State
```rust
fn absorb_block(&mut self, block: &[u8]) {
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        self.state[i] ^= word;
    }
    keccak_f(&mut self.state);
}
```

#### Optimization Techniques

**A. Manual Loop Unrolling**
- **Source:** Benchmarking best practices
- **Technique:** Unroll the XOR loop based on rate
  - KMAC128: 21 u64 words (168 bytes / 8)
  - KMAC256: 17 u64 words (136 bytes / 8)
- **Benefits:** Eliminates iterator overhead, explicit bounds
- **Expected Impact:** 3-5% improvement
- **Code Pattern:**
  ```rust
  #[inline(always)]
  fn absorb_block_128(&mut self, block: &[u8; 168]) {
      self.state[0] ^= u64::from_le_bytes(block[0..8].try_into().unwrap());
      self.state[1] ^= u64::from_le_bytes(block[8..16].try_into().unwrap());
      // ... unroll all 21 words
      self.state[20] ^= u64::from_le_bytes(block[160..168].try_into().unwrap());
      keccak_f(&mut self.state);
  }
  ```

**B. Unsafe Pointer-Based XOR**
- **Source:** High-performance crypto implementations
- **Technique:** Use pointer casts to XOR in-place
- **Warning:** Requires alignment guarantees
- **Benefits:** Zero-copy XOR operation
- **Expected Impact:** 5-8% improvement
- **Code Pattern:**
  ```rust
  #[inline(always)]
  unsafe fn absorb_block_unchecked(&mut self, block: &[u8]) {
      let words = block.as_ptr() as *const u64;
      for i in 0..(block.len() / 8) {
          self.state[i] ^= (*words.add(i)).to_le();
      }
      keccak_f(&mut self.state);
  }
  ```
- **Safety Requirements:** Block must be 8-byte aligned
- **Trade-off:** Removes `#![forbid(unsafe_code)]` from module

### 3. Encoding Functions (lines 115-158)

#### Current State
- `left_encode()` and `right_encode()` use heap allocation (Vec)
- Called during initialization for every KMAC operation
- Allocates 2-9 bytes typically

#### Optimization Techniques

**A. Stack Allocation with Fixed-Size Arrays**
- **Source:** Rust performance book - heap allocation avoidance
- **Technique:** Use [u8; 9] maximum size (1 length byte + 8 value bytes)
- **Benefits:** Eliminates heap allocation overhead
- **Expected Impact:** 15-25% improvement for small messages
- **Code Pattern:**
  ```rust
  fn left_encode(value: usize) -> ([u8; 9], usize) {
      if value == 0 {
          return ([1, 0, 0, 0, 0, 0, 0, 0, 0], 2);
      }
      let mut result = [0u8; 9];
      let num_bytes = ((64 - value.leading_zeros()) / 8) + 1;
      result[0] = num_bytes as u8;
      for i in 0..num_bytes {
          result[1 + i as usize] = ((value >> ((num_bytes - 1 - i) * 8)) & 0xFF) as u8;
      }
      (result, 1 + num_bytes as usize)
  }
  ```

**B. Compile-Time Constant Folding**
- **Source:** Const generics documentation
- **Technique:** Make encoding functions `const fn` where possible
- **Benefits:** Precompute common values at compile time
- **Implementation:**
  ```rust
  const fn left_encode_const(value: usize) -> ([u8; 9], usize) {
      // Same logic but const-evaluable
  }

  // Usage:
  const ENCODED_ZERO: ([u8; 9], usize) = left_encode_const(0);
  ```

**C. Lookup Table for Common Values**
- **Source:** General optimization practice
- **Technique:** Precompute encodings for 0-255
- **Benefits:** O(1) lookup for small values
- **Trade-off:** 2KB of static data
- **Expected Impact:** 10-15% for small output lengths

### 4. Bytepad Function (lines 162-172)

#### Current State
```rust
fn bytepad(input: &[u8], rate: usize) -> Vec<u8> {
    let mut result = left_encode(rate);
    result.extend_from_slice(input);
    while result.len() % rate != 0 {
        result.push(0);
    }
    result
}
```

#### Optimization Techniques

**A. Preallocate Output Vector**
- **Source:** Rust performance book
- **Technique:** Calculate final size upfront
- **Benefits:** Single allocation instead of multiple reallocations
- **Expected Impact:** 5-10% improvement
- **Code Pattern:**
  ```rust
  fn bytepad(input: &[u8], rate: usize) -> Vec<u8> {
      let encoded_len = left_encode_len(rate); // Don't construct, just get length
      let total_len = ((encoded_len + input.len() + rate - 1) / rate) * rate;
      let mut result = Vec::with_capacity(total_len);

      // Append encoded rate
      result.extend_from_slice(&left_encode(rate));
      result.extend_from_slice(input);
      result.resize(total_len, 0);
      result
  }
  ```

**B. In-Place Padding**
- **Source:** Zero-copy design patterns
- **Technique:** Write directly to preallocated buffer
- **Benefits:** Eliminates intermediate allocations
- **Expected Impact:** 8-12% improvement

### 5. Update Function (lines 215-246, 330-358)

#### Current State
- Handles partial buffer fills
- Processes complete blocks in a loop
- Buffers remaining data

#### Optimization Techniques

**A. Branch Prediction Hints**
- **Source:** Likely/unlikely annotations
- **Technique:** Use `#[cold]` for rare paths
- **Benefits:** Better branch prediction
- **Code Pattern:**
  ```rust
  #[cold]
  fn handle_partial_buffer(&mut self, data: &[u8]) {
      // Rare case: partial buffer
  }

  #[inline(always)]
  fn process_full_blocks(&mut self, data: &[u8]) {
      // Hot path: multiple blocks
  }
  ```

**B. Prefetching**
- **Source:** Modern CPU optimization techniques
- **Technique:** Hint next block load while processing current
- **Note:** Requires unstable features or assembly
- **Expected Impact:** 5-10% on large inputs

**C. Const Generic Rate Specialization**
- **Source:** Rust const generics
- **Technique:** Separate CShake128/256 with const generic RATE
- **Benefits:** Compile-time optimizations per variant
- **Expected Impact:** 3-5% improvement
- **Code Pattern:**
  ```rust
  struct CShake<const RATE: usize, const SECURITY: usize> {
      state: [u64; 25],
      buffer: [u8; RATE],
      buffer_len: usize,
  }

  type CShake128 = CShake<168, 128>;
  type CShake256 = CShake<136, 256>;
  ```

### 6. Finalize/Squeeze Function (lines 249-277, 361-389)

#### Current State
- Byte-at-a-time output extraction
- Permutes between output blocks

#### Optimization Techniques

**A. Word-at-a-Time Extraction**
- **Source:** Our SHA-3 implementation (sha3.rs lines 12-32)
- **Technique:** Extract u64 words, then convert to bytes
- **Status:** Already implemented in SHA-3, needs migration
- **Benefits:** 8x fewer memory operations
- **Expected Impact:** 40-50% improvement on small outputs
- **Code Pattern:** (from our sha3.rs)
  ```rust
  let complete_words = output.len() / 8;
  for i in 0..complete_words {
      let bytes = self.state[i].to_le_bytes();
      output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
  }
  // Handle remainder 0-7 bytes
  ```

**B. Batch Squeezing**
- **Source:** XKCP incremental API design
- **Technique:** Allow multiple `squeeze()` calls without re-finalizing
- **Architecture Change:** Separate finalize and squeeze phases
- **Benefits:** Enables XOF usage patterns
- **Code Pattern:**
  ```rust
  pub fn finalize(self) -> KmacXof128 { ... }

  impl KmacXof128 {
      pub fn squeeze(&mut self, output: &mut [u8]) { ... }
  }
  ```

### 7. State Precomputation

#### Optimization Technique

**Precompute Fixed Prefix**
- **Source:** NIST SP 800-185, Section 4.3
- **Technique:** Cache state after processing fixed N, S, and K
- **Quote:** "An implementation can precompute the result of processing this padded block"
- **Architecture:**
  ```rust
  pub struct PrecomputedKmac128 {
      precomputed_state: [u64; 25],
      buffer: [u8; 168],
      buffer_len: usize,
  }

  impl PrecomputedKmac128 {
      pub fn new(key: &[u8], customization: &[u8]) -> Self {
          let mut cshake = CShake128::new(b"KMAC", customization);
          let encoded_key = bytepad(&encode_string(key), 168);
          cshake.update(&encoded_key);
          // Save state here instead of in KMAC wrapper
          PrecomputedKmac128 {
              precomputed_state: cshake.state,
              buffer: cshake.buffer,
              buffer_len: cshake.buffer_len,
          }
      }

      pub fn compute(&self, message: &[u8], output_len: usize) -> Vec<u8> {
          let mut state = self.clone(); // Copy precomputed state
          state.update(message);
          state.finalize(output_len)
      }
  }
  ```
- **Benefits:** Amortizes initialization cost over multiple messages
- **Expected Impact:** 50-70% improvement for small repeated messages with same key

---

## Algorithmic Improvements

### 1. Avoid Redundant Padding Allocation

**Current Flow:**
1. `bytepad()` allocates Vec for encoded key
2. Copy to CShake buffer
3. Process and discard Vec

**Optimized Flow:**
1. Write encoded key directly to CShake buffer
2. Mark buffer as full, process immediately

**Expected Impact:** 10-15% improvement during initialization

### 2. Small Message Fast Path

**Technique:** Detect when message + key + overhead fits in single rate block
- **Condition:** `encoded_key.len() + message.len() + right_encode(L).len() < rate`
- **Optimization:** Single permutation instead of multiple absorb cycles
- **Expected Impact:** 30-40% for messages < 100 bytes

---

## Rust-Specific Optimizations

### 1. Compiler Hints and Attributes

**A. Inline Attributes**
```rust
#[inline(always)]  // Force inline for small hot functions
fn absorb_block(&mut self, block: &[u8]) { ... }

#[inline(never)]   // Prevent bloat for cold paths
fn handle_error(&self) { ... }

#[cold]            // Mark unlikely branches
fn slow_path(&mut self) { ... }
```

**B. Target Features**
```rust
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "bmi2")]
unsafe fn keccak_f_bmi2(state: &mut [u64; 25]) {
    // Use BMI2 instructions for rotations
}
```

**C. Profile-Guided Optimization Hints**
```rust
#[cfg_attr(feature = "pgo", inline(always))]
pub fn update(&mut self, data: &[u8]) { ... }
```

### 2. Type System Optimizations

**A. Zero-Sized Type Markers**
```rust
pub struct Kmac128<S = NotPrecomputed> {
    cshake: CShake128,
    _state: PhantomData<S>,
}

pub struct Precomputed;
pub struct NotPrecomputed;

impl Kmac128<Precomputed> {
    // Only available for precomputed variant
    pub fn mac_fast(&self, message: &[u8]) -> Vec<u8> { ... }
}
```

**B. Const Generic Specialization**
```rust
impl<const RATE: usize> CShake<RATE> {
    #[inline(always)]
    fn absorb_block(&mut self, block: &[u8; RATE]) {
        // Compiler knows RATE at compile time
        // Enables better optimization
    }
}
```

### 3. Memory Layout Optimizations

**A. Struct Field Ordering**
```rust
#[repr(C)]
pub struct CShake128 {
    state: [u64; 25],        // 200 bytes, align 8
    buffer: [u8; 168],       // 168 bytes
    buffer_len: usize,       // 8 bytes
    rate: usize,             // 8 bytes
    is_custom: bool,         // 1 byte
    // Total: 385 bytes (well-aligned)
}
```

**B. Cache Line Alignment**
```rust
#[repr(align(64))]  // Align to cache line
pub struct KmacState {
    state: [u64; 25],
    // ...
}
```

### 4. Feature Flags for Optimization Levels

**Cargo.toml configuration:**
```toml
[features]
default = ["std"]
std = []
unsafe_optimizations = []  # Enable unsafe fast paths
precomputation = []        # Enable state precomputation
const_generics = []        # Use const generic specialization
unrolled_permutation = []  # Full round unrolling
```

---

## Comparison with Other Implementations

### tiny-keccak
**Strengths:**
- Fully unrolled Keccak-f permutation
- Minimal dependencies
- Compact code using macros

**Techniques We Can Adopt:**
1. Macro-based permutation generation
2. Full round unrolling
3. Separation of state from API

### RustCrypto (sha3 crate)
**Strengths:**
- Unroll macros (`unroll5!`, `unroll24!`)
- Optional SIMD backends (not relevant for our scope)
- const generic support

**Techniques We Can Adopt:**
1. Unrolling macros for Theta and Chi
2. Const generic architecture
3. Feature flag organization

### XKCP (C Reference)
**Strengths:**
- Multiple optimization levels (compact, generic, optimized)
- Lane complementing technique
- Bit interleaving for 32-bit platforms

**Techniques We Can Adopt:**
1. Lane complementing for Chi step
2. Instruction interleaving strategy
3. Multi-level optimization approach

---

## Implementation Priority Recommendations

### High Priority (Immediate Impact, Low Risk)

1. **Word-at-a-Time Squeezing** (40-50% improvement)
   - Copy from our sha3.rs implementation
   - Effort: 30 minutes
   - Risk: Low (already tested in SHA-3)

2. **Stack-Allocated Encoding** (15-25% improvement)
   - Replace Vec with fixed arrays
   - Effort: 1-2 hours
   - Risk: Low (purely performance)

3. **Unroll Theta and Chi Steps** (5-10% improvement)
   - Copy macros from sha3.rs
   - Effort: 1-2 hours
   - Risk: Low (already tested)

4. **Preallocate bytepad() Output** (5-10% improvement)
   - Calculate size before allocation
   - Effort: 30 minutes
   - Risk: Low

### Medium Priority (Good Impact, Moderate Risk)

5. **Full Round Unrolling** (10-20% improvement)
   - Generate 24 round functions
   - Effort: 3-4 hours
   - Risk: Medium (binary size, code complexity)

6. **Const Generic Architecture** (3-5% improvement)
   - Refactor CShake with const RATE
   - Effort: 4-6 hours
   - Risk: Medium (API changes)

7. **Manual absorb_block Unrolling** (3-5% improvement)
   - Unroll XOR loops
   - Effort: 1 hour
   - Risk: Low

### Low Priority (Advanced Optimizations)

8. **Lane Complementing** (8-12% improvement)
   - Requires extensive testing
   - Effort: 6-8 hours
   - Risk: High (algorithmic correctness)

9. **Precomputation API** (50-70% for repeated operations)
   - New API surface
   - Effort: 4-6 hours
   - Risk: Medium (API design)

10. **Unsafe Pointer Optimizations** (5-8% improvement)
    - Removes safety guarantees
    - Effort: 2-3 hours
    - Risk: High (unsafe code)

---

## Estimated Cumulative Impact

**Phase 1 (High Priority):** 60-95% improvement
**Phase 2 (Medium Priority):** Additional 15-30%
**Phase 3 (Low Priority):** Additional 13-32%

**Total Potential:** 88-157% improvement (1.88x - 2.57x speedup)

---

## Testing and Validation Strategy

### 1. Correctness Tests
- Maintain all existing NIST test vectors
- Add property-based tests for equivalence
- Cross-validate against tiny-keccak and RustCrypto

### 2. Performance Benchmarks
```rust
#[bench]
fn bench_kmac128_small_message(b: &mut Bencher) {
    let key = &[0u8; 32];
    let message = &[0u8; 32];
    b.iter(|| kmac128(key, message, b"", 32));
}

#[bench]
fn bench_kmac128_large_message(b: &mut Bencher) {
    let key = &[0u8; 32];
    let message = &[0u8; 4096];
    b.iter(|| kmac128(key, message, b"", 32));
}

#[bench]
fn bench_kmac128_precomputed(b: &mut Bencher) {
    let precomputed = PrecomputedKmac128::new(&[0u8; 32], b"");
    let message = &[0u8; 32];
    b.iter(|| precomputed.compute(message, 32));
}
```

### 3. Regression Prevention
- Benchmark suite run on CI
- Performance metrics tracked over time
- Alert on >5% regression

---

## References

1. **NIST SP 800-185** - SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash
   - https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf

2. **IACR ePrint 2024/1515** - Optimized Software Implementation of Keccak, Kyber, and Dilithium
   - https://eprint.iacr.org/2024/1515.pdf
   - Lane complementing technique
   - Instruction interleaving

3. **Keccak Implementation Overview 3.2** - Keccak Team
   - https://keccak.team/files/Keccak-implementation-3.2.pdf
   - Bit interleaving, in-place processing

4. **IACR ePrint 2023/773** - An update on Keccak performance on ARMv7-M
   - https://eprint.iacr.org/2023/773.pdf
   - ARM-specific optimizations

5. **Optimizing Keccak** - Ethereum Foundation
   - https://notes.ethereum.org/@chfast/optimizing-keccak
   - BMI2 instruction usage
   - Benchmark methodology

6. **RustCrypto/sponges** - GitHub Repository
   - https://github.com/RustCrypto/sponges/tree/master/keccak
   - Unroll macros implementation
   - Const generic architecture

7. **tiny-keccak** - GitHub Repository
   - https://github.com/debris/tiny-keccak
   - Fully unrolled permutation
   - Minimal design patterns

8. **Rust Performance Book** - Nicholas Nethercote
   - https://nnethercote.github.io/perf-book/
   - Heap allocation avoidance
   - Inlining strategies

9. **XKCP** - eXtended Keccak Code Package
   - https://github.com/XKCP/XKCP
   - Reference C implementations
   - Multiple optimization levels

10. **Comparative Study of Keccak SHA-3 Implementations (2023)** - MDPI
    - https://www.mdpi.com/2410-387X/7/4/60
    - Cross-platform performance analysis

---

## Conclusion

KMAC128/256 optimization offers substantial performance gains through a combination of:

1. **Algorithmic optimizations:** Lane complementing, round unrolling, instruction interleaving
2. **Rust-specific techniques:** Const generics, stack allocation, inline hints
3. **Implementation strategies:** Precomputation, word-at-a-time operations, specialized paths

The recommended phased approach prioritizes low-risk, high-impact changes first (word-based squeezing, stack allocation) before tackling more complex optimizations (lane complementing, const generics).

All optimizations should maintain:
- Correctness (NIST test vectors)
- API compatibility (where possible)
- Code clarity (avoid premature obfuscation)
- Safety (unsafe code only where necessary and documented)

**Next Steps:**
1. Implement Phase 1 optimizations (1-2 days)
2. Benchmark and validate improvements
3. Proceed with Phase 2 based on results
4. Consider adding `kmac-precomputed` feature for specialized use cases
