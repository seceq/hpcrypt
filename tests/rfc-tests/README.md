# RFC Test Suite

This test suite validates HPCrypt implementations against official IETF RFC test vectors.

## Overview

The RFC test suite complements the existing test infrastructure:

- **Wycheproof** (`../wycheproof-tests/`) - Security vulnerability testing (edge cases, CVEs)
- **NIST CAVP** (`../cavp-tests/`) - FIPS compliance and standards conformance
- **RFC Tests** (`./`) - Protocol correctness and interoperability

## Test Vectors

All test vectors are located in `../rfc-vectors/`:

| RFC | Algorithm | Status | Source |
|-----|-----------|--------|--------|
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) | HPKE | Placeholder | [CFRG](https://github.com/cfrg/draft-irtf-cfrg-hpke) |
| [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) | OPAQUE | Placeholder | [CFRG](https://github.com/cfrg/draft-irtf-cfrg-opaque) |
| [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) | Argon2 | Placeholder | RFC Section 5 |
| [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) | scrypt | Implemented | RFC Section 12 |
| [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054.html) | SRP | Placeholder | RFC Appendix B |

**Legend:**
- Implemented - Test runner fully implemented
- Placeholder - Test infrastructure ready, implementation pending
- Not Started - No test file yet

## Running Tests

### Run All RFC Tests

```bash
cargo test --package rfc-tests --features enable-all-tests
```

### Run Specific Tests

```bash
# scrypt (working implementation)
cargo test --package rfc-tests --features enable-kdf-tests scrypt

# HPKE (placeholder)
cargo test --package rfc-tests --features enable-hpke-tests hpke

# OPAQUE (placeholder)
cargo test --package rfc-tests --features enable-opaque-tests opaque

# Argon2 (placeholder)
cargo test --package rfc-tests --features enable-kdf-tests argon2

# SRP (placeholder)
cargo test --package rfc-tests --features enable-srp-tests srp
```

### Run Just Vector Loading Tests

```bash
# Verify all test vectors load correctly
cargo test --package rfc-tests --features enable-all-tests vector_count
```

## Test Status

### scrypt (RFC 7914)

- **Implementation:** `hpcrypt-kdf::scrypt`
- **Test File:** `tests/scrypt.rs`
- **Vectors:** 4 test cases from RFC 7914 Section 12
- **Status:** Fully implemented and passing

### HPKE (RFC 9180)

- **Implementation:** `hpcrypt-hpke` (exists but needs testing)
- **Test File:** `tests/hpke.rs` (placeholder)
- **Vectors:** Official CFRG vectors from GitHub
- **Next Steps:** Implement test runner using hpcrypt-hpke API

### OPAQUE (RFC 9497)

- **Implementation:** `hpcrypt-pake` (exists but needs testing)
- **Test File:** `tests/opaque.rs` (placeholder)
- **Vectors:** Official CFRG vectors (454 test cases)
- **Next Steps:** Implement test runner using hpcrypt-pake API

### Argon2 (RFC 9106)

- **Implementation:** `hpcrypt-kdf::argon2` (check availability)
- **Test File:** `tests/argon2.rs` (placeholder)
- **Vectors:** 3 test cases (Argon2d, Argon2i, Argon2id)
- **Next Steps:** Verify Argon2 API in hpcrypt-kdf

### SRP (RFC 5054)

- **Implementation:** `hpcrypt-srp` (exists but needs testing)
- **Test File:** `tests/srp.rs` (placeholder)
- **Vectors:** 1 test case from RFC 5054 Appendix B
- **Next Steps:** Implement test runner using hpcrypt-srp API

## Implementation Guide

### For HPCrypt Developers

To activate a placeholder test:

1. **Check the implementation exists:**
   ```bash
   # Example for HPKE
   ls ../../hpcrypt-hpke/src/
   ```

2. **Review the API:**
   ```rust
   // Read the public API
   cat ../../hpcrypt-hpke/src/lib.rs
   ```

3. **Implement the test runner:**
   - Open the corresponding test file (e.g., `tests/hpke.rs`)
   - Replace the placeholder code with actual API calls
   - Match the test vector structure to the API

4. **Run the test:**
   ```bash
   cargo test --package rfc-tests --features enable-hpke-tests hpke
   ```

### Test Structure

All tests follow this pattern:

```rust
use rfc_tests::{load_test_file, decode_hex, encode_hex, TestStats};
use serde::Deserialize;

#[derive(Deserialize)]
struct MyTestVector {
    // Match JSON structure
}

#[test]
fn test_my_rfc() {
    let vectors: Vec<MyTestVector> = load_test_file("rfcXXXX-algorithm.json");
    let mut stats = TestStats::new();

    for test in &vectors {
        // 1. Decode inputs
        // 2. Call hpcrypt API
        // 3. Compare outputs
        // 4. Update stats
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0);
}
```

## Why RFC Test Vectors?

### Interoperability
RFC test vectors ensure HPCrypt implementations can interoperate with other libraries following the same RFCs.

### Standards Compliance
Unlike Wycheproof (security) or CAVP (FIPS), RFC vectors validate protocol-level correctness.

### Stable References
RFCs are frozen specifications - vectors don't change (except via rare errata).

## Contributing

When adding new RFC test vectors:

1. Add vectors to `../rfc-vectors/rfcXXXX-algorithm.json`
2. Create test file in `tests/algorithm.rs`
3. Add Cargo.toml entry for the test
4. Update this README
5. Run and verify tests

## License

Test vectors are extracted from IETF RFCs and CFRG specifications (public domain).
Test runner code is part of HPCrypt (check repository license).
