# RFC 5297 Test Vectors Added to Repository

## Summary

Successfully added RFC 5297 (AES-SIV) test vectors to the official RFC test suite infrastructure.

## Files Added

### 1. Test Vector File
**Location**: [`tests/rfc-vectors/rfc5297-aes-siv.json`](tests/rfc-vectors/rfc5297-aes-siv.json)

Contains 6 official test vectors:
1. RFC 5297 Appendix A.1 - Deterministic Authenticated Encryption
2. RFC 5297 Appendix A.2 - Nonce-Based with multiple AAD components
3. Wycheproof Test 2 - Empty plaintext and empty AAD
4. Wycheproof Test 31 - All-zero SIV edge case
5. Wycheproof Test 33 - All-ones SIV edge case
6. Wycheproof Test 296 - AES-256-SIV with empty inputs

### 2. RFC Test Implementation
**Location**: [`tests/rfc-tests/tests/aes_siv.rs`](tests/rfc-tests/tests/aes_siv.rs)

Comprehensive test harness that validates:
- Both AES-128-SIV and AES-256-SIV variants
- Single AAD mode (standard API)
- Multi-AAD mode (RFC A.2 with multiple AAD components)
- Empty message edge cases
- Roundtrip encryption/decryption
- Tag (SIV) verification
- Ciphertext verification

## Test Results

```
=== AES-SIV RFC 5297 Tests ===
Total test cases: 6

PASSED: RFC 5297 Appendix A.1
PASSED: RFC 5297 Appendix A.2
PASSED: Empty inputs (Wycheproof Test 2)
PASSED: All-zero SIV (Wycheproof Test 31)
PASSED: All-ones SIV (Wycheproof Test 33)
PASSED: AES-256-SIV empty (Wycheproof Test 296)

Passed:  6
Failed:  0
Skipped: 0
Total:   6
```

## Documentation Updates

### Updated Files

1. **[`tests/rfc-vectors/README.md`](tests/rfc-vectors/README.md)**
   - Added RFC 5297 section with comprehensive coverage description
   - Added RFC 5297 to errata checking list
   - Added `aes_siv` to usage examples

2. **[`tests/rfc-tests/Cargo.toml`](tests/rfc-tests/Cargo.toml)**
   - Added `aes_siv` test binary configuration
   - Test requires `enable-aead-tests` feature

## Running the Tests

```bash
# Run all RFC tests
cargo test --package rfc-tests --features enable-aead-tests

# Run only AES-SIV RFC tests
cargo test --package rfc-tests aes_siv --features enable-aead-tests

# Run with output
cargo test --package rfc-tests aes_siv --features enable-aead-tests -- --nocapture
```

## Test Vector Format

Each test vector includes:
```json
{
  "test_id": 1,
  "source": "RFC 5297 Appendix A.1",
  "description": "Deterministic Authenticated Encryption Example",
  "algorithm": "AES-128-SIV",
  "key": "...",
  "nonce": "...",
  "aad": "..." or "aad_components": [...],
  "plaintext": "...",
  "siv": "...",
  "ciphertext": "...",
  "siv_and_ciphertext": "...",
  "note": "..."
}
```

### Special Features

- **Multi-AAD Support**: Test 2 (RFC A.2) uses `aad_components` array to test multiple AAD inputs
- **Empty Values**: Empty strings (`""`) are preserved to test edge cases
- **SIV Separation**: Both `siv` and `ciphertext` are provided separately for validation
- **Full Output**: `siv_and_ciphertext` provides the complete expected output

## Integration with Existing Test Infrastructure

### Consistency with Other RFC Tests

The AES-SIV test follows the established patterns:
- Uses `rfc_tests` helper library for test vector loading
- Consistent error handling and reporting
- TestStats tracking (passed/failed/skipped)
- Proper feature gating (`enable-aead-tests`)
- Roundtrip validation for all test cases

### Test Organization

```
tests/
├── rfc-vectors/
│   ├── rfc5297-aes-siv.json   # Test vectors
│   └── README.md               # Documentation
└── rfc-tests/
    ├── Cargo.toml              # Test configuration
    ├── tests/
    │   └── aes_siv.rs          # Test implementation
    └── src/
        └── lib.rs              # Shared test utilities
```

## Coverage

The RFC test suite now covers:

### RFC 5297 Official Vectors
- Appendix A.1 - Deterministic mode
- Appendix A.2 - Nonce-based with multi-AAD

### Edge Cases from Wycheproof
- Empty plaintext and AAD
- All-zero SIV (0x00...00)
- All-ones SIV (0xFF...FF)
- AES-256-SIV variant

### Implementation Features Validated
- AES-128-SIV (32-byte keys)
- AES-256-SIV (64-byte keys)
- Single AAD component
- Multiple AAD components
- Empty message encryption
- Nonce-based mode
- Deterministic mode (no nonce)

## Relationship to Other AES-SIV Tests

### hpcrypt-aead Package Tests
**Location**: `hpcrypt-aead/tests/`
- More comprehensive (29 total tests)
- Property-based testing (determinism, sensitivity, etc.)
- Extensive Wycheproof integration (295 vectors)
- Development and debugging focus

### RFC Tests (This Addition)
**Location**: `tests/rfc-tests/`
- Official RFC compliance only (6 vectors)
- Interoperability validation
- Minimal, canonical test set
- Production compliance focus

Both test suites are complementary and serve different purposes.

## Notes

- NIST CAVP does **not** have test vectors for AES-SIV (RFC 5297)
- NIST CAVP only has AES-GCM-SIV, which is a different algorithm
- RFC 5297 test vectors are the primary official source for AES-SIV
- Wycheproof provides additional edge case coverage

## References

- [RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption](https://datatracker.ietf.org/doc/html/rfc5297)
- [RFC 5297 Errata](https://www.rfc-editor.org/errata/rfc5297)
- [Wycheproof AES-SIV Test Vectors](https://github.com/google/wycheproof)
- [RustCrypto AES-SIV Implementation](https://github.com/RustCrypto/AEADs/tree/master/aes-siv)
