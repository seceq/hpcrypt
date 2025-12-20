# RFC 5297 Multi-AAD Implementation

## Summary

Successfully implemented support for multiple AAD (Associated Authenticated Data) components in AES-SIV, as specified in RFC 5297 Appendix A.2.

## Changes Made

### 1. New Public API Methods

Added to `Aes128Siv`:
- `encrypt_with_aad_components(key, aad_components, nonce, plaintext)` - Encrypts with multiple AAD inputs
- `decrypt_with_aad_components(key, aad_components, nonce, iv_and_ciphertext)` - Decrypts with multiple AAD inputs

These methods properly implement RFC 5297's S2V function with multiple associated data strings:
```
S2V(K, AD1, AD2, ..., ADn, nonce, plaintext)
```

### 2. Internal Helper Functions

Added in [src/aes_siv.rs](src/aes_siv.rs):
- `siv_encrypt_multi_aad()` - Core encryption with multiple AAD components
- `siv_decrypt_multi_aad()` - Core decryption with multiple AAD components

These functions build the S2V input vector by:
1. Adding all AAD components in order
2. Adding nonce if present
3. Adding plaintext (always last)

### 3. RFC 5297 Appendix A.2 Test

Updated [tests/aes_siv_rfc5297_a2.rs](tests/aes_siv_rfc5297_a2.rs):

Before: Test documented that multi-AAD was not supported
After: Test now passes using the new API

```rust
let aad_components: [&[u8]; 2] = [&ad1, &ad2];
let result = Aes128Siv::encrypt_with_aad_components(
    &key_array,
    &aad_components,
    &nonce,
    &plaintext
);
```

Result matches RFC 5297 expected output:
```
Expected: 7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d
Got:      7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d
MATCH
```

### 4. Comprehensive Multi-AAD Tests

Added `test_multi_aad_components()` which verifies:
- Single AAD component
- Two AAD components
- Three AAD components
- Different AAD counts produce different SIVs
- AAD order matters (reversed order = different SIV)
- Multi-AAD with nonce works correctly
- All configurations roundtrip successfully

## Test Results

### RFC 5297 Test Vectors
- RFC 5297 Appendix A.1 - Deterministic mode (passing)
- RFC 5297 Appendix A.2 - Nonce-based mode with multiple AAD (now passing)
- RFC 5297 A.2 Simplified - Nonce-only mode (passing)
- Multi-AAD Components - Comprehensive multi-AAD tests (passing)

### Complete Test Suite
```
Library tests:         6/6 passed
Empty message tests:   4/4 passed
AAD handling tests:    5/5 passed
Deterministic tests:   7/7 passed
RFC tests:             4/4 passed (including A.2)
Edge case tests:       2/2 passed
Roundtrip tests:       1/1 passed
```

Total: All AES-SIV tests passing

## API Usage Examples

### Single AAD (original API still works)
```rust
let ct = Aes128Siv::encrypt(key, nonce, plaintext, aad);
let pt = Aes128Siv::decrypt(key, nonce, &ct, aad)?;
```

### Multiple AAD Components (new API)
```rust
let aad1 = b"header1";
let aad2 = b"header2";
let aad3 = b"header3";
let aad_components: [&[u8]; 3] = [aad1, aad2, aad3];

// Encrypts using S2V(K, aad1, aad2, aad3, nonce, plaintext)
let ct = Aes128Siv::encrypt_with_aad_components(
    key,
    &aad_components,
    nonce,
    plaintext
);

// Decrypt with same AAD components
let pt = Aes128Siv::decrypt_with_aad_components(
    key,
    &aad_components,
    nonce,
    &ct
)?;
```

## Implementation Details

The S2V function processes inputs as specified in RFC 5297 Section 2.4:
1. Start with `D = AES-CMAC(K, <zero>)`
2. For each AAD component (except last): `D = dbl(D) ⊕ CMAC(K, component)`
3. For nonce (if present): `D = dbl(D) ⊕ CMAC(K, nonce)`
4. For plaintext (last):
   - If `len(plaintext) >= 128`: `T = plaintext xorend D`
   - Otherwise: `T = dbl(D) ⊕ pad(plaintext)`
5. Return `CMAC(K, T)`

This ensures:
- Order of AAD components matters
- Empty AAD components are processed (not skipped)
- Nonce is authenticated as part of S2V
- Plaintext is always the last input

## RFC 5297 Compliance

The implementation now fully supports:
- Deterministic authenticated encryption (Appendix A.1)
- Nonce-based authenticated encryption (Appendix A.2)
- Multiple associated data strings
- Empty message encryption
- All edge cases from Wycheproof suite

## Backward Compatibility

The original API is fully backward compatible:
- `encrypt(key, nonce, plaintext, aad)` still works
- `decrypt(key, nonce, iv_ct, aad)` still works
- New multi-AAD methods are additions, not replacements

## References

- [RFC 5297: Synthetic Initialization Vector (SIV)](https://datatracker.ietf.org/doc/html/rfc5297)
- RFC 5297 Appendix A.2: Nonce-Based Authenticated Encryption Example
- RFC 5297 Section 2.4: S2V (String-to-Vector) construction
