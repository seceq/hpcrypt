# HPCrypt Testing Guide

This document describes the comprehensive testing infrastructure for the hpcrypt cryptographic library.

## Overview

HPCrypt uses [Google's Wycheproof](https://github.com/google/wycheproof) test vectors for security testing. Wycheproof contains over 80,000 test cases designed to detect common cryptographic implementation bugs and known attack vectors.

## Test Infrastructure

### Location

```
tests/
├── wycheproof/             # Git submodule with JSON test vectors
│   └── testvectors_v1/     # 327 JSON files with test cases
└── wycheproof-tests/       # Rust test infrastructure
    ├── src/lib.rs          # Common utilities
    ├── tests/
    │   ├── aead.rs         # AEAD cipher tests
    │   ├── ecdsa.rs        # ECDSA signature tests
    │   ├── rsa.rs          # RSA tests
    │   ├── hmac.rs         # HMAC tests
    │   └── ecdh.rs         # ECDH key exchange tests
    └── README.md           # Detailed documentation
```

### Running Tests

```bash
# Run all Wycheproof tests
cargo test -p wycheproof-tests

# Run specific algorithm tests
cargo test -p wycheproof-tests --test aead
cargo test -p wycheproof-tests --test ecdsa
cargo test -p wycheproof-tests --test rsa
cargo test -p wycheproof-tests --test hmac
cargo test -p wycheproof-tests --test ecdh
cargo test -p wycheproof-tests --test x25519
cargo test -p wycheproof-tests --test mac
cargo test -p wycheproof-tests --test ed25519
cargo test -p wycheproof-tests --test kdf
cargo test -p wycheproof-tests --test cipher
cargo test -p wycheproof-tests --test fpe

# Run specific test function
cargo test -p wycheproof-tests --test aead test_chacha20_poly1305_wycheproof
```

## Test Coverage

### Implemented Test Infrastructure (30,000+ test cases)

#### 1. AEAD Ciphers ([tests/aead.rs](wycheproof-tests/tests/aead.rs))
- ✅ ChaCha20-Poly1305 (325 tests)
- ✅ XChaCha20-Poly1305 (260 tests)
- ✅ AES-GCM 128/192/256 (218 tests)
- ✅ AES-GCM-SIV (137 tests)
- ✅ AES-CCM (552 tests)
- ✅ AES-EAX (612 tests)
- ✅ AES-SIV (442 tests)
- ✅ Ascon-128 (164 tests)
- ✅ Ascon-128a (164 tests)
- ✅ AEGIS-128 (475 tests)
- ✅ AEGIS-128L (475 tests)
- ✅ AEGIS-256 (472 tests)

**Tests include:**
- Valid encryption/decryption
- Invalid tags (authentication bypass attempts)
- Nonce reuse scenarios
- Edge cases (zero keys, special values)
- Wrong nonce/key sizes

#### 2. ECDSA Signatures ([tests/ecdsa.rs](wycheproof-tests/tests/ecdsa.rs))
- ✅ P-256 with SHA-256 (619 tests)
- ✅ P-256 with SHA-512 (616 tests)
- ✅ P-384 with SHA-384 (747 tests)
- ✅ P-384 with SHA-512 (747 tests)
- ✅ P-521 with SHA-512 (910 tests)
- ✅ secp256k1 with SHA-256 (489 tests) [Bitcoin/Ethereum]

**Critical vulnerabilities tested:**
- CVE-2022-21449: r=0, s=0 signatures (signature forgery)
- CVE-2020-14966: Edge case public keys
- Signature malleability
- Point at infinity
- Invalid DER encodings
- Arithmetic edge cases

#### 3. RSA ([tests/rsa.rs](wycheproof-tests/tests/rsa.rs))
- ✅ RSA-PSS 2048 SHA-256 (56 tests)
- ✅ RSA PKCS#1 v1.5 2048 SHA-256 (55 tests)
- ✅ RSA-OAEP 2048 SHA-256 (107 tests)

**Tests include:**
- Signature verification edge cases
- Padding oracle attacks
- Small public exponents
- Invalid encodings

#### 4. HMAC ([tests/hmac.rs](wycheproof-tests/tests/hmac.rs))
- ✅ HMAC-SHA-256 (168 tests)
- ✅ HMAC-SHA-384 (144 tests)
- ✅ HMAC-SHA-512 (168 tests)

**Tests include:**
- Various key sizes (empty, short, long)
- Various message sizes
- Tag truncation
- All-zero keys

#### 5. ECDH ([tests/ecdh.rs](wycheproof-tests/tests/ecdh.rs))
- ✅ P-256 (578 tests)
- ✅ P-384 (920 tests)
- ✅ P-521 (782 tests)
- ✅ secp256k1 (670 tests)

**Tests include:**
- Invalid public keys
- Point at infinity
- Low-order points
- Twist attacks
- Public key validation

#### 6. X25519/X448 ([tests/x25519.rs](wycheproof-tests/tests/x25519.rs))
- ✅ X25519 (150 tests)
- ✅ X448 (TBD tests)

**Tests include:**
- Low-order points
- All-zero outputs
- Private key clamping verification
- Invalid public keys
- Contributory behavior tests

#### 7. MAC Algorithms ([tests/mac.rs](wycheproof-tests/tests/mac.rs))
- ✅ AES-CMAC (192 tests)

**Tests include:**
- Various key sizes (128, 192, 256-bit)
- Tag truncation
- Empty messages
- Invalid tags

#### 8. Ed25519 Signatures ([tests/ed25519.rs](wycheproof-tests/tests/ed25519.rs))
- ✅ Ed25519 (532 tests)

**Critical vulnerabilities tested:**
- Signature malleability
- Low-order points
- Non-canonical encodings
- Invalid public keys
- Edge case signatures

#### 9. Key Derivation Functions ([tests/kdf.rs](wycheproof-tests/tests/kdf.rs))
- ✅ HKDF-SHA-256 (150+ tests)
- ✅ HKDF-SHA-384 (150+ tests)
- ✅ HKDF-SHA-512 (150+ tests)

**Tests include:**
- Various IKM (Input Keying Material) sizes
- Salt variations (empty, random)
- Info string variations
- Output length requests
- Maximum output length tests

#### 10. Block Cipher Modes ([tests/cipher.rs](wycheproof-tests/tests/cipher.rs))
- ✅ AES-CBC with PKCS#5 padding (216 tests)

**Critical vulnerabilities tested:**
- Padding oracle attacks (CVE-2014-3566 POODLE, CVE-2016-2107)
- Invalid padding acceptance
- Empty ciphertext handling
- Bad padding detection

**Tests include:**
- Valid encryption/decryption
- Invalid padding rejection
- Empty messages
- Messages of various sizes
- Key sizes: 128, 192, 256-bit

#### 11. Format-Preserving Encryption ([tests/fpe.rs](wycheproof-tests/tests/fpe.rs))
- ✅ AES-FF1 Radix-10 (3,845 tests)
- ✅ AES-FF1 Radix-16 (3,845 tests)
- ✅ AES-FF1 Radix-26 (3,845 tests)
- ✅ AES-FF1 Radix-32 (3,845 tests)
- ✅ AES-FF1 Radix-36 (3,845 tests)

**NIST SP 800-38G Rev. 1 compliance:**
- Minimum input length (radix^msglen >= 1,000,000)
- Edge cases in PRF computation
- Integer overflow detection
- Invalid message sizes
- Invalid key sizes
- Invalid plaintext digits

**Tests include:**
- Various radix sizes (2-65,536)
- Small message sizes (radix^msglen < 1,000,000)
- Normal message sizes
- Large message sizes (radix^msglen > 2^128)
- Tweak variations
- Edge case states in Feistel structure

## Integration Instructions

All test files support both **placeholder mode** (default) and **actual implementation testing** (via feature flags).

### Quick Start

**Placeholder Mode (Default):**
```bash
cargo test -p wycheproof-tests
```

**Test Actual Implementations:**
```bash
# Enable specific implementation tests
cargo test -p wycheproof-tests --features enable-aead-tests
cargo test -p wycheproof-tests --features enable-signature-tests

# Enable ALL implementation tests
cargo test -p wycheproof-tests --features enable-all-tests
```

For detailed integration instructions, see [wycheproof-tests/INTEGRATION.md](wycheproof-tests/INTEGRATION.md).

### Legacy Manual Integration

If you prefer to manually integrate without feature flags, you can still follow these steps: that validate test vector structure. To integrate with actual hpcrypt implementations:

### Example: ChaCha20-Poly1305

1. **Open** [tests/wycheproof-tests/tests/aead.rs](wycheproof-tests/tests/aead.rs)

2. **Find the TODO section** (around line 92):
```rust
// TODO: Uncomment when hpcrypt-aead ChaCha20-Poly1305 is ready
/*
use hpcrypt_aead::ChaCha20Poly1305;

match test.result {
    TestResult::Valid => {
        let cipher = ChaCha20Poly1305::new(&key);
        match cipher.decrypt(&nonce, &aad, &ct_with_tag) {
            Ok(decrypted) => {
                if decrypted != plaintext {
                    stats.failed += 1;
                } else {
                    stats.passed += 1;
                }
            }
            Err(_) => {
                stats.failed += 1;
            }
        }
    }
    // ... handle Invalid and Acceptable cases
}
*/
```

3. **Uncomment the code** and adjust API calls to match your implementation

4. **Update Cargo.toml** to enable the dependency:
```toml
[dependencies]
hpcrypt-aead = { workspace = true, features = ["std"] }
```

5. **Run the tests:**
```bash
cargo test -p wycheproof-tests --test aead test_chacha20_poly1305_wycheproof
```

## What Wycheproof Tests Catch

### Real-World Vulnerabilities
Wycheproof has detected bugs in major cryptographic libraries:

- **Java/JDK**: CVE-2022-21449 (accepting r=0, s=0 ECDSA signatures)
- **Go crypto**: Edge case signature validation
- **OpenSSL**: ECDH twist attacks
- **BouncyCastle**: Multiple signature malleability issues

### Common Implementation Bugs
- **Off-by-one errors** in loop bounds
- **Integer overflows** in field arithmetic
- **Missing validation** (e.g., not checking if r,s are in valid range)
- **Timing attacks** (though not directly tested, edge cases help)
- **Incorrect modular arithmetic** edge cases

## Updating Test Vectors

The test vectors are tracked as a git submodule. To update to the latest version:

```bash
cd tests/wycheproof
git pull origin master
cd ../..
git add tests/wycheproof
git commit -m "Update Wycheproof test vectors to latest version"
```

## Test Philosophy

### Why Wycheproof?

1. **Security-focused**: Tests edge cases that lead to vulnerabilities, not just correctness
2. **Real-world bugs**: Based on actual vulnerabilities found in production
3. **Comprehensive**: 80,000+ test cases across all major algorithms
4. **Language-agnostic**: JSON format works with any implementation
5. **Maintained**: Actively updated by Google's security team

### Test Structure

Each test case includes:
- **Valid/Invalid/Acceptable**: Expected result
- **Flags**: Vulnerability types (e.g., `InvalidSignature`, `EdgeCase`)
- **Comment**: Explanation of what the test checks
- **CVE references**: Links to known vulnerabilities

### Acceptable Results

Some tests are marked "Acceptable" meaning both accepting and rejecting the input is okay:
- Non-standard encodings (e.g., DER variations)
- Edge cases with no security impact
- Implementation-specific behavior

## Performance Considerations

Wycheproof tests are comprehensive but run quickly:
- **Library tests**: <1 second
- **Single algorithm**: 1-2 seconds
- **All tests**: ~10 seconds

The tests use placeholder implementations currently, so timing will increase when real crypto operations are added.

## Continuous Integration

Add to your CI pipeline:

```yaml
- name: Run Wycheproof Tests
  run: cargo test -p wycheproof-tests --all-features
```

## Additional Testing

Wycheproof complements but doesn't replace:
- **Unit tests**: Algorithm-specific correctness
- **NIST CAVP**: Standards compliance
- **Fuzzing**: Random input testing
- **Constant-time tests**: Timing attack resistance
- **Side-channel tests**: Power/cache analysis

## References

- [Wycheproof GitHub](https://github.com/google/wycheproof)
- [Wycheproof Paper](https://github.com/google/wycheproof/blob/master/doc/wycheproof.pdf)
- [Test Format Documentation](https://github.com/google/wycheproof/tree/master/doc)
- [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)

## Contributing

When adding a new cryptographic primitive:

1. ✅ Add Wycheproof tests FIRST (or alongside implementation)
2. ✅ Ensure all "Valid" tests pass
3. ✅ Ensure all "Invalid" tests are properly rejected
4. ✅ Document any "Acceptable" tests you intentionally skip
5. ✅ Never skip tests marked with CVE references

**Security is not optional. If Wycheproof tests fail, the implementation is not ready.**
