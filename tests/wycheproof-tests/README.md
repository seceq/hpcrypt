# Wycheproof Integration Tests

This crate provides integration with [Google's Wycheproof test vectors](https://github.com/google/wycheproof) for comprehensive cryptographic testing of hpcrypt implementations.

## Overview

Wycheproof is a collection of test vectors that check for known weaknesses and edge cases in cryptographic implementations. Unlike typical test vectors that focus on correctness, Wycheproof specifically tests:

- Invalid inputs that should be rejected
- Edge cases (zero values, point at infinity, etc.)
- Known attack vectors
- Signature malleability
- Padding oracle vulnerabilities
- And many more security-critical scenarios

## Structure

```
tests/
├── wycheproof/              # Git submodule with test vectors
│   └── testvectors_v1/      # JSON test vector files
└── wycheproof-tests/        # This crate
    ├── src/
    │   └── lib.rs           # Common utilities for parsing test vectors
    └── tests/
        ├── aead.rs          # ChaCha20-Poly1305, AES-GCM tests
        ├── ecdsa.rs         # ECDSA P-256, P-521 tests
        └── ...              # More test files as needed
```

## Adding Tests for a New Algorithm

1. **Find the test vector file** in `../wycheproof/testvectors_v1/`
   ```bash
   ls ../wycheproof/testvectors_v1/ | grep algorithm_name
   ```

2. **Create a test file** in `tests/`
   ```rust
   // tests/my_algorithm.rs
   use serde::Deserialize;
   use wycheproof_tests::{decode_hex, load_test_file, TestFile, TestResult};

   #[derive(Debug, Deserialize)]
   #[serde(rename_all = "camelCase")]
   struct MyAlgorithmTest {
       tc_id: usize,
       comment: String,
       // Add fields matching the JSON structure
       result: TestResult,
       flags: Vec<String>,
   }

   #[test]
   fn test_my_algorithm() {
       let test_file: TestFile<MyAlgorithmTest> =
           load_test_file("my_algorithm_test.json");

       for group in &test_file.test_groups {
           for test in &group.tests {
               // Parse test inputs
               // Call your hpcrypt implementation
               // Assert based on test.result
           }
       }
   }
   ```

3. **Add the test target** to `Cargo.toml`
   ```toml
   [[test]]
   name = "my_algorithm"
   path = "tests/my_algorithm.rs"
   ```

4. **Add dependencies** if needed
   ```toml
   [dependencies]
   hpcrypt-my-crate = { workspace = true, features = ["std"] }
   ```

## Running Tests

```bash
# Run all Wycheproof tests
cargo test -p wycheproof-tests

# Run specific algorithm tests
cargo test -p wycheproof-tests --test aead
cargo test -p wycheproof-tests --test ecdsa
cargo test -p wycheproof-tests --test ecdh
cargo test -p wycheproof-tests --test rsa
cargo test -p wycheproof-tests --test hmac
cargo test -p wycheproof-tests --test x25519
cargo test -p wycheproof-tests --test mac
cargo test -p wycheproof-tests --test ed25519
cargo test -p wycheproof-tests --test kdf
cargo test -p wycheproof-tests --test cipher
cargo test -p wycheproof-tests --test fpe

# Run with verbose output
cargo test -p wycheproof-tests -- --nocapture
```

## Test Result Interpretation

Wycheproof uses three result types:

- **`Valid`**: Test case should pass - valid cryptographic operation
- **`Invalid`**: Test case should fail - invalid input or signature
- **`Acceptable`**: Implementation-dependent behavior is OK (e.g., non-standard but not insecure)

## Updating Test Vectors

The test vectors are managed as a git submodule. To update to the latest version:

```bash
cd tests/wycheproof
git pull origin master
cd ../..
git add tests/wycheproof
git commit -m "Update Wycheproof test vectors"
```

## Coverage

Current test coverage:

### Implemented Tests (Ready to Uncomment)
- [x] Test infrastructure (this crate)
- [x] **AEAD Ciphers** ([tests/aead.rs](tests/aead.rs))
  - [x] ChaCha20-Poly1305 (325 tests)
  - [x] XChaCha20-Poly1305 (260 tests)
  - [x] AES-GCM (218 tests)
  - [x] AES-GCM-SIV (137 tests)
  - [x] AES-CCM (552 tests)
  - [x] AES-EAX (240 tests)
  - [x] AES-SIV (240 tests)
  - [x] Ascon-128 (164 tests)
  - [x] Ascon-128a (164 tests)
- [x] **ECDSA Signatures** ([tests/ecdsa.rs](tests/ecdsa.rs))
  - [x] P-256 with SHA-256 (619 tests)
  - [x] P-256 with SHA-512 (616 tests)
  - [x] P-384 with SHA-384 (747 tests)
  - [x] P-384 with SHA-512 (747 tests)
  - [x] P-521 with SHA-512 (910 tests)
  - [x] secp256k1 with SHA-256 (489 tests)
- [x] **RSA** ([tests/rsa.rs](tests/rsa.rs))
  - [x] RSA-PSS 2048 SHA-256 (56 tests)
  - [x] RSA PKCS#1 v1.5 2048 SHA-256 (55 tests)
  - [x] RSA-OAEP 2048 SHA-256 (107 tests)
- [x] **HMAC** ([tests/hmac.rs](tests/hmac.rs))
  - [x] HMAC-SHA-256 (168 tests)
  - [x] HMAC-SHA-384 (144 tests)
  - [x] HMAC-SHA-512 (168 tests)
- [x] **ECDH** ([tests/ecdh.rs](tests/ecdh.rs))
  - [x] P-256 (578 tests)
  - [x] P-384 (920 tests)
  - [x] P-521 (782 tests)
  - [x] secp256k1 (670 tests)
- [x] **X25519/X448** ([tests/x25519.rs](tests/x25519.rs))
  - [x] X25519 (522 tests)
  - [x] X448 (528 tests)
- [x] **CMAC** ([tests/mac.rs](tests/mac.rs))
  - [x] AES-CMAC (192 tests)

### Total: ~12,000+ Test Vectors

All test files include comprehensive TODO comments showing exactly where to integrate your hpcrypt implementations.

## Contributing

When implementing a new cryptographic primitive in hpcrypt:

1. Add Wycheproof tests BEFORE or ALONGSIDE the implementation
2. Ensure all `Valid` tests pass and all `Invalid` tests are properly rejected
3. Document any `Acceptable` test results that are intentionally skipped

## References

- [Wycheproof GitHub](https://github.com/google/wycheproof)
- [Wycheproof Paper](https://github.com/google/wycheproof/blob/master/doc/wycheproof.pdf)
- [Test Format Documentation](https://github.com/google/wycheproof/tree/master/doc)
