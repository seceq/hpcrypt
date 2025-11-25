# IETF RFC Test Vectors

This directory contains test vectors extracted from official IETF RFC specifications for cryptographic algorithms.

## Test Vector Files

### RFC 9180 - HPKE (Hybrid Public Key Encryption)
- **File:** `rfc9180-hpke.json`
- **Source:** https://github.com/cfrg/draft-irtf-cfrg-hpke
- **Status:** Official CFRG test vectors
- **Last Updated:** May 24, 2021
- **Coverage:** Multiple KEM/KDF/AEAD combinations, all 4 modes (Base, PSK, Auth, AuthPSK)

### RFC 9497 - OPAQUE (Password-Authenticated Key Exchange)
- **File:** `rfc9497-opaque.json`
- **Source:** https://github.com/cfrg/draft-irtf-cfrg-opaque
- **Status:** Official CFRG test vectors
- **Coverage:** ristretto255, decaf448, P-256, P-384, P-521 groups

### RFC 9106 - Argon2 (Password Hashing)
- **File:** `rfc9106-argon2.json`
- **Source:** RFC 9106 Section 5
- **Status:** Official RFC test vectors
- **Coverage:** Argon2d, Argon2i, Argon2id variants

### RFC 7914 - scrypt (Password-Based KDF)
- **File:** `rfc7914-scrypt.json`
- **Source:** RFC 7914 Section 12
- **Status:** Official RFC test vectors
- **Coverage:** 4 test cases with varying parameters (N, r, p)

### RFC 5054 - SRP (Secure Remote Password)
- **File:** `rfc5054-srp.json`
- **Source:** RFC 5054 Appendix B
- **Status:** Official RFC test vectors
- **Coverage:** 1024-bit group with SHA-1

## Update Policy

These test vectors are **manually curated** from published RFCs:

- **RFCs are frozen** after publication - vectors rarely change
- Updates only occur via RFC Errata (rare events)
- Check RFC Errata pages for any corrections:
  - https://www.rfc-editor.org/errata/rfc9180
  - https://www.rfc-editor.org/errata/rfc9497
  - https://www.rfc-editor.org/errata/rfc9106
  - https://www.rfc-editor.org/errata/rfc7914
  - https://www.rfc-editor.org/errata/rfc5054

## Comparison with Other Test Suites

### Wycheproof (Security Testing)
- Focus: Edge cases, vulnerability detection, CVE coverage
- Updates: Active (Google security research)
- Purpose: Find implementation bugs

### NIST CAVP (Compliance Testing)
- Focus: FIPS validation, government standards
- Updates: Periodic additions
- Purpose: Standards conformance

### RFC Vectors (Interoperability Testing)
- Focus: Protocol correctness, RFC compliance
- Updates: Static (only via errata)
- Purpose: Ensure interoperability between implementations

## Usage

These vectors are used by the `rfc-tests` test suite in `../rfc-tests/`.

```bash
# Run all RFC tests
cargo test --package rfc-tests

# Run specific RFC tests
cargo test --package rfc-tests hpke
cargo test --package rfc-tests opaque
cargo test --package rfc-tests argon2
cargo test --package rfc-tests scrypt
cargo test --package rfc-tests srp
```

## Adding New RFC Vectors

When adding new RFC test vectors:

1. Create a JSON file: `rfcXXXX-algorithm.json`
2. Use consistent format (array of test objects)
3. Include metadata: RFC number, section, algorithm details
4. Add entry to this README
5. Create corresponding test in `../rfc-tests/`

## License

Test vectors are extracted from IETF RFCs and CFRG specifications, which are in the public domain.
