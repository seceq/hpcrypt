# RFC and Standards Test Vectors

This directory contains test vectors from official specifications: IETF RFCs, NIST standards, and official algorithm repositories.

## Test Vector Files

### Hash Functions

#### FIPS 180-4 - SHA-2 Family
- **File:** `fips180-4-sha.json`
- **Source:** NIST FIPS 180-4
- **Coverage:** SHA-224, SHA-256, SHA-384, SHA-512

#### RFC 7693 - BLAKE2
- **File:** `rfc7693-blake2.json`
- **Source:** RFC 7693 Appendix E
- **Coverage:** BLAKE2b and BLAKE2s test vectors

#### BLAKE2 KAT (Comprehensive)
- **File:** `blake2-kat.json`
- **Source:** https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json
- **Coverage:** 1024 test vectors (512 BLAKE2b, 512 BLAKE2s)

#### BLAKE3 KAT (Comprehensive)
- **File:** `blake3-kat.json`
- **Source:** https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
- **Coverage:** Hash, keyed hash, and key derivation modes

#### BLAKE3 Official
- **File:** `blake3-official.json`
- **Source:** BLAKE3 team official test vectors
- **Coverage:** Standard test vectors

#### RFC 9861 - TurboSHAKE
- **File:** `rfc9861-turboshake.json`
- **Source:** RFC 9861
- **Coverage:** TurboSHAKE128, TurboSHAKE256

### Symmetric Encryption

#### RFC 8439 - ChaCha20
- **File:** `rfc8439-chacha20.json`
- **Source:** RFC 8439 Section 2.4
- **Coverage:** ChaCha20 stream cipher test vectors

#### RFC 7253 - OCB (Offset Codebook Mode)
- **File:** `rfc7253-ocb.json`
- **Source:** RFC 7253 Appendix A
- **Coverage:** OCB3 AEAD test vectors

#### RFC 5297 - AES-SIV
- **File:** `rfc5297-aes-siv.json`
- **Source:** RFC 5297 Appendix A
- **Coverage:** AES-128-SIV and AES-256-SIV, deterministic and nonce-based modes

#### NIST SP 800-38A - AES-OFB
- **File:** `nist-sp800-38a-ofb.json`
- **Source:** NIST SP 800-38A Appendix F.4
- **Coverage:** OFB-AES128, OFB-AES192, OFB-AES256

#### NIST LWC - Ascon AEAD
- **File:** `nist-lwc-ascon-aead.json`
- **Source:** Official KAT vectors from ascon-c repository (NIST SP 800-232)
- **Coverage:** Ascon-128 AEAD variant

### Message Authentication

#### RFC 8439 - Poly1305
- **File:** `rfc8439-poly1305.json`
- **Source:** RFC 8439 Section 2.5
- **Coverage:** Poly1305 MAC test vectors

#### RFC 4493 - AES-CMAC
- **File:** `rfc4493-cmac.json`
- **Source:** RFC 4493
- **Coverage:** CMAC-AES test vectors

#### NIST SP 800-38D - GHASH
- **File:** `nist-sp800-38d-ghash.json`
- **Source:** NIST SP 800-38D (GCM specification)
- **Coverage:** GHASH universal hash function

#### RFC 8452 - POLYVAL
- **File:** `rfc8452-polyval.json`
- **Source:** RFC 8452 (AES-GCM-SIV)
- **Coverage:** POLYVAL universal hash function

### Key Derivation Functions

#### RFC 5869 - HKDF-SHA
- **File:** `rfc5869-hkdf-sha.json`
- **Source:** RFC 5869
- **Coverage:** HKDF-SHA256, HKDF-SHA384, HKDF-SHA512

#### RFC 8448 - TLS 1.3 KDF
- **File:** `rfc8448-tls13-kdf.json`
- **Source:** RFC 8448 Section 3
- **Coverage:** TLS 1.3 HKDF-Expand-Label with SHA-256 and SHA-384

#### RFC 7914 - scrypt
- **File:** `rfc7914-scrypt.json`
- **Source:** RFC 7914 Section 12
- **Coverage:** 4 test cases with varying parameters (N, r, p)

#### RFC 9106 - Argon2
- **File:** `rfc9106-argon2.json`
- **Source:** RFC 9106 Section 5
- **Coverage:** Argon2d, Argon2i, Argon2id variants

### Elliptic Curves and Signatures

#### RFC 7748 - X25519
- **File:** `rfc7748-x25519.json`
- **Source:** RFC 7748 Section 6.1
- **Coverage:** X25519 ECDH test vectors

#### RFC 7748 - X448
- **File:** `rfc7748-x448.json`
- **Source:** RFC 7748 Section 6.2
- **Coverage:** X448 ECDH test vectors

#### RFC 8032 - Ed25519
- **File:** `rfc8032-ed25519.json`
- **Source:** RFC 8032 Section 7.1
- **Coverage:** Ed25519 signature test vectors

#### RFC 8032 - Ed448
- **File:** `rfc8032-ed448.json`
- **Source:** RFC 8032 Section 7.4
- **Coverage:** Ed448 signature test vectors

#### FIPS 186-4 - ECDSA P-521
- **File:** `fips186-4-ecdsa-p521.json`
- **Source:** NIST FIPS 186-4
- **Coverage:** ECDSA with P-521 curve

### Post-Quantum Cryptography

#### FIPS 203 - ML-KEM
- **File:** `fips203-mlkem.json`
- **Source:** NIST FIPS 203
- **Coverage:** ML-KEM-512, ML-KEM-768, ML-KEM-1024

#### FIPS 204 - ML-DSA
- **File:** `fips204-mldsa.json`
- **Source:** NIST FIPS 204
- **Coverage:** ML-DSA-44, ML-DSA-65, ML-DSA-87

#### FIPS 205 - SLH-DSA
- **File:** `fips205-slhdsa.json`
- **Source:** NIST FIPS 205
- **Coverage:** SLH-DSA (SPHINCS+) variants

### Protocols

#### RFC 9180 - HPKE
- **File:** `rfc9180-hpke.json`
- **Source:** https://github.com/cfrg/draft-irtf-cfrg-hpke
- **Coverage:** Multiple KEM/KDF/AEAD combinations, all 4 modes

#### RFC 9497 - OPAQUE
- **File:** `rfc9497-opaque.json`
- **Source:** https://github.com/cfrg/draft-irtf-cfrg-opaque
- **Coverage:** ristretto255, decaf448, P-256, P-384, P-521 groups

#### RFC 5054 - SRP
- **File:** `rfc5054-srp.json`
- **Source:** RFC 5054 Appendix B
- **Coverage:** 1024-bit group with SHA-1

#### RFC 9001 - QUIC
- **File:** `rfc9001-quic.json`
- **Source:** RFC 9001
- **Coverage:** QUIC TLS key derivation

## File Naming Convention

Files follow these naming patterns:
- `rfcXXXX-algorithm.json` - IETF RFC test vectors
- `fipsXXX-algorithm.json` - NIST FIPS test vectors
- `nist-spXXX-XX-algorithm.json` - NIST Special Publication vectors
- `algorithm-kat.json` - Official KAT (Known Answer Test) vectors from algorithm authors

## Usage

These vectors are used by the `rfc-tests` test suite in `../rfc-tests/`.

```bash
# Run all RFC tests
cargo test --package rfc-tests --features enable-all-tests

# Run specific tests
cargo test --package rfc-tests blake2
cargo test --package rfc-tests hkdf
cargo test --package rfc-tests chacha20
```

## Adding New Test Vectors

When adding new test vectors:

1. Create a JSON file following the naming convention above
2. Use consistent format (array of test objects)
3. Include metadata: source, section, algorithm details
4. Add entry to this README
5. Create corresponding test in `../rfc-tests/tests/`

## License

Test vectors are extracted from IETF RFCs, NIST publications, and official algorithm specifications.
