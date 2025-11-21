# CAVP Test API Requirements

This document describes the API requirements for CAVP tests and the current status of implementations.

## Overview

The CAVP tests are written against trait-based APIs that provide deterministic key generation, signing, and encryption operations. These tests are ready to use once the trait-based APIs are added to the respective crates.

## Required Traits

### ML-KEM (hpcrypt-mlkem)

```rust
pub trait KemCore {
    /// Generate keypair from deterministic seed (d || z)
    fn generate_deterministic(seed: &[u8]) -> Result<(EncapsulationKey, DecapsulationKey), Error>;

    /// Encapsulate with deterministic randomness m
    fn encapsulate_deterministic(ek: &[u8], m: &[u8]) -> Result<(Ciphertext, SharedSecret), Error>;

    /// Decapsulate ciphertext
    fn decapsulate(dk: &[u8], ct: &[u8]) -> Result<SharedSecret, Error>;
}

// Implement for: MlKem512, MlKem768, MlKem1024
```

### ML-DSA (hpcrypt-mldsa)

```rust
pub trait SignatureScheme {
    /// Generate keypair from deterministic seed
    fn generate_deterministic(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error>;

    /// Sign deterministically (no randomness)
    fn sign_deterministic(sk: &[u8], message: &[u8]) -> Result<Signature, Error>;

    /// Sign with RNG (hedged mode)
    fn sign_with_rng(sk: &[u8], message: &[u8], rnd: &[u8]) -> Result<Signature, Error>;

    /// Sign with default RNG
    fn sign(sk: &[u8], message: &[u8]) -> Result<Signature, Error>;

    /// Verify signature
    fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error>;
}

// Implement for: MlDsa44, MlDsa65, MlDsa87
```

### SLH-DSA (hpcrypt-slhdsa)

```rust
pub trait SignatureScheme {
    /// Generate keypair from deterministic seed (sk.seed || sk.prf || pk.seed)
    fn generate_deterministic(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error>;

    /// Sign deterministically
    fn sign_deterministic(sk: &[u8], message: &[u8]) -> Result<Signature, Error>;

    /// Sign with additional randomness
    fn sign_with_rng(sk: &[u8], message: &[u8], additional_randomness: &[u8]) -> Result<Signature, Error>;

    /// Sign with default RNG
    fn sign(sk: &[u8], message: &[u8]) -> Result<Signature, Error>;

    /// Verify signature
    fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error>;
}

// Implement for: SlhDsa128s, SlhDsa128f, SlhDsa192s, SlhDsa192f, SlhDsa256s, SlhDsa256f
```

## Current Implementation Status

### ML-KEM
- **Current API**: `KeyPair` struct with `generate()`, `from_seed()`, `encapsulate()`, `decapsulate()` methods
- **CAVP Tests**: Written, awaiting trait-based API
- **Action Required**:
  1. Add `KemCore` trait to `hpcrypt-mlkem`
  2. Implement for `MlKem512`, `MlKem768`, `MlKem1024`
  3. Ensure deterministic operations match FIPS-203 test vector format

### ML-DSA
- **Current API**: TBD (check hpcrypt-mldsa)
- **CAVP Tests**: Written, awaiting trait-based API
- **Action Required**:
  1. Add `SignatureScheme` trait to `hpcrypt-mldsa`
  2. Implement for `MlDsa44`, `MlDsa65`, `MlDsa87`
  3. Support both deterministic and hedged signing modes

### SLH-DSA
- **Current API**: TBD (check hpcrypt-slhdsa)
- **CAVP Tests**: Written, awaiting trait-based API
- **Action Required**:
  1. Add `SignatureScheme` trait to `hpcrypt-slhdsa`
  2. Implement for all 6 parameter sets (SHA2-128s/f, SHA2-192s/f, SHA2-256s/f)
  3. Handle deterministic and randomized signing

## Running Tests

Once the trait APIs are implemented:

```bash
# Run all PQC CAVP tests
cargo test -p cavp-tests --features enable-pqc-tests

# Run specific algorithm
cargo test -p cavp-tests --test mlkem --features enable-pqc-tests
cargo test -p cavp-tests --test mldsa --features enable-pqc-tests
cargo test -p cavp-tests --test slhdsa --features enable-pqc-tests
```

## Test Coverage

Each test file includes tests for all operations specified in FIPS standards:

### ML-KEM (FIPS-203)
- ✅ KeyGen test structure ready
- ✅ Encap/Decap test structure ready
- Covers all 3 parameter sets (512, 768, 1024)

### ML-DSA (FIPS-204)
- ✅ KeyGen test structure ready
- ✅ SigGen test structure ready (deterministic + hedged)
- ✅ SigVer test structure ready
- Covers all 3 parameter sets (44, 65, 87)

### SLH-DSA (FIPS-205)
- ✅ KeyGen test structure ready
- ✅ SigGen test structure ready (deterministic + randomized)
- ✅ SigVer test structure ready
- Covers all 6 SHA2 parameter sets

## Notes

- Tests are written to be byte-exact with NIST test vectors
- All deterministic operations must produce identical output to ACVP test expectations
- Error handling should distinguish between valid failures (e.g., invalid signature) and internal errors
- Tests use the official NIST ACVP-Server test vectors from the git submodule
