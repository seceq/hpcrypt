# Test API Implementation Status

This document tracks the implementation status of the test APIs created for CAVP/ACVP validation testing.

## Overview

Three test API modules have been created:
- `hpcrypt-mlkem/src/test_api.rs` - ML-KEM test interface
- `hpcrypt-mldsa/src/test_api.rs` - ML-DSA test interface
- `hpcrypt-slhdsa/src/test_api.rs` - SLH-DSA test interface

These modules are feature-gated with `#[cfg(feature = "cavp")]` and provide deterministic interfaces matching NIST CAVP test vector requirements.

## Implementation Requirements

### 1. ML-KEM (hpcrypt-mlkem)

**Status**: ✅ **COMPLETE AND READY**

**Completed**:
- ✅ Added `ml_kem_keygen_internal()` in `src/keygen.rs` (lines 230-271)
- ✅ Function accepts separate `d` and `z` seeds as required by CAVP
- ✅ Test API trait `KemCore` implemented for all parameter sets in `src/test_api.rs`
- ✅ Module added to lib.rs with `#[cfg(feature = "cavp")]` feature gate
- ✅ Feature `cavp` added to Cargo.toml
- ✅ CAVP test file updated to use `hpcrypt_mlkem::test_api::KemCore`

**Test API Functions**:
- `KemCore::generate_deterministic(seed: &[u8])` - Takes 64-byte seed (d || z)
- `KemCore::encapsulate_deterministic(ek: &[u8], m: &[u8])` - Deterministic encapsulation
- `KemCore::decapsulate(dk: &[u8], ct: &[u8])` - Standard decapsulation

**Usage in CAVP Tests**:
```rust
use hpcrypt_mlkem::{MlKem768, test_api::KemCore};

let seed = [/* 64 bytes: d || z */];
let (ek, dk) = MlKem768::generate_deterministic(&seed)?;

let m = [/* 32 bytes */];
let (ct, ss1) = MlKem768::encapsulate_deterministic(&ek, &m)?;
let ss2 = MlKem768::decapsulate(&dk, &ct)?;
```

### 2. ML-DSA (hpcrypt-mldsa)

**Status**: ✅ **TEST API CREATED - AWAITING INTERNAL FUNCTIONS**

**Test API Completed**:
- ✅ Test API trait `SignatureScheme` implemented in `src/test_api.rs`
- ✅ Module added to lib.rs with `#[cfg(feature = "cavp")]` feature gate
- ✅ Feature `cavp` added to Cargo.toml
- ✅ CAVP test file updated to use `hpcrypt_mldsa::test_api::SignatureScheme`

**Required Functions** (need to be added to hpcrypt-mldsa):

1. **In `src/keygen.rs`**:
   ```rust
   pub fn keygen_with_seed<P: DsaParams>(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>);
   ```
   - Deterministic key generation from 32-byte seed
   - Should be similar to existing `keygen()` but with explicit seed

2. **In `src/sign.rs`**:
   ```rust
   pub fn sign_deterministic<P: DsaParams>(
       sk: &[u8],
       message: &[u8],
       rnd: &[u8]
   ) -> Result<Vec<u8>, Error>;
   ```
   - When `rnd` is empty: pure deterministic signing
   - When `rnd` has 32 bytes: hedged/randomized signing
   - This may already exist as internal implementation

**Test API Functions**:
- `SignatureScheme::generate_deterministic(seed: &[u8])` - 32-byte seed -> (pk, sk)
- `SignatureScheme::sign_deterministic(sk: &[u8], message: &[u8])` - Pure deterministic
- `SignatureScheme::sign_with_randomness(sk: &[u8], message: &[u8], rnd: &[u8])` - Hedged
- `SignatureScheme::verify(pk: &[u8], message: &[u8], signature: &[u8])` - Verification

**Usage in CAVP Tests**:
```rust
use hpcrypt_mldsa::{MlDsa65, test_api::SignatureScheme};

// KeyGen test
let seed = [/* 32 bytes */];
let (pk, sk) = MlDsa65::generate_deterministic(&seed)?;

// SigGen (deterministic)
let sig = MlDsa65::sign_deterministic(&sk, message)?;

// SigGen (randomized)
let rnd = [/* 32 bytes */];
let sig = MlDsa65::sign_with_randomness(&sk, message, &rnd)?;

// SigVer
let valid = MlDsa65::verify(&pk, message, &sig);
```

### 3. SLH-DSA (hpcrypt-slhdsa)

**Status**: ✅ **TEST API CREATED - AWAITING INTERNAL FUNCTIONS**

**Test API Completed**:
- ✅ Test API trait `SignatureScheme` implemented in `src/test_api.rs`
- ✅ Module added to lib.rs with `#[cfg(feature = "cavp")]` feature gate
- ✅ Feature `cavp` added to Cargo.toml
- ✅ CAVP test file updated to use `hpcrypt_slhdsa::test_api::SignatureScheme`

**Required Functions** (need to be added to hpcrypt-slhdsa):

1. **In `src/slhdsa.rs` - KeyPair implementation**:
   ```rust
   impl<P: ParameterSet> KeyPair<P> {
       pub fn from_seed_components(
           sk_seed: &[u8],
           sk_prf: &[u8],
           pk_seed: &[u8]
       ) -> Result<Self, Error>;
   }
   ```
   - Create keypair from explicit seed components
   - CAVP provides: sk.seed || sk.prf || pk.seed (3*N bytes total)

2. **In `src/slhdsa.rs`**:
   ```rust
   pub fn sign_internal<P: ParameterSet>(
       secret_key: &SecretKey<P>,
       message: &[u8],
       opt_rand: Option<&[u8]>
   ) -> Vec<u8>;
   ```
   - When `opt_rand` is None: pure deterministic signing
   - When `opt_rand` is Some(&[u8; N]): randomized signing with explicit optRand
   - This may already exist as internal implementation

3. **In `src/slhdsa.rs` - SecretKey and PublicKey**:
   ```rust
   impl<P: ParameterSet> SecretKey<P> {
       pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;
       pub fn to_bytes(&self) -> Vec<u8>;
   }

   impl<P: ParameterSet> PublicKey<P> {
       pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;
       pub fn to_bytes(&self) -> Vec<u8>;
   }
   ```

**Test API Functions**:
- `SignatureScheme::generate_deterministic(seed: &[u8])` - 3*N-byte seed -> (pk, sk)
- `SignatureScheme::sign_deterministic(sk: &[u8], message: &[u8])` - Pure deterministic
- `SignatureScheme::sign_with_randomness(sk: &[u8], message: &[u8], opt_rand: &[u8])` - Randomized
- `SignatureScheme::verify(pk: &[u8], message: &[u8], signature: &[u8])` - Verification

**Usage in CAVP Tests**:
```rust
use hpcrypt_slhdsa::{Sha2_128s, test_api::SignatureScheme};

// KeyGen test (3*N-byte seed)
let seed = vec![/* 3 * N bytes: sk.seed || sk.prf || pk.seed */];
let (pk, sk) = Sha2_128s::generate_deterministic(&seed)?;

// SigGen (deterministic)
let sig = Sha2_128s::sign_deterministic(&sk, message)?;

// SigGen (randomized)
let opt_rand = vec![/* N bytes */];
let sig = Sha2_128s::sign_with_randomness(&sk, message, &opt_rand)?;

// SigVer
let valid = Sha2_128s::verify(&pk, message, &sig);
```

## Feature Flag Configuration

Add to each PQC crate's `Cargo.toml`:

```toml
[features]
# ... existing features ...
cavp = []  # Enable CAVP/ACVP test API
```

## CAVP Test Integration

Once the internal functions are implemented, the CAVP tests can use these APIs:

**In `tests/cavp-tests/tests/mlkem.rs`**:
```rust
#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mlkem::test_api::KemCore;
```

**In `tests/cavp-tests/tests/mldsa.rs`**:
```rust
#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_mldsa::test_api::SignatureScheme;
```

**In `tests/cavp-tests/tests/slhdsa.rs`**:
```rust
#[cfg(feature = "enable-pqc-tests")]
use hpcrypt_slhdsa::test_api::SignatureScheme;
```

## Next Steps

### For ML-KEM ✅
- [x] Implementation complete - ready for testing
- [x] Test API created and integrated
- [x] CAVP tests updated to use test_api
- [x] Feature flags configured
- **Status: READY TO RUN TESTS**

### For ML-DSA ✅
1. [x] Test API trait created in `src/test_api.rs`
2. [x] Module added to lib.rs with feature gate
3. [x] Add `cavp` feature to Cargo.toml
4. [x] CAVP test file updated to import from test_api
5. [x] **DONE**: Fixed test_api.rs to use `keygen_from_seed()` (already existed!)
6. [x] **DONE**: Added serialization/deserialization to test_api.rs
7. [x] Test the API with simple unit tests - **ALL TESTS PASS (8/8)**
- **Status: READY TO RUN CAVP TESTS**

### For SLH-DSA ✅
1. [x] Test API trait created in `src/test_api.rs`
2. [x] Module added to lib.rs with feature gate
3. [x] Add `cavp` feature to Cargo.toml
4. [x] CAVP test file updated to import from test_api
5. [x] **DONE**: Implemented `KeyPair::from_seed_components()` in `hpcrypt-slhdsa/src/slhdsa.rs`
6. [x] **DONE**: Implemented `sign_with_opt_rand()` with optRand support
7. [x] **DONE**: Serialization methods already existed (to_bytes/from_bytes)
8. [x] Test the API with simple unit tests - **ALL TESTS PASS (7/7)**
- **Status: READY TO RUN CAVP TESTS**

## Testing Strategy

1. **Unit Tests**: Each test_api.rs includes unit tests to verify basic functionality
2. **CAVP Integration**: Once APIs are complete, run full CAVP test suite:
   ```bash
   cargo test -p cavp-tests --features enable-pqc-tests
   ```
3. **Incremental Testing**: Test each algorithm independently:
   ```bash
   cargo test -p cavp-tests --test mlkem --features enable-pqc-tests
   cargo test -p cavp-tests --test mldsa --features enable-pqc-tests
   cargo test -p cavp-tests --test slhdsa --features enable-pqc-tests
   ```

## Design Rationale

### Why Separate test_api.rs Files?

1. **Separation of Concerns**: Test APIs are distinct from production APIs
2. **Feature Gating**: Can be completely removed in production builds
3. **Maintainability**: Clear boundary between test and production code
4. **Documentation**: Dedicated space for test-specific documentation

### Why Not Modify Existing APIs?

The production APIs are designed for security and ease of use:
- Single seed for key generation (simpler, more secure)
- Automatic randomness generation (prevents misuse)
- High-level abstractions (KeyPair, encapsulate/decapsulate)

CAVP tests require low-level control:
- Separate seed components (d and z for ML-KEM)
- Explicit randomness values (for reproducibility)
- Raw byte interfaces (matching test vector format)

Mixing these concerns would make the production API more complex and error-prone.

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA Standard
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA Standard
- [ACVP-Server](https://github.com/usnistgov/ACVP-Server) - Test vector repository
