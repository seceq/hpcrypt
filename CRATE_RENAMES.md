# Crate Rename Summary

This document describes the crate renaming changes made to improve naming clarity and consistency.

## Renamed Crates

### 1. `hpcrypt-kex` → `hpcrypt-pake`

**Rationale:**
- `kex` is an abbreviation for "Key Exchange" which was too generic and cryptic
- The crate specifically implements Password-Authenticated Key Exchange (PAKE) protocols
- Main content: OPAQUE (RFC 9807) and OPRF (RFC 9497)
- "PAKE" is the industry-standard term for this category of protocols

**Changes:**
- Directory renamed: `hpcrypt-kex/` → `hpcrypt-pake/`
- Package name: `hpcrypt-kex` → `hpcrypt-pake`
- Description updated to reflect PAKE focus
- Module documentation updated
- All code examples updated (README.md, lib.rs, opaque.rs, oprf.rs)
- Test commands updated

**Import Changes:**
```rust
// Before
use hpcrypt_kex::opaque::{OpaqueClient, OpaqueServer};

// After
use hpcrypt_pake::opaque::{OpaqueClient, OpaqueServer};
```

### 2. `hpcrypt-shamir` → `hpcrypt-threshold`

**Rationale:**
- Named after a person (Adi Shamir) rather than the functionality
- The crate provides "Threshold Cryptography" primitives (as stated in its module docs)
- More general name allows for future additions (threshold signatures, distributed key generation)
- "Threshold" is the professional cryptography term for this category

**Changes:**
- Directory renamed: `hpcrypt-shamir/` → `hpcrypt-threshold/`
- Package name: `hpcrypt-shamir` → `hpcrypt-threshold`
- Description added: "Threshold cryptography primitives including Shamir Secret Sharing"
- Dependencies updated to use workspace dependencies
- Added `os-rng` feature to hpcrypt-rng dependency
- Documentation example updated

**Import Changes:**
```rust
// Before
use hpcrypt_shamir::shamir::{split_secret, reconstruct_secret};

// After
use hpcrypt_threshold::shamir::{split_secret, reconstruct_secret};
```

## Files Updated

### Workspace Configuration
- [Cargo.toml](Cargo.toml): Updated workspace members and dependencies

### hpcrypt-pake
- [hpcrypt-pake/Cargo.toml](hpcrypt-pake/Cargo.toml): Package name and description
- [hpcrypt-pake/src/lib.rs](hpcrypt-pake/src/lib.rs): Module documentation
- [hpcrypt-pake/src/opaque.rs](hpcrypt-pake/src/opaque.rs): Code examples (3 occurrences)
- [hpcrypt-pake/src/oprf.rs](hpcrypt-pake/src/oprf.rs): Code examples (1 occurrence)
- [hpcrypt-pake/README.md](hpcrypt-pake/README.md): All references updated

### hpcrypt-threshold
- [hpcrypt-threshold/Cargo.toml](hpcrypt-threshold/Cargo.toml): Package name, description, dependencies
- [hpcrypt-threshold/src/lib.rs](hpcrypt-threshold/src/lib.rs): Documentation example

### Documentation
- [STRUCTURE_RESTORED.md](STRUCTURE_RESTORED.md): Updated crate list and descriptions

## Verification

Both renamed crates compile successfully and all tests pass:

```bash
# hpcrypt-pake
cargo test -p hpcrypt-pake --lib
# Result: 10 passed; 0 failed; 3 ignored

# hpcrypt-threshold
cargo test -p hpcrypt-threshold --lib
# Result: 9 passed; 0 failed
```

## Migration Guide

### For Users of hpcrypt-kex

Update your `Cargo.toml`:
```toml
[dependencies]
# Before
hpcrypt-kex = "0.1"

# After
hpcrypt-pake = "0.1"
```

Update imports:
```rust
// Before
use hpcrypt_kex::opaque::*;
use hpcrypt_kex::oprf::*;

// After
use hpcrypt_pake::opaque::*;
use hpcrypt_pake::oprf::*;
```

### For Users of hpcrypt-shamir

Update your `Cargo.toml`:
```toml
[dependencies]
# Before
hpcrypt-shamir = "0.1"

# After
hpcrypt-threshold = "0.1"
```

Update imports:
```rust
// Before
use hpcrypt_shamir::shamir::*;

// After
use hpcrypt_threshold::shamir::*;
```

## Naming Consistency

After these changes, the workspace follows consistent naming conventions:

**Descriptive Names:**
- `hpcrypt-core` - Foundation utilities
- `hpcrypt-hash` - Hash functions
- `hpcrypt-curves` - Elliptic curves
- `hpcrypt-signatures` - Signature schemes
- `hpcrypt-threshold` - Threshold cryptography

**Standard Protocol Names:**
- `hpcrypt-mlkem` - ML-KEM (FIPS 203)
- `hpcrypt-mldsa` - ML-DSA (FIPS 204)
- `hpcrypt-slhdsa` - SLH-DSA (FIPS 205)
- `hpcrypt-pake` - PAKE protocols
- `hpcrypt-hpke` - HPKE (RFC 9180)

**Functional Names:**
- `hpcrypt-rng` - Random number generation
- `hpcrypt-kdf` - Key derivation functions
- `hpcrypt-aead` - Authenticated encryption
- `hpcrypt-mac` - Message authentication codes

## Date

November 12, 2025
