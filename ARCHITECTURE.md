# HPCrypt Architecture

This document describes the architecture and design principles of the HPCrypt cryptography library.

## Design Philosophy

HPCrypt follows these core principles:

1. **Security First**: Prioritize correctness and security over performance
2. **No Unsafe Code**: 100% safe Rust implementations
3. **no_std Compatible**: Support embedded and bare-metal environments
4. **Modular Design**: Each crate focuses on a specific domain
5. **Pay for What You Use**: Fine-grained feature flags and minimal dependencies
6. **Well Documented**: Production-ready documentation and examples
7. **Thoroughly Tested**: Comprehensive test coverage with KAT vectors

## Crate Organization

HPCrypt uses a multi-crate workspace structure with clear dependency boundaries:

```
hpcrypt/                    # Umbrella crate (convenience)
├── hpcrypt-core/          # Foundation (error types, utilities)
├── hpcrypt-hash/          # Hash functions
├── hpcrypt-rng/           # Random number generation
├── hpcrypt-curves/        # Elliptic curves
├── hpcrypt-signatures/    # Classical signatures
├── hpcrypt-mlkem/         # Post-quantum KEM
├── hpcrypt-mldsa/         # Post-quantum signatures (ML-DSA)
└── hpcrypt-slhdsa/        # Post-quantum signatures (SLH-DSA)
```

### Dependency Graph

```
Layer 0 (Primitives - No Internal Dependencies):
  ├── hpcrypt-core       (error types, utilities)
  ├── hpcrypt-hash       (hash functions)
  ├── hpcrypt-curves     (elliptic curves)
  └── hpcrypt-rng        (RNG)

Layer 1 (Algorithms - Depend on Layer 0):
  ├── hpcrypt-signatures (→ core, curves, hash, rng)
  ├── hpcrypt-mlkem      (→ rng + external sha3)
  ├── hpcrypt-mldsa      (→ rng + external sha3)
  └── hpcrypt-slhdsa     (→ rng + external sha3)

Layer 2 (Convenience - Depend on Layer 0+1):
  └── hpcrypt            (→ all crates, feature-gated)
```

**Key Design Decisions:**

1. **Layer 0 is self-contained**: Primitives have no internal dependencies
2. **Post-quantum crates are independent**: ML-KEM, ML-DSA, SLH-DSA don't depend on each other
3. **Minimal external dependencies**: Only sha3 for NIST standards compliance
4. **Umbrella crate is optional**: Users can import specific crates directly

## Core Components

### hpcrypt-core

**Purpose**: Foundation layer providing shared utilities

**Exports**:
- Error types (`Error`, `Result`)
- Constant-time utilities (`ct_eq`, `ct_select`)
- Trait definitions

**Dependencies**: None (only external: `subtle`, `zeroize`)

**Design Notes**:
- Must remain minimal to avoid bloat in all dependent crates
- No algorithm implementations, only shared infrastructure

### hpcrypt-hash

**Purpose**: Cryptographic hash functions and hash-based constructions

**Exports**:
- Hash algorithms: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2, BLAKE3
- Hash-based MACs: HMAC, KMAC
- XOF readers: SHAKE128, SHAKE256

**Dependencies**: None

**Design Notes**:
- All implementations are constant-time where applicable
- Unified `Digest` trait for consistent API
- Optimized inner loops for performance

### hpcrypt-rng

**Purpose**: Cryptographically secure random number generation

**Exports**:
- `generate_random_bytes()` - Fill buffer with random bytes
- `generate_key::<N>()` - Type-safe key generation

**Dependencies**: None (external: `getrandom`)

**Features**:
- `os-rng`: OS-provided CSPRNG (default)
- `chacha-rng`: ChaCha20-based DRBG (future)

**Design Notes**:
- Simple interface wrapping OS entropy sources
- All crypto crates depend on this for key generation

### hpcrypt-curves

**Purpose**: Elliptic curve implementations

**Exports**:
- NIST curves: P-256, P-384, P-521
- Bitcoin: secp256k1
- Edwards curves: Ed25519, Ed448
- Montgomery curves: X25519, X448

**Dependencies**: None

**Design Notes**:
- Each curve is feature-gated for tree-shaking
- Optimized field arithmetic (Montgomery reduction, Barrett reduction)
- Point compression/decompression
- Scalar multiplication with side-channel protections

### hpcrypt-signatures

**Purpose**: Classical digital signature schemes

**Exports**:
- ECDSA: P-256, P-384, P-521, secp256k1
- EdDSA: Ed25519, Ed448
- Schnorr signatures (future)

**Dependencies**: `hpcrypt-core`, `hpcrypt-curves`, `hpcrypt-hash`, `hpcrypt-rng`

**Design Notes**:
- Unified trait for signature operations
- Deterministic nonce generation (RFC 6979)
- Batch verification support where applicable

### hpcrypt-mlkem

**Purpose**: ML-KEM (Module-Lattice-Based KEM) per FIPS 203

**Exports**:
- `MlKem512`, `MlKem768`, `MlKem1024`
- `KeyPair` with `generate()`, `encapsulate()`, `decapsulate()`

**Dependencies**: `hpcrypt-rng`, external `sha3`

**Design Notes**:
- Self-contained implementation (includes NTT, sampling, compression)
- Implicit rejection for CCA security
- Constant-time operations for side-channel resistance
- KAT tests from NIST vectors

### hpcrypt-mldsa

**Purpose**: ML-DSA (Module-Lattice-Based Digital Signatures) per FIPS 204

**Exports**:
- `MlDsa44`, `MlDsa65`, `MlDsa87`
- `SigningKey`, `VerifyingKey`

**Dependencies**: `hpcrypt-rng`, external `sha3`

**Design Notes**:
- Self-contained implementation
- Deterministic and hedged signing modes
- KAT tests from NIST vectors

### hpcrypt-slhdsa

**Purpose**: SLH-DSA (Stateless Hash-Based Signatures / SPHINCS+) per FIPS 205

**Exports**:
- Multiple parameter sets (128s, 128f, 192s, 192f, 256s, 256f)
- `SigningKey`, `VerifyingKey`

**Dependencies**: `hpcrypt-rng`, external `sha3`

**Design Notes**:
- Hash-based signatures (post-quantum, no lattices)
- Larger signatures but simpler security assumptions
- KAT tests from NIST vectors

### hpcrypt (Umbrella)

**Purpose**: Convenience crate for unified imports

**Exports**: Re-exports all sub-crates with feature gates

**Dependencies**: All HPCrypt crates (feature-gated)

**Features**:
- `classical`: curves + signatures
- `pq`: pq-kem + pq-sig
- `full`: classical + pq

**Design Notes**:
- Users can choose between umbrella crate or specific crates
- Feature flags enable tree-shaking
- Prelude module for common imports

## Feature Flag Strategy

All crates follow consistent feature flag naming:

### Common Features
- `std`: Enable standard library (heap allocation, I/O)
- `alloc`: Enable heap allocation without full std
- `serde`: Enable serialization/deserialization

### Algorithm-Specific Features
- Individual curves/algorithms are feature-gated
- Example: `hpcrypt-curves` has `p256`, `secp256k1`, `ed25519`, etc.

### Example Feature Combinations

```toml
# Minimal: Only ML-KEM-768 for no_std embedded
hpcrypt-mlkem = { version = "0.1", default-features = false }

# Post-quantum only
hpcrypt = { version = "0.1", default-features = false, features = ["pq"] }

# Everything
hpcrypt = { version = "0.1", features = ["full"] }
```

## Performance Considerations

### Optimization Levels

**Release Profile** (in workspace Cargo.toml):
```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
```

**Benchmark Profile**:
```toml
[profile.bench]
opt-level = 3
lto = "fat"
codegen-units = 1
```

### Critical Performance Paths

1. **Field arithmetic** (curves): Optimized Montgomery/Barrett reduction
2. **NTT** (lattice crypto): Optimized butterflies and reduction
3. **Hash functions**: Unrolled compression functions
4. **Scalar multiplication**: Windowed/comb methods with precomputation

### Benchmarking

Each crate includes:
- `benches/` directory with Criterion benchmarks
- Comparison against reference implementations
- Regression prevention in CI

## Security Considerations

### Side-Channel Resistance

**Constant-Time Operations**:
- Field arithmetic uses constant-time selection
- Array lookups use constant-time indexing
- Comparisons use constant-time equality checks

**Timing Leaks**:
- No secret-dependent branches in critical paths
- No secret-dependent memory access patterns
- Validated with `dudect-bencher` (future)

### Key Material Handling

- Use `zeroize` feature for automatic key cleanup
- Private keys stored in protected memory
- Constant-time comparison for key equality

### Input Validation

All public APIs validate inputs:
- Key sizes match parameter sets
- Points are on curve (curves)
- Signatures are correctly formatted
- Ciphertexts are expected length

### Panic Safety

- Public APIs should not panic on invalid input
- Use `Result<T, Error>` for fallible operations
- `debug_assert!` for internal invariants
- `panic!` only for unrecoverable logic errors

## Testing Strategy

### Test Coverage

Each crate includes:

1. **Unit tests**: Test individual functions
2. **Integration tests**: Test public API
3. **Known Answer Tests (KAT)**: From NIST/RFC test vectors
4. **Property tests**: Using `proptest` (where applicable)
5. **Wycheproof tests**: Google's crypto test vectors

### Test Organization

```
crate/
├── src/
│   └── *.rs           # Inline unit tests with #[cfg(test)]
├── tests/
│   ├── kat_*.rs       # Known answer tests
│   └── integration.rs # Integration tests
└── benches/           # Performance benchmarks
```

### CI/CD

- All tests run on push/PR
- Multiple Rust versions (MSRV, stable, nightly)
- Multiple platforms (Linux, macOS, Windows)
- Clippy with `-D warnings`
- `cargo doc` validation

## Future Directions

See `future-crates/README.md` for planned additions:

### Near-Term (Next 6 months)
- AEAD implementations (AES-GCM, ChaCha20-Poly1305)
- KDF implementations (HKDF, PBKDF2)
- RSA signatures and encryption

### Medium-Term (6-12 months)
- HPKE (RFC 9180)
- Key exchange protocols (ECDH variants)
- Format-preserving encryption

### Long-Term (12+ months)
- Advanced protocols (OPAQUE, SRP)
- Threshold cryptography
- Zero-knowledge proofs

## Contributing Guidelines

When adding new functionality:

1. **Start with Layer 0**: Ensure primitives are self-contained
2. **Minimize dependencies**: Only add essential external deps
3. **Document thoroughly**: Every public item needs docs
4. **Add comprehensive tests**: Include KAT vectors
5. **Benchmark**: Add performance benchmarks
6. **no_std first**: Design for no_std, add std features later
7. **Security review**: Side-channel analysis for sensitive operations

## References

- [NIST FIPS 203](https://csrc.nist.gov/publications/detail/fips/203/final) - ML-KEM
- [NIST FIPS 204](https://csrc.nist.gov/publications/detail/fips/204/final) - ML-DSA
- [NIST FIPS 205](https://csrc.nist.gov/publications/detail/fips/205/final) - SLH-DSA
- [RFC 6979](https://tools.ietf.org/html/rfc6979) - Deterministic ECDSA
- [SEC 1](https://www.secg.org/sec1-v2.pdf) - Elliptic Curve Cryptography
- [FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final) - Digital Signature Standard

## Questions?

For architecture questions or design discussions, please open an issue on GitHub.
