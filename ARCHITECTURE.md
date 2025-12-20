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

HPCrypt uses a multi-crate workspace structure:

```
Layer 0 (Primitives):
├── hpcrypt-core       # Error types, utilities
├── hpcrypt-hash       # Hash functions (SHA-2, SHA-3, BLAKE2/3)
├── hpcrypt-curves     # Elliptic curves (NIST, secp256k1, Ed25519, X25519)
├── hpcrypt-rng        # Random number generation
└── hpcrypt-cipher     # Block ciphers and modes (AES, ChaCha20)

Layer 1 (Cryptographic Schemes):
├── hpcrypt-mac        # MACs (HMAC, CMAC, Poly1305, GHASH, KMAC)
├── hpcrypt-aead       # Authenticated encryption (AES-GCM, ChaCha20-Poly1305, Ascon)
├── hpcrypt-kdf        # Key derivation (HKDF, PBKDF2, Argon2, scrypt)
├── hpcrypt-signatures # Digital signatures (ECDSA, EdDSA)
├── hpcrypt-rsa        # RSA signatures and encryption
├── hpcrypt-mlkem      # Post-quantum KEM (FIPS 203)
├── hpcrypt-mldsa      # Post-quantum signatures (FIPS 204)
├── hpcrypt-slhdsa     # Post-quantum hash-based signatures (FIPS 205)
└── hpcrypt-threshold  # Shamir's Secret Sharing

Layer 2 (Protocols):
├── hpcrypt-ecies      # Elliptic Curve Integrated Encryption
├── hpcrypt-hpke       # Hybrid Public Key Encryption (RFC 9180)
├── hpcrypt-fpe        # Format-Preserving Encryption (FF1)
├── hpcrypt-pake       # Password-Authenticated Key Exchange (OPAQUE)
└── hpcrypt-srp        # Secure Remote Password (SRP-6a)

Layer 3 (Umbrella):
└── hpcrypt            # Re-exports all crates with feature gates
```

## Key Design Decisions

1. **Layered Architecture**: Dependencies flow downward only - no circular dependencies
2. **Separation of Concerns**: Encryption (cipher), authentication (mac), and combined (aead) are separate
3. **Self-Contained Primitives**: Layer 0 has no internal dependencies
4. **Protocol Independence**: High-level protocols can be used standalone
5. **Minimal External Dependencies**: Only essential crates (`subtle`, `zeroize`, `sha3`, `getrandom`, `num-bigint`)

## Feature Flags

### Common Features
- `std`: Standard library support (default)
- `alloc`: Heap allocation without std
- `serde`: Serialization support

### Specialized Features
- `ascon-only`: Minimal AEAD for embedded (hpcrypt-aead)
- `os-rng`: OS random number generation (default)
- `quic-header-protection`: QUIC protocol support (hpcrypt-kdf)
- Algorithm-specific flags: `p256`, `secp256k1`, `ed25519`, etc.

### Example Usage

```toml
# Minimal embedded: Only Ascon AEAD
hpcrypt-aead = { version = "0.1", default-features = false, features = ["ascon-only"] }

# Umbrella with symmetric crypto only
hpcrypt = { version = "0.1", features = ["symmetric"] }

# Everything
hpcrypt = { version = "0.1", features = ["full"] }
```

## Testing Strategy

The codebase includes multiple layers of testing:

1. **Unit Tests**: Inline tests in each module
2. **Integration Tests**: Public API testing
3. **Known Answer Tests (KAT)**: From authoritative sources
4. **Test Vector Sources**:
   - Wycheproof (Google's crypto test suite)
   - NIST CAVP (Cryptographic Algorithm Validation Program)
   - RFC test vectors (protocol-specific)

### Test Organization

```
crate/
├── src/*.rs           # Unit tests
├── tests/             # Integration and KAT tests
│   ├── wycheproof_*.rs
│   ├── cavp_*.rs
│   └── rfc_*.rs
└── benches/           # Performance benchmarks
```

## Performance Considerations

### Optimization Strategy

- Release builds use LTO and aggressive optimization (`opt-level = 3`)
- Multiple implementation variants for critical operations (MACs have 30+ variants)
- Hardware acceleration where available (AVX2, PCLMULQDQ on x86/x86_64)
- Graceful fallback to portable implementations

### Critical Paths

- Field arithmetic (Montgomery/Barrett reduction)
- NTT for lattice crypto
- GHASH/POLYVAL (hardware-accelerated polynomial evaluation)
- Hash function compression loops

## Security Considerations

### Side-Channel Resistance

- Constant-time operations for sensitive data (via `subtle` crate)
- No secret-dependent branches or memory access
- Multiple constant-time implementation variants tested

### Key Material Handling

- Automatic zeroing on drop (via `zeroize`)
- Constant-time equality checks
- Protected memory for private keys

### Standards Compliance

- **NIST FIPS**: ML-KEM (203), ML-DSA (204), SLH-DSA (205)
- **NIST SP**: AES-GCM (800-38D), FF1 (800-38G)
- **RFCs**: HPKE (9180), OPAQUE (9497), ChaCha20-Poly1305 (8439), and more
- **PKCS/SEC**: RSA (PKCS#1 v2.2), ECIES (SEC 1 v2.0)

## Contributing

When adding functionality:

1. Respect the layer structure
2. Minimize external dependencies
3. Add comprehensive tests with KAT vectors
4. Include benchmarks
5. Document security properties
6. Design for no_std first

## References

### Standards
- [NIST FIPS 203/204/205](https://csrc.nist.gov/publications) - Post-quantum cryptography
- [RFC 9180](https://tools.ietf.org/html/rfc9180) - HPKE
- [RFC 8439](https://tools.ietf.org/html/rfc8439) - ChaCha20-Poly1305
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HKDF
- [RFC 9497](https://tools.ietf.org/html/rfc9497) - OPAQUE

### Test Vectors
- [Wycheproof](https://github.com/google/wycheproof) - Google's test suite
- [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) - Algorithm validation

---

For questions or design discussions, please open an issue on GitHub.
