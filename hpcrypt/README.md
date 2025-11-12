# HPCrypt - High-Performance Cryptography Library

[![Crates.io](https://img.shields.io/crates/v/hpcrypt.svg)](https://crates.io/crates/hpcrypt)
[![Documentation](https://docs.rs/hpcrypt/badge.svg)](https://docs.rs/hpcrypt)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Pure-Rust cryptography library focused on performance, security, and correctness.

## Features

- 🔒 **No unsafe code** - 100% safe Rust implementations
- 🚀 **High performance** - Optimized implementations with comprehensive benchmarks
- 📦 **no_std compatible** - Works in embedded and bare-metal environments
- 🔮 **Post-quantum ready** - NIST-standardized PQC algorithms
- 📚 **Well documented** - Production-ready with extensive documentation
- ✅ **Thoroughly tested** - Comprehensive test coverage including KAT vectors

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
hpcrypt = "0.1"
```

### Post-Quantum Key Encapsulation (ML-KEM)

```rust
use hpcrypt::mlkem::{MlKem768, KeyPair};

// Generate a key pair
let keypair = KeyPair::generate::<MlKem768>();

// Encapsulate a shared secret
let (ciphertext, shared_secret_sender) = keypair.encapsulate::<MlKem768>();

// Decapsulate to recover the shared secret
let shared_secret_receiver = keypair.decapsulate::<MlKem768>(&ciphertext);

assert_eq!(shared_secret_sender, shared_secret_receiver);
```

### Classical ECDSA Signatures

```rust
use hpcrypt::signatures::ecdsa::{EcdsaP256, SigningKey};

// Generate signing key
let signing_key = SigningKey::<EcdsaP256>::generate();
let verifying_key = signing_key.verifying_key();

// Sign a message
let message = b"Hello, world!";
let signature = signing_key.sign(message);

// Verify the signature
assert!(verifying_key.verify(message, &signature).is_ok());
```

### Cryptographic Hashing

```rust
use hpcrypt::hash::{Sha256, Digest};

let mut hasher = Sha256::new();
hasher.update(b"hello world");
let result = hasher.finalize();
```

## Supported Algorithms

### Hash Functions
- **SHA-2**: SHA-256, SHA-384, SHA-512
- **SHA-3**: SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
- **BLAKE2**: BLAKE2b, BLAKE2s
- **BLAKE3**: Latest version with SIMD optimizations

### Elliptic Curves
- **NIST**: P-256, P-384, P-521
- **Bitcoin**: secp256k1
- **Edwards**: Ed25519, Ed448
- **Montgomery**: X25519, X448

### Digital Signatures
- **ECDSA**: P-256, P-384, P-521, secp256k1
- **EdDSA**: Ed25519, Ed448
- **ML-DSA**: ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
- **SLH-DSA**: Multiple parameter sets (FIPS 205)

### Key Encapsulation
- **ML-KEM**: ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)

## Feature Flags

```toml
[dependencies]
hpcrypt = { version = "0.1", features = ["full"] }
```

Available features:
- `std` (default): Enable standard library support
- `curves`: Enable elliptic curve primitives
- `signatures`: Enable classical signature schemes
- `pq-kem`: Enable post-quantum key encapsulation (ML-KEM)
- `pq-sig`: Enable post-quantum signatures (ML-DSA + SLH-DSA)
- `pq`: Enable all post-quantum cryptography
- `classical`: Enable all classical cryptography
- `full`: Enable everything

## Crate Organization

HPCrypt is organized into focused sub-crates:

| Crate | Description | Status |
|-------|-------------|--------|
| `hpcrypt-core` | Common utilities and error types | ✅ Stable |
| `hpcrypt-hash` | Cryptographic hash functions | ✅ Stable |
| `hpcrypt-rng` | Secure random number generation | ✅ Stable |
| `hpcrypt-curves` | Elliptic curve implementations | ✅ Stable |
| `hpcrypt-signatures` | Classical signature schemes | ✅ Stable |
| `hpcrypt-mlkem` | ML-KEM (FIPS 203) | ✅ Stable |
| `hpcrypt-mldsa` | ML-DSA (FIPS 204) | ✅ Stable |
| `hpcrypt-slhdsa` | SLH-DSA (FIPS 205) | ✅ Stable |

Each crate can be used independently if you only need specific functionality.

## Security

- **No unsafe code**: All implementations use 100% safe Rust
- **Constant-time operations**: Where cryptographically relevant
- **Comprehensive testing**: Including known answer tests from standards
- **Regular audits**: Security-focused code reviews
- **Fuzzing**: Continuous fuzzing of critical components

## Performance

HPCrypt is designed for high performance:
- Optimized field arithmetic for elliptic curves
- Vectorized operations where beneficial
- Cache-friendly data structures
- Comprehensive benchmarks

See individual crate documentation for detailed performance characteristics.

## no_std Support

HPCrypt works without the standard library:

```toml
[dependencies]
hpcrypt = { version = "0.1", default-features = false, features = ["pq-kem"] }
```

This enables use in embedded systems, bootloaders, and other bare-metal environments.

## Minimum Supported Rust Version (MSRV)

Rust 1.70 or later.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

HPCrypt builds upon the excellent work of the Rust cryptography community.
See individual crate READMEs for specific acknowledgments.
