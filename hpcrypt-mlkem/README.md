# hpcrypt-mlkem

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Pure Rust implementation of ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) per NIST FIPS 203.

This is a **portable, reference implementation** focusing on correctness and broad platform compatibility. For optimized implementations with SIMD support, see the main [HPCrypt](https://github.com/yourusername/hpcrypt) repository.

## Features

- **NIST FIPS 203 Compliant**: Complete implementation of ML-KEM standard
- **Pure Rust**: `#![deny(unsafe_code)]` - no unsafe code
- **No-std Compatible**: Works in embedded and constrained environments
- **Three Security Levels**:
  - ML-KEM-512 (128-bit security)
  - ML-KEM-768 (192-bit security) ⭐ Recommended
  - ML-KEM-1024 (256-bit security)
- **Extensively Tested**: Known Answer Tests (KAT), property-based tests, constant-time verification
- **Well Documented**: Every public API documented with examples

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
hpcrypt-mlkem = "0.1"
```

### Basic Usage

```rust
use hpcrypt_mlkem::{MlKem768, KeyPair};

// Generate a key pair
let keypair = KeyPair::generate::<MlKem768>();

// Sender: Encapsulate to create shared secret
let (ciphertext, shared_secret_sender) = keypair.public_key().encapsulate::<MlKem768>();

// Receiver: Decapsulate to recover shared secret
let shared_secret_receiver = keypair.decapsulate::<MlKem768>(&ciphertext);

assert_eq!(shared_secret_sender, shared_secret_receiver);
```

## Security Levels

| Variant | Classical Security | Quantum Security | Public Key | Ciphertext | Shared Secret |
|---------|-------------------|------------------|------------|------------|---------------|
| ML-KEM-512 | 128-bit | 101-bit | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 ⭐ | 192-bit | 161-bit | 1184 bytes | 1088 bytes | 32 bytes |
| ML-KEM-1024 | 256-bit | 230-bit | 1568 bytes | 1568 bytes | 32 bytes |

*⭐ NIST-recommended variant for general use*

## Features

### Optional Features

```toml
[dependencies]
hpcrypt-mlkem = { version = "0.1", features = ["serde", "zeroize"] }
```

- **std**: Enable standard library support (enabled by default in most environments)
- **serde**: Enable serialization/deserialization of keys
- **zeroize**: Automatic zeroing of private key material on drop
- **timing-tests**: Enable statistical timing analysis tests (requires std)

## No-std Usage

This library is `no_std` compatible (with `alloc`):

```toml
[dependencies]
hpcrypt-mlkem = { version = "0.1", default-features = false }
getrandom = { version = "0.2", features = ["custom"] }
```

You'll need to provide a random number generator implementation suitable for your platform.

## Performance

This is a **portable reference implementation**. Performance characteristics (approximate, on modern x86_64):

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|------------|-------------|
| KeyGen | ~40 µs | ~60 µs | ~100 µs |
| Encaps | ~50 µs | ~75 µs | ~125 µs |
| Decaps | ~60 µs | ~90 µs | ~150 µs |

For optimized implementations with AVX2/AVX-512/NEON support (up to 2x faster), see the main [hpenc](https://github.com/yourusername/hpenc) repository.

## Algorithm Overview

ML-KEM is a lattice-based key encapsulation mechanism designed to be secure against both classical and quantum computers. It's based on the hardness of the Module Learning With Errors (M-LWE) problem.

**Key Operations:**
- **KeyGen**: Generate a public/private key pair
- **Encaps**: Use the public key to generate a shared secret and ciphertext
- **Decaps**: Use the private key and ciphertext to recover the shared secret

The implementation includes:
- Number Theoretic Transform (NTT) for efficient polynomial multiplication
- Centered Binomial Distribution (CBD) sampling for noise generation
- Constant-time operations to resist timing attacks
- Implicit rejection to prevent active attacks

## Testing

```bash
# Run all tests
cargo test

# Run Known Answer Tests
cargo test kat

# Run timing analysis (requires std feature)
cargo test --features "timing-tests std" timing_analysis
```

## Benchmarking

```bash
cargo bench
```

## Security Considerations

- **Constant-time operations**: Critical operations use constant-time implementations
- **Implicit rejection**: Decapsulation always returns a valid-looking key to prevent oracle attacks
- **No unsafe code**: Leverages Rust's memory safety guarantees
- **Validated**: Tested against official NIST test vectors

## Architecture

The implementation is organized into:

- **lib.rs**: Public API and parameter sets
- **keygen.rs**: Key generation (ML-KEM.KeyGen)
- **encaps.rs**: Encapsulation (ML-KEM.Encaps)
- **decaps.rs**: Decapsulation with implicit rejection (ML-KEM.Decaps)
- **poly.rs**: Polynomial arithmetic
- **ntt.rs**: Number Theoretic Transform
- **sampling.rs**: Centered Binomial Distribution sampling
- **compress.rs**: Polynomial compression/decompression
- **serialize.rs**: Byte encoding/decoding
- **symmetric.rs**: SHA-3 wrappers (SHAKE, SHA3)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Specification
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/) - Original algorithm
- [pq-crystals/kyber](https://github.com/pq-crystals/kyber) - Reference C implementation

## Contributing

Contributions are welcome! Please ensure all tests pass and add appropriate test coverage for new features.
