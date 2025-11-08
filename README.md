# HPCrypt Curves

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![no_std compatible](https://img.shields.io/badge/no__std-compatible-success)](https://docs.rust-embedded.org/book/intro/no-std.html)

A high-performance elliptic curve cryptography library written in 100% safe Rust, providing production-ready implementations of modern elliptic curves with a focus on security, performance, and usability.

## Features

- **100% Safe Rust** - Zero unsafe code, memory-safe by design
- **no_std Compatible** - Runs in embedded and constrained environments
- **Standards Compliant** - Full RFC and NIST FIPS compliance
- **Comprehensive Testing** - Validated against official test vectors including Wycheproof
- **Constant-Time Operations** - Protection against timing side-channel attacks
- **Secure by Default** - Automatic memory zeroization, deterministic signatures

## Supported Curves

### Curve25519 Family (RFC 7748, RFC 8032)

| Curve | Type | Key Size | Security Level | Use Case |
|-------|------|----------|----------------|----------|
| **X25519** | ECDH | 32 bytes | ~128-bit | Key exchange |
| **Ed25519** | EdDSA | 32 bytes | ~128-bit | Digital signatures |

### Curve448 Family (RFC 7748, RFC 8032)

| Curve | Type | Key Size | Security Level | Use Case |
|-------|------|----------|----------------|----------|
| **X448** | ECDH | 56 bytes | ~224-bit | High-security key exchange |
| **Ed448** | EdDSA | 57 bytes | ~224-bit | High-security signatures |

### NIST Curves (FIPS 186-4)

| Curve | Type | Key Size | Security Level | Use Case |
|-------|------|----------|----------------|----------|
| **P-256** | ECDSA/ECDH | 32 bytes | 128-bit | General purpose, TLS |
| **P-384** | ECDSA/ECDH | 48 bytes | 192-bit | High security |
| **P-521** | ECDSA/ECDH | 66 bytes | 256-bit | Maximum security |

### secp256k1 (SEC 2)

| Curve | Type | Key Size | Security Level | Use Case |
|-------|------|----------|----------------|----------|
| **secp256k1** | ECDSA/ECDH | 32 bytes | 128-bit | Bitcoin, Ethereum, cryptocurrency |

## Crates

The library is organized into focused, composable crates:

| Crate | Description | Version |
|-------|-------------|---------|
| **hpcrypt-curves** | Elliptic curve implementations | 0.1.0 |
| **hpcrypt-signatures** | Digital signature schemes (Ed25519, Ed448, ECDSA) | 0.1.0 |
| **hpcrypt-hash** | Cryptographic hash functions (SHA-2, SHA-3, BLAKE2/3) | 0.1.0 |
| **hpcrypt-rng** | Cryptographically secure random number generation | 0.1.0 |
| **hpcrypt-core** | Core utilities and error types | 0.1.0 |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
hpcrypt-curves = "0.1"
hpcrypt-signatures = "0.1"
hpcrypt-rng = "0.1"
```

### X25519 Key Exchange

```rust
use hpcrypt_curves::X25519;

// Alice generates keypair
let alice_private = [/* 32 random bytes */];
let alice_public = X25519::public_key(&alice_private);

// Bob generates keypair
let bob_private = [/* 32 random bytes */];
let bob_public = X25519::public_key(&bob_private);

// Compute shared secret
let alice_shared = X25519::shared_secret(&alice_private, &bob_public)?;
let bob_shared = X25519::shared_secret(&bob_private, &alice_public)?;

assert_eq!(alice_shared, bob_shared);
```

### Ed25519 Digital Signatures

```rust
use hpcrypt_curves::Ed25519;

// Generate keypair
let private_key = [/* 32 random bytes */];
let public_key = Ed25519::public_key(&private_key);

// Sign message
let message = b"Important message";
let signature = Ed25519::sign(&private_key, message);

// Verify signature
let is_valid = Ed25519::verify(&public_key, message, &signature);
assert!(is_valid);
```

### ECDSA Signatures

```rust
use hpcrypt_signatures::EcdsaP256;
use hpcrypt_rng::generate_key;

// Generate keypair
let private_key: [u8; 32] = generate_key()?;
let public_key = EcdsaP256::public_key(&private_key)?;

// Sign message
let message = b"Transaction data";
let signature = EcdsaP256::sign(&private_key, message)?;

// Verify signature
let is_valid = EcdsaP256::verify(&public_key, message, &signature)?;
assert!(is_valid);
```

## Hash Functions

| Algorithm | Output Size | Standard | Use Case |
|-----------|-------------|----------|----------|
| **SHA-256** | 32 bytes | FIPS 180-4 | General purpose |
| **SHA-384** | 48 bytes | FIPS 180-4 | High security |
| **SHA-512** | 64 bytes | FIPS 180-4 | High security |
| **SHA3-256** | 32 bytes | FIPS 202 | NIST standard |
| **SHA3-512** | 64 bytes | FIPS 202 | NIST standard |
| **BLAKE2b** | 1-64 bytes | RFC 7693 | Fast hashing, MACs |
| **BLAKE3** | 32 bytes | Official spec | High-performance hashing |

## Examples

The [`examples/`](examples/) directory contains working examples:

- [ed25519_signatures.rs](examples/ed25519_signatures.rs) - Ed25519 signing and verification
- [x25519_key_exchange.rs](examples/x25519_key_exchange.rs) - X25519 ECDH
- [ecdsa_signatures.rs](examples/ecdsa_signatures.rs) - ECDSA with NIST curves
- [schnorr_bitcoin.rs](examples/schnorr_bitcoin.rs) - Schnorr signatures
- [ecies_secp256k1.rs](examples/ecies_secp256k1.rs) - ECIES hybrid encryption
- [ecies_p521_high_security.rs](examples/ecies_p521_high_security.rs) - High-security ECIES

Run an example:

```bash
cargo run --example ed25519_signatures
cargo run --example x25519_key_exchange
```

## Testing

Run the complete test suite:

```bash
cargo test --workspace
```

Run tests for a specific crate:

```bash
cargo test -p hpcrypt-curves
cargo test -p hpcrypt-signatures
cargo test -p hpcrypt-hash
```

Run benchmarks:

```bash
cargo bench
```

## Security

### Constant-Time Operations

Critical operations use constant-time algorithms to prevent timing side-channel attacks:
- Field arithmetic uses the `subtle` crate for constant-time comparisons
- Scalar multiplication avoids data-dependent branches
- Memory comparisons are constant-time

### Memory Safety

- **100% safe Rust** - No unsafe code blocks
- Automatic memory zeroization on drop via `zeroize` crate
- No buffer overflows, use-after-free, or memory corruption vulnerabilities

### Secure Random Number Generation

The RNG module provides cryptographically secure random number generation:
- OS-based entropy via `getrandom`
- Type-safe API with compile-time size checking
- Suitable for key generation and nonce creation

### Standards Compliance

All implementations are validated against official test vectors:

- **RFC 7748** - Curve25519 and Curve448 (X25519, X448)
- **RFC 8032** - Edwards-Curve Digital Signature Algorithm (Ed25519, Ed448)
- **RFC 6979** - Deterministic ECDSA
- **NIST FIPS 186-4** - Digital Signature Standard (ECDSA P-256/P-384/P-521)
- **SEC 2** - Recommended Elliptic Curve Domain Parameters (secp256k1)
- **NIST FIPS 180-4** - Secure Hash Standard (SHA-2)
- **NIST FIPS 202** - SHA-3 Standard
- **RFC 7693** - BLAKE2 Cryptographic Hash
- **Wycheproof** - Google's cryptographic test suite for edge cases

## Performance

The library is optimized for performance while maintaining security:

- Efficient field arithmetic with lazy reduction techniques
- Optimized scalar multiplication with windowing methods
- SIMD-friendly implementations where applicable
- Minimal dependencies for fast compilation

See [`benches/`](benches/) for detailed performance benchmarks.

## no_std Support

All crates support `no_std` environments:

```toml
[dependencies]
hpcrypt-curves = { version = "0.1", default-features = false }
hpcrypt-signatures = { version = "0.1", default-features = false }
hpcrypt-hash = { version = "0.1", default-features = false }
```

Features:
- `std` (default) - Standard library support
- `alloc` - Allocation support without std

## Minimum Supported Rust Version (MSRV)

This crate requires Rust 1.70 or later.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test --workspace`
2. Code is formatted: `cargo fmt --all`
3. No clippy warnings: `cargo clippy --workspace -- -D warnings`
4. Add tests for new features
5. Update documentation as needed

## Disclaimer

This library has been developed with care and tested against official test vectors. However, it has not undergone an independent security audit. Users are advised to conduct their own security review before using this library in production systems.

**Use at your own risk.** No warranty is provided.

## Acknowledgments

This project implements cryptographic algorithms as specified in:
- IETF RFCs 6979, 7748, 8032
- NIST FIPS 186-4, 180-4, 202
- SEC 2 v2.0
- Official BLAKE2 and BLAKE3 specifications

Special thanks to the Rust community and the authors of the cryptographic specifications.
