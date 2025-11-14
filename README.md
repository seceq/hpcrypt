# HPCrypt

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![no_std compatible](https://img.shields.io/badge/no__std-compatible-success)](https://docs.rust-embedded.org/book/intro/no-std.html)

A comprehensive, high-performance cryptography library written in pure Rust, providing production-ready implementations of modern cryptographic primitives with a focus on security, performance, and usability.

## Features

- **100% Safe Rust** - Zero unsafe code, memory-safe by design
- **no_std Compatible** - Runs in embedded and constrained environments
- **Standards Compliant** - Full RFC and NIST FIPS compliance
- **Post-Quantum Ready** - ML-DSA, ML-KEM, SLH-DSA implementations
- **Comprehensive Testing** - Validated against official test vectors including Wycheproof
- **Constant-Time Operations** - Protection against timing side-channel attacks
- **Modular Design** - Use only what you need

## Crates Overview

The library is organized into focused, composable crates:

### Core Primitives

| Crate | Description | Standards |
|-------|-------------|-----------|
| **hpcrypt-core** | Core utilities, error types, traits | - |
| **hpcrypt-hash** | Hash functions (SHA-2, SHA-3, BLAKE2/3) | FIPS 180-4, FIPS 202, RFC 7693 |
| **hpcrypt-cipher** | Block ciphers (AES, ChaCha20) and modes (CBC, CTR, XTS) | NIST SP 800-38A/E |
| **hpcrypt-mac** | MACs (HMAC, CMAC, KMAC, GMAC, Poly1305) and universal hashes (GHASH, Polyval) | FIPS 198-1, RFC 2104, RFC 4493 |
| **hpcrypt-aead** | Authenticated encryption (AES-GCM, ChaCha20-Poly1305, Ascon) | RFC 5116, RFC 7539, RFC 5297 |
| **hpcrypt-kdf** | Key derivation (HKDF, PBKDF2, Argon2, scrypt, TLS/QUIC KDF) | RFC 5869, RFC 2898, RFC 9106 |
| **hpcrypt-rng** | Cryptographically secure random generation | - |

### Elliptic Curve Cryptography

| Crate | Description | Standards |
|-------|-------------|-----------|
| **hpcrypt-curves** | Elliptic curves (Curve25519, P-256, P-384, P-521, secp256k1) | RFC 7748, RFC 8032, FIPS 186-4, SEC 2 |
| **hpcrypt-signatures** | Digital signatures (Ed25519, Ed448, ECDSA, Schnorr) | RFC 8032, FIPS 186-4, BIP-340 |
| **hpcrypt-ecies** | Hybrid encryption scheme | ISO/IEC 18033-2 |

### Post-Quantum Cryptography

| Crate | Description | Standards |
|-------|-------------|-----------|
| **hpcrypt-mlkem** | ML-KEM (Kyber) key encapsulation | FIPS 203 |
| **hpcrypt-mldsa** | ML-DSA (Dilithium) signatures | FIPS 204 |
| **hpcrypt-slhdsa** | SLH-DSA (SPHINCS+) signatures | FIPS 205 |

### High-Level Protocols

| Crate | Description | Standards |
|-------|-------------|-----------|
| **hpcrypt-rsa** | RSA encryption and signatures (OAEP, PSS, PKCS#1) | RFC 8017 |
| **hpcrypt-hpke** | Hybrid Public Key Encryption | RFC 9180 |
| **hpcrypt-pake** | Password-authenticated key exchange (OPAQUE) | RFC 9497 |
| **hpcrypt-srp** | Secure Remote Password protocol | RFC 2945, RFC 5054 |
| **hpcrypt-fpe** | Format-preserving encryption (FF1) | NIST SP 800-38G |
| **hpcrypt-threshold** | Threshold cryptography (Shamir secret sharing) | - |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
hpcrypt = { version = "0.1", features = ["curves", "aead", "hash"] }
```

### AES-GCM Authenticated Encryption

```rust
use hpcrypt::aead::{Aes256Gcm, Aead};
use hpcrypt::rng::OsRng;

// Generate random key and nonce
let key = OsRng::generate_bytes::<32>();
let nonce = OsRng::generate_bytes::<12>();

// Encrypt
let cipher = Aes256Gcm::new(&key);
let plaintext = b"Secret message";
let ciphertext = cipher.encrypt(&nonce, plaintext, &[])?;

// Decrypt
let recovered = cipher.decrypt(&nonce, &ciphertext, &[])?;
assert_eq!(recovered, plaintext);
```

### Ed25519 Digital Signatures

```rust
use hpcrypt::curves::Ed25519;
use hpcrypt::rng::OsRng;

// Generate keypair
let private_key = OsRng::generate_bytes::<32>();
let public_key = Ed25519::public_key(&private_key);

// Sign message
let message = b"Important message";
let signature = Ed25519::sign(&private_key, message);

// Verify signature
assert!(Ed25519::verify(&public_key, message, &signature));
```

### ML-DSA Post-Quantum Signatures

```rust
use hpcrypt_mldsa::{MlDsa65, keygen::keygen};

// Generate post-quantum keypair
let (pk, sk) = keygen::<MlDsa65>();

// Sign message
let message = b"Future-proof signature";
let signature = sk.sign(message)?;

// Verify signature
assert!(pk.verify(message, &signature));
```

### Password Hashing with Argon2

```rust
use hpcrypt::kdf::Argon2id;

let password = b"user_password";
let salt = b"unique_salt_16bt";

// Hash password
let params = Argon2id::default_params();
let mut output = [0u8; 32];
Argon2id::hash(password, salt, &params, &mut output)?;

// Verify password
let mut verify = [0u8; 32];
Argon2id::hash(password, salt, &params, &mut verify)?;
assert_eq!(output, verify);
```

## Supported Algorithms

### Hash Functions

- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256
- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, TurboShake
- **BLAKE Family**: BLAKE2b, BLAKE2s, BLAKE3

### Message Authentication

- HMAC (with SHA-256, SHA-384, SHA-512, BLAKE2b)
- KMAC (KMAC128, KMAC256, cSHAKE)
- CMAC (AES-based)
- GMAC (Galois MAC for AES)
- Poly1305
- GHASH (universal hash for GCM)
- Polyval (universal hash for AES-GCM-SIV)

### Authenticated Encryption (AEAD)

- AES-GCM (128/192/256-bit keys)
- AES-GCM-SIV (nonce misuse-resistant)
- AES-CCM (128/256-bit keys)
- AES-SIV (deterministic AEAD)
- AES-EAX
- AES-OCB3
- ChaCha20-Poly1305
- XChaCha20-Poly1305
- Ascon-128, Ascon-128a (NIST lightweight crypto winner)

### Elliptic Curves

- **Curve25519**: X25519 (ECDH), Ed25519 (signatures)
- **Curve448**: X448 (ECDH), Ed448 (signatures)
- **NIST Curves**: P-256, P-384, P-521
- **secp256k1**: Bitcoin/Ethereum curve

### Key Derivation

- HKDF (with SHA-256, SHA-384, SHA-512)
- PBKDF2
- Argon2 (Argon2i, Argon2d, Argon2id)
- scrypt
- X9.63 KDF
- TLS 1.2 PRF
- TLS 1.3 HKDF-Expand-Label
- QUIC HKDF-Expand-Label

### Post-Quantum Cryptography

- **ML-KEM** (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **ML-DSA** (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (FIPS 205): Multiple parameter sets

## Architecture Decisions

### No Protocol-Specific Crates

HPCrypt focuses on **cryptographic primitives**, not protocol implementations:

- **KDF functions** for TLS, QUIC are in `hpcrypt-kdf` (not separate `hpcrypt-tls` or `hpcrypt-quic` crates)
- **QUIC header protection** is in `hpcrypt-kdf` with `quic-header-protection` feature
- This maintains architectural consistency and reduces crate proliferation

### Cipher Architecture

HPCrypt maintains clear separation of concerns:

- **`hpcrypt-cipher`**: Block ciphers (AES, ChaCha20) and cipher modes (CBC, CTR, CFB, OFB, XTS)
- **`hpcrypt-mac`**: All MAC implementations and universal hashes
- **`hpcrypt-aead`**: Authenticated encryption schemes combining ciphers and MACs

For encryption, **prefer `hpcrypt-aead`** (AES-GCM, ChaCha20-Poly1305) which provides both confidentiality and authentication. Only use `hpcrypt-cipher` for legacy protocols or disk encryption.

### Dependency Hierarchy

Clean, acyclic dependency structure:

```
hpcrypt-cipher (block ciphers, modes)
    ↓
hpcrypt-mac (depends on cipher for AES-based MACs)
    ↓
hpcrypt-aead (depends on both cipher and mac)
```

This eliminates circular dependencies and provides clear module boundaries.

## Security

### Constant-Time Operations

Critical operations use constant-time algorithms to prevent timing attacks:
- Field arithmetic uses the `subtle` crate for constant-time comparisons
- Scalar multiplication avoids data-dependent branches
- Memory comparisons are constant-time

### Memory Safety

- **100% safe Rust** - No unsafe code except in performance-critical SIMD code
- Automatic memory zeroization on drop via `zeroize` crate
- No buffer overflows or memory corruption vulnerabilities

### Standards Compliance

All implementations validated against official test vectors:

- **NIST**: FIPS 180-4, 186-4, 197, 198-1, 202, 203, 204, 205
- **RFCs**: 2104, 2898, 2945, 5054, 5116, 5297, 5869, 6979, 7539, 7693, 7748, 8017, 8032, 9106, 9180, 9497
- **Wycheproof**: Google's cryptographic test suite for edge cases

## Testing

Run the complete test suite:

```bash
cargo test --workspace --all-features
```

Run tests for specific package:

```bash
cargo test --package hpcrypt-aead
cargo test --package hpcrypt-mldsa
cargo test --package hpcrypt-rsa
```

## no_std Support

All crates support `no_std` environments:

```toml
[dependencies]
hpcrypt-hash = { version = "0.1", default-features = false }
hpcrypt-aead = { version = "0.1", default-features = false, features = ["alloc"] }
```

Features:
- `std` (default) - Standard library support
- `alloc` - Allocation support without std

## Minimum Supported Rust Version (MSRV)

This project requires Rust **1.70** or later.

## Recent Changes

- **Reorganized cryptographic primitives**: Consolidated block ciphers to `hpcrypt-cipher` and all MACs to `hpcrypt-mac`
- **Moved AES and ChaCha20**: From `hpcrypt-aead` to `hpcrypt-cipher` where they architecturally belong
- **Consolidated MAC implementations**: HMAC, KMAC moved from `hpcrypt-hash` to `hpcrypt-mac`
- **Moved universal hashes**: GHASH and Polyval now in `hpcrypt-mac` alongside other MACs
- **Fixed dependency hierarchy**: Eliminated circular dependencies between cipher, mac, and aead crates
- **Cleaned codebase**: Removed 4,000+ lines of debug files, Python scripts, and obsolete code
- **Renamed modules**: `quic_header_protection` → `quic_header` for clarity
- **Fixed critical bugs**: P-256 Montgomery reduction bug fix

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test --workspace --all-features`
2. Code is formatted: `cargo fmt --all`
3. No clippy warnings: `cargo clippy --workspace --all-features -- -D warnings`
4. Add tests for new features
5. Update documentation as needed

## Disclaimer

This library has been developed with care and tested against official test vectors. However, it has not undergone an independent security audit. Users are advised to conduct their own security review before using this library in production systems.

**Use at your own risk.** No warranty is provided.

## Acknowledgments

Special thanks to:
- The Rust community
- NIST for cryptographic standards
- IETF for RFCs
- Google's Wycheproof project
- Authors of cryptographic specifications
