# HPCrypt Quick Start Guide

## Installation

Add to your `Cargo.toml`:

```toml
# Option 1: Umbrella crate with default features
[dependencies]
hpcrypt = "0.1"

# Option 2: Umbrella crate with specific features
[dependencies]
hpcrypt = { version = "0.1", features = ["pq-kem", "pq-sig"] }

# Option 3: Specific crate only
[dependencies]
hpcrypt-mlkem = "0.1"
```

## Feature Flags

```toml
# Core (always included)
- std (default)

# Classical Cryptography
- curves           # Elliptic curves
- signatures       # ECDSA, EdDSA (requires curves)
- classical        # All classical crypto

# Post-Quantum Cryptography
- pq-kem          # ML-KEM (key encapsulation)
- pq-sig-mldsa    # ML-DSA signatures
- pq-sig-slhdsa   # SLH-DSA signatures
- pq-sig          # All PQ signatures
- pq              # All PQ crypto

# Convenience
- full            # Everything
```

## Usage Examples

### Post-Quantum Key Encapsulation (ML-KEM)

```rust
use hpcrypt::mlkem::{MlKem768, KeyPair};

fn main() {
    // Generate key pair
    let keypair = KeyPair::generate::<MlKem768>();

    // Alice: Encapsulate shared secret
    let (ciphertext, shared_secret_alice) = keypair.encapsulate::<MlKem768>();

    // Bob: Decapsulate to recover shared secret
    let shared_secret_bob = keypair.decapsulate::<MlKem768>(&ciphertext);

    assert_eq!(shared_secret_alice, shared_secret_bob);
}
```

### Cryptographic Hashing

```rust
use hpcrypt::hash::{Sha256, Digest};

fn main() {
    let mut hasher = Sha256::new();
    hasher.update(b"hello world");
    let hash = hasher.finalize();

    println!("SHA-256: {:x}", hash);
}
```

### Using the Prelude

```rust
use hpcrypt::prelude::*;

fn main() {
    // Hash functions
    let hash = Sha256::new();

    // RNG
    let mut buffer = [0u8; 32];
    generate_random_bytes(&mut buffer).expect("RNG failed");

    // ML-KEM
    let keypair = MlKemKeyPair::generate::<MlKem768>();
}
```

## Import Styles

### Style 1: Umbrella Crate (Recommended for Most Users)

```rust
use hpcrypt::mlkem::{MlKem768, KeyPair};
use hpcrypt::hash::{Sha256, Digest};
```

**Pros:**
- Clean, unified imports
- Clear hierarchy
- Easy to discover APIs

### Style 2: Direct Crate Import (For Size-Conscious Projects)

```rust
use hpcrypt_mlkem::{MlKem768, KeyPair};
use hpcrypt_hash::{Sha256, Digest};
```

**Pros:**
- Minimal dependencies
- Fastest compile times
- Maximum tree-shaking

### Style 3: Prelude (For Quick Prototyping)

```rust
use hpcrypt::prelude::*;
```

**Pros:**
- Fastest to write
- Good for examples/prototypes
- Most commonly used types

## no_std Usage

All crates support `no_std`:

```toml
[dependencies]
hpcrypt-mlkem = { version = "0.1", default-features = false }

# Enable alloc if you have a heap allocator
hpcrypt-mlkem = { version = "0.1", default-features = false, features = ["alloc"] }
```

## Performance Tips

1. **Use Release Mode**: Always benchmark in `--release` mode
   ```bash
   cargo build --release
   cargo test --release
   cargo bench
   ```

2. **Enable LTO**: Already configured in workspace profile
   ```toml
   [profile.release]
   lto = "fat"
   ```

3. **Feature Selection**: Only enable features you need
   ```toml
   # Bad: Includes everything
   hpcrypt = { version = "0.1", features = ["full"] }

   # Good: Only ML-KEM
   hpcrypt = { version = "0.1", default-features = false, features = ["pq-kem"] }
   ```

## Security Best Practices

1. **Always Use OS RNG for Production**:
   ```rust
   // Good
   let keypair = KeyPair::generate::<MlKem768>();

   // Bad (only for testing)
   let seed = [0x42; 32];
   let keypair = KeyPair::from_seed::<MlKem768>(&seed);
   ```

2. **Enable Zeroization for Sensitive Keys**:
   ```toml
   [dependencies]
   hpcrypt-mlkem = { version = "0.1", features = ["zeroize"] }
   ```

3. **Validate All Inputs**:
   ```rust
   // Check key sizes
   assert_eq!(public_key.len(), MlKem768::EK_SIZE);
   ```

4. **Use Type-Safe APIs**:
   ```rust
   // Good: Type parameter prevents mixing parameter sets
   let kp512 = KeyPair::generate::<MlKem512>();
   let (ct, ss) = kp512.encapsulate::<MlKem512>();

   // Compiler prevents this mistake:
   // let ss2 = kp512.decapsulate::<MlKem768>(&ct); // ERROR!
   ```

## Testing

```bash
# Run all tests
cargo test --workspace --release

# Run tests for specific crate
cargo test -p hpcrypt-mlkem --release

# Run tests with specific features
cargo test -p hpcrypt --features full --release

# Run benchmarks
cargo bench -p hpcrypt-mlkem
```

## Documentation

```bash
# Build and open documentation
cargo doc --open

# Build with all features
cargo doc --all-features --open

# Build specific crate
cargo doc -p hpcrypt-mlkem --open
```

## Troubleshooting

### Compilation Errors

**Error**: `cannot find type 'MlKem768'`
- **Solution**: Add feature flag: `features = ["pq-kem"]`

**Error**: `no_std` compatibility issues
- **Solution**: Disable default features: `default-features = false`

### Performance Issues

**Slow Debug Builds**
- **Solution**: Always use `--release` for crypto operations

**Large Binary Size**
- **Solution**: Only enable needed features
- **Solution**: Use direct crate imports instead of umbrella crate

## Getting Help

- 📖 **Documentation**: <https://docs.rs/hpcrypt>
- 🏗️ **Architecture**: See [ARCHITECTURE.md](ARCHITECTURE.md)
- 🐛 **Issues**: <https://github.com/yourusername/hpcrypt/issues>
- 💬 **Discussions**: <https://github.com/yourusername/hpcrypt/discussions>

## Next Steps

1. Read [ARCHITECTURE.md](ARCHITECTURE.md) for design details
2. Check [examples/](examples/) for more usage patterns
3. Browse API documentation: `cargo doc --open`
4. Explore [future-crates/](future-crates/) for upcoming features
