# DRBG CAVP Tests - Implementation Status

## Overview

NIST SP 800-90A DRBG (Deterministic Random Bit Generator) implementations exist in `hpcrypt-rng/src/drbg/` but are not yet fully integrated into the build system. CAVP test vectors are available and ready for validation once integration is complete.

## Available Test Vectors

Located in `tests/cavp-vectors/gen-val/json-files/`:
- **ctrDRBG-1.0**: AES-128/192/256 Counter mode DRBG
- **hashDRBG-1.0**: SHA-256/384/512 Hash-based DRBG
- **hmacDRBG-1.0**: HMAC-SHA256/384/512 DRBG

## DRBG Implementations Status

### Existing Implementations
✅ **CTR_DRBG** (`hpcrypt-rng/src/drbg/ctr_drbg.rs`)
- AES-256-CTR based
- NIST SP 800-90A compliant
- Uses `hpcrypt-cipher` for AES

✅ **HMAC_DRBG** (`hpcrypt-rng/src/drbg/hmac_drbg.rs`)
- HMAC-SHA256 based
- NIST SP 800-90A compliant
- Uses `hpcrypt-mac` for HMAC

✅ **HASH_DRBG** (`hpcrypt-rng/src/drbg/hash_drbg.rs`)
- SHA-256 based
- NIST SP 800-90A compliant
- Uses `hpcrypt-hash` for SHA

✅ **ChaCha20_DRBG** (`hpcrypt-rng/src/drbg/chacha20_drbg.rs`)
- ChaCha20-based (non-NIST)
- Fast, constant-time
- Uses `hpcrypt-cipher` for ChaCha20

### Integration Requirements

To enable DRBG tests, the following needs to be completed:

#### 1. Update `hpcrypt-rng/Cargo.toml`

Add dependencies:
```toml
[dependencies]
hpcrypt-cipher = { path = "../hpcrypt-cipher", optional = true }
hpcrypt-hash = { path = "../hpcrypt-hash", optional = true }
hpcrypt-mac = { path = "../hpcrypt-mac", optional = true }

[features]
# DRBG implementations
ctr-drbg = ["hpcrypt-cipher"]
hash-drbg = ["hpcrypt-hash"]
hmac-drbg = ["hpcrypt-mac"]
chacha20-drbg = ["hpcrypt-cipher"]
drbg = ["ctr-drbg", "hash-drbg", "hmac-drbg"]
```

#### 2. Update `hpcrypt-rng/src/lib.rs`

Expose DRBG module:
```rust
#[cfg(feature = "drbg")]
pub mod drbg;

#[cfg(feature = "drbg")]
pub use drbg::Drbg;
```

#### 3. Update `tests/cavp-tests/Cargo.toml`

Add dependency:
```toml
[dependencies]
hpcrypt-rng = { path = "../../hpcrypt-rng", features = ["drbg", "ctr-drbg", "hash-drbg", "hmac-drbg"] }

[features]
enable-drbg-tests = []
```

## API Mismatch with NIST Test Vectors

### NIST Test Vector Format

NIST DRBG tests expect this workflow:

```
1. Instantiate(entropy_input, nonce, personalization_string)
2. Reseed(entropy_input, additional_input)  [optional]
3. Generate(additional_input, entropy_input_pr) → discard output
4. Generate(additional_input, entropy_input_pr) → return bits
```

### Current hpcrypt-rng API

```rust
pub trait Drbg {
    fn from_seed(seed: &[u8]) -> Result<Self>;
    fn generate(&mut self, output: &mut [u8]) -> Result<()>;
    fn reseed_with(&mut self, entropy: &[u8]) -> Result<()>;
}
```

### Required API Extensions

To support full NIST test vectors, the DRBG implementations need:

```rust
pub trait DrbgNist {
    /// Instantiate with entropy, nonce, and personalization string
    fn instantiate(
        entropy_input: &[u8],
        nonce: &[u8],
        personalization_string: &[u8]
    ) -> Result<Self>;

    /// Generate with additional input (per-generate entropy for prediction resistance)
    fn generate_with_additional(
        &mut self,
        output: &mut [u8],
        additional_input: &[u8],
        prediction_resistance_entropy: Option<&[u8]>
    ) -> Result<()>;

    /// Reseed with additional input
    fn reseed_with_additional(
        &mut self,
        entropy_input: &[u8],
        additional_input: &[u8]
    ) -> Result<()>;
}
```

## Test Implementation Strategy

### Option 1: Basic Tests (Current API)

Test with simplified seed-based API:
- Combine `entropy_input + nonce + personalization_string` into one seed
- Skip tests requiring per-generate additional input
- Skip prediction resistance tests
- Coverage: ~30-40% of test vectors

### Option 2: Extended API Tests (Full NIST Compliance)

Implement extended API to match NIST requirements:
- Full instantiate/reseed/generate workflow
- Support additional input per operation
- Support prediction resistance
- Coverage: ~95-100% of test vectors (skipping MCT)

## Test Vector Structure

### Prompt File Schema

```json
{
  "testGroups": [
    {
      "tgId": 1,
      "testType": "AFT",           // Algorithm Functional Test
      "derFunc": true,              // Derivation function used
      "reSeed": true,               // Includes reseed operation
      "predResistance": true,       // Prediction resistance enabled
      "entropyInputLen": 256,       // bits
      "nonceLen": 256,
      "persoStringLen": 256,
      "additionalInputLen": 256,
      "returnedBitsLen": 4096,
      "mode": "AES-128",            // For CTR_DRBG
      "tests": [
        {
          "tcId": 1,
          "entropyInput": "841AE74F...",
          "nonce": "A2AA1E54...",
          "persoString": "70CE5D34...",
          "otherInput": [
            {
              "intendedUse": "generate",
              "additionalInput": "47B171D2...",
              "entropyInput": "4520F2CC..."  // For prediction resistance
            },
            {
              "intendedUse": "generate",
              "additionalInput": "C129DB89...",
              "entropyInput": "0E086F40..."
            }
          ]
        }
      ]
    }
  ]
}
```

### Expected Results Schema

```json
{
  "testGroups": [
    {
      "tgId": 1,
      "tests": [
        {
          "tcId": 1,
          "returnedBits": "5A02786DE4..."  // Final generate output (512 bytes for 4096 bits)
        }
      ]
    }
  ]
}
```

## Test Complexity Breakdown

### Test Types

1. **AFT (Algorithm Functional Test)** - Standard tests ✅
2. **MCT (Monte Carlo Test)** - Iterative tests ⏭️ (Skip recommended)

### Test Parameters

- **Derivation Function**: `derFunc: true/false`
- **Reseeding**: `reSeed: true/false`
- **Prediction Resistance**: `predResistance: true/false`
- **AES Modes** (CTR_DRBG): AES-128, AES-192, AES-256
- **Hash Variants** (HASH_DRBG): SHA-256, SHA-384, SHA-512
- **HMAC Variants** (HMAC_DRBG): HMAC-SHA256, HMAC-SHA384, HMAC-SHA512

### Test Counts (Approximate)

- **ctrDRBG**: ~300 AFT tests (AES-128/192/256 variants)
- **hashDRBG**: ~200 AFT tests (SHA-256/384/512 variants)
- **hmacDRBG**: ~200 AFT tests (HMAC variants)
- **Total**: ~700 tests

## Next Steps

1. ✅ DRBG implementations exist
2. ⏳ Integrate into hpcrypt-rng Cargo.toml
3. ⏳ Expose DRBG module in lib.rs
4. ⏳ Add extended API for NIST compliance (optional but recommended)
5. ⏳ Create CAVP test files (templates ready)
6. ⏳ Run tests and validate against NIST vectors

## References

- NIST SP 800-90A Rev. 1: Recommendation for Random Number Generation Using Deterministic Random Bit Generators
- NIST CAVP/ACVP: Cryptographic Algorithm Validation Program
- FIPS 140-2/3: Security Requirements for Cryptographic Modules
