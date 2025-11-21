# CAVP Test API Implementation Plan

This document provides a detailed analysis and implementation plan for completing the CAVP test infrastructure for PQC algorithms.

## Investigation Summary

After analyzing the existing code, here's what I found:

### ML-DSA (hpcrypt-mldsa) - ✅ Almost Complete!

**Good News**: The functions we need already exist, but the test_api is calling them incorrectly.

#### Existing Functions:
1. **`keygen::keygen_from_seed<P: DsaParams>(xi: &[u8; 32]) -> (PublicKey<P>, SecretKey<P>)`**
   - Location: `src/keygen.rs:207`
   - Takes a 32-byte seed and generates deterministic keypair
   - **Already implements CAVP requirements!**

2. **`sign::sign_deterministic<P: DsaParams>(sk: &SecretKey<P>, message: &[u8], rnd: &[u8; 32]) -> Option<Signature<P>>`**
   - Location: `src/sign.rs:147`
   - Takes secret key, message, and 32-byte randomness
   - **Already implements CAVP requirements!**

#### Problem in test_api.rs:
The test_api is trying to use these functions but:
1. Calls `keygen::keygen_with_seed()` (wrong name, should be `keygen_from_seed`)
2. Passes `sk: &[u8]` instead of `&SecretKey<P>`
3. Needs to deserialize keys from bytes

#### Solution - Option 1 (Recommended): Fix test_api.rs
Change the test_api implementation to properly use existing functions:

```rust
// In hpcrypt-mldsa/src/test_api.rs

fn generate_deterministic(seed: &[u8]) -> Result<(PublicKey, SecretKey), CavpError> {
    if seed.len() != 32 {
        return Err(CavpError::InvalidSeedLength);
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);

    // FIX: Use correct function name
    let (pk, sk) = keygen::keygen_from_seed::<Self>(&seed_array);

    // Convert to bytes for trait API
    let pk_bytes = serialize_public_key(&pk);  // Need to implement
    let sk_bytes = serialize_secret_key(&sk);  // Need to implement

    Ok((pk_bytes, sk_bytes))
}

fn sign_deterministic(sk: &[u8], message: &[u8]) -> Result<Signature, CavpError> {
    // Deserialize secret key from bytes
    let secret_key = deserialize_secret_key::<Self>(sk)
        .map_err(|_| CavpError::InvalidSecretKey)?;

    // Use empty randomness for pure deterministic mode
    let empty_rnd = [0u8; 32];

    // FIX: Pass SecretKey reference, not bytes
    let signature = sign::sign_deterministic::<Self>(&secret_key, message, &empty_rnd)
        .ok_or(CavpError::SigningFailed)?;

    Ok(serialize_signature(&signature))  // Need to implement
}

fn sign_with_randomness(sk: &[u8], message: &[u8], rnd: &[u8]) -> Result<Signature, CavpError> {
    if rnd.len() != 32 {
        return Err(CavpError::InvalidRandomnessLength);
    }

    let secret_key = deserialize_secret_key::<Self>(sk)
        .map_err(|_| CavpError::InvalidSecretKey)?;

    let mut rnd_array = [0u8; 32];
    rnd_array.copy_from_slice(rnd);

    let signature = sign::sign_deterministic::<Self>(&secret_key, message, &rnd_array)
        .ok_or(CavpError::SigningFailed)?;

    Ok(serialize_signature(&signature))
}

fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Deserialize public key and signature
    let public_key = match deserialize_public_key::<Self>(pk) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let sig = match deserialize_signature::<Self>(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verify::verify::<Self>(&public_key, message, &sig)
}
```

**What needs to be implemented:**
1. ✅ **Serialization functions** - Check if they already exist in ML-DSA
2. ✅ **Deserialization functions** - Check if they already exist in ML-DSA
3. ✅ **Update test_api.rs** - Fix function calls and add serialization

#### Solution - Option 2 (Alternative): Create wrapper functions
If serialization doesn't exist or is complex, create thin wrapper functions in the main modules that match what test_api expects.

---

### SLH-DSA (hpcrypt-slhdsa) - WARNING: Needs New Functions

#### Existing Functions:
1. **`KeyPair::<P>::generate() -> Self`**
   - Location: `src/slhdsa.rs:188`
   - Uses RNG to generate random seeds
   - **Cannot be used directly for CAVP (needs deterministic version)**

2. **`sign<P: ParameterSet>(secret_key: &SecretKey<P>, message: &[u8]) -> Vec<u8>`**
   - Location: `src/slhdsa.rs:222`
   - Uses `prf_msg()` to generate internal randomness
   - **Does not accept explicit optRand parameter**

#### What Needs to Be Implemented:

##### 1. Add `KeyPair::from_seed_components()` to `src/slhdsa.rs`

```rust
impl<P: ParameterSet> KeyPair<P> {
    /// Create a keypair from explicit seed components (for CAVP testing)
    ///
    /// # Arguments
    /// * `sk_seed` - Secret seed (N bytes)
    /// * `sk_prf` - PRF key (N bytes)
    /// * `pk_seed` - Public seed (N bytes)
    ///
    /// # Returns
    /// Complete keypair with computed public key root
    #[cfg(feature = "cavp")]
    pub fn from_seed_components(sk_seed: &[u8], sk_prf: &[u8], pk_seed: &[u8]) -> Result<Self, Error> {
        if sk_seed.len() != P::N || sk_prf.len() != P::N || pk_seed.len() != P::N {
            return Err(Error::InvalidSeedLength);
        }

        // Convert to owned vectors
        let sk_seed = sk_seed.to_vec();
        let sk_prf = sk_prf.to_vec();
        let pk_seed = pk_seed.to_vec();

        // Compute public key root (same logic as generate())
        let mut pk_root = vec![0u8; P::N];
        let mut addr = Address::new();

        with_hash!(P::N, P::HASH_TYPE, hash, {
            ht_pk_gen::<P, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk_root);
        });

        let secret_key = SecretKey::new(sk_seed, sk_prf, pk_seed.clone());
        let public_key = PublicKey::new(pk_seed, pk_root);

        Ok(KeyPair {
            secret_key,
            public_key,
        })
    }
}
```

**Implementation Details:**
- Copy the logic from `generate()` but use provided seeds instead of random ones
- The public key computation (`ht_pk_gen`) remains the same
- Feature-gate with `#[cfg(feature = "cavp")]`

##### 2. Add `sign_with_opt_rand()` to `src/slhdsa.rs`

```rust
/// Sign with explicit optRand (for CAVP testing)
///
/// # Arguments
/// * `secret_key` - The secret key
/// * `message` - Message to sign
/// * `opt_rand` - Optional randomness (N bytes, or empty for deterministic)
///
/// # Returns
/// Signature bytes
#[cfg(feature = "cavp")]
pub fn sign_with_opt_rand<P: ParameterSet>(
    secret_key: &SecretKey<P>,
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    let mut addr = Address::new();

    macro_rules! sign_with_explicit_rand {
        ($n:expr, $digest_size:expr) => {{
            let mut opt_rand_buf = [0u8; $n];
            let mut digest_buf = [0u8; $digest_size];

            let opt_rand_slice = &mut opt_rand_buf[..P::N];
            let digest = &mut digest_buf[..P::FORS_MSG_BYTES + 8];

            let (fors_sig, _fors_pk, ht_sig) = with_hash!(P::N, P::HASH_TYPE, hash, {
                // Use provided optRand or generate it
                if let Some(provided_rand) = opt_rand {
                    opt_rand_slice.copy_from_slice(provided_rand);
                } else {
                    // Deterministic mode: optRand is empty/zero
                    opt_rand_slice.fill(0);
                }

                // Hash message (rest is same as original sign())
                hash.h_msg(
                    opt_rand_slice,
                    secret_key.pk_seed(),
                    secret_key.pk_seed(),
                    message,
                    digest,
                );

                // ... rest of signing logic from original sign() ...
            });

            // ... concatenate signature components ...
        }};
    }

    // Match on parameter set size (same as original)
    match (P::N, P::FORS_MSG_BYTES + 8) {
        (16, d) if d <= 256 => sign_with_explicit_rand!(16, 256),
        (24, d) if d <= 256 => sign_with_explicit_rand!(24, 256),
        (32, d) if d <= 256 => sign_with_explicit_rand!(32, 256),
        _ => panic!("Unsupported parameter set"),
    }
}
```

**Implementation Details:**
- Copy the entire `sign()` function
- Modify to accept `opt_rand: Option<&[u8]>` parameter
- If `opt_rand` is `Some`, use it; if `None`, use zeros (deterministic)
- Remove the `prf_msg` call that generates random optRand
- Feature-gate with `#[cfg(feature = "cavp")]`

##### 3. Add Serialization Methods

Check if these already exist. If not, add:

```rust
impl<P: ParameterSet> SecretKey<P> {
    /// Serialize secret key to bytes
    #[cfg(feature = "cavp")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3 * P::N);
        bytes.extend_from_slice(&self.sk_seed);
        bytes.extend_from_slice(&self.sk_prf);
        bytes.extend_from_slice(&self.pk_seed);
        bytes
    }

    /// Deserialize secret key from bytes
    #[cfg(feature = "cavp")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 3 * P::N {
            return Err(Error::InvalidKeyLength);
        }

        let sk_seed = bytes[0..P::N].to_vec();
        let sk_prf = bytes[P::N..2 * P::N].to_vec();
        let pk_seed = bytes[2 * P::N..3 * P::N].to_vec();

        Ok(Self::new(sk_seed, sk_prf, pk_seed))
    }
}

impl<P: ParameterSet> PublicKey<P> {
    /// Serialize public key to bytes
    #[cfg(feature = "cavp")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * P::N);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }

    /// Deserialize public key from bytes
    #[cfg(feature = "cavp")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 2 * P::N {
            return Err(Error::InvalidKeyLength);
        }

        let pk_seed = bytes[0..P::N].to_vec();
        let pk_root = bytes[P::N..2 * P::N].to_vec();

        Ok(Self::new(pk_seed, pk_root))
    }
}
```

##### 4. Update test_api.rs

Once the above functions exist, update test_api.rs to call them:

```rust
// In hpcrypt-slhdsa/src/test_api.rs

fn generate_deterministic(seed: &[u8]) -> Result<(PublicKey, SecretKey), CavpError> {
    let expected_len = 3 * Self::N;
    if seed.len() != expected_len {
        return Err(CavpError::InvalidSeedLength);
    }

    let sk_seed = &seed[0..Self::N];
    let sk_prf = &seed[Self::N..2 * Self::N];
    let pk_seed = &seed[2 * Self::N..3 * Self::N];

    let keypair = KeyPair::<Self>::from_seed_components(sk_seed, sk_prf, pk_seed)
        .map_err(|_| CavpError::KeyGenFailed)?;

    Ok((keypair.public_key.to_bytes(), keypair.secret_key.to_bytes()))
}

// Change sign_with_opt_rand() call to sign_with_opt_rand()
fn sign_with_randomness(sk: &[u8], message: &[u8], opt_rand: &[u8]) -> Result<Signature, CavpError> {
    if opt_rand.len() != Self::N {
        return Err(CavpError::InvalidRandomnessLength);
    }

    let secret_key = crate::slhdsa::SecretKey::<Self>::from_bytes(sk)
        .map_err(|_| CavpError::InvalidSecretKey)?;

    let signature = crate::slhdsa::sign_with_opt_rand(&secret_key, message, Some(opt_rand));

    Ok(signature)
}
```

---

## Implementation Priority

### Phase 1: ML-DSA (Quick Win - ~1 hour)
1. Check if serialization/deserialization already exists (likely does with `serde` or `pem` feature)
2. Update `test_api.rs` to fix function names and add serialization calls
3. Test with CAVP vectors

### Phase 2: SLH-DSA (More Work - ~3-4 hours)
1. Add `KeyPair::from_seed_components()` to `src/slhdsa.rs`
2. Add `sign_with_opt_rand()` to `src/slhdsa.rs`
3. Add serialization methods (to_bytes/from_bytes) if they don't exist
4. Update `test_api.rs` to use new functions
5. Test with CAVP vectors

---

## Testing Strategy

After implementing:

1. **Unit Tests**: Test each new function independently
   ```bash
   # Test ML-DSA
   cargo test -p hpcrypt-mldsa --features cavp

   # Test SLH-DSA
   cargo test -p hpcrypt-slhdsa --features cavp
   ```

2. **CAVP Integration Tests**: Run full test suite
   ```bash
   # Test ML-DSA CAVP
   cargo test -p cavp-tests --test mldsa --features enable-pqc-tests

   # Test SLH-DSA CAVP
   cargo test -p cavp-tests --test slhdsa --features enable-pqc-tests

   # Test all PQC
   cargo test -p cavp-tests --features enable-pqc-tests
   ```

---

## Key Insights

1. **ML-DSA is 95% done** - Just needs test_api fixes
2. **SLH-DSA needs 3 new functions** - All straightforward to implement by copying existing code
3. **No breaking changes** - All new functions are feature-gated and additive
4. **ML-KEM already works** - Can be tested immediately

---

## Next Steps

1. ✅ Investigation complete
2. [ ] Implement ML-DSA test_api fixes
3. [ ] Implement SLH-DSA new functions
4. [ ] Run CAVP tests
5. [ ] Document any test failures for algorithm teams
