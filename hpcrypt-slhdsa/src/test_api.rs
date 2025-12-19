//! CAVP test API
//!
//! This module provides a simplified interface for CAVP testing.

use crate::params::ParameterSet;
use crate::slhdsa::{KeyPair, PublicKey, SecretKey};
use crate::utils::SignatureError;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Trait for CAVP-compatible signature schemes
pub trait SignatureScheme {
    /// Generate a key pair from deterministic seed
    fn generate_deterministic(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignatureError>;

    /// Verify a signature
    fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Macro to implement SignatureScheme for a parameter set
macro_rules! impl_signature_scheme {
    ($param:ty) => {
        impl SignatureScheme for $param {
            fn generate_deterministic(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignatureError> {
                // Extract the three seeds from combined seed
                // CAVP provides: sk_seed || sk_prf || pk_seed
                let n = <$param>::N;

                if seed.len() != 3 * n {
                    return Err(SignatureError::InvalidSecretKey);
                }

                let sk_seed = &seed[0..n];
                let sk_prf = &seed[n..2*n];
                let pk_seed = &seed[2*n..3*n];

                // Generate key pair from seeds
                let keypair = KeyPair::<$param>::generate_from_seed(sk_seed, sk_prf, pk_seed)?;

                Ok((keypair.public_key.to_bytes(), keypair.secret_key.to_bytes()))
            }

            fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
                let public_key = match PublicKey::<$param>::from_bytes(pk) {
                    Ok(pk) => pk,
                    Err(_) => return false,
                };

                crate::slhdsa::verify_internal(&public_key, message, signature)
            }
        }
    };
}

// Implement for all parameter sets
impl_signature_scheme!(crate::params::Sha2_128s);
impl_signature_scheme!(crate::params::Sha2_128f);
impl_signature_scheme!(crate::params::Sha2_192s);
impl_signature_scheme!(crate::params::Sha2_192f);
impl_signature_scheme!(crate::params::Sha2_256s);
impl_signature_scheme!(crate::params::Sha2_256f);
impl_signature_scheme!(crate::params::Shake128s);
impl_signature_scheme!(crate::params::Shake128f);
impl_signature_scheme!(crate::params::Shake192s);
impl_signature_scheme!(crate::params::Shake192f);
impl_signature_scheme!(crate::params::Shake256s);
impl_signature_scheme!(crate::params::Shake256f);
