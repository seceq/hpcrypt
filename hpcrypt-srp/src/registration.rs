//! SRP user registration - create password verifier

use crate::error::{Result, SrpError};
use crate::groups::SrpGroup;
use crate::utils::{compute_x, pad};
use crate::SrpHashFunction;
use alloc::vec::Vec;
use num_traits::Zero;

/// SRP registration result containing salt and verifier
#[derive(Clone)]
pub struct SrpRegistration {
    /// Random salt (should be at least 16 bytes)
    pub salt: Vec<u8>,
    /// Password verifier: v = g^x % N
    pub verifier: Vec<u8>,
}

/// Register a new user and create password verifier with SHA-256 (recommended)
///
/// # Parameters
/// - `username`: User identifier (will be UTF-8 validated)
/// - `password`: User password (will be zeroized after use)
/// - `group`: SRP group parameters
///
/// # Returns
/// `SrpRegistration` containing salt and verifier to be stored by the server
///
/// # Note
/// Uses SHA-256 by default (secure and AWS Cognito compatible).
/// For SHA-1 (RFC 5054) or SHA-512, use `register_user_with_hash()`.
///
/// # Example
/// ```
/// use hpcrypt_srp::{register_user, SrpGroup};
///
/// let registration = register_user(
///     b"alice",
///     b"password123",
///     SrpGroup::Srp2048,
///     &mut rand::thread_rng()
/// ).unwrap();
///
/// // Store registration.salt and registration.verifier in database
/// ```
pub fn register_user<R: rand::Rng>(
    username: &[u8],
    password: &[u8],
    group: SrpGroup,
    rng: &mut R,
) -> Result<SrpRegistration> {
    register_user_with_hash(username, password, group, rng, SrpHashFunction::default())
}

/// Register a new user with specific hash function
///
/// # Parameters
/// - `username`: User identifier
/// - `password`: User password
/// - `group`: SRP group parameters
/// - `rng`: Random number generator
/// - `hash_fn`: Hash function (SHA-1, SHA-256, or SHA-512)
///
/// # Examples
/// ```
/// use hpcrypt_srp::{register_user_with_hash, SrpGroup, SrpHashFunction};
///
/// // Modern secure registration (SHA-256)
/// let registration = register_user_with_hash(
///     b"alice",
///     b"password123",
///     SrpGroup::Srp2048,
///     &mut rand::thread_rng(),
///     SrpHashFunction::Sha256
/// ).unwrap();
///
/// // Legacy RFC 5054 registration (SHA-1)
/// let legacy_registration = register_user_with_hash(
///     b"alice",
///     b"password123",
///     SrpGroup::Srp2048,
///     &mut rand::thread_rng(),
///     SrpHashFunction::Sha1
/// ).unwrap();
/// ```
pub fn register_user_with_hash<R: rand::Rng>(
    username: &[u8],
    password: &[u8],
    group: SrpGroup,
    rng: &mut R,
    hash_fn: SrpHashFunction,
) -> Result<SrpRegistration> {
    // Validate inputs
    if username.is_empty() {
        return Err(SrpError::InvalidUsername);
    }
    if password.is_empty() {
        return Err(SrpError::InvalidPassword);
    }

    // Generate random salt (16 bytes recommended)
    let mut salt = vec![0u8; 16];
    rng.fill_bytes(&mut salt);

    // Get group parameters
    let n = group.n();
    let g = group.g();

    // Compute x = H(s | H(I | ":" | P))
    let x = compute_x(username, password, &salt, hash_fn);

    // Compute verifier: v = g^x % N
    let verifier_num = g.modpow(&x, &n);

    if verifier_num.is_zero() {
        return Err(SrpError::ComputationError);
    }

    // Convert to bytes (padded to group length)
    let verifier = pad(&verifier_num, group.byte_length());

    Ok(SrpRegistration { salt, verifier })
}

/// Create verifier from existing salt with SHA-256 (recommended)
///
/// This is useful when updating a password but keeping the same salt.
///
/// # Note
/// Uses SHA-256 by default. For SHA-1 or SHA-512, use `create_verifier_with_hash()`.
pub fn create_verifier(
    username: &[u8],
    password: &[u8],
    salt: &[u8],
    group: SrpGroup,
) -> Result<Vec<u8>> {
    create_verifier_with_hash(username, password, salt, group, SrpHashFunction::default())
}

/// Create verifier from existing salt with specific hash function
///
/// # Parameters
/// - `username`: User identifier
/// - `password`: User password
/// - `salt`: Existing salt
/// - `group`: SRP group parameters
/// - `hash_fn`: Hash function (SHA-1, SHA-256, or SHA-512)
///
/// # Examples
/// ```
/// use hpcrypt_srp::{create_verifier_with_hash, SrpGroup, SrpHashFunction};
///
/// let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
///
/// // Modern secure verifier (SHA-256)
/// let verifier = create_verifier_with_hash(
///     b"alice",
///     b"new_password",
///     &salt,
///     SrpGroup::Srp2048,
///     SrpHashFunction::Sha256
/// ).unwrap();
/// ```
pub fn create_verifier_with_hash(
    username: &[u8],
    password: &[u8],
    salt: &[u8],
    group: SrpGroup,
    hash_fn: SrpHashFunction,
) -> Result<Vec<u8>> {
    // Validate inputs
    if username.is_empty() {
        return Err(SrpError::InvalidUsername);
    }
    if password.is_empty() {
        return Err(SrpError::InvalidPassword);
    }
    if salt.is_empty() {
        return Err(SrpError::InvalidSalt);
    }

    // Get group parameters
    let n = group.n();
    let g = group.g();

    // Compute x = H(s | H(I | ":" | P))
    let x = compute_x(username, password, salt, hash_fn);

    // Compute verifier: v = g^x % N
    let verifier_num = g.modpow(&x, &n);

    if verifier_num.is_zero() {
        return Err(SrpError::ComputationError);
    }

    // Convert to bytes (padded to group length)
    Ok(pad(&verifier_num, group.byte_length()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_register_user() {
        let mut rng = thread_rng();
        let registration =
            register_user(b"alice", b"password123", SrpGroup::Srp2048, &mut rng).unwrap();

        assert_eq!(registration.salt.len(), 16);
        assert_eq!(registration.verifier.len(), 256); // 2048 bits = 256 bytes
    }

    #[test]
    fn test_create_verifier_deterministic() {
        let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let v1 = create_verifier(b"alice", b"password123", &salt, SrpGroup::Srp2048).unwrap();
        let v2 = create_verifier(b"alice", b"password123", &salt, SrpGroup::Srp2048).unwrap();

        // Same inputs should produce same verifier
        assert_eq!(v1, v2);

        // Different password should produce different verifier
        let v3 = create_verifier(b"alice", b"different", &salt, SrpGroup::Srp2048).unwrap();
        assert_ne!(v1, v3);
    }

    #[test]
    fn test_invalid_inputs() {
        let salt = vec![1, 2, 3, 4];

        assert_eq!(
            create_verifier(b"", b"password", &salt, SrpGroup::Srp2048).unwrap_err(),
            SrpError::InvalidUsername
        );

        assert_eq!(
            create_verifier(b"alice", b"", &salt, SrpGroup::Srp2048).unwrap_err(),
            SrpError::InvalidPassword
        );

        assert_eq!(
            create_verifier(b"alice", b"password", &[], SrpGroup::Srp2048).unwrap_err(),
            SrpError::InvalidSalt
        );
    }

    #[test]
    fn test_register_with_different_hash_functions() {
        let mut rng = thread_rng();

        // Test with SHA-256 (default)
        let reg_sha256 =
            register_user(b"alice", b"password123", SrpGroup::Srp2048, &mut rng).unwrap();
        assert_eq!(reg_sha256.salt.len(), 16);
        assert_eq!(reg_sha256.verifier.len(), 256);

        // Test with SHA-512
        let reg_sha512 = register_user_with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            &mut rng,
            SrpHashFunction::Sha512,
        )
        .unwrap();
        assert_eq!(reg_sha512.salt.len(), 16);
        assert_eq!(reg_sha512.verifier.len(), 256);

        // Test with SHA-1 (legacy)
        let reg_sha1 = register_user_with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            &mut rng,
            SrpHashFunction::Sha1,
        )
        .unwrap();
        assert_eq!(reg_sha1.salt.len(), 16);
        assert_eq!(reg_sha1.verifier.len(), 256);

        // Different hash functions produce different verifiers (with same salt)
        let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let v1 = create_verifier_with_hash(
            b"alice",
            b"password",
            &salt,
            SrpGroup::Srp2048,
            SrpHashFunction::Sha256,
        )
        .unwrap();
        let v512 = create_verifier_with_hash(
            b"alice",
            b"password",
            &salt,
            SrpGroup::Srp2048,
            SrpHashFunction::Sha512,
        )
        .unwrap();
        let v_sha1 = create_verifier_with_hash(
            b"alice",
            b"password",
            &salt,
            SrpGroup::Srp2048,
            SrpHashFunction::Sha1,
        )
        .unwrap();

        assert_ne!(v1, v512);
        assert_ne!(v1, v_sha1);
        assert_ne!(v512, v_sha1);
    }
}
