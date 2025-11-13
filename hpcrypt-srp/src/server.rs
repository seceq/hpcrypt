//! SRP server implementation

use crate::error::{Result, SrpError};
use crate::groups::SrpGroup;
use crate::utils::{compute_k, compute_k_from_s, compute_m1, compute_m2, compute_u, pad};
use crate::SrpHashFunction;
use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::Zero;
use zeroize::Zeroize;

/// SRP server state during authentication
#[derive(Clone)]
enum ServerState {
    /// Initial state, ready to generate public key
    Initial,
    /// Public key generated, waiting for client response
    AwaitingClient { b: BigUint, b_pub: BigUint },
    /// Client response received, ready to verify proof
    ReadyForVerification {
        #[allow(dead_code)] // Retained for state completeness
        b: BigUint,
        b_pub: BigUint,
        a_pub: BigUint,
        #[allow(dead_code)] // Retained for state completeness
        shared_secret: BigUint,
        session_key: Vec<u8>,
    },
    /// Authentication complete
    Authenticated {
        a_pub: BigUint,
        session_key: Vec<u8>,
        m1: Vec<u8>,
    },
}

/// SRP server for authentication
pub struct SrpServer {
    verifier: Vec<u8>,
    salt: Vec<u8>,
    username: Vec<u8>,
    group: SrpGroup,
    hash_fn: SrpHashFunction,
    state: ServerState,
}

impl SrpServer {
    /// Create a new SRP server with SHA-256 (recommended)
    ///
    /// # Parameters
    /// - `verifier`: Password verifier from registration
    /// - `salt`: Salt from registration
    /// - `username`: Username for this authentication session
    /// - `group`: SRP group parameters (must match client's group)
    ///
    /// # Note
    /// Uses SHA-256 by default (secure and AWS Cognito compatible).
    /// For SHA-1 (RFC 5054) or SHA-512, use `with_hash()`.
    pub fn new(verifier: &[u8], salt: &[u8], username: &[u8], group: SrpGroup) -> Self {
        Self::with_hash(verifier, salt, username, group, SrpHashFunction::default())
    }

    /// Create a new SRP server with specific hash function
    ///
    /// # Parameters
    /// - `verifier`: Password verifier from registration
    /// - `salt`: Salt from registration
    /// - `username`: Username for this authentication session
    /// - `group`: SRP group parameters (must match client's group)
    /// - `hash_fn`: Hash function (SHA-1, SHA-256, or SHA-512)
    ///
    /// # Examples
    /// ```
    /// use hpcrypt_srp::{SrpServer, SrpGroup, SrpHashFunction};
    ///
    /// # let verifier = vec![1u8; 256];
    /// # let salt = vec![2u8; 16];
    /// // Modern secure server (SHA-256)
    /// let server = SrpServer::with_hash(
    ///     &verifier,
    ///     &salt,
    ///     b"alice",
    ///     SrpGroup::Srp2048,
    ///     SrpHashFunction::Sha256
    /// );
    ///
    /// // Legacy RFC 5054 server (SHA-1)
    /// let legacy_server = SrpServer::with_hash(
    ///     &verifier,
    ///     &salt,
    ///     b"alice",
    ///     SrpGroup::Srp2048,
    ///     SrpHashFunction::Sha1
    /// );
    /// ```
    pub fn with_hash(
        verifier: &[u8],
        salt: &[u8],
        username: &[u8],
        group: SrpGroup,
        hash_fn: SrpHashFunction,
    ) -> Self {
        Self {
            verifier: verifier.to_vec(),
            salt: salt.to_vec(),
            username: username.to_vec(),
            group,
            hash_fn,
            state: ServerState::Initial,
        }
    }

    /// Generate server public key B = k*v + g^b % N
    ///
    /// Returns the public key to send to the client
    pub fn compute_public<R: rand::Rng>(&mut self, rng: &mut R) -> Result<Vec<u8>> {
        if !matches!(self.state, ServerState::Initial) {
            return Err(SrpError::InvalidState);
        }

        let n = self.group.n();
        let g = self.group.g();
        let byte_len = self.group.byte_length();

        // Parse verifier
        let v = BigUint::from_bytes_be(&self.verifier);
        if v.is_zero() || v >= n {
            return Err(SrpError::InvalidVerifier);
        }

        // Compute k = H(N | PAD(g)) for SRP-6a
        let k = compute_k(&n, &g, byte_len, self.hash_fn);

        // Generate random private key b (at least 256 bits)
        let mut b_bytes = vec![0u8; byte_len];
        rng.fill_bytes(&mut b_bytes);
        let b = BigUint::from_bytes_be(&b_bytes);

        // Compute B = k*v + g^b % N
        let gb = g.modpow(&b, &n);
        let kv = (&k * &v) % &n;
        let b_pub = (&kv + &gb) % &n;

        if b_pub.is_zero() || &b_pub % &n == BigUint::zero() {
            return Err(SrpError::ComputationError);
        }

        let b_pub_bytes = pad(&b_pub, byte_len);

        self.state = ServerState::AwaitingClient {
            b,
            b_pub: b_pub.clone(),
        };

        Ok(b_pub_bytes)
    }

    /// Get salt to send to client
    pub fn get_salt(&self) -> &[u8] {
        &self.salt
    }

    /// Process client's public key A
    ///
    /// # Parameters
    /// - `a_pub_bytes`: Client's public key A
    pub fn process_client_public(&mut self, a_pub_bytes: &[u8]) -> Result<()> {
        let (b, b_pub) = match &self.state {
            ServerState::AwaitingClient { b, b_pub } => (b.clone(), b_pub.clone()),
            _ => return Err(SrpError::InvalidState),
        };

        let n = self.group.n();
        let byte_len = self.group.byte_length();

        // Parse A
        let a_pub = BigUint::from_bytes_be(a_pub_bytes);

        // Validate A % N != 0 (RFC 5054 security requirement)
        if a_pub.is_zero() || &a_pub % &n == BigUint::zero() {
            return Err(SrpError::InvalidPublicKey);
        }

        // Parse verifier
        let v = BigUint::from_bytes_be(&self.verifier);

        // Compute u = H(PAD(A) | PAD(B))
        let u = compute_u(&a_pub, &b_pub, byte_len, self.hash_fn);

        // Compute shared secret S = (A * v^u)^b % N
        let vu = v.modpow(&u, &n);
        let base = (&a_pub * &vu) % &n;
        let shared_secret = base.modpow(&b, &n);

        if shared_secret.is_zero() {
            return Err(SrpError::ComputationError);
        }

        // Derive session key K = H(S)
        let session_key = compute_k_from_s(&shared_secret, byte_len, self.hash_fn);

        self.state = ServerState::ReadyForVerification {
            b,
            b_pub,
            a_pub,
            shared_secret,
            session_key,
        };

        Ok(())
    }

    /// Verify client's proof M1
    ///
    /// Returns Ok(()) if proof is valid
    pub fn verify_client_proof(&mut self, m1_received: &[u8]) -> Result<()> {
        let (a_pub, b_pub, session_key) = match &self.state {
            ServerState::ReadyForVerification {
                a_pub,
                b_pub,
                session_key,
                ..
            } => (a_pub.clone(), b_pub.clone(), session_key.clone()),
            _ => return Err(SrpError::InvalidState),
        };

        let n = self.group.n();
        let g = self.group.g();
        let byte_len = self.group.byte_length();

        // Compute expected M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
        let m1_expected = compute_m1(
            &n,
            &g,
            &self.username,
            &self.salt,
            &a_pub,
            &b_pub,
            &session_key,
            byte_len,
            self.hash_fn,
        );

        // Constant-time comparison
        if subtle::ConstantTimeEq::ct_eq(&m1_expected[..], m1_received).into() {
            self.state = ServerState::Authenticated {
                a_pub,
                session_key,
                m1: m1_received.to_vec(),
            };
            Ok(())
        } else {
            Err(SrpError::ProofVerificationFailed)
        }
    }

    /// Compute server proof M2 to send to client
    ///
    /// Must be called after verify_client_proof succeeds
    pub fn compute_proof(&self) -> Result<Vec<u8>> {
        let (a_pub, session_key, m1) = match &self.state {
            ServerState::Authenticated {
                a_pub,
                session_key,
                m1,
            } => (a_pub, session_key, m1),
            _ => return Err(SrpError::InvalidState),
        };

        let byte_len = self.group.byte_length();

        // Compute M2 = H(A | M1 | K)
        let m2 = compute_m2(a_pub, m1, session_key, byte_len, self.hash_fn);

        Ok(m2)
    }

    /// Get the session key after successful authentication
    pub fn get_session_key(&self) -> Result<Vec<u8>> {
        match &self.state {
            ServerState::Authenticated { session_key, .. } => Ok(session_key.clone()),
            _ => Err(SrpError::SessionKeyNotAvailable),
        }
    }
}

impl Drop for SrpServer {
    fn drop(&mut self) {
        // Zeroize sensitive data
        self.verifier.zeroize();
        self.salt.zeroize();
        self.username.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_server_state_machine() {
        let mut rng = thread_rng();

        // Create dummy verifier
        let verifier = vec![1u8; 256];
        let salt = vec![2u8; 16];

        let mut server = SrpServer::new(&verifier, &salt, b"alice", SrpGroup::Srp2048);

        // Should be able to compute public key
        let b_pub = server.compute_public(&mut rng).unwrap();
        assert_eq!(b_pub.len(), 256);

        // Can't compute public key twice
        assert!(server.compute_public(&mut rng).is_err());
    }

    #[test]
    fn test_server_with_different_hash_functions() {
        let mut rng = thread_rng();
        let verifier = vec![1u8; 256];
        let salt = vec![2u8; 16];

        // Test with SHA-256 (default)
        let mut server_sha256 = SrpServer::new(&verifier, &salt, b"alice", SrpGroup::Srp2048);
        let b_pub_sha256 = server_sha256.compute_public(&mut rng).unwrap();
        assert_eq!(b_pub_sha256.len(), 256);

        // Test with SHA-512
        let mut server_sha512 = SrpServer::with_hash(
            &verifier,
            &salt,
            b"alice",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha512,
        );
        let b_pub_sha512 = server_sha512.compute_public(&mut rng).unwrap();
        assert_eq!(b_pub_sha512.len(), 256);

        // Test with SHA-1 (legacy)
        let mut server_sha1 = SrpServer::with_hash(
            &verifier,
            &salt,
            b"alice",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha1,
        );
        let b_pub_sha1 = server_sha1.compute_public(&mut rng).unwrap();
        assert_eq!(b_pub_sha1.len(), 256);
    }
}
