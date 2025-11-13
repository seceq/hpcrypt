//! SRP client implementation

use crate::error::{Result, SrpError};
use crate::groups::SrpGroup;
use crate::utils::{
    compute_k, compute_k_from_s, compute_m1, compute_m2, compute_u, compute_x, pad,
};
use crate::SrpHashFunction;
use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::Zero;
use zeroize::{Zeroize, Zeroizing};

/// SRP client state during authentication
#[derive(Clone)]
enum ClientState {
    /// Initial state, ready to generate public key
    Initial,
    /// Public key generated, waiting for server response
    AwaitingServer { a: BigUint, a_pub: BigUint },
    /// Server response received, ready to compute proof
    ReadyForProof {
        #[allow(dead_code)] // Retained for state completeness
        a: BigUint,
        a_pub: BigUint,
        b_pub: BigUint,
        salt: Vec<u8>,
        #[allow(dead_code)] // Retained for state completeness
        shared_secret: BigUint,
        session_key: Vec<u8>,
    },
    /// Proof sent, waiting for server verification
    AwaitingServerProof {
        a_pub: BigUint,
        #[allow(dead_code)] // Retained for state completeness
        b_pub: BigUint,
        #[allow(dead_code)] // Retained for state completeness
        salt: Vec<u8>,
        session_key: Vec<u8>,
        m1: Vec<u8>,
    },
    /// Authentication complete
    Authenticated { session_key: Vec<u8> },
}

/// SRP client for authentication
pub struct SrpClient {
    username: Vec<u8>,
    password: Zeroizing<Vec<u8>>,
    group: SrpGroup,
    hash_fn: SrpHashFunction,
    state: ClientState,
}

impl SrpClient {
    /// Create a new SRP client with SHA-256 (recommended)
    ///
    /// # Parameters
    /// - `username`: User identifier
    /// - `password`: User password (will be zeroized after authentication)
    /// - `group`: SRP group parameters (must match server's group)
    ///
    /// # Note
    /// Uses SHA-256 by default (secure and AWS Cognito compatible).
    /// For SHA-1 (RFC 5054) or SHA-512, use `with_hash()`.
    pub fn new(username: &[u8], password: &[u8], group: SrpGroup) -> Self {
        Self::with_hash(username, password, group, SrpHashFunction::default())
    }

    /// Create a new SRP client with specific hash function
    ///
    /// # Parameters
    /// - `username`: User identifier
    /// - `password`: User password (will be zeroized after authentication)
    /// - `group`: SRP group parameters (must match server's group)
    /// - `hash_fn`: Hash function (SHA-1, SHA-256, or SHA-512)
    ///
    /// # Examples
    /// ```
    /// use hpcrypt_srp::{SrpClient, SrpGroup, SrpHashFunction};
    ///
    /// // Modern secure client (SHA-256)
    /// let client = SrpClient::with_hash(
    ///     b"alice",
    ///     b"password",
    ///     SrpGroup::Srp2048,
    ///     SrpHashFunction::Sha256
    /// );
    ///
    /// // Legacy RFC 5054 client (SHA-1)
    /// let legacy_client = SrpClient::with_hash(
    ///     b"alice",
    ///     b"password",
    ///     SrpGroup::Srp2048,
    ///     SrpHashFunction::Sha1
    /// );
    /// ```
    pub fn with_hash(
        username: &[u8],
        password: &[u8],
        group: SrpGroup,
        hash_fn: SrpHashFunction,
    ) -> Self {
        Self {
            username: username.to_vec(),
            password: Zeroizing::new(password.to_vec()),
            group,
            hash_fn,
            state: ClientState::Initial,
        }
    }

    /// Generate client public key A = g^a % N
    ///
    /// Returns the public key to send to the server
    pub fn compute_public<R: rand::Rng>(&mut self, rng: &mut R) -> Result<Vec<u8>> {
        if !matches!(self.state, ClientState::Initial) {
            return Err(SrpError::InvalidState);
        }

        let n = self.group.n();
        let g = self.group.g();

        // Generate random private key a (at least 256 bits)
        let byte_len = self.group.byte_length();
        let mut a_bytes = vec![0u8; byte_len];
        rng.fill_bytes(&mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);

        // Compute A = g^a % N
        let a_pub = g.modpow(&a, &n);

        if a_pub.is_zero() || &a_pub % &n == BigUint::zero() {
            return Err(SrpError::ComputationError);
        }

        let a_pub_bytes = pad(&a_pub, byte_len);

        self.state = ClientState::AwaitingServer {
            a: a.clone(),
            a_pub: a_pub.clone(),
        };

        Ok(a_pub_bytes)
    }

    /// Process server's public key B and salt
    ///
    /// # Parameters
    /// - `b_pub_bytes`: Server's public key B
    /// - `salt`: Salt from user registration
    pub fn process_server_response(&mut self, b_pub_bytes: &[u8], salt: &[u8]) -> Result<()> {
        let (a, a_pub) = match &self.state {
            ClientState::AwaitingServer { a, a_pub } => (a.clone(), a_pub.clone()),
            _ => return Err(SrpError::InvalidState),
        };

        let n = self.group.n();
        let g = self.group.g();
        let byte_len = self.group.byte_length();

        // Parse B
        let b_pub = BigUint::from_bytes_be(b_pub_bytes);

        // Validate B % N != 0 (RFC 5054 security requirement)
        if b_pub.is_zero() || &b_pub % &n == BigUint::zero() {
            return Err(SrpError::InvalidPublicKey);
        }

        // Compute u = H(PAD(A) | PAD(B))
        let u = compute_u(&a_pub, &b_pub, byte_len, self.hash_fn);

        // Compute k = H(N | PAD(g)) for SRP-6a
        let k = compute_k(&n, &g, byte_len, self.hash_fn);

        // Compute x = H(s | H(I | ":" | P))
        let x = compute_x(&self.username, &self.password, salt, self.hash_fn);

        // Compute shared secret S = (B - k*g^x)^(a + u*x) % N
        // First: k*g^x % N
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;

        // Second: B - k*g^x (mod N)
        let base = if b_pub >= kgx {
            (&b_pub - &kgx) % &n
        } else {
            // Handle negative case: (B + N - kgx) % N
            (&b_pub + &n - &kgx) % &n
        };

        // Third: a + u*x
        let exp = &a + (&u * &x);

        // Finally: S = base^exp % N
        let shared_secret = base.modpow(&exp, &n);

        if shared_secret.is_zero() {
            return Err(SrpError::ComputationError);
        }

        // Derive session key K = H(S)
        let session_key = compute_k_from_s(&shared_secret, byte_len, self.hash_fn);

        self.state = ClientState::ReadyForProof {
            a,
            a_pub,
            b_pub,
            salt: salt.to_vec(),
            shared_secret,
            session_key,
        };

        Ok(())
    }

    /// Compute client proof M1 to send to server
    pub fn compute_proof(&mut self) -> Result<Vec<u8>> {
        let (a_pub, b_pub, salt, session_key) = match &self.state {
            ClientState::ReadyForProof {
                a_pub,
                b_pub,
                salt,
                session_key,
                ..
            } => (
                a_pub.clone(),
                b_pub.clone(),
                salt.clone(),
                session_key.clone(),
            ),
            _ => return Err(SrpError::InvalidState),
        };

        let n = self.group.n();
        let g = self.group.g();
        let byte_len = self.group.byte_length();

        // Compute M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
        let m1 = compute_m1(
            &n,
            &g,
            &self.username,
            &salt,
            &a_pub,
            &b_pub,
            &session_key,
            byte_len,
            self.hash_fn,
        );

        self.state = ClientState::AwaitingServerProof {
            a_pub,
            b_pub,
            salt,
            session_key,
            m1: m1.clone(),
        };

        Ok(m1)
    }

    /// Verify server's proof M2
    pub fn verify_server_proof(&mut self, m2_received: &[u8]) -> Result<()> {
        let (a_pub, session_key, m1) = match &self.state {
            ClientState::AwaitingServerProof {
                a_pub,
                session_key,
                m1,
                ..
            } => (a_pub.clone(), session_key.clone(), m1.clone()),
            _ => return Err(SrpError::InvalidState),
        };

        let byte_len = self.group.byte_length();

        // Compute expected M2 = H(A | M1 | K)
        let m2_expected = compute_m2(&a_pub, &m1, &session_key, byte_len, self.hash_fn);

        // Constant-time comparison
        if subtle::ConstantTimeEq::ct_eq(&m2_expected[..], m2_received).into() {
            self.state = ClientState::Authenticated { session_key };
            Ok(())
        } else {
            Err(SrpError::ProofVerificationFailed)
        }
    }

    /// Get the session key after successful authentication
    pub fn get_session_key(&self) -> Result<Vec<u8>> {
        match &self.state {
            ClientState::Authenticated { session_key } => Ok(session_key.clone()),
            _ => Err(SrpError::SessionKeyNotAvailable),
        }
    }
}

impl Drop for SrpClient {
    fn drop(&mut self) {
        // Zeroize sensitive data
        self.username.zeroize();
        // password is already Zeroizing<Vec<u8>>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_client_state_machine() {
        let mut rng = thread_rng();
        let mut client = SrpClient::new(b"alice", b"password123", SrpGroup::Srp2048);

        // Should be able to compute public key
        let a_pub = client.compute_public(&mut rng).unwrap();
        assert_eq!(a_pub.len(), 256);

        // Can't compute public key twice
        assert!(client.compute_public(&mut rng).is_err());
    }

    #[test]
    fn test_client_with_different_hash_functions() {
        let mut rng = thread_rng();

        // Test with SHA-256 (default)
        let mut client_sha256 = SrpClient::new(b"alice", b"password123", SrpGroup::Srp2048);
        let a_pub_sha256 = client_sha256.compute_public(&mut rng).unwrap();
        assert_eq!(a_pub_sha256.len(), 256);

        // Test with SHA-512
        let mut client_sha512 = SrpClient::with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha512,
        );
        let a_pub_sha512 = client_sha512.compute_public(&mut rng).unwrap();
        assert_eq!(a_pub_sha512.len(), 256);

        // Test with SHA-1 (legacy)
        let mut client_sha1 = SrpClient::with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha1,
        );
        let a_pub_sha1 = client_sha1.compute_public(&mut rng).unwrap();
        assert_eq!(a_pub_sha1.len(), 256);
    }
}
