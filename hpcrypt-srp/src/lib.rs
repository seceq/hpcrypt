//! # hpcrypt-srp - Secure Remote Password (SRP-6a) Protocol
//!
//! This crate implements the SRP-6a protocol as specified in RFC 5054.
//! SRP is a password-authenticated key exchange (PAKE) protocol that allows
//! secure authentication without transmitting the password over the network.
//!
//! ## Features
//!
//! - **SRP-6a protocol** with k = SHA1(N | g) multiplier (improved security over SRP-6)
//! - **Multiple group sizes** from 1024-bit to 8192-bit safe primes (RFC 5054 Appendix A)
//! - **Constant-time verification** to prevent timing attacks
//! - **Zero-knowledge proof** - server never learns the password
//! - **Mutual authentication** - both client and server prove knowledge
//! - **no_std support** with optional `alloc` feature
//!
//! ## Security Properties
//!
//! - **Forward secrecy**: Ephemeral keys protect past sessions
//! - **Dictionary attack resistance**: Server stores verifier, not password
//! - **Two-for-one attack prevention**: SRP-6a multiplier k = H(N,g)
//! - **Zero-knowledge**: Server never sees plaintext password
//!
//! ## Protocol Flow
//!
//! ### 1. Registration (One-time setup)
//!
//! ```rust
//! use hpcrypt_srp::{register_user, SrpGroup};
//! use rand::thread_rng;
//!
//! // User registers with password
//! let registration = register_user(
//!     b"alice",
//!     b"password123",
//!     SrpGroup::Srp2048,
//!     &mut thread_rng()
//! ).unwrap();
//!
//! // Server stores: registration.salt, registration.verifier
//! // Never store the password itself!
//! ```
//!
//! ### 2. Authentication
//!
//! ```rust
//! use hpcrypt_srp::{SrpClient, SrpServer, SrpGroup};
//! use rand::thread_rng;
//! # use hpcrypt_srp::register_user;
//! # let registration = register_user(b"alice", b"password123", SrpGroup::Srp2048, &mut rand::thread_rng()).unwrap();
//!
//! let mut rng = thread_rng();
//!
//! // Client starts authentication
//! let mut client = SrpClient::new(b"alice", b"password123", SrpGroup::Srp2048);
//! let a_pub = client.compute_public(&mut rng).unwrap();
//!
//! // Server responds with B and salt
//! let mut server = SrpServer::new(
//!     &registration.verifier,
//!     &registration.salt,
//!     b"alice",
//!     SrpGroup::Srp2048
//! );
//! let b_pub = server.compute_public(&mut rng).unwrap();
//! let salt = server.get_salt();
//!
//! // Client processes server response and computes proof
//! client.process_server_response(&b_pub, salt).unwrap();
//! let m1 = client.compute_proof().unwrap();
//!
//! // Server verifies client proof and responds
//! server.process_client_public(&a_pub).unwrap();
//! server.verify_client_proof(&m1).unwrap();
//! let m2 = server.compute_proof().unwrap();
//!
//! // Client verifies server proof
//! client.verify_server_proof(&m2).unwrap();
//!
//! // Both parties now have the same session key
//! let client_key = client.get_session_key().unwrap();
//! let server_key = server.get_session_key().unwrap();
//! assert_eq!(client_key, server_key);
//! ```
//!
//! ## Group Selection
//!
//! The security level depends on the chosen group size:
//!
//! - **1024-bit**: Minimum acceptable, ~80-bit security
//! - **2048-bit**: Recommended for most applications, ~112-bit security
//! - **3072-bit**: High security, ~128-bit security
//! - **4096-bit** and larger: Maximum security for long-term protection
//!
//! ## RFC 5054 Compliance
//!
//! This implementation follows RFC 5054 specifications:
//!
//! - Uses SHA-1 for all hash operations (as specified in RFC 5054)
//! - Implements SRP-6a with k = SHA1(N | PAD(g))
//! - Includes all standard groups from RFC 5054 Appendix A
//! - Validates A % N != 0 and B % N != 0 (security requirement)
//! - Uses constant-time comparison for proof verification
//!
//! ## Security Considerations
//!
//! - **Never store passwords**: Always store salt and verifier
//! - **Use appropriate group size**: Minimum 2048-bit for new deployments
//! - **Protect verifiers**: Leaked verifier enables impersonation and offline attacks
//! - **Use strong passwords**: SRP doesn't prevent weak password choices
//! - **Rate limiting**: Implement authentication attempt limiting on server
//!
//! ## References
//!
//! - [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054) - Using SRP for TLS Authentication
//! - [RFC 2945](https://datatracker.ietf.org/doc/html/rfc2945) - SRP Authentication and Key Exchange System
//! - [SRP Homepage](http://srp.stanford.edu/) - Original SRP documentation

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod client;
mod error;
mod groups;
mod registration;
mod server;
mod utils;

pub use client::SrpClient;
pub use error::{Result, SrpError};
pub use groups::SrpGroup;
pub use registration::{create_verifier, create_verifier_with_hash, register_user, register_user_with_hash, SrpRegistration};
pub use server::SrpServer;

/// Hash function to use for SRP protocol
///
/// Different hash functions provide different security levels and compatibility:
///
/// - **Sha1**: RFC 5054 standard (legacy, not recommended for new deployments)
/// - **Sha256**: Modern standard, compatible with AWS Cognito and most systems
/// - **Sha512**: Highest security, recommended for new deployments
///
/// # Security Recommendation
///
/// ⚠️ **SHA-1 is cryptographically broken** (collision attacks since 2017).
/// Use **SHA-256** or **SHA-512** for new applications.
///
/// SHA-1 is provided only for:
/// - RFC 5054 compatibility
/// - Interoperability with legacy systems
/// - Testing against RFC 5054 test vectors
///
/// # Compatibility
///
/// - **AWS Cognito**: Uses SHA-256
/// - **Apple iCloud**: Likely SHA-256 or stronger
/// - **RFC 5054**: Specifies SHA-1 (legacy)
///
/// # Examples
///
/// ```rust
/// use hpcrypt_srp::SrpHashFunction;
///
/// // Recommended for new applications
/// let hash = SrpHashFunction::Sha256;
///
/// // Highest security
/// let hash = SrpHashFunction::Sha512;
///
/// // Legacy compatibility only
/// let hash = SrpHashFunction::Sha1; // ⚠️ Not recommended
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpHashFunction {
    /// SHA-1 (RFC 5054 standard)
    ///
    /// ⚠️ **WARNING**: SHA-1 is cryptographically broken. Use only for:
    /// - RFC 5054 compatibility
    /// - Legacy system interoperability
    ///
    /// **Not recommended for new deployments.**
    Sha1,

    /// SHA-256 (Modern standard)
    ///
    /// **Recommended** for most applications. Compatible with:
    /// - AWS Cognito
    /// - Modern SRP implementations
    /// - Provides 128-bit security
    Sha256,

    /// SHA-512 (Highest security)
    ///
    /// **Recommended** for high-security applications.
    /// - Provides 256-bit security
    /// - Best choice for long-term security
    Sha512,
}

impl Default for SrpHashFunction {
    /// Default hash function is SHA-256 (modern, secure, widely compatible)
    fn default() -> Self {
        Self::Sha256
    }
}

impl SrpHashFunction {
    /// Get the output size in bytes for this hash function
    pub const fn output_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Check if this hash function is considered secure
    ///
    /// SHA-1 is NOT considered secure due to collision attacks.
    pub const fn is_secure(&self) -> bool {
        !matches!(self, Self::Sha1)
    }

    /// Get a description of this hash function
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1 (legacy, not recommended)",
            Self::Sha256 => "SHA-256 (recommended)",
            Self::Sha512 => "SHA-512 (high security)",
        }
    }
}
