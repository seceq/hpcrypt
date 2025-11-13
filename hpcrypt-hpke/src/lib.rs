//! # HPCrypt-HPKE: Hybrid Public Key Encryption (RFC 9180)
//!
//! This crate implements HPKE (Hybrid Public Key Encryption)
//! as specified in [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
//!
//! HPKE combines asymmetric and symmetric cryptography to provide efficient authenticated
//! encryption with support for multiple modes:
//! - **Base mode**: Standard public key encryption
//! - **PSK mode**: Pre-shared key authentication
//! - **Auth mode**: Sender authentication via public key
//! - **AuthPSK mode**: Combined PSK and sender authentication
//!
//! ## Features
//!
//! - RFC 9180 Compliant - Full implementation of the standard
//! - Four Modes - Base, PSK, Auth, AuthPSK
//! - Multiple Cipher Suites - P-256, P-384, P-521, X25519 (KEM)
//! - Multiple AEADs - AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//! - Stateful Encryption - Automatic nonce management
//! - Export Secrets - Derive application-specific secrets
//! - no_std Compatible - Works in embedded environments
//!
//! ## Quick Start
//!
//! ```rust
//! use hpcrypt_hpke::{HpkeP256, Result};
//! use rand::thread_rng;
//!
//! fn main() -> Result<()> {
//!     let mut rng = thread_rng();
//!     let hpke = HpkeP256::new();
//!
//!     // Generate recipient keypair
//!     let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng)?;
//!
//!     let info = b"application context";
//!     let aad = b"associated data";
//!     let plaintext = b"secret message";
//!
//!     // Sender: setup and encrypt
//!     let (enc, mut sender_ctx) = hpke.setup_base_sender(&pk_r, info, &mut rng)?;
//!     let ciphertext = sender_ctx.seal(aad, plaintext)?;
//!
//!     // Recipient: setup and decrypt
//!     let mut recipient_ctx = hpke.setup_base_recipient(&enc, &sk_r, info)?;
//!     let decrypted = recipient_ctx.open(aad, &ciphertext)?;
//!
//!     assert_eq!(decrypted, plaintext);
//!     Ok(())
//! }
//! ```
//!
//! ## Modes
//!
//! ### Base Mode
//!
//! Standard public key encryption with no sender authentication:
//!
//! ```rust
//! # use hpcrypt_hpke::{HpkeP256, Result};
//! # use rand::thread_rng;
//! # fn example() -> Result<()> {
//! # let mut rng = thread_rng();
//! # let hpke = HpkeP256::new();
//! # let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng)?;
//! let (enc, mut ctx) = hpke.setup_base_sender(&pk_r, b"info", &mut rng)?;
//! let ct = ctx.seal(b"aad", b"message")?;
//! # Ok(())
//! # }
//! ```
//!
//! ### PSK Mode
//!
//! Pre-shared key provides sender authentication:
//!
//! ```rust
//! # use hpcrypt_hpke::{HpkeP256, Result};
//! # use rand::thread_rng;
//! # fn example() -> Result<()> {
//! # let mut rng = thread_rng();
//! # let hpke = HpkeP256::new();
//! # let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng)?;
//! let psk = b"pre-shared-secret-key-32-bytes!";
//! let psk_id = b"key-identifier";
//!
//! let (enc, mut ctx) = hpke.setup_psk_sender(
//!     &pk_r, b"info", psk, psk_id, &mut rng
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Auth Mode
//!
//! Sender proves possession of their private key:
//!
//! ```rust
//! # use hpcrypt_hpke::{HpkeP256, Result};
//! # use rand::thread_rng;
//! # fn example() -> Result<()> {
//! # let mut rng = thread_rng();
//! # let hpke = HpkeP256::new();
//! # let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng)?;
//! # let (sk_s, pk_s) = HpkeP256::generate_keypair(&mut rng)?;
//! let (enc, mut ctx) = hpke.setup_auth_sender(
//!     &pk_r, b"info", &sk_s, &mut rng
//! )?;
//!
//! // Recipient verifies sender's identity with pk_s
//! let mut recipient_ctx = hpke.setup_auth_recipient(
//!     &enc, &sk_r, b"info", &pk_s
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ### AuthPSK Mode
//!
//! Combines both PSK and sender authentication:
//!
//! ```rust
//! # use hpcrypt_hpke::{HpkeP256, Result};
//! # use rand::thread_rng;
//! # fn example() -> Result<()> {
//! # let mut rng = thread_rng();
//! # let hpke = HpkeP256::new();
//! # let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng)?;
//! # let (sk_s, pk_s) = HpkeP256::generate_keypair(&mut rng)?;
//! let psk = b"pre-shared-secret-key-32-bytes!";
//! let psk_id = b"key-identifier";
//!
//! let (enc, mut ctx) = hpke.setup_auth_psk_sender(
//!     &pk_r, b"info", psk, psk_id, &sk_s, &mut rng
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Cipher Suites
//!
//! ### P-256 (default)
//!
//! ```rust
//! use hpcrypt_hpke::HpkeP256;
//!
//! let hpke = HpkeP256::new();              // AES-128-GCM
//! let hpke = HpkeP256::with_aes256();      // AES-256-GCM
//! let hpke = HpkeP256::with_chacha();      // ChaCha20-Poly1305
//! ```
//!
//! ## Security Considerations
//!
//! - **Nonce Management**: HPKE automatically manages nonces using a sequence counter
//! - **Forward Secrecy**: Each encryption uses ephemeral keys
//! - **Authenticated Encryption**: All modes provide confidentiality and integrity
//! - **Message Limit**: Contexts track sequence numbers and prevent overflow
//! - **Export Secrets**: Can derive application-specific secrets from HPKE context
//!
//! ## Standards Compliance
//!
//! - [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) - HPKE specification
//! - Supports all mandatory cipher suites
//! - Implements all four modes (Base, PSK, Auth, AuthPSK)

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod context;
pub mod error;
pub mod hpke;
pub mod kem;

pub use context::{AeadId, CipherSuite, HpkeContext, KdfId, Mode};
pub use error::{HpkeError, Result};
pub use hpke::HpkeP256;
pub use kem::{DhkemP256, Kem, KemId};
