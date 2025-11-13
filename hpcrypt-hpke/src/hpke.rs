//! HPKE (Hybrid Public Key Encryption) implementation - RFC 9180
//!
//! This module provides the main HPKE API with support for all four modes:
//! - Base mode
//! - PSK mode
//! - Auth mode
//! - AuthPSK mode

use crate::context::{AeadId, CipherSuite, HpkeContext, KdfId, Mode};
use crate::error::{HpkeError, Result};
use crate::kem::{DhkemP256, Kem, KemId};
use alloc::vec::Vec;

/// HPKE for P-256 with default cipher suite
pub struct HpkeP256 {
    suite: CipherSuite,
}

impl HpkeP256 {
    /// Create a new HPKE instance with AES-128-GCM
    pub fn new() -> Self {
        Self {
            suite: CipherSuite {
                kem: KemId::DhkemP256HkdfSha256,
                kdf: KdfId::HkdfSha256,
                aead: AeadId::Aes128Gcm,
            },
        }
    }

    /// Create with AES-256-GCM
    pub fn with_aes256() -> Self {
        Self {
            suite: CipherSuite {
                kem: KemId::DhkemP256HkdfSha256,
                kdf: KdfId::HkdfSha256,
                aead: AeadId::Aes256Gcm,
            },
        }
    }

    /// Create with ChaCha20-Poly1305
    pub fn with_chacha() -> Self {
        Self {
            suite: CipherSuite {
                kem: KemId::DhkemP256HkdfSha256,
                kdf: KdfId::HkdfSha256,
                aead: AeadId::ChaCha20Poly1305,
            },
        }
    }

    /// Generate a keypair for HPKE
    pub fn generate_keypair<R: rand::Rng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        DhkemP256::generate_keypair(rng)
    }

    // ========== BASE MODE ==========

    /// Setup sender context in base mode
    ///
    /// Returns (encapsulated_key, sender_context)
    pub fn setup_base_sender<R: rand::Rng>(
        &self,
        pk_r: &[u8],
        info: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContext)> {
        // Encapsulate to get shared secret
        let (shared_secret, enc) = DhkemP256::encap(pk_r, rng)?;

        // Create context with no PSK
        let context = HpkeContext::new(
            self.suite,
            &shared_secret,
            info,
            &[], // no PSK
            &[], // no PSK ID
            Mode::Base,
        )?;

        Ok((enc, context))
    }

    /// Setup recipient context in base mode
    pub fn setup_base_recipient(
        &self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
    ) -> Result<HpkeContext> {
        // Decapsulate to get shared secret
        let shared_secret = DhkemP256::decap(enc, sk_r)?;

        // Create context with no PSK
        HpkeContext::new(
            self.suite,
            &shared_secret,
            info,
            &[], // no PSK
            &[], // no PSK ID
            Mode::Base,
        )
    }

    // ========== PSK MODE ==========

    /// Setup sender context in PSK mode
    ///
    /// Returns (encapsulated_key, sender_context)
    pub fn setup_psk_sender<R: rand::Rng>(
        &self,
        pk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContext)> {
        if psk.is_empty() {
            return Err(HpkeError::InvalidPsk);
        }

        // Encapsulate to get shared secret
        let (shared_secret, enc) = DhkemP256::encap(pk_r, rng)?;

        // Create context with PSK
        let context = HpkeContext::new(self.suite, &shared_secret, info, psk, psk_id, Mode::Psk)?;

        Ok((enc, context))
    }

    /// Setup recipient context in PSK mode
    pub fn setup_psk_recipient(
        &self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeContext> {
        if psk.is_empty() {
            return Err(HpkeError::InvalidPsk);
        }

        // Decapsulate to get shared secret
        let shared_secret = DhkemP256::decap(enc, sk_r)?;

        // Create context with PSK
        HpkeContext::new(self.suite, &shared_secret, info, psk, psk_id, Mode::Psk)
    }

    // ========== AUTH MODE ==========

    /// Setup sender context in Auth mode
    ///
    /// Returns (encapsulated_key, sender_context)
    pub fn setup_auth_sender<R: rand::Rng>(
        &self,
        pk_r: &[u8],
        info: &[u8],
        sk_s: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContext)> {
        // Authenticated encapsulate
        let (shared_secret, enc) = DhkemP256::auth_encap(pk_r, sk_s, rng)?;

        // Create context with no PSK
        let context = HpkeContext::new(
            self.suite,
            &shared_secret,
            info,
            &[], // no PSK
            &[], // no PSK ID
            Mode::Auth,
        )?;

        Ok((enc, context))
    }

    /// Setup recipient context in Auth mode
    pub fn setup_auth_recipient(
        &self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        pk_s: &[u8],
    ) -> Result<HpkeContext> {
        // Authenticated decapsulate
        let shared_secret = DhkemP256::auth_decap(enc, sk_r, pk_s)?;

        // Create context with no PSK
        HpkeContext::new(
            self.suite,
            &shared_secret,
            info,
            &[], // no PSK
            &[], // no PSK ID
            Mode::Auth,
        )
    }

    // ========== AUTH-PSK MODE ==========

    /// Setup sender context in AuthPSK mode
    ///
    /// Returns (encapsulated_key, sender_context)
    pub fn setup_auth_psk_sender<R: rand::Rng>(
        &self,
        pk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sk_s: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, HpkeContext)> {
        if psk.is_empty() {
            return Err(HpkeError::InvalidPsk);
        }

        // Authenticated encapsulate
        let (shared_secret, enc) = DhkemP256::auth_encap(pk_r, sk_s, rng)?;

        // Create context with PSK
        let context =
            HpkeContext::new(self.suite, &shared_secret, info, psk, psk_id, Mode::AuthPsk)?;

        Ok((enc, context))
    }

    /// Setup recipient context in AuthPSK mode
    pub fn setup_auth_psk_recipient(
        &self,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pk_s: &[u8],
    ) -> Result<HpkeContext> {
        if psk.is_empty() {
            return Err(HpkeError::InvalidPsk);
        }

        // Authenticated decapsulate
        let shared_secret = DhkemP256::auth_decap(enc, sk_r, pk_s)?;

        // Create context with PSK
        HpkeContext::new(self.suite, &shared_secret, info, psk, psk_id, Mode::AuthPsk)
    }

    // ========== SINGLE-SHOT API ==========

    /// Single-shot encryption in base mode
    pub fn seal_base<R: rand::Rng>(
        &self,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let (enc, mut context) = self.setup_base_sender(pk_r, info, rng)?;
        let ciphertext = context.seal(aad, plaintext)?;

        // Return enc || ciphertext
        let mut output = enc;
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Single-shot decryption in base mode
    pub fn open_base(
        &self,
        enc_and_ciphertext: &[u8],
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let nenc = self.suite.kem.nenc();
        if enc_and_ciphertext.len() < nenc {
            return Err(HpkeError::InvalidCiphertext);
        }

        let enc = &enc_and_ciphertext[..nenc];
        let ciphertext = &enc_and_ciphertext[nenc..];

        let mut context = self.setup_base_recipient(enc, sk_r, info)?;
        context.open(aad, ciphertext)
    }
}

impl Default for HpkeP256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_hpke_base_mode() {
        let mut rng = thread_rng();
        let hpke = HpkeP256::new();

        // Generate recipient keypair
        let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng).unwrap();

        let info = b"test info";
        let aad = b"associated data";
        let plaintext = b"secret message";

        // Sender setup
        let (enc, mut sender_ctx) = hpke.setup_base_sender(&pk_r, info, &mut rng).unwrap();

        // Encrypt
        let ciphertext = sender_ctx.seal(aad, plaintext).unwrap();

        // Recipient setup
        let mut recipient_ctx = hpke.setup_base_recipient(&enc, &sk_r, info).unwrap();

        // Decrypt
        let decrypted = recipient_ctx.open(aad, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_psk_mode() {
        let mut rng = thread_rng();
        let hpke = HpkeP256::new();

        // Generate recipient keypair
        let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng).unwrap();

        let info = b"test info";
        let aad = b"associated data";
        let plaintext = b"secret message";
        let psk = b"pre-shared-key-32-bytes-long!!!";
        let psk_id = b"psk-identifier";

        // Sender setup with PSK
        let (enc, mut sender_ctx) = hpke
            .setup_psk_sender(&pk_r, info, psk, psk_id, &mut rng)
            .unwrap();

        // Encrypt
        let ciphertext = sender_ctx.seal(aad, plaintext).unwrap();

        // Recipient setup with PSK
        let mut recipient_ctx = hpke
            .setup_psk_recipient(&enc, &sk_r, info, psk, psk_id)
            .unwrap();

        // Decrypt
        let decrypted = recipient_ctx.open(aad, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_auth_mode() {
        let mut rng = thread_rng();
        let hpke = HpkeP256::new();

        // Generate keypairs
        let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng).unwrap();
        let (sk_s, pk_s) = HpkeP256::generate_keypair(&mut rng).unwrap();

        let info = b"test info";
        let aad = b"associated data";
        let plaintext = b"secret message";

        // Sender setup with authentication
        let (enc, mut sender_ctx) = hpke
            .setup_auth_sender(&pk_r, info, &sk_s, &mut rng)
            .unwrap();

        // Encrypt
        let ciphertext = sender_ctx.seal(aad, plaintext).unwrap();

        // Recipient setup with sender's public key
        let mut recipient_ctx = hpke.setup_auth_recipient(&enc, &sk_r, info, &pk_s).unwrap();

        // Decrypt
        let decrypted = recipient_ctx.open(aad, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_auth_psk_mode() {
        let mut rng = thread_rng();
        let hpke = HpkeP256::new();

        // Generate keypairs
        let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng).unwrap();
        let (sk_s, pk_s) = HpkeP256::generate_keypair(&mut rng).unwrap();

        let info = b"test info";
        let aad = b"associated data";
        let plaintext = b"secret message";
        let psk = b"pre-shared-key-32-bytes-long!!!";
        let psk_id = b"psk-identifier";

        // Sender setup with both Auth and PSK
        let (enc, mut sender_ctx) = hpke
            .setup_auth_psk_sender(&pk_r, info, psk, psk_id, &sk_s, &mut rng)
            .unwrap();

        // Encrypt
        let ciphertext = sender_ctx.seal(aad, plaintext).unwrap();

        // Recipient setup with both Auth and PSK
        let mut recipient_ctx = hpke
            .setup_auth_psk_recipient(&enc, &sk_r, info, psk, psk_id, &pk_s)
            .unwrap();

        // Decrypt
        let decrypted = recipient_ctx.open(aad, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_single_shot() {
        let mut rng = thread_rng();
        let hpke = HpkeP256::new();

        let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng).unwrap();

        let info = b"app context";
        let aad = b"metadata";
        let plaintext = b"confidential data";

        // Single-shot seal
        let enc_and_ct = hpke
            .seal_base(&pk_r, info, aad, plaintext, &mut rng)
            .unwrap();

        // Single-shot open
        let decrypted = hpke.open_base(&enc_and_ct, &sk_r, info, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multiple_messages() {
        let mut rng = thread_rng();
        let hpke = HpkeP256::new();

        let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng).unwrap();
        let info = b"session";

        // Setup contexts
        let (enc, mut sender_ctx) = hpke.setup_base_sender(&pk_r, info, &mut rng).unwrap();
        let mut recipient_ctx = hpke.setup_base_recipient(&enc, &sk_r, info).unwrap();

        // Send multiple messages
        for i in 0..5 {
            let msg = format!("Message {}", i);
            let ct = sender_ctx.seal(&[], msg.as_bytes()).unwrap();
            let pt = recipient_ctx.open(&[], &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_export_secret() {
        let mut rng = thread_rng();
        let hpke = HpkeP256::new();

        let (sk_r, pk_r) = HpkeP256::generate_keypair(&mut rng).unwrap();
        let info = b"session";

        // Setup contexts
        let (enc, sender_ctx) = hpke.setup_base_sender(&pk_r, info, &mut rng).unwrap();
        let recipient_ctx = hpke.setup_base_recipient(&enc, &sk_r, info).unwrap();

        // Export secrets
        let context = b"application-specific-context";
        let sender_export = sender_ctx.export(context, 32);
        let recipient_export = recipient_ctx.export(context, 32);

        // Both should derive the same secret
        assert_eq!(sender_export, recipient_export);
        assert_eq!(sender_export.len(), 32);
    }
}
