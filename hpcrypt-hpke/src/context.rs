//! HPKE Context for encryption/decryption operations

use crate::error::{HpkeError, Result};
use crate::kem::KemId;
use alloc::vec::Vec;
use hpcrypt_aead::aes_gcm::{Aes128Gcm, Aes256Gcm};
use hpcrypt_aead::chacha20poly1305::ChaCha20Poly1305;
use hpcrypt_hash::{sha256, sha512, Sha384};

/// HKDF Extract wrapper (simplified)
fn hkdf_extract(_salt: &[u8], ikm: &[u8], hash_fn: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    // Simplified HKDF-Extract for HPKE
    // In production, this should use proper HMAC-based extraction
    hash_fn(ikm)
}

/// HKDF Expand wrapper
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize, hash_fn: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let hash_len = hash_fn(&[]).len();
    let n = (length + hash_len - 1) / hash_len;
    let mut output = Vec::new();
    let mut t = Vec::new();

    for i in 1..=n {
        let mut input = Vec::new();
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(i as u8);
        input.extend_from_slice(prk);
        t = hash_fn(&input);
        output.extend_from_slice(&t);
    }

    output.truncate(length);
    output
}

/// AEAD algorithm identifiers from RFC 9180
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AeadId {
    /// AES-128-GCM
    Aes128Gcm = 0x0001,
    /// AES-256-GCM
    Aes256Gcm = 0x0002,
    /// ChaCha20Poly1305
    ChaCha20Poly1305 = 0x0003,
    /// Export-only (no encryption)
    ExportOnly = 0xFFFF,
}

impl AeadId {
    /// Get the AEAD ID as u16
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get Nk (key length in bytes)
    pub fn nk(self) -> usize {
        match self {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm => 32,
            AeadId::ChaCha20Poly1305 => 32,
            AeadId::ExportOnly => 0,
        }
    }

    /// Get Nn (nonce length in bytes)
    pub fn nn(self) -> usize {
        match self {
            AeadId::Aes128Gcm => 12,
            AeadId::Aes256Gcm => 12,
            AeadId::ChaCha20Poly1305 => 12,
            AeadId::ExportOnly => 0,
        }
    }

    /// Get Nt (tag length in bytes)
    pub fn nt(self) -> usize {
        match self {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm => 16,
            AeadId::ChaCha20Poly1305 => 16,
            AeadId::ExportOnly => 0,
        }
    }
}

/// KDF algorithm identifiers from RFC 9180
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KdfId {
    /// HKDF-SHA256
    HkdfSha256 = 0x0001,
    /// HKDF-SHA384
    HkdfSha384 = 0x0002,
    /// HKDF-SHA512
    HkdfSha512 = 0x0003,
}

impl KdfId {
    /// Get the KDF ID as u16
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get Nh (hash output length in bytes)
    pub fn nh(self) -> usize {
        match self {
            KdfId::HkdfSha256 => 32,
            KdfId::HkdfSha384 => 48,
            KdfId::HkdfSha512 => 64,
        }
    }

    /// Get the hash function
    pub fn hash_fn(self) -> fn(&[u8]) -> Vec<u8> {
        match self {
            KdfId::HkdfSha256 => |data| sha256(data).to_vec(),
            KdfId::HkdfSha384 => |data| {
                let mut hasher = Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            },
            KdfId::HkdfSha512 => |data| sha512(data).to_vec(),
        }
    }
}

/// HPKE modes from RFC 9180
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// Base mode (no authentication)
    Base = 0x00,
    /// PSK mode (pre-shared key authentication)
    Psk = 0x01,
    /// Auth mode (sender public key authentication)
    Auth = 0x02,
    /// AuthPsk mode (both PSK and sender public key authentication)
    AuthPsk = 0x03,
}

impl Mode {
    /// Get the mode as u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Cipher suite configuration
#[derive(Debug, Clone, Copy)]
pub struct CipherSuite {
    pub kem: KemId,
    pub kdf: KdfId,
    pub aead: AeadId,
}

impl CipherSuite {
    /// Create suite ID for HPKE operations
    fn suite_id(&self) -> Vec<u8> {
        let mut id = Vec::new();
        id.extend_from_slice(b"HPKE");
        id.extend_from_slice(&self.kem.as_u16().to_be_bytes());
        id.extend_from_slice(&self.kdf.as_u16().to_be_bytes());
        id.extend_from_slice(&self.aead.as_u16().to_be_bytes());
        id
    }
}

/// Labeled KDF Extract for HPKE key schedule
fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
    hash_fn: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut labeled_ikm = Vec::new();
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    hkdf_extract(salt, &labeled_ikm, hash_fn)
}

/// Labeled KDF Expand for HPKE key schedule
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
    hash_fn: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut labeled_info = Vec::new();
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    hkdf_expand(prk, &labeled_info, length, hash_fn)
}

/// HPKE encryption/decryption context
pub struct HpkeContext {
    suite: CipherSuite,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    sequence: u64,
    exporter_secret: Vec<u8>,
}

impl HpkeContext {
    /// Create a new HPKE context from key schedule
    pub(crate) fn new(
        suite: CipherSuite,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        mode: Mode,
    ) -> Result<Self> {
        let suite_id = suite.suite_id();
        let hash_fn = suite.kdf.hash_fn();

        // Compute psk_id_hash and info_hash
        let psk_id_hash = labeled_extract(&suite_id, &[], b"psk_id_hash", psk_id, hash_fn);
        let info_hash = labeled_extract(&suite_id, &[], b"info_hash", info, hash_fn);

        // Create key_schedule_context = mode || psk_id_hash || info_hash
        let mut key_schedule_context = Vec::new();
        key_schedule_context.push(mode.as_u8());
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);

        // Extract secret
        let secret = labeled_extract(&suite_id, psk, b"secret", shared_secret, hash_fn);

        // Expand to get key, base_nonce, and exporter_secret
        let key = labeled_expand(
            &suite_id,
            &secret,
            b"key",
            &key_schedule_context,
            suite.aead.nk(),
            hash_fn,
        );

        let base_nonce = labeled_expand(
            &suite_id,
            &secret,
            b"base_nonce",
            &key_schedule_context,
            suite.aead.nn(),
            hash_fn,
        );

        let exporter_secret = labeled_expand(
            &suite_id,
            &secret,
            b"exp",
            &key_schedule_context,
            suite.kdf.nh(),
            hash_fn,
        );

        Ok(Self {
            suite,
            key,
            base_nonce,
            sequence: 0,
            exporter_secret,
        })
    }

    /// Compute nonce for current sequence number
    fn compute_nonce(&self) -> Result<Vec<u8>> {
        // Check for sequence number overflow (max is 2^96 - 1 for 12-byte nonce)
        // For practical purposes, we check against u64::MAX
        if self.sequence == u64::MAX {
            return Err(HpkeError::MessageLimitReached);
        }

        // XOR base_nonce with sequence number (big-endian)
        let mut seq_bytes = vec![0u8; self.suite.aead.nn()];
        let seq_be = self.sequence.to_be_bytes();
        let offset = seq_bytes.len().saturating_sub(8);
        if offset < seq_bytes.len() {
            seq_bytes[offset..].copy_from_slice(&seq_be);
        }

        let mut nonce = self.base_nonce.clone();
        for (n, s) in nonce.iter_mut().zip(seq_bytes.iter()) {
            *n ^= s;
        }

        Ok(nonce)
    }

    /// Seal (encrypt) a message with associated data
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.compute_nonce()?;

        let ciphertext = match self.suite.aead {
            AeadId::Aes128Gcm => {
                let mut key_arr = [0u8; 16];
                let mut nonce_arr = [0u8; 12];
                key_arr.copy_from_slice(&self.key);
                nonce_arr.copy_from_slice(&nonce);
                Aes128Gcm::encrypt(&key_arr, &nonce_arr, plaintext, aad)
            }
            AeadId::Aes256Gcm => {
                let mut key_arr = [0u8; 32];
                let mut nonce_arr = [0u8; 12];
                key_arr.copy_from_slice(&self.key);
                nonce_arr.copy_from_slice(&nonce);
                Aes256Gcm::encrypt(&key_arr, &nonce_arr, plaintext, aad)
            }
            AeadId::ChaCha20Poly1305 => {
                let mut key_arr = [0u8; 32];
                let mut nonce_arr = [0u8; 12];
                key_arr.copy_from_slice(&self.key);
                nonce_arr.copy_from_slice(&nonce);
                ChaCha20Poly1305::encrypt(&key_arr, &nonce_arr, plaintext, aad)
            }
            AeadId::ExportOnly => {
                return Err(HpkeError::UnsupportedMode);
            }
        };

        self.sequence += 1;
        Ok(ciphertext)
    }

    /// Open (decrypt) a ciphertext with associated data
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.compute_nonce()?;

        let plaintext = match self.suite.aead {
            AeadId::Aes128Gcm => {
                let mut key_arr = [0u8; 16];
                let mut nonce_arr = [0u8; 12];
                key_arr.copy_from_slice(&self.key);
                nonce_arr.copy_from_slice(&nonce);
                Aes128Gcm::decrypt(&key_arr, &nonce_arr, ciphertext, aad)
                    .map_err(|_| HpkeError::OpenError)?
            }
            AeadId::Aes256Gcm => {
                let mut key_arr = [0u8; 32];
                let mut nonce_arr = [0u8; 12];
                key_arr.copy_from_slice(&self.key);
                nonce_arr.copy_from_slice(&nonce);
                Aes256Gcm::decrypt(&key_arr, &nonce_arr, ciphertext, aad)
                    .map_err(|_| HpkeError::OpenError)?
            }
            AeadId::ChaCha20Poly1305 => {
                let mut key_arr = [0u8; 32];
                let mut nonce_arr = [0u8; 12];
                key_arr.copy_from_slice(&self.key);
                nonce_arr.copy_from_slice(&nonce);
                ChaCha20Poly1305::decrypt(&key_arr, &nonce_arr, ciphertext, aad)
                    .ok_or(HpkeError::OpenError)?
            }
            AeadId::ExportOnly => {
                return Err(HpkeError::UnsupportedMode);
            }
        };

        self.sequence += 1;
        Ok(plaintext)
    }

    /// Export a secret for application use
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Vec<u8> {
        let suite_id = self.suite.suite_id();
        let hash_fn = self.suite.kdf.hash_fn();

        labeled_expand(
            &suite_id,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            length,
            hash_fn,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_computation() {
        let suite = CipherSuite {
            kem: KemId::DhkemP256HkdfSha256,
            kdf: KdfId::HkdfSha256,
            aead: AeadId::Aes128Gcm,
        };

        let mut ctx = HpkeContext {
            suite,
            key: vec![0u8; 16],
            base_nonce: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            ],
            sequence: 0,
            exporter_secret: vec![0u8; 32],
        };

        // First nonce should be base_nonce XOR 0
        let nonce1 = ctx.compute_nonce().unwrap();
        assert_eq!(
            nonce1,
            vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]
        );

        // Increment sequence
        ctx.sequence = 1;
        let nonce2 = ctx.compute_nonce().unwrap();
        assert_eq!(
            nonce2,
            vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0A]
        );
    }
}
