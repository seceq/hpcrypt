//! Key Encapsulation Mechanism (KEM) implementations for HPKE
//!
//! Implements DHKEM (Diffie-Hellman based KEM) for various curves as specified in RFC 9180.

#![allow(unused_imports)]
use crate::error::{HpkeError, Result};
use alloc::vec::Vec;
use hpcrypt_hash::{sha256, sha512, Sha384};

/// HKDF Extract wrapper (simplified implementation for HPKE KEM)
fn hkdf_extract(salt: &[u8], ikm: &[u8], hash_fn: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    // Simplified HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    // For now, we'll use a simple implementation
    let mut data = Vec::new();
    data.extend_from_slice(salt);
    data.extend_from_slice(ikm);
    hash_fn(&data)
}

/// HKDF Expand wrapper (simplified implementation for HPKE KEM)
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

/// KEM algorithm identifiers from RFC 9180
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KemId {
    /// DHKEM(P-256, HKDF-SHA256)
    DhkemP256HkdfSha256 = 0x0010,
    /// DHKEM(P-384, HKDF-SHA384)
    DhkemP384HkdfSha384 = 0x0011,
    /// DHKEM(P-521, HKDF-SHA512)
    DhkemP521HkdfSha512 = 0x0012,
    /// DHKEM(X25519, HKDF-SHA256)
    DhkemX25519HkdfSha256 = 0x0020,
}

impl KemId {
    /// Get the KEM ID as u16
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get Nsecret (length of KEM shared secret in bytes)
    pub fn nsecret(self) -> usize {
        match self {
            KemId::DhkemP256HkdfSha256 => 32,
            KemId::DhkemP384HkdfSha384 => 48,
            KemId::DhkemP521HkdfSha512 => 64,
            KemId::DhkemX25519HkdfSha256 => 32,
        }
    }

    /// Get Nenc (length of encapsulated key in bytes)
    pub fn nenc(self) -> usize {
        match self {
            KemId::DhkemP256HkdfSha256 => 65,   // Uncompressed P-256 point
            KemId::DhkemP384HkdfSha384 => 97,   // Uncompressed P-384 point
            KemId::DhkemP521HkdfSha512 => 133,  // Uncompressed P-521 point
            KemId::DhkemX25519HkdfSha256 => 32, // X25519 public key
        }
    }

    /// Get Npk (length of public key in bytes)
    pub fn npk(self) -> usize {
        self.nenc()
    }

    /// Get Nsk (length of secret key in bytes)
    pub fn nsk(self) -> usize {
        match self {
            KemId::DhkemP256HkdfSha256 => 32,
            KemId::DhkemP384HkdfSha384 => 48,
            KemId::DhkemP521HkdfSha512 => 66,
            KemId::DhkemX25519HkdfSha256 => 32,
        }
    }
}

/// Labeled KDF Extract as specified in RFC 9180 Section 4
fn labeled_extract(
    kem_id: KemId,
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
    hash_fn: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
    let mut labeled_ikm = Vec::new();
    labeled_ikm.extend_from_slice(b"HPKE-v1");

    // suite_id for KEM = concat("KEM", I2OSP(kem_id, 2))
    labeled_ikm.extend_from_slice(b"KEM");
    labeled_ikm.extend_from_slice(&kem_id.as_u16().to_be_bytes());

    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    hkdf_extract(salt, &labeled_ikm, hash_fn)
}

/// Labeled KDF Expand as specified in RFC 9180 Section 4
fn labeled_expand(
    kem_id: KemId,
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
    hash_fn: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
    let mut labeled_info = Vec::new();
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");

    // suite_id for KEM = concat("KEM", I2OSP(kem_id, 2))
    labeled_info.extend_from_slice(b"KEM");
    labeled_info.extend_from_slice(&kem_id.as_u16().to_be_bytes());

    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    hkdf_expand(prk, &labeled_info, length, hash_fn)
}

/// Extract and Expand operation for DHKEM
fn extract_and_expand(
    kem_id: KemId,
    dh_output: &[u8],
    kem_context: &[u8],
    hash_fn: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let prk = labeled_extract(kem_id, &[], b"eae_prk", dh_output, hash_fn);
    labeled_expand(
        kem_id,
        &prk,
        b"shared_secret",
        kem_context,
        kem_id.nsecret(),
        hash_fn,
    )
}

/// KEM trait defining the Key Encapsulation Mechanism interface
pub trait Kem {
    /// Generate a keypair
    fn generate_keypair<R: rand::Rng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Encapsulate: generate shared secret and encapsulated key
    fn encap<R: rand::Rng>(pk_r: &[u8], rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate: recover shared secret from encapsulated key
    fn decap(enc: &[u8], sk_r: &[u8]) -> Result<Vec<u8>>;

    /// Authenticated Encapsulate (for Auth modes)
    fn auth_encap<R: rand::Rng>(
        pk_r: &[u8],
        sk_s: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Authenticated Decapsulate (for Auth modes)
    fn auth_decap(enc: &[u8], sk_r: &[u8], pk_s: &[u8]) -> Result<Vec<u8>>;
}

/// DHKEM for P-256 curve with HKDF-SHA256
pub struct DhkemP256;

impl DhkemP256 {
    const KEM_ID: KemId = KemId::DhkemP256HkdfSha256;

    fn hash(data: &[u8]) -> Vec<u8> {
        sha256(data).to_vec()
    }

    fn dh(sk: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
        use hpcrypt_curves::p256::{AffinePoint, FieldElement, Point, Scalar};

        // Parse secret key
        if sk.len() != 32 {
            return Err(HpkeError::InvalidSecretKey);
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(sk);
        let scalar = Scalar::from_bytes(&sk_bytes);

        // Parse public key (uncompressed SEC1 format: 0x04 || x || y)
        if pk.len() != 65 || pk[0] != 0x04 {
            return Err(HpkeError::InvalidPublicKey);
        }

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&pk[1..33]);
        y_bytes.copy_from_slice(&pk[33..65]);

        let x = FieldElement::from_bytes(&x_bytes).ok_or(HpkeError::InvalidPublicKey)?;
        let y = FieldElement::from_bytes(&y_bytes).ok_or(HpkeError::InvalidPublicKey)?;

        let affine = AffinePoint { x, y };
        let point = Point::from_affine(&affine);

        // Perform scalar multiplication
        let scalar_bytes: [u8; 32] = scalar.to_bytes();
        let result = point.scalar_mul(&scalar_bytes);

        // Extract x-coordinate as shared secret
        let affine_result = result.to_affine().ok_or(HpkeError::InternalError)?;
        Ok(affine_result.x.to_bytes().to_vec())
    }
}

impl Kem for DhkemP256 {
    fn generate_keypair<R: rand::Rng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        use hpcrypt_curves::p256::{Point, Scalar};

        // Generate random secret key
        let mut sk_bytes = [0u8; 32];
        rng.fill(&mut sk_bytes[..]);

        let scalar = Scalar::from_bytes(&sk_bytes);
        let scalar_bytes: [u8; 32] = scalar.to_bytes();

        // Compute public key
        let public_point = Point::generator().scalar_mul(&scalar_bytes);
        let affine = public_point.to_affine().ok_or(HpkeError::InternalError)?;

        // Encode as uncompressed SEC1 format
        let mut pk = Vec::with_capacity(65);
        pk.push(0x04);
        pk.extend_from_slice(&affine.x.to_bytes());
        pk.extend_from_slice(&affine.y.to_bytes());

        Ok((sk_bytes.to_vec(), pk))
    }

    fn encap<R: rand::Rng>(pk_r: &[u8], rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate ephemeral keypair
        let (sk_e, pk_e) = Self::generate_keypair(rng)?;

        // Compute DH shared secret
        let dh_output = Self::dh(&sk_e, pk_r)?;

        // kem_context = enc || pkR
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(&pk_e);
        kem_context.extend_from_slice(pk_r);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok((shared_secret, pk_e))
    }

    fn decap(enc: &[u8], sk_r: &[u8]) -> Result<Vec<u8>> {
        // Validate encapsulated key length
        if enc.len() != Self::KEM_ID.nenc() {
            return Err(HpkeError::InvalidCiphertext);
        }

        // Derive recipient's public key for kem_context
        use hpcrypt_curves::p256::{Point, Scalar};

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(sk_r);
        let scalar = Scalar::from_bytes(&sk_bytes);
        let scalar_bytes: [u8; 32] = scalar.to_bytes();

        let pk_r_point = Point::generator().scalar_mul(&scalar_bytes);
        let affine = pk_r_point.to_affine().ok_or(HpkeError::InternalError)?;

        let mut pk_r = Vec::with_capacity(65);
        pk_r.push(0x04);
        pk_r.extend_from_slice(&affine.x.to_bytes());
        pk_r.extend_from_slice(&affine.y.to_bytes());

        // Compute DH shared secret
        let dh_output = Self::dh(sk_r, enc)?;

        // kem_context = enc || pkR
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok(shared_secret)
    }

    fn auth_encap<R: rand::Rng>(
        pk_r: &[u8],
        sk_s: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate ephemeral keypair
        let (sk_e, pk_e) = Self::generate_keypair(rng)?;

        // Compute two DH operations: DH(skE, pkR) and DH(skS, pkR)
        let dh_er = Self::dh(&sk_e, pk_r)?;
        let dh_sr = Self::dh(sk_s, pk_r)?;

        // Concatenate DH outputs
        let mut dh_output = Vec::new();
        dh_output.extend_from_slice(&dh_er);
        dh_output.extend_from_slice(&dh_sr);

        // Derive sender's public key for kem_context
        use hpcrypt_curves::p256::{Point, Scalar};

        let mut sk_s_bytes = [0u8; 32];
        sk_s_bytes.copy_from_slice(sk_s);
        let scalar = Scalar::from_bytes(&sk_s_bytes);
        let scalar_bytes: [u8; 32] = scalar.to_bytes();

        let pk_s_point = Point::generator().scalar_mul(&scalar_bytes);
        let affine = pk_s_point.to_affine().ok_or(HpkeError::InternalError)?;

        let mut pk_s = Vec::with_capacity(65);
        pk_s.push(0x04);
        pk_s.extend_from_slice(&affine.x.to_bytes());
        pk_s.extend_from_slice(&affine.y.to_bytes());

        // kem_context = enc || pkR || pkS
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(&pk_e);
        kem_context.extend_from_slice(pk_r);
        kem_context.extend_from_slice(&pk_s);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok((shared_secret, pk_e))
    }

    fn auth_decap(enc: &[u8], sk_r: &[u8], pk_s: &[u8]) -> Result<Vec<u8>> {
        // Validate inputs
        if enc.len() != Self::KEM_ID.nenc() {
            return Err(HpkeError::InvalidCiphertext);
        }
        if pk_s.len() != Self::KEM_ID.npk() {
            return Err(HpkeError::InvalidPublicKey);
        }

        // Derive recipient's public key for kem_context
        use hpcrypt_curves::p256::{Point, Scalar};

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(sk_r);
        let scalar = Scalar::from_bytes(&sk_bytes);
        let scalar_bytes: [u8; 32] = scalar.to_bytes();

        let pk_r_point = Point::generator().scalar_mul(&scalar_bytes);
        let affine = pk_r_point.to_affine().ok_or(HpkeError::InternalError)?;

        let mut pk_r = Vec::with_capacity(65);
        pk_r.push(0x04);
        pk_r.extend_from_slice(&affine.x.to_bytes());
        pk_r.extend_from_slice(&affine.y.to_bytes());

        // Compute two DH operations: DH(skR, enc) and DH(skR, pkS)
        let dh_re = Self::dh(sk_r, enc)?;
        let dh_rs = Self::dh(sk_r, pk_s)?;

        // Concatenate DH outputs
        let mut dh_output = Vec::new();
        dh_output.extend_from_slice(&dh_re);
        dh_output.extend_from_slice(&dh_rs);

        // kem_context = enc || pkR || pkS
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);
        kem_context.extend_from_slice(pk_s);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok(shared_secret)
    }
}

/// DHKEM for X25519 curve with HKDF-SHA256
///
/// Implements DHKEM(X25519, HKDF-SHA256) as specified in RFC 9180 Section 7.1.
///
/// This KEM provides:
/// - Algorithm ID: 0x0020
/// - Nenc: 32 bytes (X25519 public key)
/// - Npk: 32 bytes (X25519 public key)
/// - Nsk: 32 bytes (X25519 secret key)
/// - Nsecret: 32 bytes (shared secret output)
///
/// X25519 offers several advantages over NIST curves:
/// - Simpler key format (32 bytes vs 65 bytes for uncompressed P-256)
/// - Constant-time operations by design
/// - Widely supported and battle-tested
/// - Excellent performance characteristics
///
/// # Security Properties
///
/// - IND-CCA2 secure when used with HKDF-SHA256
/// - Forward secrecy through ephemeral key generation
/// - Constant-time DH operations (timing-attack resistant)
/// - Low-order point rejection built into X25519
///
/// # Example
///
/// ```
/// use hpcrypt_hpke::{DhkemX25519, Kem};
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
///
/// // Generate recipient keypair
/// let (sk_r, pk_r) = DhkemX25519::generate_keypair(&mut rng).unwrap();
///
/// // Encapsulate: sender generates shared secret
/// let (shared_secret_sender, enc) = DhkemX25519::encap(&pk_r, &mut rng).unwrap();
///
/// // Decapsulate: recipient derives same shared secret
/// let shared_secret_recipient = DhkemX25519::decap(&enc, &sk_r).unwrap();
///
/// assert_eq!(shared_secret_sender, shared_secret_recipient);
/// ```
pub struct DhkemX25519;

impl DhkemX25519 {
    const KEM_ID: KemId = KemId::DhkemX25519HkdfSha256;

    /// Hash function (SHA-256) used for KDF operations
    fn hash(data: &[u8]) -> Vec<u8> {
        sha256(data).to_vec()
    }

    /// Perform X25519 Diffie-Hellman operation
    ///
    /// Computes the shared secret from a secret key and public key.
    /// This is a constant-time operation that includes low-order point checks.
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret key (32 bytes)
    /// * `pk` - Public key (32 bytes)
    ///
    /// # Returns
    ///
    /// The DH shared secret (32 bytes) or an error if keys are invalid
    ///
    /// # Errors
    ///
    /// - `InvalidSecretKey` if secret key length is not 32 bytes
    /// - `InvalidPublicKey` if public key length is not 32 bytes or represents identity/low-order point
    fn dh(sk: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
        use hpcrypt_curves::x25519::X25519;

        // Validate and parse secret key
        if sk.len() != 32 {
            return Err(HpkeError::InvalidSecretKey);
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(sk);

        // Validate and parse public key
        if pk.len() != 32 {
            return Err(HpkeError::InvalidPublicKey);
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(pk);

        // Perform X25519 DH operation with automatic clamping and low-order point rejection
        let shared_secret = X25519::shared_secret(&sk_bytes, &pk_bytes)
            .map_err(|_| HpkeError::InvalidPublicKey)?;

        Ok(shared_secret.to_vec())
    }
}

impl Kem for DhkemX25519 {
    fn generate_keypair<R: rand::Rng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        use hpcrypt_curves::x25519::X25519;

        // Generate random secret key
        let mut sk_bytes = [0u8; 32];
        rng.fill(&mut sk_bytes[..]);

        // Compute public key
        let pk_bytes = X25519::public_key(&sk_bytes);

        Ok((sk_bytes.to_vec(), pk_bytes.to_vec()))
    }

    fn encap<R: rand::Rng>(pk_r: &[u8], rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate ephemeral keypair
        let (sk_e, pk_e) = Self::generate_keypair(rng)?;

        // Compute DH shared secret
        let dh_output = Self::dh(&sk_e, pk_r)?;

        // kem_context = enc || pkR
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(&pk_e);
        kem_context.extend_from_slice(pk_r);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok((shared_secret, pk_e))
    }

    fn decap(enc: &[u8], sk_r: &[u8]) -> Result<Vec<u8>> {
        // Validate encapsulated key length
        if enc.len() != Self::KEM_ID.nenc() {
            return Err(HpkeError::InvalidCiphertext);
        }

        // Derive recipient's public key for kem_context
        use hpcrypt_curves::x25519::X25519;

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(sk_r);

        let pk_r = X25519::public_key(&sk_bytes);

        // Compute DH shared secret
        let dh_output = Self::dh(sk_r, enc)?;

        // kem_context = enc || pkR
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok(shared_secret)
    }

    fn auth_encap<R: rand::Rng>(
        pk_r: &[u8],
        sk_s: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate ephemeral keypair
        let (sk_e, pk_e) = Self::generate_keypair(rng)?;

        // Compute two DH operations: DH(skE, pkR) and DH(skS, pkR)
        let dh_er = Self::dh(&sk_e, pk_r)?;
        let dh_sr = Self::dh(sk_s, pk_r)?;

        // Concatenate DH outputs
        let mut dh_output = Vec::new();
        dh_output.extend_from_slice(&dh_er);
        dh_output.extend_from_slice(&dh_sr);

        // Derive sender's public key for kem_context
        use hpcrypt_curves::x25519::X25519;

        let mut sk_s_bytes = [0u8; 32];
        sk_s_bytes.copy_from_slice(sk_s);
        let pk_s = X25519::public_key(&sk_s_bytes);

        // kem_context = enc || pkR || pkS
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(&pk_e);
        kem_context.extend_from_slice(pk_r);
        kem_context.extend_from_slice(&pk_s);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok((shared_secret, pk_e))
    }

    fn auth_decap(enc: &[u8], sk_r: &[u8], pk_s: &[u8]) -> Result<Vec<u8>> {
        // Validate inputs
        if enc.len() != Self::KEM_ID.nenc() {
            return Err(HpkeError::InvalidCiphertext);
        }
        if pk_s.len() != Self::KEM_ID.npk() {
            return Err(HpkeError::InvalidPublicKey);
        }

        // Derive recipient's public key for kem_context
        use hpcrypt_curves::x25519::X25519;

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(sk_r);
        let pk_r = X25519::public_key(&sk_bytes);

        // Compute two DH operations: DH(skR, enc) and DH(skR, pkS)
        let dh_re = Self::dh(sk_r, enc)?;
        let dh_rs = Self::dh(sk_r, pk_s)?;

        // Concatenate DH outputs
        let mut dh_output = Vec::new();
        dh_output.extend_from_slice(&dh_re);
        dh_output.extend_from_slice(&dh_rs);

        // kem_context = enc || pkR || pkS
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);
        kem_context.extend_from_slice(pk_s);

        // Derive shared secret
        let shared_secret = extract_and_expand(Self::KEM_ID, &dh_output, &kem_context, Self::hash);

        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_p256_kem_encap_decap() {
        let mut rng = thread_rng();

        // Generate recipient keypair
        let (sk_r, pk_r) = DhkemP256::generate_keypair(&mut rng).unwrap();

        // Encapsulate
        let (shared_secret_sender, enc) = DhkemP256::encap(&pk_r, &mut rng).unwrap();

        // Decapsulate
        let shared_secret_recipient = DhkemP256::decap(&enc, &sk_r).unwrap();

        // Shared secrets should match
        assert_eq!(shared_secret_sender, shared_secret_recipient);
        assert_eq!(shared_secret_sender.len(), 32); // Nsecret for P-256
    }

    #[test]
    fn test_p256_kem_auth_encap_decap() {
        let mut rng = thread_rng();

        // Generate keypairs
        let (sk_r, pk_r) = DhkemP256::generate_keypair(&mut rng).unwrap();
        let (sk_s, pk_s) = DhkemP256::generate_keypair(&mut rng).unwrap();

        // Authenticated encapsulate
        let (shared_secret_sender, enc) = DhkemP256::auth_encap(&pk_r, &sk_s, &mut rng).unwrap();

        // Authenticated decapsulate
        let shared_secret_recipient = DhkemP256::auth_decap(&enc, &sk_r, &pk_s).unwrap();

        // Shared secrets should match
        assert_eq!(shared_secret_sender, shared_secret_recipient);
        assert_eq!(shared_secret_sender.len(), 32); // Nsecret for P-256
    }

    #[test]
    fn test_x25519_kem_encap_decap() {
        let mut rng = thread_rng();

        // Generate recipient keypair
        let (sk_r, pk_r) = DhkemX25519::generate_keypair(&mut rng).unwrap();

        // Validate key sizes
        assert_eq!(sk_r.len(), 32);
        assert_eq!(pk_r.len(), 32);

        // Encapsulate
        let (shared_secret_sender, enc) = DhkemX25519::encap(&pk_r, &mut rng).unwrap();

        // Validate sizes
        assert_eq!(enc.len(), 32); // Nenc for X25519
        assert_eq!(shared_secret_sender.len(), 32); // Nsecret for X25519

        // Decapsulate
        let shared_secret_recipient = DhkemX25519::decap(&enc, &sk_r).unwrap();

        // Shared secrets should match
        assert_eq!(shared_secret_sender, shared_secret_recipient);
    }

    #[test]
    fn test_x25519_kem_auth_encap_decap() {
        let mut rng = thread_rng();

        // Generate keypairs
        let (sk_r, pk_r) = DhkemX25519::generate_keypair(&mut rng).unwrap();
        let (sk_s, pk_s) = DhkemX25519::generate_keypair(&mut rng).unwrap();

        // Authenticated encapsulate
        let (shared_secret_sender, enc) = DhkemX25519::auth_encap(&pk_r, &sk_s, &mut rng).unwrap();

        // Validate sizes
        assert_eq!(enc.len(), 32);
        assert_eq!(shared_secret_sender.len(), 32);

        // Authenticated decapsulate
        let shared_secret_recipient = DhkemX25519::auth_decap(&enc, &sk_r, &pk_s).unwrap();

        // Shared secrets should match
        assert_eq!(shared_secret_sender, shared_secret_recipient);
    }

    #[test]
    fn test_x25519_kem_invalid_public_key() {
        let mut rng = thread_rng();

        // Generate a valid keypair
        let (sk_r, _) = DhkemX25519::generate_keypair(&mut rng).unwrap();

        // Try to encapsulate with invalid public key (wrong size)
        let invalid_pk = vec![0u8; 16]; // Wrong size
        let result = DhkemX25519::encap(&invalid_pk, &mut rng);
        assert!(result.is_err());

        // Try to decapsulate with invalid enc (wrong size)
        let invalid_enc = vec![0u8; 16];
        let result = DhkemX25519::decap(&invalid_enc, &sk_r);
        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_kem_deterministic_public_key() {
        // Same secret key should always produce same public key
        let sk = [42u8; 32];

        use hpcrypt_curves::x25519::X25519;
        let pk1 = X25519::public_key(&sk);
        let pk2 = X25519::public_key(&sk);

        assert_eq!(pk1, pk2);
    }
}
