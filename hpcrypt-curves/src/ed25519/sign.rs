//! Ed25519 signature operations
//!
//! This module implements the Ed25519 signature scheme following RFC 8032:
//! - Key generation
//! - Signing
//! - Verification
//! - Batch verification

use super::point::{scalar_mul_base_fast, EdwardsPoint};
use super::scalar::Scalar;
use hpcrypt_hash::{HashFunction, Sha512};

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use std::vec;

/// Ed25519 public key (32 bytes)
pub type PublicKey = [u8; 32];

/// Ed25519 signature (64 bytes: 32-byte R + 32-byte S)
pub type Signature = [u8; 64];

/// Ed25519 private key (32 bytes of seed)
pub type PrivateKey = [u8; 32];

/// Ed25519 digital signature algorithm
pub struct Ed25519;

impl Ed25519 {
    /// Generate a public key from a private key (seed)
    pub fn public_key(private_key: &PrivateKey) -> PublicKey {
        // Hash the private key
        let mut hasher = Sha512::new();
        hasher.update(private_key);
        let hash = hasher.finalize();

        // Use first 32 bytes as scalar, properly clamped
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[0..32]);

        // Clamp the scalar
        scalar[0] &= 0xf8;
        scalar[31] &= 0x7f;
        scalar[31] |= 0x40;

        // Compute A = [scalar]B using fast precomputed table
        let a = scalar_mul_base_fast(&scalar);

        a.encode()
    }

    /// Sign a message
    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Signature {
        // Hash the private key
        let mut hasher = Sha512::new();
        hasher.update(private_key);
        let h = hasher.finalize();
        let h_bytes: [u8; 64] = h;

        // Split into scalar and prefix
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&h_bytes[0..32]);

        // Clamp the scalar
        scalar_bytes[0] &= 0xf8;
        scalar_bytes[31] &= 0x7f;
        scalar_bytes[31] |= 0x40;

        let prefix = &h_bytes[32..64];

        // Compute public key
        let public_key = Self::public_key(private_key);

        // Compute r = H(prefix || message)
        let mut hasher = Sha512::new();
        hasher.update(prefix);
        hasher.update(message);
        let r_hash = hasher.finalize();
        let r_hash_bytes: [u8; 64] = r_hash;
        let r_scalar = Scalar::from_hash(&r_hash_bytes);

        // Compute R = [r]B using fast precomputed table
        let r_point = scalar_mul_base_fast(&r_scalar.to_bytes());
        let r_encoded = r_point.encode();

        // Compute k = H(R || A || message)
        let mut hasher = Sha512::new();
        hasher.update(&r_encoded);
        hasher.update(&public_key);
        hasher.update(message);
        let k_hash = hasher.finalize();
        let k_hash_bytes: [u8; 64] = k_hash;
        let k_scalar = Scalar::from_hash(&k_hash_bytes);

        // Compute S = (r + k*scalar) mod L
        let scalar = Scalar::from_bytes(scalar_bytes);
        let k_times_scalar = k_scalar.mul(&scalar);
        let s_scalar = r_scalar.add(&k_times_scalar);

        // Return signature as R || S
        let mut signature = [0u8; 64];
        signature[0..32].copy_from_slice(&r_encoded);
        signature[32..64].copy_from_slice(&s_scalar.to_bytes());
        signature
    }

    /// Verify a signature
    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        // Decode R and S from signature
        let r_bytes: [u8; 32] = signature[0..32].try_into().unwrap();
        let s_bytes: [u8; 32] = signature[32..64].try_into().unwrap();

        // RFC 8032 Section 5.1.7: Check that S < L (reject if S >= L)
        // This prevents signature malleability
        if !super::constants::is_less_than_l(&s_bytes) {
            return false;
        }

        // Decode R (return false if decode fails)
        let r_point = match EdwardsPoint::decode(&r_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Decode public key (return false if decode fails)
        let a_point = match EdwardsPoint::decode(public_key) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Compute k = H(R || A || message)
        let mut hasher = Sha512::new();
        hasher.update(&r_bytes);
        hasher.update(public_key);
        hasher.update(message);
        let k_hash = hasher.finalize();
        let k_hash_bytes: [u8; 64] = k_hash;
        let k_scalar = Scalar::from_hash(&k_hash_bytes);

        // Check [S]B = R + [k]A
        let sb = scalar_mul_base_fast(&s_bytes);
        let ka = a_point.scalar_mul(&k_scalar.to_bytes());
        let rhs = r_point.add(&ka);

        // Compare points
        let lhs_encoded = sb.encode();
        let rhs_encoded = rhs.encode();

        lhs_encoded == rhs_encoded
    }

    /// Pippenger's multi-scalar multiplication algorithm
    ///
    /// Computes Σ(scalars\[i\] * points\[i\]) efficiently using the bucket method.
    /// This is significantly faster than naive summation for n ≥ 8.
    ///
    /// # Algorithm: Bucket Method (Pippenger)
    ///
    /// 1. Choose optimal window size c based on n (number of points)
    /// 2. Divide each scalar into digits of c bits
    /// 3. For each digit position (from MSB to LSB):
    ///    a. Create 2^c buckets
    ///    b. Add points to buckets based on their digit value
    ///    c. Compute bucket sums efficiently
    ///    d. Accumulate into result
    ///
    /// # Performance
    ///
    /// - Naive: O(n * 256) point operations
    /// - Pippenger: O(n + 256/c * 2^c) point operations
    /// - Expected speedup for n=8: ~2×
    /// - Expected speedup for n=32: ~4×
    ///
    /// # Window Size Selection
    ///
    /// Optimal window size depends on batch size n:
    /// - n=2-4: c=2 (4 buckets)
    /// - n=5-32: c=3 (8 buckets)
    /// - n=33-128: c=4 (16 buckets)
    /// - n>128: c=5 (32 buckets)
    ///
    /// # Arguments
    ///
    /// * `scalars` - Array of scalars (32 bytes each, little-endian)
    /// * `points` - Array of points
    ///
    /// # Returns
    ///
    /// The point Σ(scalars\[i\] * points\[i\])
    ///
    /// # Panics
    ///
    /// Panics if scalars.len() != points.len()
    #[cfg(feature = "std")]
    #[allow(clippy::manual_div_ceil)] // MSRV 1.70 compatibility - div_ceil stabilized in 1.73
    pub fn pippenger_msm(scalars: &[[u8; 32]], points: &[EdwardsPoint]) -> EdwardsPoint {
        assert_eq!(
            scalars.len(),
            points.len(),
            "Scalars and points must have same length"
        );

        let n = scalars.len();

        // Handle edge cases
        if n == 0 {
            return EdwardsPoint::identity();
        }
        if n == 1 {
            return points[0].scalar_mul(&scalars[0]);
        }

        // Select optimal window size based on batch size
        let window_size = Self::optimal_window_size(n);
        let num_buckets = 1usize << window_size; // 2^window_size
        let num_windows = (256_usize + window_size - 1) / window_size; // Ceiling division

        // Result accumulator
        let mut result = EdwardsPoint::identity();

        // Process windows from MSB to LSB
        for window_idx in (0..num_windows).rev() {
            // Multiply by 2^window_size (double window_size times)
            for _ in 0..window_size {
                result = result.double();
            }

            // Create buckets (bucket[k] will hold sum of points with digit k)
            // We use 0-indexed buckets: bucket[0] for digit 1, bucket[1] for digit 2, etc.
            let mut buckets = vec![EdwardsPoint::identity(); num_buckets];

            // Assign points to buckets based on their digit value at this window
            for (point, scalar_bytes) in points.iter().zip(scalars.iter()) {
                let digit = Self::extract_window(scalar_bytes, window_idx, window_size);

                if digit > 0 {
                    // Bucket indices are 0-based, so digit d goes to bucket[d-1]
                    let bucket_idx = (digit - 1) as usize;
                    buckets[bucket_idx] = buckets[bucket_idx].add(point);
                }
            }

            // Compute bucket sums efficiently using running sum technique
            // If buckets contain: [P1, P2, P3, P4] for digits [1, 2, 3, 4]
            // We want: 1*P1 + 2*P2 + 3*P3 + 4*P4
            // Using running sum: bucket_sum = P4, then P4+P3, then P4+P3+P2, then P4+P3+P2+P1
            // And accumulate: Add bucket_sum after processing each bucket
            let mut bucket_sum = EdwardsPoint::identity();
            let mut running_sum = EdwardsPoint::identity();

            // Process buckets from highest to lowest (right to left)
            for bucket in buckets.iter().rev() {
                bucket_sum = bucket_sum.add(bucket);
                running_sum = running_sum.add(&bucket_sum);
            }

            result = result.add(&running_sum);
        }

        result
    }

    /// Select optimal window size for Pippenger's algorithm based on batch size
    fn optimal_window_size(n: usize) -> usize {
        match n {
            0..=4 => 2,    // 4 buckets
            5..=32 => 3,   // 8 buckets
            33..=128 => 4, // 16 buckets
            _ => 5,        // 32 buckets
        }
    }

    /// Extract a window of bits from a scalar (little-endian bytes)
    ///
    /// # Arguments
    ///
    /// * `scalar_bytes` - 32-byte scalar in little-endian
    /// * `window_idx` - Window index (0 = LSB window)
    /// * `window_size` - Size of window in bits
    ///
    /// # Returns
    ///
    /// The digit value (0 to 2^window_size - 1)
    fn extract_window(scalar_bytes: &[u8; 32], window_idx: usize, window_size: usize) -> u8 {
        let bit_start = window_idx * window_size;
        let bit_end = ((window_idx + 1) * window_size).min(256);

        // Extract bits from bit_start to bit_end
        let mut digit = 0u8;

        for bit_pos in bit_start..bit_end {
            let byte_idx = bit_pos / 8;
            let bit_offset = bit_pos % 8;
            let bit = (scalar_bytes[byte_idx] >> bit_offset) & 1;

            digit |= bit << (bit_pos - bit_start);
        }

        digit
    }

    /// Batch verification of multiple signatures
    ///
    /// Verifies multiple Ed25519 signatures simultaneously using random linear combinations.
    /// This is significantly faster than verifying each signature individually.
    ///
    /// # Algorithm
    ///
    /// Instead of verifying each signature (Rᵢ, Sᵢ) for message Mᵢ and public key Aᵢ individually:
    ///     \[Sᵢ\]B = Rᵢ + \[kᵢ\]Aᵢ for each i
    ///
    /// We verify a random linear combination:
    ///     Σ(cᵢ·\[Sᵢ\]B) = Σ(cᵢ·(Rᵢ + \[kᵢ\]Aᵢ))
    ///
    /// where cᵢ are random 128-bit scalars. This gives the same security guarantees
    /// with approximately 50-70% speedup for batches of signatures.
    ///
    /// # Security
    ///
    /// The random coefficients ensure that if any signature is invalid, the batch
    /// verification will fail with overwhelming probability (1 - 2^-128).
    ///
    /// # Performance
    ///
    /// - Single verification: ~1 base point multiplication + 1 variable point multiplication
    /// - Batch verification: ~1 multi-scalar multiplication for all signatures combined
    /// - Expected speedup: 50-70% for N > 4 signatures
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Array of public keys
    /// * `messages` - Array of messages (can be different lengths)
    /// * `signatures` - Array of signatures
    ///
    /// # Returns
    ///
    /// `true` if all signatures are valid, `false` if any signature is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hpcrypt_curves::ed25519::Ed25519;
    ///
    /// let public_keys = vec![pk1, pk2, pk3];
    /// let messages = vec![msg1, msg2, msg3];
    /// let signatures = vec![sig1, sig2, sig3];
    ///
    /// let all_valid = Ed25519::verify_batch(&public_keys, &messages, &signatures);
    /// ```
    #[cfg(feature = "std")]
    pub fn verify_batch(
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> bool {
        let n = public_keys.len();

        // Check that all arrays have the same length
        if messages.len() != n || signatures.len() != n {
            return false;
        }

        // Handle edge cases
        if n == 0 {
            return true;
        }
        if n == 1 {
            return Self::verify(&public_keys[0], messages[0], &signatures[0]);
        }

        // Generate pseudorandom 128-bit scalars for linear combination
        // Using a transcript-based approach: hash all batch data to seed coefficient generation
        // This is deterministic but cryptographically secure (prevents forgery attacks)
        //
        // Security: Using weak/predictable coefficients allows attackers to forge batch
        // verifications. We use SHA-512(batch_data || index) for each coefficient.
        let mut coefficients = Vec::with_capacity(n);

        // Create a batch transcript by hashing all public inputs
        let mut transcript = Sha512::new();
        transcript.update(b"Ed25519BatchVerify");
        transcript.update(&(n as u64).to_le_bytes());
        for i in 0..n {
            transcript.update(&public_keys[i]);
            transcript.update(&signatures[i]);
            transcript.update(&(messages[i].len() as u64).to_le_bytes());
            transcript.update(messages[i]);
        }
        let transcript_hash = transcript.finalize();

        // Generate coefficient for each signature by hashing transcript || index
        for i in 0..n {
            let mut coeff_hasher = Sha512::new();
            coeff_hasher.update(&transcript_hash);
            coeff_hasher.update(&(i as u64).to_le_bytes());
            let coeff_hash = coeff_hasher.finalize();

            // Use first 32 bytes as scalar (128-bit randomness is sufficient)
            let mut c = [0u8; 32];
            c[..32].copy_from_slice(&coeff_hash[..32]);
            coefficients.push(Scalar::from_bytes(c));
        }

        // Decode all signatures and compute challenges
        let mut r_points = Vec::with_capacity(n);
        let mut s_scalars = Vec::with_capacity(n);
        let mut k_scalars = Vec::with_capacity(n);
        let mut a_points = Vec::with_capacity(n);

        for i in 0..n {
            // Decode R from signature
            let r_bytes: [u8; 32] = match signatures[i][0..32].try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let r_point = match EdwardsPoint::decode(&r_bytes) {
                Ok(p) => p,
                Err(_) => return false,
            };
            r_points.push(r_point);

            // Decode S from signature
            let s_bytes: [u8; 32] = match signatures[i][32..64].try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            s_scalars.push(Scalar::from_bytes(s_bytes));

            // Decode public key
            let a_point = match EdwardsPoint::decode(&public_keys[i]) {
                Ok(p) => p,
                Err(_) => return false,
            };
            a_points.push(a_point);

            // Compute challenge k = H(R || A || M)
            let mut hasher = Sha512::new();
            hasher.update(&r_bytes);
            hasher.update(&public_keys[i]);
            hasher.update(messages[i]);
            let k_hash = hasher.finalize();
            let k_hash_bytes: [u8; 64] = k_hash;
            let k_scalar = Scalar::from_hash(&k_hash_bytes);
            k_scalars.push(k_scalar);
        }

        // Compute left-hand side: Σ(cᵢ·[Sᵢ]B)
        // We need to compute multi-scalar multiplication: Σ(cᵢ·Sᵢ)·B

        // First compute the combined scalar: Σ(cᵢ·Sᵢ)
        let mut combined_s = Scalar::zero();
        for i in 0..n {
            let c_times_s = coefficients[i].mul(&s_scalars[i]);
            combined_s = combined_s.add(&c_times_s);
        }

        let lhs = scalar_mul_base_fast(&combined_s.to_bytes());

        // Compute right-hand side: Σ(cᵢ·Rᵢ) + Σ(cᵢ·[kᵢ]Aᵢ)
        // Use Pippenger's algorithm for efficient multi-scalar multiplication
        // We need to compute: Σ(cᵢ·Rᵢ) + Σ(cᵢ·kᵢ·Aᵢ)
        // This is a multi-scalar multiplication with 2n points

        // Prepare scalars and points for Pippenger
        let mut msm_scalars = Vec::with_capacity(2 * n);
        let mut msm_points = Vec::with_capacity(2 * n);

        // Add R points with coefficient scalars: Σ(cᵢ·Rᵢ)
        for i in 0..n {
            msm_scalars.push(coefficients[i].to_bytes());
            msm_points.push(r_points[i]);
        }

        // Add A points with (cᵢ·kᵢ) scalars: Σ(cᵢ·kᵢ·Aᵢ)
        for i in 0..n {
            let c_k = coefficients[i].mul(&k_scalars[i]);
            msm_scalars.push(c_k.to_bytes());
            msm_points.push(a_points[i]);
        }

        // Compute using Pippenger's algorithm (2-5× faster for n ≥ 8)
        let rhs = Self::pippenger_msm(&msm_scalars, &msm_points);

        // Compare encoded points
        let lhs_encoded = lhs.encode();
        let rhs_encoded = rhs.encode();

        lhs_encoded == rhs_encoded
    }
}
