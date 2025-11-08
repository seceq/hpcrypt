//! Batch operations for P-256
//!
//! This module provides optimized batch operations, primarily batch inversion
//! using Montgomery's trick.

extern crate alloc;
use alloc::vec::Vec;

use super::field::FieldElement;

/// Batch inversion using Montgomery's trick.
///
/// Given a slice of field elements, inverts all of them simultaneously
/// at the cost of 1 inversion + 3(n-1) multiplications, where n is the
/// number of elements.
///
/// # Performance
///
/// For n elements:
/// - Traditional approach: n inversions ≈ n × 7µs = 7n µs
/// - Batch approach: 1 inversion + 3n multiplications ≈ 7µs + 3n × 20ns ≈ 7µs + 0.06n µs
///
/// Speedup factor: ~(7n) / (7 + 0.06n)
/// - n=2: 2.0x
/// - n=10: 10x
/// - n=100: 99x
/// - n=1000: 991x
///
/// # Algorithm
///
/// ```text
/// Input: [a₁, a₂, ..., aₙ]
///
/// Forward pass (compute products):
///   p₁ = a₁
///   p₂ = a₁ · a₂
///   p₃ = a₁ · a₂ · a₃
///   ...
///   pₙ = a₁ · a₂ · ... · aₙ
///
/// Invert the final product:
///   c = 1 / pₙ
///
/// Backward pass (compute individual inverses):
///   aₙ⁻¹ = c · pₙ₋₁
///   c' = c · aₙ
///   aₙ₋₁⁻¹ = c' · pₙ₋₂
///   ...
///   a₁⁻¹ = final c value
/// ```
///
/// # Example
///
/// ```rust
/// use hpcrypt_curves::p384::FieldElement;
/// use hpcrypt_curves::p384::batch::batch_invert;
///
/// let a = FieldElement::from_u64(3);
/// let b = FieldElement::from_u64(5);
/// let c = FieldElement::from_u64(7);
///
/// let mut elems = vec![a, b, c];
/// batch_invert(&mut elems);
///
/// // elems now contains [a⁻¹, b⁻¹, c⁻¹]
/// assert_eq!(elems[0].mul(&a), FieldElement::one());
/// assert_eq!(elems[1].mul(&b), FieldElement::one());
/// assert_eq!(elems[2].mul(&c), FieldElement::one());
/// ```
///
/// # Security
///
/// This function is NOT constant-time because:
/// 1. It allocates a vector (size depends on input length)
/// 2. The loop count depends on the input length
///
/// It should ONLY be used in contexts where the number of elements being
/// inverted is not secret. For example:
/// - ✅ Batch signature verification (number of signatures is public)
/// - ✅ Affine coordinate conversion for precomputed tables
/// - ❌ DO NOT use if the count reveals secret information
pub fn batch_invert(elems: &mut [FieldElement]) {
    let n = elems.len();

    // Handle edge cases
    if n == 0 {
        return;
    }
    if n == 1 {
        elems[0] = elems[0].invert();
        return;
    }

    // Allocate space for products
    let mut products = Vec::with_capacity(n);

    // Forward pass: compute cumulative products
    // products[i] = elems[0] * elems[1] * ... * elems[i]
    products.push(elems[0]);
    for i in 1..n {
        products.push(products[i - 1].mul(&elems[i]));
    }

    // Invert the final product
    // This is the ONLY inversion in the entire batch!
    let mut acc = products[n - 1].invert();

    // Backward pass: compute individual inverses
    // Working backward from the end
    for i in (1..n).rev() {
        // Save the original value before overwriting
        let original = elems[i];

        // elems[i]⁻¹ = acc * products[i-1]
        // Because: acc = 1/(elems[0] * ... * elems[i])
        //          products[i-1] = elems[0] * ... * elems[i-1]
        // So: acc * products[i-1] = (elems[0] * ... * elems[i-1]) / (elems[0] * ... * elems[i])
        //                          = 1 / elems[i]
        elems[i] = acc.mul(&products[i - 1]);

        // Update accumulator for next iteration using the ORIGINAL value
        // acc' = acc * original_elems[i]
        //      = 1/(elems[0] * ... * elems[i]) * elems[i]
        //      = 1/(elems[0] * ... * elems[i-1])
        acc = acc.mul(&original);
    }

    // Handle first element separately (no products[i-1])
    elems[0] = acc;
}

/// Batch inversion with optional zero handling.
///
/// Similar to `batch_invert`, but skips elements that are zero
/// and leaves them as zero in the output.
///
/// # Use Case
///
/// This is useful when batch inverting points in projective/Jacobian
/// coordinates where the point-at-infinity has Z=0.
///
/// # Performance
///
/// Slightly slower than `batch_invert` due to conditional logic,
/// but still much faster than individual inversions.
///
/// # Security
///
/// This function is NOT constant-time because:
/// 1. It uses conditional branches based on zero-ness
/// 2. The positions of zeros may be secret
///
/// Use with caution in security-critical contexts.
pub fn batch_invert_with_zeros(elems: &mut [FieldElement]) {
    let n = elems.len();

    if n == 0 {
        return;
    }

    // Track which elements are non-zero
    let mut non_zero_indices = Vec::with_capacity(n);
    let mut non_zero_elems = Vec::with_capacity(n);

    for (i, elem) in elems.iter().enumerate() {
        if !bool::from(elem.is_zero()) {
            non_zero_indices.push(i);
            non_zero_elems.push(*elem);
        }
    }

    // Batch invert only the non-zero elements
    batch_invert(&mut non_zero_elems);

    // Write back the inverted values
    for (idx, inverted) in non_zero_indices.iter().zip(non_zero_elems.iter()) {
        elems[*idx] = *inverted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_batch_invert_empty() {
        let mut elems: Vec<FieldElement> = vec![];
        batch_invert(&mut elems);
        assert_eq!(elems.len(), 0);
    }

    #[test]
    fn test_batch_invert_single() {
        let a = FieldElement::from_u64(42);
        let mut elems = vec![a];

        batch_invert(&mut elems);

        assert_eq!(elems[0].mul(&a), FieldElement::one());
    }

    #[test]
    fn test_batch_invert_two() {
        let a = FieldElement::from_u64(3);
        let b = FieldElement::from_u64(5);

        let mut elems = vec![a, b];
        batch_invert(&mut elems);

        assert_eq!(elems[0].mul(&a), FieldElement::one());
        assert_eq!(elems[1].mul(&b), FieldElement::one());
    }

    #[test]
    fn test_batch_invert_many() {
        let values = [3u64, 5, 7, 11, 13, 17, 19, 23, 29, 31];
        let elems: Vec<FieldElement> = values.iter().map(|&v| FieldElement::from_u64(v)).collect();

        let mut batch = elems.clone();
        batch_invert(&mut batch);

        // Verify each inversion
        for (original, inverted) in elems.iter().zip(batch.iter()) {
            assert_eq!(inverted.mul(original), FieldElement::one());
        }
    }

    #[test]
    fn test_batch_invert_with_zeros() {
        let a = FieldElement::from_u64(3);
        let zero = FieldElement::zero();
        let b = FieldElement::from_u64(5);

        let mut elems = vec![a, zero, b];
        batch_invert_with_zeros(&mut elems);

        assert_eq!(elems[0].mul(&a), FieldElement::one());
        assert!(bool::from(elems[1].is_zero())); // Zero stays zero
        assert_eq!(elems[2].mul(&b), FieldElement::one());
    }

    #[test]
    fn test_batch_vs_individual() {
        // Test that batch inversion gives same results as individual inversions
        let values = [3u64, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
        let elems: Vec<FieldElement> = values.iter().map(|&v| FieldElement::from_u64(v)).collect();

        // Individual inversions
        let individual: Vec<FieldElement> = elems.iter().map(|e| e.invert()).collect();

        // Batch inversion
        let mut batch = elems.clone();
        batch_invert(&mut batch);

        // Compare
        for (ind, bat) in individual.iter().zip(batch.iter()) {
            assert_eq!(*ind, *bat);
        }
    }

    #[test]
    fn test_batch_invert_large() {
        // Test with a larger batch to verify correctness at scale
        let n = 100;
        let elems: Vec<FieldElement> = (1..=n).map(|i| FieldElement::from_u64(i as u64)).collect();

        let mut batch = elems.clone();
        batch_invert(&mut batch);

        // Verify each inversion
        for (original, inverted) in elems.iter().zip(batch.iter()) {
            assert_eq!(inverted.mul(original), FieldElement::one());
        }
    }
}
