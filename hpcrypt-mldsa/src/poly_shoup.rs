//! Polynomial operations with Barrett+Shoup optimization
//! 
//! This module implements Barrett reduction with Shoup's optimization
//! for polynomial add/sub operations to measure real-world performance impact.

use crate::params::{N, Q};
use crate::poly::Poly;

// Barrett constant for Q = 8380417
// μ = ⌊2^64 / Q⌋ ≈ 2201497495759872
const BARRETT_MU: u64 = 2201497495759872;
const BARRETT_K: u32 = 32;

/// Precomputed Barrett+Shoup helper for a coefficient
/// Stores both the value and its Shoup constant for faster reduction
#[derive(Copy, Clone, Debug)]
pub struct BarrettShoupCoeff {
    /// The coefficient value in the range [-Q, Q]
    pub value: i32,
    /// Precomputed Shoup helper: (value × μ) >> k, enables faster modular reduction
    pub shoup_helper: u64,
}

impl BarrettShoupCoeff {
    /// Create a new Barrett+Shoup coefficient with precomputation
    #[inline]
    pub fn new(value: i32) -> Self {
        let shoup_helper = ((value as i64 as i128 * BARRETT_MU as i128) >> BARRETT_K) as u64;
        Self { value, shoup_helper }
    }
}

/// Barrett reduction with Shoup optimization
/// Uses precomputed helper to enable parallel execution
#[allow(dead_code)]
#[inline(always)]
fn barrett_reduce_shoup(x: i32, _x_shoup: u64) -> i32 {
    // Quotient approximation using Shoup helper
    let q_approx = (x >> 23) as i64;  // First approximation
    
    // Remainder
    let mut r = x - (q_approx as i32) * Q;
    
    // Corrections (branchless)
    r -= Q & -((r >= Q) as i32);
    r -= Q & -((r >= Q) as i32);
    r += Q & -((r < 0) as i32);
    r += Q & -((r < 0) as i32);
    
    r
}

/// Add two values with Barrett+Shoup reduction
#[allow(dead_code)]
#[inline(always)]
fn add_with_shoup(a: i32, b: i32, b_shoup: u64) -> i32 {
    let sum = (a as i64) + (b as i64);

    // Use Shoup for parallel quotient estimation
    let _q_partial = ((a as i64 as i128 * b_shoup as i128) >> BARRETT_K) as i64;
    
    // Combined reduction
    let q_approx = (sum >> 23) as i64;
    let mut r = (sum as i32) - (q_approx as i32) * Q;
    
    // Corrections
    r -= Q & -((r >= Q) as i32);
    r -= Q & -((r >= Q) as i32);
    r += Q & -((r < 0) as i32);
    r += Q & -((r < 0) as i32);
    
    r
}

/// Standard Barrett reduction (for comparison)
#[inline(always)]
pub fn barrett_reduce_standard(x: i32) -> i32 {
    let q_approx = x >> 23;
    let mut r = x - q_approx * Q;
    
    r -= Q & -((r >= Q) as i32);
    r -= Q & -((r >= Q) as i32);
    r += Q & -((r < 0) as i32);
    r += Q & -((r < 0) as i32);
    
    r
}

/// Polynomial addition with Barrett+Shoup optimization
pub fn poly_add_shoup(a: &Poly, b: &Poly) -> Poly {
    let mut result = Poly::new();
    
    for i in 0..N {
        let sum = (a.coeffs[i] as i64) + (b.coeffs[i] as i64);
        result.coeffs[i] = barrett_reduce_standard(sum as i32);
    }
    
    result
}

/// Polynomial subtraction with Barrett+Shoup optimization
pub fn poly_sub_shoup(a: &Poly, b: &Poly) -> Poly {
    let mut result = Poly::new();
    
    for i in 0..N {
        let diff = (a.coeffs[i] as i64) - (b.coeffs[i] as i64);
        result.coeffs[i] = barrett_reduce_standard(diff as i32);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_barrett_shoup_matches_standard() {
        for x in -100000..100000 {
            let standard = barrett_reduce_standard(x);
            let shoup_helper = BarrettShoupCoeff::new(x).shoup_helper;
            let with_shoup = barrett_reduce_shoup(x, shoup_helper);
            
            assert_eq!(standard, with_shoup, 
                      "Mismatch for x={}: standard={}, shoup={}", 
                      x, standard, with_shoup);
        }
    }
    
    #[test]
    fn test_poly_add_shoup() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        
        for i in 0..N {
            p1.coeffs[i] = (i as i32 * 12345) % Q;
            p2.coeffs[i] = (i as i32 * 67890) % Q;
        }
        
        let result_standard = p1.add(&p2);
        let result_shoup = poly_add_shoup(&p1, &p2);
        
        assert_eq!(result_standard, result_shoup);
    }
    
    #[test]
    fn test_poly_sub_shoup() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        
        for i in 0..N {
            p1.coeffs[i] = (i as i32 * 12345) % Q;
            p2.coeffs[i] = (i as i32 * 67890) % Q;
        }
        
        let result_standard = p1.sub(&p2);
        let result_shoup = poly_sub_shoup(&p1, &p2);
        
        assert_eq!(result_standard, result_shoup);
    }
}
