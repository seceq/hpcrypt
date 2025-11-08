// Macros for generating unrolled field arithmetic operations
//
// These macros generate efficient inline unrolled code for squaring and other
// symmetric operations, eliminating loop overhead and improving performance.

/// Generate unrolled squaring for N-limb field elements
///
/// This macro generates all off-diagonal products once and doubles them,
/// then adds diagonal products. For N limbs, this requires:
/// - N*(N-1)/2 off-diagonal multiplications
/// - N diagonal multiplications
/// - Total: N*(N+1)/2 multiplications vs N^2 for naive multiplication
///
/// # Example
/// ```ignore
/// // For 4 limbs:
/// unrolled_square_symmetric!(4, a0, a1, a2, a3)
/// // Generates:
/// // m01 = a0*a1, m02 = a0*a2, m03 = a0*a3,
/// // m12 = a1*a2, m13 = a1*a3, m23 = a2*a3  (6 products)
/// // d0 = a0*a0, d1 = a1*a1, d2 = a2*a2, d3 = a3*a3  (4 products)
/// // Then combines with doubling: result[i+j] += 2*m_ij (i≠j), result[2i] += d_i
/// ```
macro_rules! unrolled_square_symmetric {
    // 4-limb version (for 64-bit FieldElement)
    (4, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        // Off-diagonal products (6 multiplications for 4x4 upper triangle)
        let m01 = $a0 * $a1;
        let m02 = $a0 * $a2;
        let m03 = $a0 * $a3;
        let m12 = $a1 * $a2;
        let m13 = $a1 * $a3;
        let m23 = $a2 * $a3;

        // Diagonal products (4 multiplications)
        let d0 = $a0 * $a0;
        let d1 = $a1 * $a1;
        let d2 = $a2 * $a2;
        let d3 = $a3 * $a3;

        // Return tuple: (diagonals, off-diagonals, combined 512-bit result)
        ([d0, d1, d2, d3], [m01, m02, m03, m12, m13, m23])
    }};

    // 5-limb version (for 52-bit FieldElement52)
    (5, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        // Off-diagonal products (10 multiplications for 5x5 upper triangle)
        let m01 = $a0 * $a1;
        let m02 = $a0 * $a2;
        let m03 = $a0 * $a3;
        let m04 = $a0 * $a4;
        let m12 = $a1 * $a2;
        let m13 = $a1 * $a3;
        let m14 = $a1 * $a4;
        let m23 = $a2 * $a3;
        let m24 = $a2 * $a4;
        let m34 = $a3 * $a4;

        // Diagonal products (5 multiplications)
        let d0 = $a0 * $a0;
        let d1 = $a1 * $a1;
        let d2 = $a2 * $a2;
        let d3 = $a3 * $a3;
        let d4 = $a4 * $a4;

        // Return tuple: (diagonals, off-diagonals)
        (
            [d0, d1, d2, d3, d4],
            [m01, m02, m03, m04, m12, m13, m14, m23, m24, m34],
        )
    }};
}

/// Combine symmetric square products into wide result with inline carry chain (64-bit, 4 limbs)
///
/// Takes precomputed diagonal and off-diagonal products and builds the 512-bit result
/// with inline carry propagation. This eliminates loops and enables better compiler optimization.
macro_rules! combine_square_64bit_inline {
    ($diag:expr, $off_diag:expr) => {{
        let [d0, d1, d2, d3] = $diag;
        let [m01, m02, m03, m12, m13, m23] = $off_diag;

        // Build 512-bit result with inline carry propagation
        // Result layout: wide[0..7] where wide = a^2
        //
        // Coefficients of 2^(64*i):
        // wide[0] = d0_lo
        // wide[1] = d0_hi + 2*m01_lo
        // wide[2] = 2*m01_hi + d1_lo + 2*m02_lo
        // wide[3] = 2*m02_hi + 2*m12_lo + d1_hi + 2*m03_lo
        // wide[4] = 2*m03_hi + 2*m12_hi + d2_lo + 2*m13_lo
        // wide[5] = 2*m13_hi + 2*m23_lo + d2_hi
        // wide[6] = 2*m23_hi + d3_lo
        // wide[7] = d3_hi

        // w0 = d0_lo
        let w0 = d0 as u64;

        // w1 = d0_hi + 2*m01_lo (+ carry from w0, which is 0)
        let t = (d0 >> 64) + (m01 << 1);
        let w1 = t as u64;

        // w2 = 2*m01_hi + d1_lo + 2*m02_lo (+ carry from w1)
        let t = (t >> 64) + (m01 >> 63) + d1 + (m02 << 1);
        let w2 = t as u64;

        // w3 = 2*m02_hi + 2*m12_lo + d1_hi + 2*m03_lo (+ carry from w2)
        let t = (t >> 64) + (m02 >> 63) + (d1 >> 64) + (m12 << 1) + (m03 << 1);
        let w3 = t as u64;

        // w4 = 2*m03_hi + 2*m12_hi + d2_lo + 2*m13_lo (+ carry from w3)
        let t = (t >> 64) + (m03 >> 63) + (m12 >> 63) + d2 + (m13 << 1);
        let w4 = t as u64;

        // w5 = 2*m13_hi + 2*m23_lo + d2_hi (+ carry from w4)
        let t = (t >> 64) + (m13 >> 63) + (d2 >> 64) + (m23 << 1);
        let w5 = t as u64;

        // w6 = 2*m23_hi + d3_lo (+ carry from w5)
        let t = (t >> 64) + (m23 >> 63) + d3;
        let w6 = t as u64;

        // w7 = d3_hi (+ carry from w6)
        let w7 = ((t >> 64) + (d3 >> 64)) as u64;

        [w0, w1, w2, w3, w4, w5, w6, w7]
    }};
}

/// Combine symmetric square products into wide result (52-bit, 5 limbs)
///
/// Takes precomputed diagonal and off-diagonal products and builds the 520-bit result.
/// Uses direct array construction with left shifts for doubling.
macro_rules! combine_square_52bit {
    ($diag:expr, $off_diag:expr) => {{
        let [d0, d1, d2, d3, d4] = $diag;
        let [m01, m02, m03, m04, m12, m13, m14, m23, m24, m34] = $off_diag;

        // Build result with inline doubling of off-diagonal terms
        // wide[i] = sum of terms whose powers of B (2^52) add up to i
        //
        // For 5 limbs a = [a0, a1, a2, a3, a4]:
        // a^2 = sum_{i,j} a[i]*a[j]*B^(i+j)
        //
        // Grouping by power k = i+j:
        // wide[0] = a0*a0                                   = d0
        // wide[1] = 2*a0*a1                                 = 2*m01
        // wide[2] = 2*a0*a2 + a1*a1 + 2*a1*a2              = 2*m02 + d1 + 2*m12
        // wide[3] = 2*a0*a3 + 2*a1*a3                      = 2*m03 + 2*m13
        // wide[4] = 2*a0*a4 + a2*a2 + 2*a1*a4 + 2*a2*a3   = 2*m04 + d2 + 2*m14 + 2*m23
        // wide[5] = 2*a2*a4 + 2*a3*a4                      = 2*m24 + 2*m34
        // wide[6] = a3*a3                                   = d3
        // wide[7] = 0                                       = 0
        // wide[8] = a4*a4                                   = d4
        // wide[9] = 0                                       = 0

        [
            d0,                                        // w0
            (m01 << 1),                                // w1
            (m02 << 1) + d1 + (m12 << 1),              // w2
            (m03 << 1) + (m13 << 1),                   // w3
            (m04 << 1) + d2 + (m14 << 1) + (m23 << 1), // w4
            (m24 << 1) + (m34 << 1),                   // w5
            d3,                                        // w6
            0u128,                                     // w7
            d4,                                        // w8
            0u128,                                     // w9
        ]
    }};
}

/// Generate a complete unrolled squaring function for 4 limbs (64-bit)
///
/// This is a convenience macro that combines product computation and carry propagation.
macro_rules! impl_unrolled_square_64bit {
    ($self:expr) => {{
        // Load limbs as u128 for computation
        let a0 = $self.limbs[0] as u128;
        let a1 = $self.limbs[1] as u128;
        let a2 = $self.limbs[2] as u128;
        let a3 = $self.limbs[3] as u128;

        // Compute products using macro
        let (diag, off_diag) = unrolled_square_symmetric!(4, a0, a1, a2, a3);

        // Combine into 512-bit result with inline carries
        let wide = combine_square_64bit_inline!(diag, off_diag);

        wide
    }};
}

/// Generate a complete unrolled squaring function for 5 limbs (52-bit)
///
/// This is a convenience macro that combines product computation and doubling.
macro_rules! impl_unrolled_square_52bit {
    ($self:expr) => {{
        let a = $self.normalized();

        // Load limbs as u128
        let a0 = a.limbs[0] as u128;
        let a1 = a.limbs[1] as u128;
        let a2 = a.limbs[2] as u128;
        let a3 = a.limbs[3] as u128;
        let a4 = a.limbs[4] as u128;

        // Compute products using macro
        let (diag, off_diag) = unrolled_square_symmetric!(5, a0, a1, a2, a3, a4);

        // Combine into 520-bit result
        let wide = combine_square_52bit!(diag, off_diag);

        wide
    }};
}

// Export macros for use in other modules
pub(crate) use {
    combine_square_52bit, combine_square_64bit_inline, impl_unrolled_square_52bit,
    impl_unrolled_square_64bit, unrolled_square_symmetric,
};
