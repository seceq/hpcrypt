//! CPU feature detection for SIMD optimizations

/// Check if AVX2 is available at runtime
#[inline]
pub fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_feature = "avx2")]
        {
            true
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            #[cfg(feature = "std")]
            {
                std::is_x86_feature_detected!("avx2")
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_detection() {
        let _avx2 = has_avx2();
    }
}
