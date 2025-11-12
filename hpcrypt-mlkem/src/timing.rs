//! Timing Analysis and Verification
//!
//! This module provides tools for analyzing the timing behavior of cryptographic
//! operations to detect potential timing side-channels. It implements a dudect-inspired
//! statistical testing framework.
//!
//! **Note**: This module requires `std` and is only available in test builds.
//!
//! # About DudeCT
//!
//! DudeCT (Dude, is my code Constant Time?) is a statistical approach to detecting
//! timing side-channels. It uses Welch's t-test to determine if two classes of inputs
//! (e.g., with different secrets) result in statistically different execution times.
//!
//! # How It Works
//!
//! 1. **Prepare two classes of inputs**: Class A and Class B
//! 2. **Execute many times**: Measure timing for both classes (randomized order)
//! 3. **Statistical analysis**: Apply t-test to detect timing differences
//! 4. **Interpret results**: |t| > 4.5 indicates potential timing leak
//!
//! # Limitations
//!
//! This is a simplified implementation suitable for development testing.
//! For production-grade verification, use:
//! - [`dudect-bencher`](https://crates.io/crates/dudect-bencher)
//! - [`ctgrind`](https://github.com/agl/ctgrind)
//! - Manual assembly inspection
//!
//! # References
//!
//! - "DudeCT: Practical Constant-Time Leakage Detection" (CCS 2017)
//! - https://github.com/oreparaz/dudect

use std::time::Instant;
use std::vec::Vec;

/// Statistical timing measurement result
#[derive(Debug, Clone)]
pub struct TimingMeasurement {
    /// Mean execution time for class A
    pub mean_a: f64,
    /// Mean execution time for class B
    pub mean_b: f64,
    /// Variance of class A
    pub var_a: f64,
    /// Variance of class B
    pub var_b: f64,
    /// Number of samples for class A
    pub n_a: usize,
    /// Number of samples for class B
    pub n_b: usize,
    /// Welch's t-statistic
    pub t_statistic: f64,
}

impl TimingMeasurement {
    /// Check if timing difference is statistically significant
    ///
    /// Returns true if |t| > 4.5, indicating potential timing leak
    /// (This is a commonly used threshold in timing analysis)
    pub fn is_leaking(&self) -> bool {
        self.t_statistic.abs() > 4.5
    }

    /// Get confidence level that timing is constant
    ///
    /// Higher is better. Values above 95% suggest constant-time behavior.
    pub fn confidence(&self) -> f64 {
        // Rough confidence based on t-statistic
        // |t| < 2.0 is roughly 95% confidence level
        // |t| < 4.5 is very high confidence
        let abs_t = self.t_statistic.abs();
        if abs_t < 2.0 {
            95.0
        } else if abs_t < 4.5 {
            95.0 - (abs_t - 2.0) * 10.0
        } else {
            0.0
        }
    }
}

/// Timing analyzer for detecting constant-time violations
pub struct TimingAnalyzer {
    measurements_a: Vec<f64>,
    measurements_b: Vec<f64>,
}

impl Default for TimingAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TimingAnalyzer {
    /// Create a new timing analyzer
    pub fn new() -> Self {
        Self {
            measurements_a: Vec::new(),
            measurements_b: Vec::new(),
        }
    }

    /// Run timing analysis on two operations
    ///
    /// # Arguments
    ///
    /// * `iterations` - Number of iterations per class
    /// * `warmup` - Number of warmup iterations (discarded)
    /// * `class_a` - Operation for class A
    /// * `class_b` - Operation for class B
    ///
    /// # Returns
    ///
    /// Timing measurement with statistical analysis
    pub fn analyze<F, G>(&mut self, iterations: usize, warmup: usize, mut class_a: F, mut class_b: G) -> TimingMeasurement
    where
        F: FnMut(),
        G: FnMut(),
    {
        self.measurements_a.clear();
        self.measurements_b.clear();

        // Warmup phase
        for _ in 0..warmup {
            class_a();
            class_b();
        }

        // Measurement phase - randomize order to reduce systematic bias
        let mut rng = SmallRng::new(42);

        for _ in 0..iterations {
            if rng.next() % 2 == 0 {
                // Measure A then B
                let start = Instant::now();
                class_a();
                let duration_a = start.elapsed().as_nanos() as f64;
                self.measurements_a.push(duration_a);

                let start = Instant::now();
                class_b();
                let duration_b = start.elapsed().as_nanos() as f64;
                self.measurements_b.push(duration_b);
            } else {
                // Measure B then A
                let start = Instant::now();
                class_b();
                let duration_b = start.elapsed().as_nanos() as f64;
                self.measurements_b.push(duration_b);

                let start = Instant::now();
                class_a();
                let duration_a = start.elapsed().as_nanos() as f64;
                self.measurements_a.push(duration_a);
            }
        }

        self.compute_statistics()
    }

    /// Compute statistical measures from collected timings
    fn compute_statistics(&self) -> TimingMeasurement {
        let mean_a = mean(&self.measurements_a);
        let mean_b = mean(&self.measurements_b);
        let var_a = variance(&self.measurements_a, mean_a);
        let var_b = variance(&self.measurements_b, mean_b);

        let n_a = self.measurements_a.len();
        let n_b = self.measurements_b.len();

        // Welch's t-test statistic
        let t_statistic = welch_t_test(mean_a, mean_b, var_a, var_b, n_a, n_b);

        TimingMeasurement {
            mean_a,
            mean_b,
            var_a,
            var_b,
            n_a,
            n_b,
            t_statistic,
        }
    }
}

/// Calculate mean of samples
fn mean(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<f64>() / samples.len() as f64
}

/// Calculate variance of samples
fn variance(samples: &[f64], mean: f64) -> f64 {
    if samples.len() <= 1 {
        return 0.0;
    }
    samples.iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f64>() / (samples.len() - 1) as f64
}

/// Welch's t-test statistic
///
/// Tests if two samples have different means, accounting for different variances
fn welch_t_test(mean_a: f64, mean_b: f64, var_a: f64, var_b: f64, n_a: usize, n_b: usize) -> f64 {
    let numerator = mean_a - mean_b;
    let denominator = ((var_a / n_a as f64) + (var_b / n_b as f64)).sqrt();

    if denominator == 0.0 {
        return 0.0;
    }

    numerator / denominator
}

/// Simple pseudo-random number generator for timing tests
/// (Not cryptographically secure - only for test randomization)
struct SmallRng {
    state: u64,
}

impl SmallRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        // Simple LCG
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;

    #[test]
    fn test_timing_analyzer_same_operations() {
        // Test that identical operations show no timing difference
        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            1000,
            10,
            || { black_box(1 + 1); },
            || { black_box(1 + 1); },
        );

        // T-statistic should be small for identical operations
        assert!(result.t_statistic.abs() < 10.0,
            "Identical operations should have small t-statistic, got {}",
            result.t_statistic);
    }

    #[test]
    fn test_timing_analyzer_different_operations() {
        // Test that obviously different operations are detected
        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            1000,
            10,
            || {
                // Fast operation
                black_box(1 + 1);
            },
            || {
                // Slow operation
                for _ in 0..1000 {
                    black_box(1 + 1);
                }
            },
        );

        // Should detect timing difference
        assert!(result.t_statistic.abs() > 4.5,
            "Different operations should be detected, got t={}",
            result.t_statistic);

        assert!(result.is_leaking(),
            "Different operations should be flagged as leaking");
    }

    #[test]
    fn test_timing_measurement_confidence() {
        let good_timing = TimingMeasurement {
            mean_a: 100.0,
            mean_b: 101.0,
            var_a: 10.0,
            var_b: 10.0,
            n_a: 1000,
            n_b: 1000,
            t_statistic: 1.5,
        };

        assert!(!good_timing.is_leaking());
        assert!(good_timing.confidence() > 90.0);

        let bad_timing = TimingMeasurement {
            mean_a: 100.0,
            mean_b: 200.0,
            var_a: 10.0,
            var_b: 10.0,
            n_a: 1000,
            n_b: 1000,
            t_statistic: 50.0,
        };

        assert!(bad_timing.is_leaking());
        assert!(bad_timing.confidence() < 50.0);
    }

    #[test]
    fn test_mean_calculation() {
        let samples = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(mean(&samples), 3.0);

        let empty: Vec<f64> = vec![];
        assert_eq!(mean(&empty), 0.0);
    }

    #[test]
    fn test_variance_calculation() {
        let samples = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let m = mean(&samples);
        let v = variance(&samples, m);

        // Variance should be 10.0 for this sequence
        assert!((v - 10.0).abs() < 0.01, "Expected variance ~10.0, got {}", v);
    }

    #[test]
    fn test_welch_t_test_calculation() {
        // Test case where means are clearly different
        let t = welch_t_test(100.0, 110.0, 25.0, 25.0, 100, 100);
        assert!(t.abs() > 1.0, "Expected significant t-statistic, got {}", t);

        // Test case where means are identical
        let t = welch_t_test(100.0, 100.0, 25.0, 25.0, 100, 100);
        assert!(t.abs() < 0.1, "Expected near-zero t-statistic, got {}", t);
    }
}
