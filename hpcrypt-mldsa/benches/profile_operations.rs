// Profile benchmark for ML-DSA operations
// This runs enough iterations to get good profiling data

use mldsa::params::MlDsa65;
use mldsa::keygen::keygen_from_seed;
use mldsa::sign::sign_deterministic;
use mldsa::verify::verify;

fn main() {
    println!("Starting ML-DSA profiling workload...");

    // Run KeyGen 1000 times
    println!("Profiling KeyGen (1000 iterations)...");
    for i in 0..1000 {
        let seed = [(i & 0xFF) as u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Use the keys to prevent optimization
        if i == 0 {
            println!("  First pk size: {} bytes", std::mem::size_of_val(&pk));
        }
    }

    // Run Sign 500 times (more expensive)
    println!("Profiling Sign (500 iterations)...");
    let seed = [42u8; 32];
    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"Profiling test message for ML-DSA signing";
    let rnd = [0u8; 32];

    for i in 0..500 {
        let signature = sign_deterministic::<MlDsa65>(&sk, message, &rnd).unwrap();

        if i == 0 {
            println!("  First signature size: {} bytes", std::mem::size_of_val(&signature));
        }
    }

    // Run Verify 1000 times
    println!("Profiling Verify (1000 iterations)...");
    let signature = sign_deterministic::<MlDsa65>(&sk, message, &rnd).unwrap();

    for i in 0..1000 {
        let valid = verify::<MlDsa65>(&pk, message, &signature);

        if i == 0 {
            println!("  First verify result: {}", valid);
        }
    }

    println!("Profiling workload complete!");
}
