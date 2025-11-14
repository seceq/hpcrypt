//! Parallel Batch Signing Examples
//!
//! This example demonstrates how to implement parallel batch signing using
//! different threading models. All cryptographic functions in this library
//! are thread-safe, allowing applications to choose their own parallelization
//! strategy.
//!
//! # Running Examples
//!
//! ```bash
//! # Rayon example (data parallelism)
//! cargo run --example parallel_signing --release --features avx2,simd rayon
//!
//! # Thread pool example (manual threading)
//! cargo run --example parallel_signing --release --features avx2,simd threads
//!
//! # Tokio example (async runtime)
//! cargo run --example parallel_signing --release --features avx2,simd,std tokio
//! ```

use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::params::MlDsa65;
use hpcrypt_mldsa::sign::sign;
use hpcrypt_mldsa::verify::verify;
use std::sync::Arc;
use std::time::Instant;

/// Example 1: Parallel signing with Rayon (recommended for CPU-bound work)
///
/// Rayon provides data parallelism with a work-stealing thread pool.
/// Best for batch processing when all messages are available upfront.
fn example_rayon() {
    println!("\n=== Example 1: Rayon Parallel Iterator ===\n");

    // Add rayon to your Cargo.toml:
    // [dependencies]
    // rayon = "1.8"

    #[allow(unexpected_cfgs)]
    {
        #[cfg_attr(not(feature = "rayon_example"), allow(unreachable_code))]
        #[cfg(feature = "rayon_example")]
        {
            use rayon::prelude::*;

            let (pk, sk) = keygen::<MlDsa65>();

            // Generate test messages
            let messages: Vec<Vec<u8>> = (0..100)
                .map(|i| format!("Message {}", i).into_bytes())
                .collect();
            let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

            // Benchmark sequential
            let start = Instant::now();
            let _sigs_seq: Vec<_> = msg_refs.iter().map(|msg| sign(&sk, msg)).collect();
            let seq_time = start.elapsed();

            // Benchmark parallel
            let start = Instant::now();
            let sigs_par: Vec<_> = msg_refs.par_iter().map(|msg| sign(&sk, msg)).collect();
            let par_time = start.elapsed();

            // Verify all signatures
            let all_valid = messages.iter().zip(sigs_par.iter()).all(|(msg, sig_opt)| {
                sig_opt
                    .as_ref()
                    .map(|sig| verify(&pk, msg, sig))
                    .unwrap_or(false)
            });

            println!("Messages:        100");
            println!("Sequential time: {:?}", seq_time);
            println!("Parallel time:   {:?}", par_time);
            println!(
                "Speedup:         {:.2}x",
                seq_time.as_secs_f64() / par_time.as_secs_f64()
            );
            println!("All valid:       {}", all_valid);
            println!("\nCode:");
            println!("  use rayon::prelude::*;");
            println!("  let sigs: Vec<_> = messages.par_iter()");
            println!("      .map(|msg| sign(&sk, msg))");
            println!("      .collect();");
        }

        #[cfg_attr(feature = "rayon_example", allow(unreachable_code))]
        #[cfg(not(feature = "rayon_example"))]
        {
            println!("Rayon example not enabled.");
            println!("\nTo run this example, add to Cargo.toml:");
            println!("  [dependencies]");
            println!("  rayon = \"1.8\"");
            println!("\nThen uncomment the rayon example code.");
        }
    }
}

/// Example 2: Manual thread pool
///
/// Using standard library threads with a simple work distribution.
/// Good when you need explicit control over thread count and scheduling.
fn example_thread_pool() {
    println!("\n=== Example 2: Manual Thread Pool ===\n");

    use std::thread;

    let (pk, sk) = keygen::<MlDsa65>();
    let sk = Arc::new(sk);
    let pk = Arc::new(pk);

    // Generate test messages
    let messages: Vec<Vec<u8>> = (0..100)
        .map(|i| format!("Message {}", i).into_bytes())
        .collect();
    let messages = Arc::new(messages);

    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let chunk_size = (messages.len() + num_threads - 1) / num_threads;

    println!("Messages:     100");
    println!("Threads:      {}", num_threads);
    println!("Chunk size:   {}", chunk_size);

    let start = Instant::now();

    // Spawn worker threads
    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let sk = Arc::clone(&sk);
            let messages = Arc::clone(&messages);

            thread::spawn(move || {
                let start_idx = thread_id * chunk_size;
                let end_idx = ((thread_id + 1) * chunk_size).min(messages.len());

                let mut sigs = Vec::new();
                for i in start_idx..end_idx {
                    let sig = sign(&sk, &messages[i]);
                    sigs.push(sig);
                }
                sigs
            })
        })
        .collect();

    // Collect results
    let mut all_sigs = Vec::new();
    for handle in handles {
        let sigs = handle.join().unwrap();
        all_sigs.extend(sigs);
    }

    let elapsed = start.elapsed();

    // Verify
    let all_valid = messages.iter().zip(all_sigs.iter()).all(|(msg, sig_opt)| {
        sig_opt
            .as_ref()
            .map(|sig| verify(&pk, msg, sig))
            .unwrap_or(false)
    });

    println!("Time:         {:?}", elapsed);
    println!(
        "Throughput:   {:.0} sigs/sec",
        100.0 / elapsed.as_secs_f64()
    );
    println!("All valid:    {}", all_valid);
    println!("\nCode:");
    println!("  let handles: Vec<_> = (0..num_threads).map(|id| {{");
    println!("      thread::spawn(move || {{");
    println!("          // Process chunk of messages");
    println!("      }})");
    println!("  }}).collect();");
}

/// Example 3: Tokio async runtime (blocking tasks)
///
/// Using Tokio's spawn_blocking for CPU-bound crypto operations.
/// Good for servers that mix I/O and CPU-bound work.
fn example_tokio() {
    println!("\n=== Example 3: Tokio spawn_blocking ===\n");

    // Add tokio to your Cargo.toml:
    // [dependencies]
    // tokio = { version = "1", features = ["full"] }

    #[allow(unexpected_cfgs)]
    {
        #[cfg_attr(not(feature = "tokio_example"), allow(unreachable_code))]
        #[cfg(feature = "tokio_example")]
        {
            use tokio::task;

            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                let (pk, sk) = keygen::<MlDsa65>();
                let sk = Arc::new(sk);
                let pk = Arc::new(pk);

                // Generate test messages
                let messages: Vec<Vec<u8>> = (0..100)
                    .map(|i| format!("Message {}", i).into_bytes())
                    .collect();

                println!("Messages: 100");

                let start = Instant::now();

                // Spawn blocking tasks
                let mut handles = Vec::new();
                for msg in messages.iter() {
                    let sk = Arc::clone(&sk);
                    let msg = msg.clone();

                    let handle = task::spawn_blocking(move || sign(&sk, &msg));

                    handles.push(handle);
                }

                // Await all results
                let mut sigs = Vec::new();
                for handle in handles {
                    let sig = handle.await.unwrap();
                    sigs.push(sig);
                }

                let elapsed = start.elapsed();

                // Verify
                let all_valid = messages.iter().zip(sigs.iter()).all(|(msg, sig_opt)| {
                    sig_opt
                        .as_ref()
                        .map(|sig| verify(&pk, msg, sig))
                        .unwrap_or(false)
                });

                println!("Time:       {:?}", elapsed);
                println!("Throughput: {:.0} sigs/sec", 100.0 / elapsed.as_secs_f64());
                println!("All valid:  {}", all_valid);
                println!("\nCode:");
                println!("  let handle = tokio::task::spawn_blocking(move || {{");
                println!("      sign(&sk, &msg)");
                println!("  }});");
                println!("  let sig = handle.await?;");
            });
        }

        #[cfg_attr(feature = "tokio_example", allow(unreachable_code))]
        #[cfg(not(feature = "tokio_example"))]
        {
            println!("Tokio example not enabled.");
            println!("\nTo run this example, add to Cargo.toml:");
            println!("  [dependencies]");
            println!("  tokio = {{ version = \"1\", features = [\"full\"] }}");
            println!("\nThen uncomment the tokio example code.");
        }
    }
}

/// Example 4: Simple sequential baseline for comparison
///
/// Process messages sequentially to compare against parallel versions.
fn example_sequential() {
    println!("\n=== Example 4: Sequential (Baseline) ===\n");

    let (pk, sk) = keygen::<MlDsa65>();

    // Generate test messages
    let messages: Vec<Vec<u8>> = (0..100)
        .map(|i| format!("Message {}", i).into_bytes())
        .collect();

    println!("Messages: 100");

    let start = Instant::now();

    // Sequential processing
    let sigs: Vec<_> = messages.iter().map(|msg| sign(&sk, msg)).collect();

    let elapsed = start.elapsed();

    // Verify
    let all_valid = messages.iter().zip(sigs.iter()).all(|(msg, sig_opt)| {
        sig_opt
            .as_ref()
            .map(|sig| verify(&pk, msg, sig))
            .unwrap_or(false)
    });

    println!("Time:       {:?}", elapsed);
    println!("Throughput: {:.0} sigs/sec", 100.0 / elapsed.as_secs_f64());
    println!("All valid:  {}", all_valid);
    println!("\nCode:");
    println!("  let sigs: Vec<_> = messages.iter()");
    println!("      .map(|msg| sign(&sk, msg))");
    println!("      .collect();");
    println!("\n  // Compare this to parallel versions above");
}

fn main() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║         ML-DSA Parallel Signing Examples                 ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("\nAll cryptographic functions are thread-safe.");
    println!("Choose the threading model that fits your application:");

    let args: Vec<String> = std::env::args().collect();
    let example = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    match example {
        "rayon" => example_rayon(),
        "threads" => example_thread_pool(),
        "tokio" => example_tokio(),
        "sequential" => example_sequential(),
        "all" => {
            example_sequential();
            example_rayon();
            example_thread_pool();
            example_tokio();
        }
        _ => {
            println!("\nUsage: parallel_signing [rayon|threads|tokio|sequential|all]");
            println!("\nExamples:");
            println!("  cargo run --example parallel_signing --release sequential");
            println!("  cargo run --example parallel_signing --release rayon");
            println!("  cargo run --example parallel_signing --release threads");
            println!("  cargo run --example parallel_signing --release tokio");
        }
    }

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║ Recommendation: Use Rayon for CPU-bound batch processing ║");
    println!("║                 Use Tokio for mixed I/O + CPU work       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
}
