use hpcrypt_mldsa::{MlDsa44, DsaParams};
use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::sign::sign;
use hpcrypt_mldsa::verify::verify;
use hpcrypt_mldsa::{sign_batch, verify_batch};

fn main() {
    println!("Testing batch verification with different sizes...\n");

    let (pk, sk) = keygen::<MlDsa44>();

    // Test with 2 signatures (should use simple loop)
    println!("=== Testing with 2 signatures (simple loop path) ===");
    let messages_2 = vec![
        b"Message 1".as_slice(),
        b"Message 2".as_slice(),
    ];
    
    let sigs_2 = sign_batch(&sk, &messages_2);
    let sig_refs_2: Vec<_> = sigs_2.iter().map(|s| s.as_ref().unwrap()).collect();
    
    let results_2 = verify_batch(&pk, &messages_2, &sig_refs_2);
    println!("Batch results: {:?}", results_2);
    
    for (i, &result) in results_2.iter().enumerate() {
        let individual = verify(&pk, messages_2[i], sig_refs_2[i]);
        println!("  Sig {}: batch={}, individual={}", i, result, individual);
    }

    // Test with 4 signatures (should use optimized path)
    println!("\n=== Testing with 4 signatures (optimized path) ===");
    let messages_4 = vec![
        b"Message 1".as_slice(),
        b"Message 2".as_slice(),
        b"Message 3".as_slice(),
        b"Message 4".as_slice(),
    ];
    
    let sigs_4 = sign_batch(&sk, &messages_4);
    let sig_refs_4: Vec<_> = sigs_4.iter().map(|s| s.as_ref().unwrap()).collect();
    
    let results_4 = verify_batch(&pk, &messages_4, &sig_refs_4);
    println!("Batch results: {:?}", results_4);
    
    for (i, &result) in results_4.iter().enumerate() {
        let individual = verify(&pk, messages_4[i], sig_refs_4[i]);
        println!("  Sig {}: batch={}, individual={}", i, result, individual);
    }
}
