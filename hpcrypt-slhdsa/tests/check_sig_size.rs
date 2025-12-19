use hpcrypt_slhdsa::{Sha2_128f, KeyPair};
use rand::rngs::OsRng;

#[test]
fn check_signature_size() {
    let keypair = KeyPair::<Sha2_128f>::generate(&mut OsRng);
    let message = b"Test message";
    
    // Pure signing
    let sig1 = hpcrypt_slhdsa::sign(&keypair.secret_key, message);
    println!("Pure sign signature size: {} bytes (expected ~17088)", sig1.len());
    
    // Context signing
    let sig2 = hpcrypt_slhdsa::sign_ctx(&keypair.secret_key, b"context", message);
    println!("sign_ctx signature size: {} bytes (expected ~17088)", sig2.len());
    
    // Prehash signing
    let sig3 = hpcrypt_slhdsa::sign_prehash(&keypair.secret_key, b"context", "SHA2-256", message).unwrap();
    println!("sign_prehash signature size: {} bytes (expected ~17088)", sig3.len());
    
    assert_eq!(sig1.len(), Sha2_128f::SIG_BYTES);
    assert_eq!(sig2.len(), Sha2_128f::SIG_BYTES);
    assert_eq!(sig3.len(), Sha2_128f::SIG_BYTES);
}
