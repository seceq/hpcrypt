//! SHA-1 usage in SRP-6a protocol (RFC 5054)
//!
//! This example demonstrates how SHA-1 is used in the Secure Remote Password
//! protocol, which is one of the primary use cases for SHA-1 in modern systems.
//!
//! **NOTE**: SRP-6a specifically requires SHA-1 per RFC 5054, which is why
//! we continue to support it despite SHA-1 being cryptographically broken.
//!
//! Run with: cargo run --example sha1_srp

use hpcrypt_hash::sha1::{sha1, Sha1};

fn main() {
    println!("=== SHA-1 in SRP-6a Protocol ===\n");
    println!("SRP-6a (RFC 5054) uses SHA-1 as its hash function.\n");

    // SRP parameters
    let username = b"alice";
    let password = b"password123";
    let salt = b"random_salt_value";

    // Example 1: Computing the password hash
    println!("1. SRP Password Hashing:");
    println!("   Username: {}", String::from_utf8_lossy(username));
    println!("   Password: {}", String::from_utf8_lossy(password));
    println!("   Salt: {}", hex_encode(salt));

    // In SRP, we compute: x = H(salt | H(username | ":" | password))
    let mut inner_hasher = Sha1::new();
    inner_hasher.update(username);
    inner_hasher.update(b":");
    inner_hasher.update(password);
    let inner_hash = inner_hasher.finalize();

    println!("   H(username:password) = {}", hex_encode(&inner_hash));

    let mut outer_hasher = Sha1::new();
    outer_hasher.update(salt);
    outer_hasher.update(&inner_hash);
    let x = outer_hasher.finalize();

    println!("   x = H(salt | H(username:password))");
    println!("     = {}", hex_encode(&x));
    println!();

    // Example 2: Computing the scrambling parameter 'u'
    println!("2. SRP Scrambling Parameter:");
    let a_pub = b"client_public_ephemeral";
    let b_pub = b"server_public_ephemeral";

    // u = H(A | B) where A and B are public ephemeral values
    let mut hasher = Sha1::new();
    hasher.update(a_pub);
    hasher.update(b_pub);
    let u = hasher.finalize();

    println!("   Client public (A): {}", hex_encode(a_pub));
    println!("   Server public (B): {}", hex_encode(b_pub));
    println!("   u = H(A | B) = {}", hex_encode(&u));
    println!();

    // Example 3: Session key derivation
    println!("3. SRP Session Key Derivation:");
    let shared_secret = b"computed_shared_secret_S";

    // K = H(S)
    let session_key = sha1(shared_secret);
    println!("   Shared secret (S): {}", hex_encode(shared_secret));
    println!("   Session key (K) = H(S)");
    println!("   K = {}", hex_encode(&session_key));
    println!();

    // Example 4: Client proof (M1)
    println!("4. SRP Client Proof:");
    // M1 = H(H(N) XOR H(g) | H(username) | salt | A | B | K)
    let n = b"modulus_N";
    let g = b"generator_g";

    let h_n = sha1(n);
    let h_g = sha1(g);
    let h_username = sha1(username);

    // Simplified version for demonstration
    let mut m1_hasher = Sha1::new();
    // In real SRP, we'd XOR H(N) and H(g)
    m1_hasher.update(&h_n);
    m1_hasher.update(&h_g);
    m1_hasher.update(&h_username);
    m1_hasher.update(salt);
    m1_hasher.update(a_pub);
    m1_hasher.update(b_pub);
    m1_hasher.update(&session_key);
    let m1 = m1_hasher.finalize();

    println!("   Client proof (M1) = {}", hex_encode(&m1));
    println!();

    // Example 5: Server proof (M2)
    println!("5. SRP Server Proof:");
    // M2 = H(A | M1 | K)
    let mut m2_hasher = Sha1::new();
    m2_hasher.update(a_pub);
    m2_hasher.update(&m1);
    m2_hasher.update(&session_key);
    let m2 = m2_hasher.finalize();

    println!("   Server proof (M2) = H(A | M1 | K)");
    println!("   M2 = {}", hex_encode(&m2));
    println!();

    println!("=== Why SRP Still Uses SHA-1 ===");
    println!("While SHA-1 is broken for collision resistance, SRP-6a uses it");
    println!("in contexts where collision resistance is not the primary requirement.");
    println!("The protocol relies more on the discrete logarithm problem than");
    println!("hash collision resistance. However, newer protocols should prefer");
    println!("SHA-256 or stronger hash functions.");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}
