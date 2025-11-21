//! Example: X25519 Key Exchange (ECDH)
//!
//! This example demonstrates how to use X25519 for Elliptic Curve Diffie-Hellman (ECDH):
//! - Generate keypairs for two parties
//! - Compute shared secrets
//! - Verify both parties derive the same shared secret
//! - Demonstrate security properties

use hpcrypt_curves::X25519;

fn main() {
    println!("=== X25519 Key Exchange Example ===\n");

    // Example 1: Basic key exchange between Alice and Bob
    println!("1. Basic Key Exchange:");

    // Alice generates her keypair
    let alice_private = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let alice_public = X25519::public_key(&alice_private);

    println!(
        "   Alice's private key: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        alice_private[0],
        alice_private[1],
        alice_private[2],
        alice_private[3],
        alice_private[28],
        alice_private[29],
        alice_private[30],
        alice_private[31]
    );
    println!(
        "   Alice's public key:  {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        alice_public[0],
        alice_public[1],
        alice_public[2],
        alice_public[3],
        alice_public[28],
        alice_public[29],
        alice_public[30],
        alice_public[31]
    );

    // Bob generates his keypair
    let bob_private = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    let bob_public = X25519::public_key(&bob_private);

    println!(
        "   Bob's private key:   {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        bob_private[0],
        bob_private[1],
        bob_private[2],
        bob_private[3],
        bob_private[28],
        bob_private[29],
        bob_private[30],
        bob_private[31]
    );
    println!(
        "   Bob's public key:    {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        bob_public[0],
        bob_public[1],
        bob_public[2],
        bob_public[3],
        bob_public[28],
        bob_public[29],
        bob_public[30],
        bob_public[31]
    );

    // Alice computes shared secret using her private key and Bob's public key
    let alice_shared = X25519::shared_secret(&alice_private, &bob_public)
        .expect("Failed to compute Alice's shared secret");

    // Bob computes shared secret using his private key and Alice's public key
    let bob_shared = X25519::shared_secret(&bob_private, &alice_public)
        .expect("Failed to compute Bob's shared secret");

    println!(
        "   Alice's shared:      {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        alice_shared[0],
        alice_shared[1],
        alice_shared[2],
        alice_shared[3],
        alice_shared[28],
        alice_shared[29],
        alice_shared[30],
        alice_shared[31]
    );
    println!(
        "   Bob's shared:        {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        bob_shared[0],
        bob_shared[1],
        bob_shared[2],
        bob_shared[3],
        bob_shared[28],
        bob_shared[29],
        bob_shared[30],
        bob_shared[31]
    );

    // Verify they computed the same shared secret
    if alice_shared == bob_shared {
        println!("   - Shared secrets match!");
    } else {
        println!("   - Shared secrets don't match (this shouldn't happen)");
    }
    println!();

    // Example 2: Multiple parties
    println!("2. Three-Party Key Exchange:");

    // Carol joins the conversation
    let carol_private = [0x42; 32];
    let carol_public = X25519::public_key(&carol_private);

    println!(
        "   Carol's public key: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        carol_public[0],
        carol_public[1],
        carol_public[2],
        carol_public[3],
        carol_public[28],
        carol_public[29],
        carol_public[30],
        carol_public[31]
    );

    // Each pair can establish a shared secret
    let alice_carol_shared = X25519::shared_secret(&alice_private, &carol_public).unwrap();
    let bob_carol_shared = X25519::shared_secret(&bob_private, &carol_public).unwrap();
    let carol_alice_shared = X25519::shared_secret(&carol_private, &alice_public).unwrap();

    println!(
        "   Alice-Carol shared: {:02x}{:02x}{:02x}{:02x}...",
        alice_carol_shared[0], alice_carol_shared[1], alice_carol_shared[2], alice_carol_shared[3]
    );
    println!(
        "   Bob-Carol shared:   {:02x}{:02x}{:02x}{:02x}...",
        bob_carol_shared[0], bob_carol_shared[1], bob_carol_shared[2], bob_carol_shared[3]
    );
    println!(
        "   Carol-Alice shared: {:02x}{:02x}{:02x}{:02x}...",
        carol_alice_shared[0], carol_alice_shared[1], carol_alice_shared[2], carol_alice_shared[3]
    );

    println!(
        "   Alice-Carol = Carol-Alice: {}",
        if alice_carol_shared == carol_alice_shared {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "   Alice-Carol ≠ Bob-Carol:   {}",
        if alice_carol_shared != bob_carol_shared {
            "- Correct"
        } else {
            "- Wrong"
        }
    );
    println!();

    // Example 3: Security property - public keys are safe to share
    println!("3. Public Key Security:");
    println!("   - Public keys can be shared openly");
    println!("   - Private keys must be kept secret");
    println!("   - Attacker with only public keys cannot compute shared secret");
    println!("   - Each party needs their private key + other's public key");
    println!();

    // Example 4: RFC 7748 Test Vector
    println!("4. RFC 7748 Compliance:");
    let rfc_alice_sk = [
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e,
        0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44,
        0x9a, 0xc4,
    ];
    let rfc_bob_pk = [
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f,
        0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab,
        0x1c, 0x4c,
    ];
    let rfc_expected_shared = [
        0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08,
        0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2,
        0x85, 0x52,
    ];

    let rfc_shared = X25519::shared_secret(&rfc_alice_sk, &rfc_bob_pk).unwrap();

    println!("   Test vector: RFC 7748 Section 6.1");
    println!(
        "   Computed:    {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        rfc_shared[0],
        rfc_shared[1],
        rfc_shared[2],
        rfc_shared[3],
        rfc_shared[28],
        rfc_shared[29],
        rfc_shared[30],
        rfc_shared[31]
    );
    println!(
        "   Expected:    {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        rfc_expected_shared[0],
        rfc_expected_shared[1],
        rfc_expected_shared[2],
        rfc_expected_shared[3],
        rfc_expected_shared[28],
        rfc_expected_shared[29],
        rfc_expected_shared[30],
        rfc_expected_shared[31]
    );
    println!(
        "   RFC Compliant: {}",
        if rfc_shared == rfc_expected_shared {
            "Yes"
        } else {
            "No"
        }
    );
    println!();

    // Example 5: Typical usage pattern
    println!("5. Typical Usage Pattern:");
    println!("   Step 1: Alice generates keypair");
    println!("   Step 2: Bob generates keypair");
    println!("   Step 3: Alice and Bob exchange public keys (over insecure channel)");
    println!("   Step 4: Alice computes shared secret = ECDH(alice_sk, bob_pk)");
    println!("   Step 5: Bob computes shared secret = ECDH(bob_sk, alice_pk)");
    println!("   Step 6: Both use shared secret for encryption (AES-GCM, ChaCha20, etc.)");
    println!();

    // Example 6: Use shared secret for encryption
    println!("6. Using Shared Secret:");
    println!("   - Derive encryption keys from shared secret (use KDF like HKDF)");
    println!("   - Use for AES-GCM or ChaCha20-Poly1305 AEAD");
    println!("   - Forward secrecy: generate new keypairs for each session");
    println!("   - Don't reuse shared secrets across sessions");

    println!("\n=== Example Complete ===");
}
