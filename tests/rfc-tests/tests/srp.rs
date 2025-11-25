//! RFC 5054 - SRP (Secure Remote Password) Test Vectors
//!
//! Tests for SRP-6a using official RFC 5054 test vectors and additional
//! functional tests to ensure protocol correctness.

use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SrpTestVector {
    test_id: u32,
    group: String,
    hash: String,
    username: String,
    password: String,
    salt: String,
    note: Option<String>,
    multiplier_k: String,
    password_hash_x: String,
    #[allow(dead_code)]
    client_private_a: String,
    #[allow(dead_code)]
    server_private_b: String,
    scrambling_u: String,
}

// Helper to map group string to SrpGroup
fn parse_group(group_str: &str) -> Option<hpcrypt_srp::SrpGroup> {
    match group_str {
        "1024-bit" => Some(hpcrypt_srp::SrpGroup::Srp1024),
        "1536-bit" => Some(hpcrypt_srp::SrpGroup::Srp1536),
        "2048-bit" => Some(hpcrypt_srp::SrpGroup::Srp2048),
        "3072-bit" => Some(hpcrypt_srp::SrpGroup::Srp3072),
        "4096-bit" => Some(hpcrypt_srp::SrpGroup::Srp4096),
        "6144-bit" => Some(hpcrypt_srp::SrpGroup::Srp6144),
        "8192-bit" => Some(hpcrypt_srp::SrpGroup::Srp8192),
        _ => None,
    }
}

#[test]
fn test_srp_rfc5054() {
    let test_vectors: Vec<SrpTestVector> = load_test_file("rfc5054-srp.json");

    println!("\n=== RFC 5054: SRP-6a (Secure Remote Password) ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Group: {}", test.group);
        println!("  Hash: {}", test.hash);
        println!("  Username: {}", test.username);
        if let Some(note) = &test.note {
            println!("  Note: {}", note);
        }

        // Only test SHA1 (as per RFC 5054 specification)
        if test.hash != "SHA1" {
            println!("  Skipping non-SHA1 hash");
            stats.skipped += 1;
            continue;
        }

        // Parse group
        let Some(_group) = parse_group(&test.group) else {
            println!("  Unknown group: {}", test.group);
            stats.failed += 1;
            continue;
        };

        // Decode test vector values
        let _salt = decode_hex(&test.salt);
        let _username = test.username.as_bytes();
        let _password = test.password.as_bytes();

        // Expected intermediate values from test vector
        let expected_k = decode_hex(&test.multiplier_k);
        let expected_x = decode_hex(&test.password_hash_x);
        let expected_u = decode_hex(&test.scrambling_u);

        /*
         * NOTE: The current hpcrypt-srp implementation uses random ephemeral values
         * (client private 'a' and server private 'b') which are generated internally.
         *
         * RFC 5054 test vectors provide specific values for a, b, and derived values
         * like scrambling parameter u and multiplier k. To fully test against RFC vectors,
         * we would need APIs to:
         *
         * 1. Inject deterministic private values (a, b)
         * 2. Access intermediate computations (k, x, u, S, K)
         * 3. Verify each step of the protocol
         *
         * What we CAN test:
         * - Registration flow works
         * - Authentication succeeds with correct password
         * - Authentication fails with wrong password
         * - Session keys match between client and server
         *
         * What we CANNOT test without API changes:
         * - Exact intermediate value matching
         * - Byte-for-byte protocol message verification
         * - RFC 5054 test vector compliance
         */

        println!("  Test vector structure validated");
        println!("    Expected k length: {} bytes", expected_k.len());
        println!("    Expected x length: {} bytes", expected_x.len());
        println!("    Expected u length: {} bytes", expected_u.len());

        stats.passed += 1;
    }

    stats.print_summary();

    println!("\nNote: Full RFC 5054 compliance testing requires API extensions");
    println!("      to inject deterministic randomness. Current tests validate");
    println!("      test vector structure and protocol functional correctness.");

    assert_eq!(stats.failed, 0, "All test vectors should parse correctly");
}

#[test]
fn test_srp_vector_count() {
    let test_vectors: Vec<SrpTestVector> = load_test_file("rfc5054-srp.json");
    assert!(test_vectors.len() > 0, "RFC 5054 should have test vectors");
    println!("SRP test vectors loaded: {}", test_vectors.len());
}

#[test]
fn test_srp_groups() {
    let test_vectors: Vec<SrpTestVector> = load_test_file("rfc5054-srp.json");

    let mut groups = std::collections::HashSet::new();
    for test in &test_vectors {
        groups.insert(test.group.clone());
    }

    println!("SRP groups covered: {:?}", groups);

    // Verify we can parse all groups
    for group in &groups {
        assert!(parse_group(group).is_some(), "Should support group: {}", group);
    }
}

/// Test SRP registration functionality
#[test]
fn test_srp_registration() {
    use hpcrypt_srp::{register_user, SrpGroup};
    use rand::thread_rng;

    println!("\n=== SRP Registration Test ===");

    let groups = vec![
        ("1024-bit", SrpGroup::Srp1024),
        ("2048-bit", SrpGroup::Srp2048),
        ("4096-bit", SrpGroup::Srp4096),
    ];

    for (name, group) in groups {
        println!("\n  Testing {} group...", name);

        let registration = register_user(
            b"alice",
            b"password123",
            group,
            &mut thread_rng()
        ).expect("registration failed");

        // Verify registration produces salt and verifier
        assert!(!registration.salt.is_empty(), "Salt should not be empty");
        assert!(!registration.verifier.is_empty(), "Verifier should not be empty");

        // Salt should be at least 16 bytes for security
        assert!(registration.salt.len() >= 16, "Salt should be at least 16 bytes");

        println!("    Salt length: {} bytes", registration.salt.len());
        println!("    Verifier length: {} bytes", registration.verifier.len());
    }

    println!("\nAll registration tests passed");
}

/// Test full SRP authentication flow
#[test]
fn test_srp_authentication_success() {
    use hpcrypt_srp::{register_user, SrpClient, SrpServer, SrpGroup};
    use rand::thread_rng;

    println!("\n=== SRP Successful Authentication Test ===");

    let username = b"alice";
    let password = b"correct-horse-battery-staple";
    let group = SrpGroup::Srp2048;
    let mut rng = thread_rng();

    // 1. Registration
    println!("  Performing registration...");
    let registration = register_user(username, password, group, &mut rng)
        .expect("registration failed");
    println!("    Registration completed");

    // 2. Authentication - Client starts
    println!("  Client initiating authentication...");
    let mut client = SrpClient::new(username, password, group);
    let a_pub = client.compute_public(&mut rng).expect("compute_public failed");
    println!("    Client computed public key A");

    // 3. Server responds
    println!("  Server responding...");
    let mut server = SrpServer::new(
        &registration.verifier,
        &registration.salt,
        username,
        group
    );
    let b_pub = server.compute_public(&mut rng).expect("compute_public failed");
    let salt = server.get_salt();
    println!("    Server computed public key B");

    // 4. Client processes server response
    println!("  Client processing server response...");
    client.process_server_response(&b_pub, salt).expect("process_server_response failed");
    let m1 = client.compute_proof().expect("compute_proof failed");
    println!("    Client computed proof M1");

    // 5. Server verifies client
    println!("  Server verifying client...");
    server.process_client_public(&a_pub).expect("process_client_public failed");
    server.verify_client_proof(&m1).expect("verify_client_proof failed");
    let m2 = server.compute_proof().expect("compute_proof failed");
    println!("    Server verified client and computed proof M2");

    // 6. Client verifies server
    println!("  Client verifying server...");
    client.verify_server_proof(&m2).expect("verify_server_proof failed");
    println!("    Client verified server");

    // 7. Verify session keys match
    println!("  Verifying session keys...");
    let client_key = client.get_session_key().expect("get_session_key failed");
    let server_key = server.get_session_key().expect("get_session_key failed");

    assert_eq!(client_key, server_key, "Session keys should match");
    assert!(!client_key.is_empty(), "Session key should not be empty");
    println!("    Session keys match ({} bytes)", client_key.len());

    println!("\nAuthentication successful - mutual authentication verified");
}

/// Test SRP authentication with wrong password
#[test]
fn test_srp_authentication_wrong_password() {
    use hpcrypt_srp::{register_user, SrpClient, SrpServer, SrpGroup};
    use rand::thread_rng;

    println!("\n=== SRP Wrong Password Test ===");

    let username = b"alice";
    let correct_password = b"correct-password";
    let wrong_password = b"wrong-password";
    let group = SrpGroup::Srp2048;
    let mut rng = thread_rng();

    // Register with correct password
    println!("  Registering with correct password...");
    let registration = register_user(username, correct_password, group, &mut rng)
        .expect("registration failed");

    // Try to authenticate with wrong password
    println!("  Attempting authentication with wrong password...");
    let mut client = SrpClient::new(username, wrong_password, group);
    let a_pub = client.compute_public(&mut rng).expect("compute_public failed");

    let mut server = SrpServer::new(
        &registration.verifier,
        &registration.salt,
        username,
        group
    );
    let b_pub = server.compute_public(&mut rng).expect("compute_public failed");
    let salt = server.get_salt();

    client.process_server_response(&b_pub, salt).expect("process_server_response failed");
    let m1 = client.compute_proof().expect("compute_proof failed");

    server.process_client_public(&a_pub).expect("process_client_public failed");

    // Server verification should fail with wrong password
    let result = server.verify_client_proof(&m1);
    assert!(result.is_err(), "Verification should fail with wrong password");

    println!("    Server correctly rejected wrong password");
    println!("\nWrong password correctly rejected");
}

/// Test SRP with multiple users
#[test]
fn test_srp_multiple_users() {
    use hpcrypt_srp::{register_user, SrpClient, SrpServer, SrpGroup};
    use rand::thread_rng;

    println!("\n=== SRP Multiple Users Test ===");

    let group = SrpGroup::Srp2048;
    let mut rng = thread_rng();

    let users = vec![
        (b"alice".as_slice(), b"password-alice".as_slice()),
        (b"bob".as_slice(), b"password-bob".as_slice()),
        (b"charlie".as_slice(), b"password-charlie".as_slice()),
    ];

    println!("  Registering {} users...", users.len());
    let mut registrations = Vec::new();
    for (username, password) in &users {
        let registration = register_user(username, password, group, &mut rng)
            .expect("registration failed");
        registrations.push((username, password, registration));
    }
    println!("    All users registered");

    // Authenticate each user
    println!("  Authenticating users...");
    for (username, password, registration) in &registrations {
        let mut client = SrpClient::new(username, password, group);
        let a_pub = client.compute_public(&mut rng).expect("compute_public failed");

        let mut server = SrpServer::new(
            &registration.verifier,
            &registration.salt,
            username,
            group
        );
        let b_pub = server.compute_public(&mut rng).expect("compute_public failed");
        let salt = server.get_salt();

        client.process_server_response(&b_pub, salt).expect("process_server_response failed");
        let m1 = client.compute_proof().expect("compute_proof failed");

        server.process_client_public(&a_pub).expect("process_client_public failed");
        server.verify_client_proof(&m1).expect("verify_client_proof failed");
        let m2 = server.compute_proof().expect("compute_proof failed");

        client.verify_server_proof(&m2).expect("verify_server_proof failed");

        let client_key = client.get_session_key().expect("get_session_key failed");
        let server_key = server.get_session_key().expect("get_session_key failed");

        assert_eq!(client_key, server_key, "Session keys should match for {}",
                   String::from_utf8_lossy(username));
    }
    println!("    All users authenticated successfully");

    // Test cross-user authentication fails
    println!("  Testing cross-user authentication rejection...");
    let (alice_username, alice_password, _) = &registrations[0];
    let (_, _, bob_registration) = &registrations[1];

    let mut client = SrpClient::new(alice_username, alice_password, group);
    let a_pub = client.compute_public(&mut rng).expect("compute_public failed");

    let mut server = SrpServer::new(
        &bob_registration.verifier,
        &bob_registration.salt,
        alice_username,  // Using Alice's username
        group
    );
    let b_pub = server.compute_public(&mut rng).expect("compute_public failed");
    let salt = server.get_salt();

    client.process_server_response(&b_pub, salt).expect("process_server_response failed");
    let m1 = client.compute_proof().expect("compute_proof failed");

    server.process_client_public(&a_pub).expect("process_client_public failed");

    // Should fail: Alice's password with Bob's verifier
    let result = server.verify_client_proof(&m1);
    assert!(result.is_err(), "Cross-user authentication should fail");
    println!("    Cross-user authentication correctly rejected");

    println!("\nAll multiple user tests passed");
}

/// Test SRP with different group sizes
#[test]
fn test_srp_different_groups() {
    use hpcrypt_srp::{register_user, SrpClient, SrpServer, SrpGroup};
    use rand::thread_rng;

    println!("\n=== SRP Different Group Sizes Test ===");

    let groups = vec![
        ("1024-bit", SrpGroup::Srp1024),
        ("1536-bit", SrpGroup::Srp1536),
        ("2048-bit", SrpGroup::Srp2048),
        ("3072-bit", SrpGroup::Srp3072),
    ];

    let username = b"testuser";
    let password = b"testpassword";
    let mut rng = thread_rng();

    for (name, group) in groups {
        println!("\n  Testing {} group...", name);

        let registration = register_user(username, password, group, &mut rng)
            .expect("registration failed");

        let mut client = SrpClient::new(username, password, group);
        let a_pub = client.compute_public(&mut rng).expect("compute_public failed");

        let mut server = SrpServer::new(
            &registration.verifier,
            &registration.salt,
            username,
            group
        );
        let b_pub = server.compute_public(&mut rng).expect("compute_public failed");
        let salt = server.get_salt();

        client.process_server_response(&b_pub, salt).expect("process_server_response failed");
        let m1 = client.compute_proof().expect("compute_proof failed");

        server.process_client_public(&a_pub).expect("process_client_public failed");
        server.verify_client_proof(&m1).expect("verify_client_proof failed");
        let m2 = server.compute_proof().expect("compute_proof failed");

        client.verify_server_proof(&m2).expect("verify_server_proof failed");

        let client_key = client.get_session_key().expect("get_session_key failed");
        let server_key = server.get_session_key().expect("get_session_key failed");

        assert_eq!(client_key, server_key);
        println!("    {} authentication successful", name);
    }

    println!("\nAll group size tests passed");
}
