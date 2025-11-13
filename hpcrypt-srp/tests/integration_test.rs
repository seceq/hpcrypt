//! Integration tests for SRP protocol

use hpcrypt_srp::{
    register_user, register_user_with_hash, SrpClient, SrpGroup, SrpHashFunction, SrpServer,
};
use rand::thread_rng;

#[test]
fn test_full_authentication_flow() {
    let mut rng = thread_rng();

    // Step 1: User registration
    let registration =
        register_user(b"alice", b"password123", SrpGroup::Srp2048, &mut rng).unwrap();

    // Server stores salt and verifier
    let stored_salt = registration.salt.clone();
    let stored_verifier = registration.verifier.clone();

    // Step 2: Authentication begins
    let mut client = SrpClient::new(b"alice", b"password123", SrpGroup::Srp2048);
    let mut server = SrpServer::new(&stored_verifier, &stored_salt, b"alice", SrpGroup::Srp2048);

    // Step 3: Client sends public key A
    let a_pub = client.compute_public(&mut rng).unwrap();

    // Step 4: Server sends public key B and salt
    let b_pub = server.compute_public(&mut rng).unwrap();
    let salt = server.get_salt();

    // Step 5: Client processes server response and computes proof M1
    client.process_server_response(&b_pub, salt).unwrap();
    let m1 = client.compute_proof().unwrap();

    // Step 6: Server processes client public key and verifies proof M1
    server.process_client_public(&a_pub).unwrap();
    server.verify_client_proof(&m1).unwrap();

    // Step 7: Server sends proof M2
    let m2 = server.compute_proof().unwrap();

    // Step 8: Client verifies server proof M2
    client.verify_server_proof(&m2).unwrap();

    // Step 9: Both parties should have the same session key
    let client_key = client.get_session_key().unwrap();
    let server_key = server.get_session_key().unwrap();

    assert_eq!(client_key, server_key);
    assert_eq!(client_key.len(), 32); // SHA-256 output (default)
}

#[test]
fn test_wrong_password_fails() {
    let mut rng = thread_rng();

    // Registration with correct password
    let registration =
        register_user(b"alice", b"correct_password", SrpGroup::Srp2048, &mut rng).unwrap();

    // Authentication with wrong password
    let mut client = SrpClient::new(b"alice", b"wrong_password", SrpGroup::Srp2048);
    let mut server = SrpServer::new(
        &registration.verifier,
        &registration.salt,
        b"alice",
        SrpGroup::Srp2048,
    );

    let a_pub = client.compute_public(&mut rng).unwrap();
    let b_pub = server.compute_public(&mut rng).unwrap();

    client
        .process_server_response(&b_pub, server.get_salt())
        .unwrap();
    let m1 = client.compute_proof().unwrap();

    server.process_client_public(&a_pub).unwrap();

    // Server should reject the proof with wrong password
    assert!(server.verify_client_proof(&m1).is_err());
}

#[test]
fn test_multiple_group_sizes() {
    let mut rng = thread_rng();

    for group in [
        SrpGroup::Srp1024,
        SrpGroup::Srp1536,
        SrpGroup::Srp2048,
        SrpGroup::Srp3072,
    ] {
        let registration = register_user(b"user", b"pass", group, &mut rng).unwrap();

        let mut client = SrpClient::new(b"user", b"pass", group);
        let mut server = SrpServer::new(&registration.verifier, &registration.salt, b"user", group);

        let a_pub = client.compute_public(&mut rng).unwrap();
        let b_pub = server.compute_public(&mut rng).unwrap();

        client
            .process_server_response(&b_pub, server.get_salt())
            .unwrap();
        let m1 = client.compute_proof().unwrap();

        server.process_client_public(&a_pub).unwrap();
        server.verify_client_proof(&m1).unwrap();
        let m2 = server.compute_proof().unwrap();

        client.verify_server_proof(&m2).unwrap();

        let client_key = client.get_session_key().unwrap();
        let server_key = server.get_session_key().unwrap();

        assert_eq!(client_key, server_key);
    }
}

#[test]
fn test_zero_public_key_rejected() {
    let mut rng = thread_rng();

    let registration = register_user(b"alice", b"password", SrpGroup::Srp2048, &mut rng).unwrap();
    let mut server = SrpServer::new(
        &registration.verifier,
        &registration.salt,
        b"alice",
        SrpGroup::Srp2048,
    );

    // Try to send zero as public key (should be rejected)
    let zero_pub = vec![0u8; 256]; // 2048 bits = 256 bytes

    server.process_client_public(&zero_pub).unwrap_err();
}

#[test]
fn test_deterministic_verifier() {
    // Same username, password, salt should produce same verifier
    let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let v1 =
        hpcrypt_srp::create_verifier(b"alice", b"password123", &salt, SrpGroup::Srp2048).unwrap();
    let v2 =
        hpcrypt_srp::create_verifier(b"alice", b"password123", &salt, SrpGroup::Srp2048).unwrap();

    assert_eq!(v1, v2);

    // Different password should produce different verifier
    let v3 =
        hpcrypt_srp::create_verifier(b"alice", b"different", &salt, SrpGroup::Srp2048).unwrap();
    assert_ne!(v1, v3);

    // Different username should produce different verifier
    let v4 =
        hpcrypt_srp::create_verifier(b"bob", b"password123", &salt, SrpGroup::Srp2048).unwrap();
    assert_ne!(v1, v4);
}

#[test]
fn test_authentication_with_different_hash_functions() {
    let mut rng = thread_rng();

    // Test SHA-256 (default)
    {
        let registration =
            register_user(b"alice", b"password123", SrpGroup::Srp2048, &mut rng).unwrap();
        let mut client = SrpClient::new(b"alice", b"password123", SrpGroup::Srp2048);
        let mut server = SrpServer::new(
            &registration.verifier,
            &registration.salt,
            b"alice",
            SrpGroup::Srp2048,
        );

        let a_pub = client.compute_public(&mut rng).unwrap();
        let b_pub = server.compute_public(&mut rng).unwrap();

        client
            .process_server_response(&b_pub, server.get_salt())
            .unwrap();
        let m1 = client.compute_proof().unwrap();

        server.process_client_public(&a_pub).unwrap();
        server.verify_client_proof(&m1).unwrap();
        let m2 = server.compute_proof().unwrap();

        client.verify_server_proof(&m2).unwrap();

        let client_key = client.get_session_key().unwrap();
        let server_key = server.get_session_key().unwrap();

        assert_eq!(client_key, server_key);
        assert_eq!(client_key.len(), 32); // SHA-256
    }

    // Test SHA-512
    {
        let registration = register_user_with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            &mut rng,
            SrpHashFunction::Sha512,
        )
        .unwrap();

        let mut client = SrpClient::with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha512,
        );

        let mut server = SrpServer::with_hash(
            &registration.verifier,
            &registration.salt,
            b"alice",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha512,
        );

        let a_pub = client.compute_public(&mut rng).unwrap();
        let b_pub = server.compute_public(&mut rng).unwrap();

        client
            .process_server_response(&b_pub, server.get_salt())
            .unwrap();
        let m1 = client.compute_proof().unwrap();

        server.process_client_public(&a_pub).unwrap();
        server.verify_client_proof(&m1).unwrap();
        let m2 = server.compute_proof().unwrap();

        client.verify_server_proof(&m2).unwrap();

        let client_key = client.get_session_key().unwrap();
        let server_key = server.get_session_key().unwrap();

        assert_eq!(client_key, server_key);
        assert_eq!(client_key.len(), 64); // SHA-512
    }

    // Test SHA-1 (legacy)
    {
        let registration = register_user_with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            &mut rng,
            SrpHashFunction::Sha1,
        )
        .unwrap();

        let mut client = SrpClient::with_hash(
            b"alice",
            b"password123",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha1,
        );

        let mut server = SrpServer::with_hash(
            &registration.verifier,
            &registration.salt,
            b"alice",
            SrpGroup::Srp2048,
            SrpHashFunction::Sha1,
        );

        let a_pub = client.compute_public(&mut rng).unwrap();
        let b_pub = server.compute_public(&mut rng).unwrap();

        client
            .process_server_response(&b_pub, server.get_salt())
            .unwrap();
        let m1 = client.compute_proof().unwrap();

        server.process_client_public(&a_pub).unwrap();
        server.verify_client_proof(&m1).unwrap();
        let m2 = server.compute_proof().unwrap();

        client.verify_server_proof(&m2).unwrap();

        let client_key = client.get_session_key().unwrap();
        let server_key = server.get_session_key().unwrap();

        assert_eq!(client_key, server_key);
        assert_eq!(client_key.len(), 20); // SHA-1
    }
}

#[test]
fn test_hash_function_mismatch_fails() {
    let mut rng = thread_rng();

    // Register with SHA-256
    let registration =
        register_user(b"alice", b"password123", SrpGroup::Srp2048, &mut rng).unwrap();

    // Client uses SHA-256, server uses SHA-512 (mismatch)
    let mut client = SrpClient::new(b"alice", b"password123", SrpGroup::Srp2048);
    let mut server = SrpServer::with_hash(
        &registration.verifier,
        &registration.salt,
        b"alice",
        SrpGroup::Srp2048,
        SrpHashFunction::Sha512, // Wrong hash function!
    );

    let a_pub = client.compute_public(&mut rng).unwrap();
    let b_pub = server.compute_public(&mut rng).unwrap();

    client
        .process_server_response(&b_pub, server.get_salt())
        .unwrap();
    let m1 = client.compute_proof().unwrap();

    server.process_client_public(&a_pub).unwrap();

    // Server should reject the proof due to hash function mismatch
    assert!(server.verify_client_proof(&m1).is_err());
}
