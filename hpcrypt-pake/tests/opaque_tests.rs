//! OPAQUE protocol tests

use hpcrypt_pake::opaque::*;

#[test]
fn test_opaque_full_registration_flow() {
    let config = Config::ristretto255_sha512();
    let password = b"correct-horse-battery-staple";
    let client_id = b"alice@example.com";
    let server_id = b"server.example.com";

    // Client creates registration request
    let (client_state, reg_request) =
        OpaqueClient::create_registration_request(password, &config).unwrap();

    // Server processes registration
    let (_server_state, reg_response) =
        OpaqueServer::create_registration_response(&reg_request, server_id, &config).unwrap();

    // Client finalizes registration
    let reg_record = OpaqueClient::finalize_registration_request(
        password,
        &client_state,
        &reg_response,
        client_id,
        server_id,
        &config,
    )
    .unwrap();

    // Registration record should be created
    assert!(!reg_record.envelope.is_empty());
    assert!(!reg_record.client_public_key.is_empty());
}

#[test]
fn test_opaque_full_authentication_flow() {
    let config = Config::ristretto255_sha512();
    let password = b"secure-password-123";
    let client_id = b"user@domain.com";
    let server_id = b"auth.domain.com";

    // Registration phase
    let (client_state, reg_request) =
        OpaqueClient::create_registration_request(password, &config).unwrap();
    let (_server_state, reg_response) =
        OpaqueServer::create_registration_response(&reg_request, server_id, &config).unwrap();
    let reg_record = OpaqueClient::finalize_registration_request(
        password,
        &client_state,
        &reg_response,
        client_id,
        server_id,
        &config,
    )
    .unwrap();

    // Authentication phase - Client initiates
    let (client_auth, ke1) = OpaqueClient::generate_ke1(password, &config).unwrap();

    // Server responds
    let (server_auth, ke2) =
        OpaqueServer::generate_ke2(&ke1, &reg_record, server_id, &config).unwrap();

    // Client finalizes
    let (ke3, client_session_key) =
        OpaqueClient::generate_ke3(&client_auth, &ke2, client_id, server_id, &config).unwrap();

    // Server verifies
    let server_session_key = OpaqueServer::server_finish(&server_auth, &ke3, &config).unwrap();

    // Session keys should match
    assert_eq!(client_session_key, server_session_key);
}

#[test]
fn test_opaque_wrong_password_fails() {
    let config = Config::ristretto255_sha512();
    let correct_password = b"correct-password";
    let wrong_password = b"wrong-password";
    let client_id = b"user@test.com";
    let server_id = b"server.test.com";

    // Registration with correct password
    let (client_state, reg_request) =
        OpaqueClient::create_registration_request(correct_password, &config).unwrap();
    let (_server_state, reg_response) =
        OpaqueServer::create_registration_response(&reg_request, server_id, &config).unwrap();
    let reg_record = OpaqueClient::finalize_registration_request(
        correct_password,
        &client_state,
        &reg_response,
        client_id,
        server_id,
        &config,
    )
    .unwrap();

    // Authentication with wrong password
    let (client_auth, ke1) = OpaqueClient::generate_ke1(wrong_password, &config).unwrap();
    let (server_auth, ke2) =
        OpaqueServer::generate_ke2(&ke1, &reg_record, server_id, &config).unwrap();
    let result = OpaqueClient::generate_ke3(&client_auth, &ke2, client_id, server_id, &config);

    // Should fail with wrong password
    assert!(result.is_err());
}

#[test]
fn test_opaque_different_users_different_records() {
    let config = Config::ristretto255_sha512();
    let password = b"same-password";
    let server_id = b"server.com";

    // User 1 registration
    let (client_state1, reg_request1) =
        OpaqueClient::create_registration_request(password, &config).unwrap();
    let (_server_state1, reg_response1) =
        OpaqueServer::create_registration_response(&reg_request1, server_id, &config).unwrap();
    let reg_record1 = OpaqueClient::finalize_registration_request(
        password,
        &client_state1,
        &reg_response1,
        b"user1@test.com",
        server_id,
        &config,
    )
    .unwrap();

    // User 2 registration
    let (client_state2, reg_request2) =
        OpaqueClient::create_registration_request(password, &config).unwrap();
    let (_server_state2, reg_response2) =
        OpaqueServer::create_registration_response(&reg_request2, server_id, &config).unwrap();
    let reg_record2 = OpaqueClient::finalize_registration_request(
        password,
        &client_state2,
        &reg_response2,
        b"user2@test.com",
        server_id,
        &config,
    )
    .unwrap();

    // Records should be different (different random blinding)
    assert_ne!(reg_record1.envelope, reg_record2.envelope);
}

#[test]
fn test_opaque_server_storage_trait() {
    let storage = InMemoryStorage::new_with_test_keys();

    // Should be able to retrieve test keys
    let oprf_seed = storage.get_oprf_seed().unwrap();
    let server_key = storage.get_server_private_key().unwrap();

    assert!(!oprf_seed.is_empty());
    assert!(!server_key.is_empty());
}

#[test]
fn test_oprf_client_server_flow() {
    use hpcrypt_pake::oprf::*;

    // Server setup
    let oprf_key = OprfServer::generate_key().unwrap();

    // Client blinds input
    let input = b"password";
    let (blind, blinded_element) = OprfClient::blind(input).unwrap();

    // Server evaluates
    let evaluated_element = OprfServer::evaluate(&oprf_key, &blinded_element).unwrap();

    // Client finalizes
    let output = OprfClient::finalize(input, &blind, &evaluated_element).unwrap();

    // Output should be deterministic for same input
    let (blind2, blinded_element2) = OprfClient::blind(input).unwrap();
    let evaluated_element2 = OprfServer::evaluate(&oprf_key, &blinded_element2).unwrap();
    let output2 = OprfClient::finalize(input, &blind2, &evaluated_element2).unwrap();

    assert_eq!(output, output2);
}
