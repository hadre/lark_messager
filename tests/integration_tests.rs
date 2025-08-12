use axum_test::TestServer;
use lark_messager::{
    auth::AuthService,
    config::Config,
    database::Database,
    handlers::AppState,
    lark::LarkClient,
    models::{CreateApiKeyRequest, LoginRequest, SendMessageRequest, VerifyRecipientRequest},
    routes::create_router,
};
use serde_json::{json, Value};
use std::env;
use tempfile::NamedTempFile;
use uuid::Uuid;

async fn create_test_server() -> TestServer {
    // Create a temporary database file
    let db_file = NamedTempFile::new().unwrap();
    let database_url = format!("sqlite:{}", db_file.path().display());

    // Initialize database
    let db = Database::new(&database_url).await.unwrap();

    // Create test user
    let auth = AuthService::new("test_jwt_secret".to_string(), db.clone());
    let password_hash = auth.hash_password("testpass123").unwrap();
    let _test_user = db.create_user("testuser", &password_hash).await.unwrap();

    // Initialize Lark client with dummy credentials
    let lark = LarkClient::new("test_app_id".to_string(), "test_app_secret".to_string());

    let state = AppState { db, auth, lark };
    let app = create_router(state);

    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn test_health_check() {
    let server = create_test_server().await;

    let response = server.get("/health").await;
    response.assert_status_ok();

    let body: Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].is_string());
    assert!(body["version"].is_string());
}

#[tokio::test]
async fn test_login_success() {
    let server = create_test_server().await;

    let login_request = LoginRequest {
        username: "testuser".to_string(),
        password: "testpass123".to_string(),
    };

    let response = server.post("/auth/login").json(&login_request).await;
    response.assert_status_ok();

    let body: Value = response.json();
    assert!(body["token"].is_string());
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let server = create_test_server().await;

    let login_request = LoginRequest {
        username: "testuser".to_string(),
        password: "wrongpassword".to_string(),
    };

    let response = server.post("/auth/login").json(&login_request).await;
    response.assert_status(401);

    let body: Value = response.json();
    assert_eq!(body["error"], "Authentication failed");
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let server = create_test_server().await;

    let login_request = LoginRequest {
        username: "nonexistent".to_string(),
        password: "testpass123".to_string(),
    };

    let response = server.post("/auth/login").json(&login_request).await;
    response.assert_status(401);
}

#[tokio::test]
async fn test_send_message_without_auth() {
    let server = create_test_server().await;

    let message_request = SendMessageRequest {
        recipient: "test@example.com".to_string(),
        message: "Test message".to_string(),
        recipient_type: Some("email".to_string()),
    };

    let response = server.post("/messages/send").json(&message_request).await;
    response.assert_status(401);
}

#[tokio::test]
async fn test_send_message_with_jwt_auth() {
    let server = create_test_server().await;

    // First login to get JWT token
    let login_request = LoginRequest {
        username: "testuser".to_string(),
        password: "testpass123".to_string(),
    };

    let login_response = server.post("/auth/login").json(&login_request).await;
    let login_body: Value = login_response.json();
    let token = login_body["token"].as_str().unwrap();

    // Try to send message with JWT (will fail due to invalid Lark credentials)
    let message_request = SendMessageRequest {
        recipient: "test_user_id".to_string(),
        message: "Test message".to_string(),
        recipient_type: Some("user_id".to_string()),
    };

    let response = server
        .post("/messages/send")
        .add_header("Authorization".parse().unwrap(), format!("Bearer {}", token).parse().unwrap())
        .json(&message_request)
        .await;

    // Should fail with bad gateway due to invalid Lark credentials
    response.assert_status(502);
}

#[tokio::test]
async fn test_send_message_validation() {
    let server = create_test_server().await;

    // Login first
    let login_request = LoginRequest {
        username: "testuser".to_string(),
        password: "testpass123".to_string(),
    };

    let login_response = server.post("/auth/login").json(&login_request).await;
    let login_body: Value = login_response.json();
    let token = login_body["token"].as_str().unwrap();

    // Test empty message
    let message_request = SendMessageRequest {
        recipient: "test@example.com".to_string(),
        message: "".to_string(),
        recipient_type: Some("email".to_string()),
    };

    let response = server
        .post("/messages/send")
        .add_header("Authorization".parse().unwrap(), format!("Bearer {}", token).parse().unwrap())
        .json(&message_request)
        .await;

    response.assert_status(400);

    // Test message too long
    let long_message = "a".repeat(10001);
    let message_request = SendMessageRequest {
        recipient: "test@example.com".to_string(),
        message: long_message,
        recipient_type: Some("email".to_string()),
    };

    let response = server
        .post("/messages/send")
        .add_header("Authorization".parse().unwrap(), format!("Bearer {}", token).parse().unwrap())
        .json(&message_request)
        .await;

    response.assert_status(400);
}

#[tokio::test]
async fn test_verify_recipient_without_auth() {
    let server = create_test_server().await;

    let verify_request = VerifyRecipientRequest {
        recipient: "test@example.com".to_string(),
        recipient_type: Some("email".to_string()),
    };

    let response = server.post("/recipients/verify").json(&verify_request).await;
    response.assert_status(401);
}

#[tokio::test]
async fn test_create_api_key_without_admin() {
    let server = create_test_server().await;

    // Login as regular user
    let login_request = LoginRequest {
        username: "testuser".to_string(),
        password: "testpass123".to_string(),
    };

    let login_response = server.post("/auth/login").json(&login_request).await;
    let login_body: Value = login_response.json();
    let token = login_body["token"].as_str().unwrap();

    // Try to create API key (should fail - user is not admin)
    let api_key_request = CreateApiKeyRequest {
        name: "Test API Key".to_string(),
        permissions: "send_messages".to_string(),
    };

    let response = server
        .post("/auth/api-keys")
        .add_header("Authorization".parse().unwrap(), format!("Bearer {}", token).parse().unwrap())
        .json(&api_key_request)
        .await;

    response.assert_status(403);
}

#[tokio::test]
async fn test_revoke_nonexistent_api_key() {
    let server = create_test_server().await;

    // Login as regular user
    let login_request = LoginRequest {
        username: "testuser".to_string(),
        password: "testpass123".to_string(),
    };

    let login_response = server.post("/auth/login").json(&login_request).await;
    let login_body: Value = login_response.json();
    let token = login_body["token"].as_str().unwrap();

    let fake_key_id = Uuid::new_v4();
    let response = server
        .delete(&format!("/auth/api-keys/{}", fake_key_id))
        .add_header("Authorization".parse().unwrap(), format!("Bearer {}", token).parse().unwrap())
        .await;

    // Should fail with 403 (not admin) or 404 (key not found)
    assert!(response.status_code() == 403 || response.status_code() == 404);
}

#[tokio::test]
async fn test_cors_headers() {
    let server = create_test_server().await;

    let response = server
        .options("/health")
        .add_header("Origin".parse().unwrap(), "http://localhost:3000".parse().unwrap())
        .add_header("Access-Control-Request-Method".parse().unwrap(), "GET".parse().unwrap())
        .await;

    // CORS preflight should be handled
    assert!(response.status_code() == 200 || response.status_code() == 204);
}

#[tokio::test]
async fn test_invalid_jwt_token() {
    let server = create_test_server().await;

    let message_request = SendMessageRequest {
        recipient: "test@example.com".to_string(),
        message: "Test message".to_string(),
        recipient_type: Some("email".to_string()),
    };

    let response = server
        .post("/messages/send")
        .add_header("Authorization".parse().unwrap(), "Bearer invalid_token".parse().unwrap())
        .json(&message_request)
        .await;

    response.assert_status(401);
}

#[tokio::test]
async fn test_malformed_auth_header() {
    let server = create_test_server().await;

    let message_request = SendMessageRequest {
        recipient: "test@example.com".to_string(),
        message: "Test message".to_string(),
        recipient_type: Some("email".to_string()),
    };

    let response = server
        .post("/messages/send")
        .add_header("Authorization".parse().unwrap(), "InvalidFormat".parse().unwrap())
        .json(&message_request)
        .await;

    response.assert_status(401);
}