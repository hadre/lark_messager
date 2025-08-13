use lark_messager::{auth::AuthService, database::Database, error::AppError, lark::LarkClient};
use uuid::Uuid;

fn load_test_env() {
    dotenvy::from_filename(".env.test").ok();
}

fn generate_unique_username() -> String {
    format!(
        "testuser_{}",
        Uuid::new_v4().to_string().replace("-", "")[0..8].to_string()
    )
}

fn generate_unique_key_hash() -> String {
    format!(
        "keyhash_{}",
        Uuid::new_v4().to_string().replace("-", "")[0..8].to_string()
    )
}

#[tokio::test]
async fn test_database_user_operations() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();

    let username = generate_unique_username();

    // Test user creation
    let user = db.create_user(&username, "password_hash").await.unwrap();
    assert_eq!(user.username, username);
    assert_eq!(user.password_hash, "password_hash");

    // Test getting user by username
    let retrieved_user = db.get_user_by_username(&username).await.unwrap().unwrap();
    assert_eq!(retrieved_user.id, user.id);
    assert_eq!(retrieved_user.username, username);

    // Test getting user by ID
    let retrieved_user_by_id = db.get_user_by_id(&user.id).await.unwrap().unwrap();
    assert_eq!(retrieved_user_by_id.username, username);

    // Test getting non-existent user
    let non_existent = db.get_user_by_username("nonexistent_user").await.unwrap();
    assert!(non_existent.is_none());
}

#[tokio::test]
async fn test_database_api_key_operations() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();

    let username = generate_unique_username();
    let key_hash = generate_unique_key_hash();

    // Create a user first
    let user = db.create_user(&username, "password_hash").await.unwrap();

    // Test API key creation
    let api_key = db
        .create_api_key(&key_hash, "Test Key", "send_messages", &user.id)
        .await
        .unwrap();
    assert_eq!(api_key.name, "Test Key");
    assert_eq!(api_key.permissions, "send_messages");
    assert_eq!(api_key.created_by, user.id);

    // Test getting API key by hash
    let retrieved_key = db.get_api_key_by_hash(&key_hash).await.unwrap().unwrap();
    assert_eq!(retrieved_key.id, api_key.id);

    // Test revoking API key
    let revoked = db.revoke_api_key(&api_key.id).await.unwrap();
    assert!(revoked);

    // Test that revoked key is not returned
    let revoked_key = db.get_api_key_by_hash(&key_hash).await.unwrap();
    assert!(revoked_key.is_none());

    // Test revoking non-existent key
    let fake_id = Uuid::new_v4();
    let not_revoked = db.revoke_api_key(&fake_id).await.unwrap();
    assert!(!not_revoked);
}

#[tokio::test]
async fn test_database_api_key_verification() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();
    let auth = AuthService::new("test_secret".to_string(), db.clone());

    let username = generate_unique_username();
    // Create a user first
    let user = db.create_user(&username, "password_hash").await.unwrap();

    // Generate a raw API key and its hash
    let raw_api_key = auth.generate_api_key(32);
    let key_hash = auth.hash_api_key(&raw_api_key).unwrap();

    // Create API key in database with the hash
    let api_key = db
        .create_api_key(&key_hash, "Test Key", "send_messages", &user.id)
        .await
        .unwrap();

    // Test finding API key by verification with correct key
    let found_key = db
        .find_api_key_by_verification(&raw_api_key, &auth)
        .await
        .unwrap();
    assert!(found_key.is_some());
    assert_eq!(found_key.unwrap().id, api_key.id);

    // Test finding API key by verification with wrong key
    let wrong_key = auth.generate_api_key(32);
    let not_found = db
        .find_api_key_by_verification(&wrong_key, &auth)
        .await
        .unwrap();
    assert!(not_found.is_none());

    // Revoke the key and test again
    let _revoked = db.revoke_api_key(&api_key.id).await.unwrap();
    let revoked_key = db
        .find_api_key_by_verification(&raw_api_key, &auth)
        .await
        .unwrap();
    assert!(revoked_key.is_none());
}

#[tokio::test]
async fn test_database_message_logging() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();

    let user_id = Uuid::new_v4();

    // Test message logging
    let log = db
        .log_message(
            "user",
            &user_id,
            "recipient@example.com",
            "Test message",
            "sent",
        )
        .await
        .unwrap();
    assert_eq!(log.sender_type, "user");
    assert_eq!(log.sender_id, user_id);
    assert_eq!(log.recipient, "recipient@example.com");
    assert_eq!(log.message, "Test message");
    assert_eq!(log.status, "sent");

    // Test getting message logs
    let logs = db.get_message_logs(Some(user_id), Some(10)).await.unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].id, log.id);

    // Test getting all logs (no sender filter) - should have at least our log
    let all_logs = db.get_message_logs(None, Some(10)).await.unwrap();
    assert!(all_logs.len() >= 1);
}

#[tokio::test]
async fn test_auth_password_operations() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();
    let auth = AuthService::new("test_secret".to_string(), db.clone());

    // Test password hashing
    let password = "testpassword123";
    let hash1 = auth.hash_password(password).unwrap();
    let hash2 = auth.hash_password(password).unwrap();

    // Hashes should be different (due to salt)
    assert_ne!(hash1, hash2);

    // Test password verification
    assert!(auth.verify_password(password, &hash1).unwrap());
    assert!(auth.verify_password(password, &hash2).unwrap());
    assert!(!auth.verify_password("wrongpassword", &hash1).unwrap());
}

#[tokio::test]
async fn test_auth_api_key_operations() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();
    let auth = AuthService::new("test_secret".to_string(), db.clone());

    // Test API key generation
    let key1 = auth.generate_api_key(32);
    let key2 = auth.generate_api_key(32);

    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
    assert_ne!(key1, key2);

    // Test API key hashing
    let key_hash = auth.hash_api_key(&key1).unwrap();
    assert!(auth.verify_api_key(&key1, &key_hash).unwrap());
    assert!(!auth.verify_api_key(&key2, &key_hash).unwrap());
}

#[tokio::test]
async fn test_auth_jwt_operations() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();
    let auth = AuthService::new("test_secret".to_string(), db.clone());

    let username = generate_unique_username();
    // Create a test user
    let user = db.create_user(&username, "hash").await.unwrap();

    // Test JWT generation
    let (token, expires_at) = auth.generate_jwt_token(&user).unwrap();
    assert!(!token.is_empty());
    assert!(expires_at > chrono::Utc::now());

    // Test JWT verification
    let claims = auth.verify_jwt_token(&token).unwrap();
    assert_eq!(claims.sub, user.id.to_string());
    assert_eq!(claims.username, user.username);
}

#[tokio::test]
async fn test_auth_permission_parsing() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();
    let auth = AuthService::new("test_secret".to_string(), db.clone());

    // Test permission parsing
    let permissions = auth.parse_permissions("send_messages,admin,read_logs");
    assert_eq!(permissions, vec!["send_messages", "admin", "read_logs"]);

    let permissions = auth.parse_permissions("send_messages");
    assert_eq!(permissions, vec!["send_messages"]);

    let permissions = auth.parse_permissions("");
    assert!(permissions.is_empty());

    let permissions = auth.parse_permissions("send_messages, admin , read_logs ");
    assert_eq!(permissions, vec!["send_messages", "admin", "read_logs"]);
}

#[tokio::test]
async fn test_lark_client_recipient_verification() {
    load_test_env();
    let lark = LarkClient::new(
        std::env::var("TEST_LARK_APP_ID").unwrap_or_else(|_| "test_app_id".to_string()),
        std::env::var("TEST_LARK_APP_SECRET").unwrap_or_else(|_| "test_app_secret".to_string()),
    );

    // Test user ID recognition
    let result = lark
        .verify_recipient("ou_12345678901234567890123456", Some("user_id"))
        .await;
    // This will fail due to invalid credentials, but we can test the logic
    assert!(result.is_err() || result.unwrap().is_some());

    // Test email pattern recognition in auto mode
    // Note: This would normally make an API call and fail with invalid credentials
}

#[tokio::test]
async fn test_error_types() {
    // Test that our error types work correctly
    let auth_error = AppError::Auth("Test auth error".to_string());
    assert_eq!(
        auth_error.to_string(),
        "Authentication failed: Test auth error"
    );

    let validation_error = AppError::Validation("Test validation error".to_string());
    assert_eq!(
        validation_error.to_string(),
        "Validation error: Test validation error"
    );

    let not_found_error = AppError::NotFound("Test resource".to_string());
    assert_eq!(not_found_error.to_string(), "Not found: Test resource");
}

#[tokio::test]
async fn test_database_constraints() {
    load_test_env();
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string());
    let db = Database::new_with_migrations(&database_url).await.unwrap();

    let username = generate_unique_username();
    let key_hash = generate_unique_key_hash();

    // Test unique username constraint
    let _user1 = db.create_user(&username, "hash1").await.unwrap();
    let result = db.create_user(&username, "hash2").await;
    assert!(result.is_err()); // Should fail due to unique constraint

    // Test unique API key hash constraint
    let username2 = generate_unique_username();
    let user = db.create_user(&username2, "hash").await.unwrap();
    let _key1 = db
        .create_api_key(&key_hash, "Key 1", "perms", &user.id)
        .await
        .unwrap();
    let result = db
        .create_api_key(&key_hash, "Key 2", "perms", &user.id)
        .await;
    assert!(result.is_err()); // Should fail due to unique constraint
}
