use chrono::FixedOffset;
use lark_messager::{
    auth::AuthService,
    database::Database,
    models::{
        ApiKeyStatus, CreateApiKeyRequest, ResetApiKeyFailuresRequest, UpdateApiKeyStatusRequest,
    },
};
use uuid::Uuid;

fn load_test_env() {
    dotenvy::from_filename(".env.test").ok();
}

fn test_database_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string())
}

fn test_timezone() -> FixedOffset {
    let secs = std::env::var("TEST_TIMEZONE_OFFSET_SECS")
        .unwrap_or_else(|_| "0".to_string())
        .parse::<i32>()
        .unwrap_or(0);
    FixedOffset::east_opt(secs).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap())
}

#[tokio::test]
async fn test_create_user_and_api_key_flow() {
    load_test_env();
    let db = Database::new_with_migrations(&test_database_url(), test_timezone())
        .await
        .unwrap();
    let auth = AuthService::new("unit_test_secret".to_string(), db.clone())
        .await
        .unwrap();

    let username = format!("unit_user_{}", Uuid::new_v4());
    let user = auth
        .create_user(&username, "StrongPassw0rd!", true)
        .await
        .unwrap();
    assert_eq!(user.username, username);
    assert!(user.is_admin);

    let api_key = auth
        .create_api_key(
            &user,
            CreateApiKeyRequest {
                name: "unit-key".to_string(),
                rate_limit_per_minute: 10,
            },
        )
        .await
        .unwrap();

    assert_eq!(api_key.name, "unit-key");
    assert_eq!(api_key.status, ApiKeyStatus::Enabled);
    assert_eq!(api_key.rate_limit_per_minute, 10);

    let stored = db.get_api_key_by_id(&api_key.id).await.unwrap().unwrap();
    assert_eq!(stored.status, "enabled");
    assert_eq!(stored.rate_limit_per_minute, 10);
    assert_eq!(stored.failure_count, 0);
}

#[tokio::test]
async fn test_api_key_status_and_failure_reset() {
    load_test_env();
    let db = Database::new_with_migrations(&test_database_url(), test_timezone())
        .await
        .unwrap();
    let auth = AuthService::new("unit_test_secret".to_string(), db.clone())
        .await
        .unwrap();

    let username = format!("status_user_{}", Uuid::new_v4());
    let user = auth
        .create_user(&username, "AnotherPassw0rd!", false)
        .await
        .unwrap();

    let api_key = auth
        .create_api_key(
            &user,
            CreateApiKeyRequest {
                name: "status-key".to_string(),
                rate_limit_per_minute: 20,
            },
        )
        .await
        .unwrap();

    // Disable the key
    auth.update_api_key_status(
        &user,
        api_key.id,
        UpdateApiKeyStatusRequest { enable: false },
    )
    .await
    .unwrap();
    let stored = db.get_api_key_by_id(&api_key.id).await.unwrap().unwrap();
    assert_eq!(stored.status, "disabled");
    assert!(stored.disabled_at.is_some());

    // Reset failures (should succeed even when disabled)
    auth.reset_api_key_failures(&user, api_key.id, ResetApiKeyFailuresRequest {})
        .await
        .unwrap();
    let stored = db.get_api_key_by_id(&api_key.id).await.unwrap().unwrap();
    assert_eq!(stored.failure_count, 0);
    assert!(stored.last_failed_at.is_none());
}
