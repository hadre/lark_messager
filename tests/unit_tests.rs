use chrono::{Duration, Utc};
use lark_messager::{
    auth::AuthService,
    database::Database,
    error::AppError,
    models::{
        ApiKeyStatus, CreateApiKeyRequest, MessageLogFilters, OperationLogFilters,
        ResetApiKeyFailuresRequest, UpdateApiKeyStatusRequest,
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

#[tokio::test]
async fn test_create_user_and_api_key_flow() {
    load_test_env();
    let db = Database::new_with_migrations(&test_database_url())
        .await
        .unwrap();
    let auth = AuthService::new("unit_test_secret".to_string(), db.clone())
        .await
        .unwrap();

    let username = format!("unit_user_{}", Uuid::new_v4());
    let user = auth
        .create_user(None, &username, "StrongPassw0rd!", true)
        .await
        .unwrap();
    assert_eq!(user.username, username);
    assert!(user.is_admin);
    assert!(!user.is_super_admin);

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
    let db = Database::new_with_migrations(&test_database_url())
        .await
        .unwrap();
    let auth = AuthService::new("unit_test_secret".to_string(), db.clone())
        .await
        .unwrap();

    let username = format!("status_user_{}", Uuid::new_v4());
    let user = auth
        .create_user(None, &username, "AnotherPassw0rd!", false)
        .await
        .unwrap();
    assert!(!user.is_super_admin);

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

#[tokio::test]
async fn test_delete_super_admin_is_blocked() {
    load_test_env();
    let db = Database::new_with_migrations(&test_database_url())
        .await
        .unwrap();
    let auth = AuthService::new("unit_test_secret".to_string(), db.clone())
        .await
        .unwrap();

    let super_admin = db
        .get_user_by_username("super_admin")
        .await
        .unwrap()
        .expect("super_admin seed missing");

    let err = auth
        .delete_user(&super_admin, super_admin.id)
        .await
        .unwrap_err();
    match err {
        AppError::Conflict(message) => {
            assert!(message.contains("Super admin"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn test_operation_log_query_filters() {
    load_test_env();
    let db = Database::new_with_migrations(&test_database_url())
        .await
        .unwrap();
    let auth = AuthService::new("unit_test_secret".to_string(), db.clone())
        .await
        .unwrap();

    let username = format!("op_user_{}", Uuid::new_v4());
    let user = auth
        .create_user(None, &username, "Password123!", false)
        .await
        .unwrap();

    let now = Utc::now();
    db.record_operation_log(Some(user.id), "user.test", "created sample")
        .await
        .unwrap();

    let logs = db
        .list_operation_logs(OperationLogFilters {
            username: Some(user.username.clone()),
            operation_type: Some("user.test".to_string()),
            start_time: Some(now - Duration::minutes(1)),
            end_time: Some(now + Duration::minutes(1)),
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!logs.is_empty());
    assert_eq!(logs[0].operation_type, "user.test");
    assert_eq!(logs[0].username.as_deref(), Some(user.username.as_str()));
}

#[tokio::test]
async fn test_message_log_query_filters() {
    load_test_env();
    let db = Database::new_with_migrations(&test_database_url())
        .await
        .unwrap();
    let auth = AuthService::new("unit_test_secret".to_string(), db.clone())
        .await
        .unwrap();

    let username = format!("msg_user_{}", Uuid::new_v4());
    let user = auth
        .create_user(None, &username, "Password123!", false)
        .await
        .unwrap();

    let api_key = auth
        .create_api_key(
            &user,
            CreateApiKeyRequest {
                name: "log-key".to_string(),
                rate_limit_per_minute: 30,
            },
        )
        .await
        .unwrap();

    db.log_message("api_key", &api_key.id, "user@example.com", "hello", "sent")
        .await
        .unwrap();

    let logs = db
        .list_message_logs(MessageLogFilters {
            sender_id: Some(api_key.id),
            status: Some("sent".to_string()),
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!logs.is_empty());
    assert_eq!(logs[0].sender_id, api_key.id);
    assert_eq!(logs[0].status, "sent");
    assert_eq!(
        logs[0].owner_username.as_deref(),
        Some(user.username.as_str())
    );
}
