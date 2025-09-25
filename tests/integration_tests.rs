use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum_test::TestServer;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, DecodingKey, Validation};
use lark_messager::{
    auth::AuthService,
    database::Database,
    handlers::AppState,
    lark::LarkClient,
    models::{
        CreateApiKeyRequest, CreateUserRequest, LoginRequest, ResetApiKeyFailuresRequest,
        SendGroupMessageRequest, SendMessageRequest, UpdateApiKeyStatusRequest,
        UpdateAuthConfigRequest, UpdateUserPasswordRequest, UserResponse,
    },
    routes::create_router,
};
use serde::Deserialize;
use serde_json::{self, Value};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

fn load_test_env() {
    dotenvy::from_filename(".env.test").ok();
}

fn test_database_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@localhost:3306/test_lark_messager".to_string())
}

fn required_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(val) if !val.trim().is_empty() => Some(val),
        _ => {
            eprintln!("Skipping test because environment variable {key} is not set");
            None
        }
    }
}

fn sign_api_request(
    secret: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
) -> String {
    let canonical = format!(
        "{timestamp}\n{nonce}\n{method}\n{path}",
        method = method.to_uppercase()
    );
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

struct TestContext {
    server: TestServer,
    username: String,
    password: String,
}

async fn try_create_test_server() -> Option<TestContext> {
    load_test_env();

    let db = match Database::new_with_migrations(&test_database_url()).await {
        Ok(db) => db,
        Err(err) => {
            eprintln!("Skipping integration test (database unavailable): {err}");
            return None;
        }
    };

    let jwt_secret =
        std::env::var("TEST_JWT_SECRET").unwrap_or_else(|_| "test_jwt_secret".to_string());
    let auth = match AuthService::new(jwt_secret, db.clone()).await {
        Ok(auth) => auth,
        Err(err) => {
            eprintln!("Skipping integration test (auth init failed): {err}");
            return None;
        }
    };

    let username = format!(
        "admin_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "testpass123".to_string();
    if let Err(err) = auth.create_user(None, &username, &password, true).await {
        eprintln!("Skipping integration test (user init failed): {err}");
        return None;
    }

    let lark = LarkClient::new(
        std::env::var("TEST_LARK_APP_ID").unwrap_or_else(|_| "test_app_id".to_string()),
        std::env::var("TEST_LARK_APP_SECRET").unwrap_or_else(|_| "test_app_secret".to_string()),
    );

    let state = AppState { db, auth, lark };
    let app = create_router(state);

    Some(TestContext {
        server: TestServer::new(app).unwrap(),
        username,
        password,
    })
}

fn bearer_headers(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
    )
}

async fn create_api_key_for_user(ctx: &TestContext, key_name: &str) -> (Uuid, String) {
    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let login_body: Value = login.json();
    let token = login_body["token"].as_str().unwrap();
    let (header_name, header_value) = bearer_headers(token);

    let create = ctx
        .server
        .post("/auth/api-keys")
        .add_header(header_name, header_value)
        .json(&CreateApiKeyRequest {
            name: key_name.to_string(),
            rate_limit_per_minute: 60,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: Value = create.json();
    let key_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    let secret = created["secret"].as_str().unwrap().to_string();
    (key_id, secret)
}

#[tokio::test]
async fn test_health_check() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };
    let response = ctx.server.get("/health").await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_login_success_and_failure() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let success = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    success.assert_status_ok();

    let failure = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: "wrong".to_string(),
        })
        .await;
    failure.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_extend_jwt_token_uses_configured_window() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let token = body["token"].as_str().unwrap();
    let initial_exp: DateTime<Utc> =
        DateTime::parse_from_rfc3339(body["expires_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);

    let (header_name, header_value) = bearer_headers(token);
    let extend = ctx
        .server
        .post("/auth/token/extend")
        .add_header(header_name, header_value)
        .await;
    extend.assert_status(StatusCode::OK);
    let extended: Value = extend.json();
    let new_token = extended["token"].as_str().unwrap();
    let new_exp: DateTime<Utc> =
        DateTime::parse_from_rfc3339(extended["expires_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);

    assert_ne!(token, new_token);
    assert!(new_exp > initial_exp);
    let diff = (new_exp - initial_exp).num_seconds();
    assert!(
        diff >= 1,
        "expected expiration to be extended, diff {diff}s"
    );
}

#[tokio::test]
async fn test_non_admin_can_manage_own_api_keys() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let admin_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    let admin_body: Value = admin_login.json();
    let admin_token = admin_body["token"].as_str().unwrap();

    let new_username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "userpass123".to_string();

    let (admin_header_name, admin_header_value) = bearer_headers(admin_token);
    let create_user = ctx
        .server
        .post("/auth/users")
        .add_header(admin_header_name.clone(), admin_header_value.clone())
        .json(&CreateUserRequest {
            username: new_username.clone(),
            password: password.clone(),
            is_admin: false,
        })
        .await;
    create_user.assert_status(StatusCode::OK);

    let user_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username.clone(),
            password: password.clone(),
        })
        .await;
    user_login.assert_status_ok();
    let user_body: Value = user_login.json();
    let user_token = user_body["token"].as_str().unwrap();

    let (user_header_name, user_header_value) = bearer_headers(user_token);
    let create_key = ctx
        .server
        .post("/auth/api-keys")
        .add_header(user_header_name.clone(), user_header_value.clone())
        .json(&CreateApiKeyRequest {
            name: "non-admin-key".to_string(),
            rate_limit_per_minute: 10,
        })
        .await;
    create_key.assert_status(StatusCode::OK);
    let created_key: Value = create_key.json();
    let key_id = Uuid::parse_str(created_key["id"].as_str().unwrap()).unwrap();

    let list = ctx
        .server
        .get("/auth/api-keys")
        .add_header(user_header_name.clone(), user_header_value.clone())
        .await;
    list.assert_status(StatusCode::OK);

    let disable = ctx
        .server
        .patch(&format!("/auth/api-keys/{}/status", key_id))
        .add_header(user_header_name.clone(), user_header_value.clone())
        .json(&UpdateApiKeyStatusRequest { enable: false })
        .await;
    disable.assert_status(StatusCode::NO_CONTENT);

    let enable = ctx
        .server
        .patch(&format!("/auth/api-keys/{}/status", key_id))
        .add_header(user_header_name.clone(), user_header_value.clone())
        .json(&UpdateApiKeyStatusRequest { enable: true })
        .await;
    enable.assert_status(StatusCode::NO_CONTENT);

    let reset = ctx
        .server
        .post(&format!("/auth/api-keys/{}/reset-failures", key_id))
        .add_header(user_header_name.clone(), user_header_value.clone())
        .json(&ResetApiKeyFailuresRequest {})
        .await;
    reset.assert_status(StatusCode::NO_CONTENT);

    let delete = ctx
        .server
        .delete(&format!("/auth/api-keys/{}", key_id))
        .add_header(user_header_name, user_header_value)
        .await;
    delete.assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_auth_configs_require_admin() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let admin_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    let admin_body: Value = admin_login.json();
    let admin_token = admin_body["token"].as_str().unwrap();

    let (name, value) = bearer_headers(admin_token);
    let response = ctx
        .server
        .get("/auth/configs")
        .add_header(name, value)
        .await;
    response.assert_status(StatusCode::OK);

    let new_username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "configtest123".to_string();

    let (admin_header_name, admin_header_value) = bearer_headers(admin_token);
    let create_user = ctx
        .server
        .post("/auth/users")
        .add_header(admin_header_name, admin_header_value)
        .json(&CreateUserRequest {
            username: new_username.clone(),
            password: password.clone(),
            is_admin: false,
        })
        .await;
    create_user.assert_status(StatusCode::OK);

    let user_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username.clone(),
            password: password.clone(),
        })
        .await;
    user_login.assert_status_ok();
    let user_body: Value = user_login.json();
    let user_token = user_body["token"].as_str().unwrap();
    let (user_header_name, user_header_value) = bearer_headers(user_token);

    let forbidden_get = ctx
        .server
        .get("/auth/configs")
        .add_header(user_header_name.clone(), user_header_value.clone())
        .await;
    forbidden_get.assert_status(StatusCode::FORBIDDEN);

    let forbidden_patch = ctx
        .server
        .patch("/auth/configs")
        .add_header(user_header_name, user_header_value)
        .json(&UpdateAuthConfigRequest { entries: vec![] })
        .await;
    forbidden_patch.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_admin_can_create_user_and_non_admin_is_forbidden() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let admin_token = body["token"].as_str().unwrap();

    let new_username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let new_password = "newpass123".to_string();

    let (header_name, header_value) = bearer_headers(admin_token);
    let create = ctx
        .server
        .post("/auth/users")
        .add_header(header_name, header_value)
        .json(&CreateUserRequest {
            username: new_username.clone(),
            password: new_password.clone(),
            is_admin: false,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: UserResponse = create.json();
    assert_eq!(created.username, new_username);
    assert!(!created.is_admin);
    assert!(!created.is_super_admin);

    let login_non_admin = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username.clone(),
            password: new_password.clone(),
        })
        .await;
    login_non_admin.assert_status_ok();
    let non_admin_body: Value = login_non_admin.json();
    let non_admin_token = non_admin_body["token"].as_str().unwrap();

    let (header_name, header_value) = bearer_headers(non_admin_token);
    let forbidden = ctx
        .server
        .post("/auth/users")
        .add_header(header_name, header_value)
        .json(&CreateUserRequest {
            username: format!(
                "user_{}",
                Uuid::new_v4().to_string().split('-').next().unwrap()
            ),
            password: "anotherpass123".to_string(),
            is_admin: false,
        })
        .await;
    forbidden.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_admin_cannot_create_admin_without_super_privileges() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let admin_token = body["token"].as_str().unwrap();

    let (header_name, header_value) = bearer_headers(admin_token);
    let response = ctx
        .server
        .post("/auth/users")
        .add_header(header_name, header_value)
        .json(&CreateUserRequest {
            username: format!(
                "admin_candidate_{}",
                Uuid::new_v4().to_string().split('-').next().unwrap()
            ),
            password: "AnotherPass123!".to_string(),
            is_admin: true,
        })
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_super_admin_can_create_admin_user() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: "super_admin".to_string(),
            password: "ChangeMe123!".to_string(),
        })
        .await;
    login.assert_status_ok();
    let login_body: Value = login.json();
    let token = login_body["token"].as_str().unwrap();

    let (header_name, header_value) = bearer_headers(token);
    let admin_username = format!(
        "promoted_admin_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let admin_password = "PromotedPass123!".to_string();

    let create = ctx
        .server
        .post("/auth/users")
        .add_header(header_name.clone(), header_value.clone())
        .json(&CreateUserRequest {
            username: admin_username.clone(),
            password: admin_password.clone(),
            is_admin: true,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: UserResponse = create.json();
    assert!(created.is_admin);
    assert!(!created.is_super_admin);

    let login_new_admin = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: admin_username,
            password: admin_password,
        })
        .await;
    login_new_admin.assert_status_ok();
}

#[tokio::test]
async fn test_super_admin_cannot_delete_self() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: "super_admin".to_string(),
            password: "ChangeMe123!".to_string(),
        })
        .await;
    login.assert_status_ok();
    let login_body: Value = login.json();
    let token = login_body["token"].as_str().unwrap();

    let super_admin_id = extract_sub_from_jwt(token).expect("missing sub");

    let (header_name, header_value) = bearer_headers(token);
    let delete = ctx
        .server
        .delete(&format!("/auth/users/{super_admin_id}"))
        .add_header(header_name, header_value)
        .await;
    delete.assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_user_can_update_own_password_with_current_secret() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let admin_token = body["token"].as_str().unwrap();

    let new_username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let original_password = "origpass123".to_string();

    let (header_name, header_value) = bearer_headers(admin_token);
    let create = ctx
        .server
        .post("/auth/users")
        .add_header(header_name.clone(), header_value.clone())
        .json(&CreateUserRequest {
            username: new_username.clone(),
            password: original_password.clone(),
            is_admin: false,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: UserResponse = create.json();
    assert!(!created.is_super_admin);

    let user_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username.clone(),
            password: original_password.clone(),
        })
        .await;
    user_login.assert_status_ok();
    let user_body: Value = user_login.json();
    let user_token = user_body["token"].as_str().unwrap();
    let (user_header_name, user_header_value) = bearer_headers(user_token);

    let updated_password = "updatedpass456".to_string();
    let update = ctx
        .server
        .patch(&format!("/auth/users/{}/password", created.id))
        .add_header(user_header_name, user_header_value)
        .json(&UpdateUserPasswordRequest {
            current_password: original_password.clone(),
            new_password: updated_password.clone(),
        })
        .await;
    update.assert_status(StatusCode::OK);

    let old_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username.clone(),
            password: original_password,
        })
        .await;
    old_login.assert_status(StatusCode::UNAUTHORIZED);

    let new_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username,
            password: updated_password,
        })
        .await;
    new_login.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn test_admin_can_delete_user() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let admin_token = body["token"].as_str().unwrap();

    let new_username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "deleteme123".to_string();

    let (header_name, header_value) = bearer_headers(admin_token);
    let create = ctx
        .server
        .post("/auth/users")
        .add_header(header_name.clone(), header_value.clone())
        .json(&CreateUserRequest {
            username: new_username.clone(),
            password: password.clone(),
            is_admin: false,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: UserResponse = create.json();

    let delete = ctx
        .server
        .delete(&format!("/auth/users/{}", created.id))
        .add_header(header_name, header_value)
        .await;
    delete.assert_status(StatusCode::NO_CONTENT);

    let login_deleted = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username,
            password,
        })
        .await;
    login_deleted.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_cannot_update_other_users_password() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let admin_token = body["token"].as_str().unwrap();

    let user_one = format!(
        "user1_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let user_two = format!(
        "user2_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password_one = "password1".to_string();
    let password_two = "password2".to_string();

    let (admin_header_name, admin_header_value) = bearer_headers(admin_token);
    let create_first = ctx
        .server
        .post("/auth/users")
        .add_header(admin_header_name.clone(), admin_header_value.clone())
        .json(&CreateUserRequest {
            username: user_one.clone(),
            password: password_one.clone(),
            is_admin: false,
        })
        .await;
    create_first.assert_status(StatusCode::OK);
    let first_user: UserResponse = create_first.json();
    assert!(!first_user.is_super_admin);

    let create_second = ctx
        .server
        .post("/auth/users")
        .add_header(admin_header_name, admin_header_value)
        .json(&CreateUserRequest {
            username: user_two.clone(),
            password: password_two.clone(),
            is_admin: false,
        })
        .await;
    create_second.assert_status(StatusCode::OK);
    let _second_user: UserResponse = create_second.json();

    let (admin_attempt_name, admin_attempt_value) = bearer_headers(admin_token);
    let admin_attempt = ctx
        .server
        .patch(&format!("/auth/users/{}/password", first_user.id))
        .add_header(admin_attempt_name, admin_attempt_value)
        .json(&UpdateUserPasswordRequest {
            current_password: password_one.clone(),
            new_password: "adminchange".to_string(),
        })
        .await;
    admin_attempt.assert_status(StatusCode::FORBIDDEN);

    let user_one_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: user_one.clone(),
            password: password_one.clone(),
        })
        .await;
    user_one_login.assert_status_ok();
    let user_one_body: Value = user_one_login.json();
    let _user_one_token = user_one_body["token"].as_str().unwrap();

    let user_two_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: user_two.clone(),
            password: password_two.clone(),
        })
        .await;
    user_two_login.assert_status_ok();
    let user_two_body: Value = user_two_login.json();
    let user_two_token = user_two_body["token"].as_str().unwrap();
    let (user_two_header_name, user_two_header_value) = bearer_headers(user_two_token);

    let unauthorized_attempt = ctx
        .server
        .patch(&format!("/auth/users/{}/password", first_user.id))
        .add_header(user_two_header_name, user_two_header_value)
        .json(&UpdateUserPasswordRequest {
            current_password: password_one.clone(),
            new_password: "shouldnotwork".to_string(),
        })
        .await;
    unauthorized_attempt.assert_status(StatusCode::FORBIDDEN);

    let user_one_still_valid = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: user_one,
            password: password_one,
        })
        .await;
    user_one_still_valid.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn test_update_password_requires_current_password_validation() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let admin_token = body["token"].as_str().unwrap();

    let new_username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let original_password = "origpass123".to_string();

    let (admin_header_name, admin_header_value) = bearer_headers(admin_token);
    let create = ctx
        .server
        .post("/auth/users")
        .add_header(admin_header_name, admin_header_value)
        .json(&CreateUserRequest {
            username: new_username.clone(),
            password: original_password.clone(),
            is_admin: false,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: UserResponse = create.json();

    let user_login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username.clone(),
            password: original_password.clone(),
        })
        .await;
    user_login.assert_status_ok();
    let user_body: Value = user_login.json();
    let user_token = user_body["token"].as_str().unwrap();
    let (user_header_name, user_header_value) = bearer_headers(user_token);

    let attempt = ctx
        .server
        .patch(&format!("/auth/users/{}/password", created.id))
        .add_header(user_header_name, user_header_value)
        .json(&UpdateUserPasswordRequest {
            current_password: "wrongpass".to_string(),
            new_password: "newpass456".to_string(),
        })
        .await;
    attempt.assert_status(StatusCode::UNAUTHORIZED);

    let login_still_valid = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username,
            password: original_password,
        })
        .await;
    login_still_valid.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn test_non_admin_cannot_delete_users() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let login = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: ctx.username.clone(),
            password: ctx.password.clone(),
        })
        .await;
    login.assert_status_ok();
    let body: Value = login.json();
    let admin_token = body["token"].as_str().unwrap();

    let new_username = format!(
        "user_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password = "regularpass123".to_string();

    let (admin_header_name, admin_header_value) = bearer_headers(admin_token);
    let create = ctx
        .server
        .post("/auth/users")
        .add_header(admin_header_name, admin_header_value)
        .json(&CreateUserRequest {
            username: new_username.clone(),
            password: password.clone(),
            is_admin: false,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: UserResponse = create.json();

    let login_non_admin = ctx
        .server
        .post("/auth/login")
        .json(&LoginRequest {
            username: new_username.clone(),
            password: password.clone(),
        })
        .await;
    login_non_admin.assert_status_ok();
    let body: Value = login_non_admin.json();
    let non_admin_token = body["token"].as_str().unwrap();

    let (header_name, header_value) = bearer_headers(non_admin_token);
    let forbidden_delete = ctx
        .server
        .delete(&format!("/auth/users/{}", created.id))
        .add_header(header_name, header_value)
        .await;
    forbidden_delete.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_send_message_to_user_via_api_key() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let Some(recipient) = required_env("TEST_LARK_RECIPIENT_USER") else {
        return;
    };
    let recipient_type = std::env::var("TEST_LARK_RECIPIENT_USER_TYPE").ok();

    let (key_id, secret) = create_api_key_for_user(&ctx, "user-message-key").await;

    let timestamp = Utc::now().timestamp().to_string();
    let nonce = Uuid::new_v4().to_string();
    let signature = sign_api_request(&secret, "POST", "/messages/send", &timestamp, &nonce);

    let message = format!(
        "Integration direct message sent at {}",
        Utc::now().to_rfc3339()
    );
    let response = ctx
        .server
        .post("/messages/send")
        .add_header(
            HeaderName::from_static("x-lark-access-key"),
            HeaderValue::from_str(&key_id.to_string()).unwrap(),
        )
        .add_header(
            HeaderName::from_static("x-lark-timestamp"),
            HeaderValue::from_str(&timestamp).unwrap(),
        )
        .add_header(
            HeaderName::from_static("x-lark-nonce"),
            HeaderValue::from_str(&nonce).unwrap(),
        )
        .add_header(
            HeaderName::from_static("x-lark-signature"),
            HeaderValue::from_str(&signature).unwrap(),
        )
        .json(&SendMessageRequest {
            recipient,
            message,
            recipient_type,
        })
        .await;

    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["status"], "sent");
    assert!(body["message_id"].is_string());
}

#[tokio::test]
async fn test_send_message_to_group_via_api_key() {
    let Some(ctx) = try_create_test_server().await else {
        return;
    };

    let Some(recipient) = required_env("TEST_LARK_RECIPIENT_GROUP") else {
        return;
    };
    let recipient_type = std::env::var("TEST_LARK_RECIPIENT_GROUP_TYPE").ok();

    let (key_id, secret) = create_api_key_for_user(&ctx, "group-message-key").await;

    let timestamp = Utc::now().timestamp().to_string();
    let nonce = Uuid::new_v4().to_string();
    let signature = sign_api_request(&secret, "POST", "/messages/send-group", &timestamp, &nonce);

    let message = format!(
        "Integration group message sent at {}",
        Utc::now().to_rfc3339()
    );
    let response = ctx
        .server
        .post("/messages/send-group")
        .add_header(
            HeaderName::from_static("x-lark-access-key"),
            HeaderValue::from_str(&key_id.to_string()).unwrap(),
        )
        .add_header(
            HeaderName::from_static("x-lark-timestamp"),
            HeaderValue::from_str(&timestamp).unwrap(),
        )
        .add_header(
            HeaderName::from_static("x-lark-nonce"),
            HeaderValue::from_str(&nonce).unwrap(),
        )
        .add_header(
            HeaderName::from_static("x-lark-signature"),
            HeaderValue::from_str(&signature).unwrap(),
        )
        .json(&SendGroupMessageRequest {
            recipient,
            message,
            recipient_type,
        })
        .await;

    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["status"], "sent");
    assert!(body["message_id"].is_string());
}
#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    username: String,
    exp: usize,
    iat: usize,
    is_admin: bool,
    #[serde(default)]
    is_super_admin: bool,
}

fn extract_sub_from_jwt(token: &str) -> Option<String> {
    let secret = std::env::var("TEST_JWT_SECRET").unwrap_or_else(|_| "test_jwt_secret".to_string());
    let decoded = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?;
    Some(decoded.claims.sub)
}
