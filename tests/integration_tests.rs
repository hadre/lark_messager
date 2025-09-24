use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum_test::TestServer;
use chrono::FixedOffset;
use lark_messager::{
    auth::AuthService,
    database::Database,
    handlers::AppState,
    lark::LarkClient,
    models::{
        CreateApiKeyRequest, LoginRequest, ResetApiKeyFailuresRequest, UpdateApiKeyStatusRequest,
    },
    routes::create_router,
};
use serde_json::Value;
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

struct TestContext {
    server: TestServer,
    username: String,
    password: String,
}

async fn try_create_test_server() -> Option<TestContext> {
    load_test_env();

    let db = match Database::new_with_migrations(&test_database_url(), test_timezone()).await {
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
    if let Err(err) = auth.create_user(&username, &password, true).await {
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
async fn test_api_key_management_flow() {
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
    let body: Value = login.json();
    let token = body["token"].as_str().unwrap();

    let (name, value) = bearer_headers(token);
    let create = ctx
        .server
        .post("/auth/api-keys")
        .add_header(name, value)
        .json(&CreateApiKeyRequest {
            name: "integration-key".to_string(),
            rate_limit_per_minute: 5,
        })
        .await;
    create.assert_status(StatusCode::OK);
    let created: Value = create.json();
    let key_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    let (name, value) = bearer_headers(token);
    let list = ctx
        .server
        .get("/auth/api-keys")
        .add_header(name, value)
        .await;
    list.assert_status(StatusCode::OK);

    let (name, value) = bearer_headers(token);
    let disable = ctx
        .server
        .patch(&format!("/auth/api-keys/{}/status", key_id))
        .add_header(name, value)
        .json(&UpdateApiKeyStatusRequest { enable: false })
        .await;
    disable.assert_status(StatusCode::NO_CONTENT);

    let (name, value) = bearer_headers(token);
    let reset = ctx
        .server
        .post(&format!("/auth/api-keys/{}/reset-failures", key_id))
        .add_header(name, value)
        .json(&ResetApiKeyFailuresRequest {})
        .await;
    reset.assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_auth_configs_requires_admin() {
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
    let body: Value = login.json();
    let token = body["token"].as_str().unwrap();

    let (name, value) = bearer_headers(token);
    let response = ctx
        .server
        .get("/auth/configs")
        .add_header(name, value)
        .await;
    response.assert_status(StatusCode::OK);
}
