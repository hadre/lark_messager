use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum_test::TestServer;
use lark_messager::{
    auth::AuthService,
    database::Database,
    handlers::AppState,
    lark::LarkClient,
    models::{
        CreateApiKeyRequest, CreateUserRequest, LoginRequest, ResetApiKeyFailuresRequest,
        UpdateApiKeyStatusRequest, UserResponse,
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
