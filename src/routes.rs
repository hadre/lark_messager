/*!
 * 路由配置模块
 *
 * 定义所有 HTTP 路由、中间件配置以及共享状态。
 */

use crate::handlers::{
    create_api_key, create_user, delete_api_key, delete_user, extend_jwt_token, get_auth_configs,
    health_check, list_api_keys, login, reset_api_key_failures, send_group_message, send_message,
    update_api_key_rate_limit, update_api_key_status, update_auth_configs, update_user_password,
    verify_recipient, AppState,
};
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/auth/login", post(login))
        .route("/auth/token/extend", post(extend_jwt_token))
        .route("/auth/users", post(create_user))
        .route("/auth/users/:user_id", delete(delete_user))
        .route("/auth/users/:user_id/password", patch(update_user_password))
        .route("/auth/api-keys", post(create_api_key))
        .route("/auth/api-keys", get(list_api_keys))
        .route("/auth/api-keys/:key_id", delete(delete_api_key))
        .route(
            "/auth/api-keys/:key_id/status",
            patch(update_api_key_status),
        )
        .route(
            "/auth/api-keys/:key_id/rate-limit",
            patch(update_api_key_rate_limit),
        )
        .route(
            "/auth/api-keys/:key_id/reset-failures",
            post(reset_api_key_failures),
        )
        .route("/auth/configs", get(get_auth_configs))
        .route("/auth/configs", patch(update_auth_configs))
        .route("/messages/send", post(send_message))
        .route("/messages/send-group", post(send_group_message))
        .route("/recipients/verify", post(verify_recipient))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
