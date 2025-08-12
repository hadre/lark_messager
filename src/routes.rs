use crate::handlers::{
    create_api_key, health_check, login, revoke_api_key, send_group_message, send_message,
    verify_recipient, AppState,
};
use axum::{
    routing::{delete, get, post},
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
        // Health check
        .route("/health", get(health_check))
        
        // Authentication routes
        .route("/auth/login", post(login))
        .route("/auth/api-keys", post(create_api_key))
        .route("/auth/api-keys/:key_id", delete(revoke_api_key))
        
        // Message routes
        .route("/messages/send", post(send_message))
        .route("/messages/send-group", post(send_group_message))
        
        // Recipient verification
        .route("/recipients/verify", post(verify_recipient))
        
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}