/*!
 * 路由配置模块
 * 
 * 定义了应用程序的所有 HTTP 路由和中间件配置。
 * 包括 API 端点、CORS 设置、请求追踪等。
 */

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

/// 创建应用程序路由器
/// 
/// 配置所有的 HTTP 路由、中间件和应用状态。
pub fn create_router(state: AppState) -> Router {
    // 配置 CORS 中间件，允许所有来源、方法和头部
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        // 系统健康检查端点
        .route("/health", get(health_check))
        
        // 认证相关路由组
        .route("/auth/login", post(login))
        .route("/auth/api-keys", post(create_api_key))
        .route("/auth/api-keys/:key_id", delete(revoke_api_key))
        
        // 消息发送路由组
        .route("/messages/send", post(send_message))
        .route("/messages/send-group", post(send_group_message))
        
        // 辅助功能路由组
        .route("/recipients/verify", post(verify_recipient))
        
        // 应用中间件层
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}