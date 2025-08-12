/*!
 * 错误处理模块
 * 
 * 定义了应用程序中所有可能出现的错误类型，并提供统一的错误处理机制。
 * 所有错误都会被转换为适当的 HTTP 响应，确保客户端能够获得有意义的错误信息。
 */

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// 应用程序结果类型的别名
/// 
/// 所有可能失败的操作都应该返回这个类型，统一错误处理
pub type AppResult<T> = Result<T, AppError>;

/// 应用程序错误枚举
/// 
/// 定义了所有可能出现的错误情况，每种错误都会映射到相应的 HTTP 状态码
#[derive(Error, Debug)]
pub enum AppError {
    /// 数据库操作错误
    /// 包括连接失败、查询错误、事务失败等
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// 数据库迁移错误
    /// 在应用启动时执行数据库迁移失败
    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// 认证失败错误
    /// 用户名密码错误、JWT 验证失败、API Key 无效等
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// 授权失败错误
    /// 用户没有执行特定操作的权限
    #[error("Authorization failed: {0}")]
    Unauthorized(String),

    /// 请求验证错误
    /// 请求参数格式错误、必填字段缺失等
    #[error("Validation error: {0}")]
    Validation(String),

    /// 飞书 API 调用错误
    /// 包括网络错误、API 限流、权限不足等
    #[error("Lark API error: {0}")]
    Lark(String),

    /// HTTP 客户端错误
    /// 网络请求失败、超时等
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    /// JSON 解析错误
    /// 请求或响应的 JSON 格式错误
    #[error("JSON parsing error: {0}")]
    JsonParsing(#[from] serde_json::Error),

    /// JWT 处理错误
    /// JWT 生成、解析、验证失败
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// 配置错误
    /// 环境变量缺失、配置格式错误等
    #[error("Configuration error: {0}")]
    Config(String),

    /// 内部服务器错误
    /// 未预期的错误情况
    #[error("Internal server error: {0}")]
    Internal(String),

    /// 资源未找到错误
    /// 请求的资源不存在
    #[error("Not found: {0}")]
    NotFound(String),

    /// 限流错误
    /// 请求频率超过限制
    #[error("Rate limit exceeded")]
    RateLimit,
}

impl IntoResponse for AppError {
    /// 将错误转换为 HTTP 响应
    /// 
    /// 根据错误类型选择适当的 HTTP 状态码，并返回包含错误信息的 JSON 响应
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Auth(_) => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            AppError::Unauthorized(_) => (StatusCode::FORBIDDEN, "Access denied"),
            AppError::Validation(_) => (StatusCode::BAD_REQUEST, "Invalid request"),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "Resource not found"),
            AppError::RateLimit => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
            AppError::Lark(_) => (StatusCode::BAD_GATEWAY, "External service error"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };

        // 构造 JSON 错误响应
        let body = Json(json!({
            "error": error_message,
            "message": self.to_string()
        }));

        (status, body).into_response()
    }
}