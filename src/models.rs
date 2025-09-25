/*!
 * 数据模型模块
 *
 * 定义了应用程序中所有的数据结构，包括：
 * - 数据库实体模型（User, ApiKey, MessageLog）
 * - HTTP 请求和响应模型
 * - 业务逻辑相关的枚举类型
 *
 * 所有模型都实现了必要的序列化/反序列化 trait，
 * 以支持 JSON API 和数据库操作。
 */

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// 数据库实体模型
// ============================================================================

/// 用户数据模型
///
/// 对应数据库中的 auth_users 表
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    /// 用户唯一标识符
    pub id: Uuid,
    /// 用户名，用于登录认证
    pub username: String,
    /// 密码哈希值
    pub password_hash: String,
    /// 是否为管理员
    pub is_admin: bool,
    /// 账户创建时间
    pub created_at: DateTime<Utc>,
    /// 最后更新时间
    pub updated_at: DateTime<Utc>,
}

/// API Key 状态
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyStatus {
    Enabled,
    Disabled,
}

impl std::fmt::Display for ApiKeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiKeyStatus::Enabled => write!(f, "enabled"),
            ApiKeyStatus::Disabled => write!(f, "disabled"),
        }
    }
}

impl ApiKeyStatus {
    pub fn from_str(value: &str) -> Self {
        match value {
            "disabled" => ApiKeyStatus::Disabled,
            _ => ApiKeyStatus::Enabled,
        }
    }
}

/// API Key 数据模型
///
/// 对应 auth_api_keys 表
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_secret: String,
    pub name: String,
    pub status: String,
    pub failure_count: i32,
    pub last_failed_at: Option<DateTime<Utc>>,
    pub rate_limit_per_minute: i32,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 配置表实体
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthConfig {
    pub config_type: String,
    pub config_key: String,
    pub config_value: String,
    pub updated_at: DateTime<Utc>,
}

/// 消息日志数据模型
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MessageLog {
    pub id: Uuid,
    pub sender_type: String,
    pub sender_id: Uuid,
    pub recipient: String,
    pub message: String,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// 认证相关的请求/响应模型
// ============================================================================

/// 用户登录请求
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// 用户登录响应（用于管理端口令）
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// 创建用户请求（仅管理员）
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub is_admin: bool,
}

/// 用户响应数据（不包含敏感字段）
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 更新用户密码请求
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserPasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            is_admin: user.is_admin,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

/// 创建 API Key 请求
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub rate_limit_per_minute: i32,
}

/// 创建 API Key 响应
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub secret: String,
    pub status: ApiKeyStatus,
    pub rate_limit_per_minute: i32,
}

/// API Key 列表项
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeySummary {
    pub id: Uuid,
    pub name: String,
    pub status: ApiKeyStatus,
    pub rate_limit_per_minute: i32,
    pub failure_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 更新 API Key 状态请求
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateApiKeyStatusRequest {
    pub enable: bool,
}

/// 更新 API Key 频率限制请求
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateApiKeyRateLimitRequest {
    pub rate_limit_per_minute: i32,
}

/// 重置失败次数请求
#[derive(Debug, Serialize, Deserialize)]
pub struct ResetApiKeyFailuresRequest {}

/// 配置项请求条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfigEntry {
    #[serde(default = "default_auth_config_type")]
    pub config_type: String,
    pub key: String,
    pub value: String,
}

fn default_auth_config_type() -> String {
    "auth".to_string()
}

/// 更新配置请求
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAuthConfigRequest {
    pub entries: Vec<AuthConfigEntry>,
}

/// 更新配置响应
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfigResponse {
    pub entries: Vec<AuthConfigEntry>,
}

// ============================================================================
// 消息发送相关的请求/响应模型
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub recipient: String,
    pub message: String,
    pub recipient_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendGroupMessageRequest {
    pub recipient: String,
    pub message: String,
    pub recipient_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRecipientRequest {
    pub recipient: String,
    pub recipient_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRecipientResponse {
    pub exists: bool,
    pub recipient_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message_id: Option<String>,
    pub status: String,
}

// ============================================================================
// 系统相关响应模型
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

// ============================================================================
// 业务逻辑枚举类型
// ============================================================================

#[derive(Debug)]
pub enum SenderType {
    User,
    ApiKey,
}

impl std::fmt::Display for SenderType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SenderType::User => write!(f, "user"),
            SenderType::ApiKey => write!(f, "api_key"),
        }
    }
}

#[derive(Debug)]
pub enum MessageStatus {
    Sent,
    Failed,
    Pending,
}

impl std::fmt::Display for MessageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MessageStatus::Sent => write!(f, "sent"),
            MessageStatus::Failed => write!(f, "failed"),
            MessageStatus::Pending => write!(f, "pending"),
        }
    }
}
