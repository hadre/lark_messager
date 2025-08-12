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
/// 对应数据库中的 users 表，存储用户的认证信息
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    /// 用户唯一标识符
    pub id: Uuid,
    /// 用户名，用于登录认证
    pub username: String,
    /// 密码哈希值，使用 Argon2 算法加密
    pub password_hash: String,
    /// 账户创建时间
    pub created_at: DateTime<Utc>,
    /// 最后更新时间
    pub updated_at: DateTime<Utc>,
}

/// API Key 数据模型
/// 
/// 对应数据库中的 api_keys 表，存储服务间认证的 API 密钥
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiKey {
    /// API Key 唯一标识符
    pub id: Uuid,
    /// API Key 的哈希值，实际密钥不存储
    pub key_hash: String,
    /// API Key 的友好名称，便于管理
    pub name: String,
    /// 权限字符串，逗号分隔的权限列表
    pub permissions: String,
    /// 创建此 API Key 的用户 ID
    pub created_by: Uuid,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 撤销时间，None 表示仍然有效
    pub revoked_at: Option<DateTime<Utc>>,
}

/// 消息日志数据模型
/// 
/// 对应数据库中的 message_logs 表，记录所有消息发送的审计信息
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MessageLog {
    /// 日志记录唯一标识符
    pub id: Uuid,
    /// 发送者类型：user 或 service
    pub sender_type: String,
    /// 发送者 ID（用户 ID 或 API Key 的创建者 ID）
    pub sender_id: Uuid,
    /// 消息接收者标识
    pub recipient: String,
    /// 消息内容
    pub message: String,
    /// 发送状态：sent, failed, pending
    pub status: String,
    /// 消息发送时间
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// 认证相关的请求/响应模型
// ============================================================================

/// 用户登录请求
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    /// 用户名
    pub username: String,
    /// 明文密码
    pub password: String,
}

/// 用户登录响应
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    /// JWT 访问令牌
    pub token: String,
    /// 令牌过期时间
    pub expires_at: DateTime<Utc>,
}

/// 创建 API Key 请求
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    /// API Key 的友好名称
    pub name: String,
    /// 权限字符串，例如 "send_messages,admin"
    pub permissions: String,
}

/// 创建 API Key 响应
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    /// 生成的 API Key（明文，仅此次返回）
    pub key: String,
    /// API Key 的数据库 ID
    pub id: Uuid,
    /// API Key 的友好名称
    pub name: String,
}

// ============================================================================
// 消息发送相关的请求/响应模型
// ============================================================================

/// 发送消息给用户的请求
#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// 接收者标识（用户 ID、邮箱、手机号等）
    pub recipient: String,
    /// 消息内容
    pub message: String,
    /// 接收者类型：user_id, email, mobile, auto
    pub recipient_type: Option<String>,
}

/// 发送群组消息的请求
#[derive(Debug, Serialize, Deserialize)]
pub struct SendGroupMessageRequest {
    /// 群组/聊天标识（聊天 ID 或聊天名称）
    pub recipient: String,
    /// 消息内容
    pub message: String,
    /// 接收者类型：chat_id, chat_name, auto（可选）
    pub recipient_type: Option<String>,
}

/// 验证接收者的请求
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRecipientRequest {
    /// 接收者标识
    pub recipient: String,
    /// 接收者类型
    pub recipient_type: Option<String>,
}

/// 验证接收者的响应
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRecipientResponse {
    /// 接收者是否存在
    pub exists: bool,
    /// 解析出的接收者 ID（如果存在）
    pub recipient_id: Option<String>,
}

/// 消息发送响应
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageResponse {
    /// 飞书返回的消息 ID（如果成功）
    pub message_id: Option<String>,
    /// 发送状态
    pub status: String,
}

// ============================================================================
// 系统相关的响应模型
// ============================================================================

/// 健康检查响应
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// 服务状态
    pub status: String,
    /// 检查时间
    pub timestamp: DateTime<Utc>,
    /// 应用版本
    pub version: String,
}

// ============================================================================
// 业务逻辑枚举类型
// ============================================================================

/// 发送者类型枚举
/// 
/// 用于区分消息是由用户直接发送还是通过服务接口发送
#[derive(Debug)]
pub enum SenderType {
    /// 通过 JWT 认证的用户
    User,
    /// 通过 API Key 认证的服务
    Service,
}

impl std::fmt::Display for SenderType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SenderType::User => write!(f, "user"),
            SenderType::Service => write!(f, "service"),
        }
    }
}

/// 消息状态枚举
/// 
/// 表示消息发送的不同状态
#[derive(Debug)]
pub enum MessageStatus {
    /// 成功发送
    Sent,
    /// 发送失败
    Failed,
    /// 等待发送
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