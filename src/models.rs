use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    pub key_hash: String,
    pub name: String,
    pub permissions: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub permissions: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub key: String,
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub recipient: String,
    pub message: String,
    pub recipient_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendGroupMessageRequest {
    pub chat_id: String,
    pub message: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

#[derive(Debug)]
pub enum SenderType {
    User,
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