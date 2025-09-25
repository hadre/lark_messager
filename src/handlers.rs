/*!
 * HTTP 请求处理器模块
 *
 * 包含所有 API 端点的处理逻辑：
 * - 健康检查
 * - 用户登录、API Key 管理
 * - 鉴权配置管理（管理员）
 * - 消息发送、验证（签名鉴权）
 */

use crate::auth::{AuthService, AuthenticatedApiKey};
use crate::database::Database;
use crate::error::{AppError, AppResult};
use crate::lark::LarkClient;
use crate::models::{
    ApiKeyStatus, ApiKeySummary, AuthConfigResponse, CreateApiKeyRequest, CreateApiKeyResponse,
    CreateUserRequest, HealthResponse, LoginRequest, LoginResponse, MessageResponse,
    MessageStatus, ResetApiKeyFailuresRequest, SendGroupMessageRequest, SendMessageRequest,
    SenderType, UpdateApiKeyRateLimitRequest, UpdateApiKeyStatusRequest, UpdateAuthConfigRequest,
    UpdateUserPasswordRequest, User, UserResponse, VerifyRecipientRequest, VerifyRecipientResponse,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use tracing::{error, info, warn};
use uuid::Uuid;

const HEADER_ACCESS_KEY: &str = "x-lark-access-key";
const HEADER_TIMESTAMP: &str = "x-lark-timestamp";
const HEADER_NONCE: &str = "x-lark-nonce";
const HEADER_SIGNATURE: &str = "x-lark-signature";

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub auth: AuthService,
    pub lark: LarkClient,
}

// -----------------------------------------------------------------------------
// 公共端点
// -----------------------------------------------------------------------------

pub async fn health_check() -> AppResult<Json<HealthResponse>> {
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

// -----------------------------------------------------------------------------
// 用户登录（管理接口使用）
// -----------------------------------------------------------------------------

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    info!("Login attempt for username: {}", request.username);

    let user = state
        .auth
        .authenticate_user(&request.username, &request.password)
        .await?;

    let (token, expires_at) = state.auth.generate_jwt_token(&user)?;

    info!("Successful login for user: {}", user.username);

    Ok(Json(LoginResponse { token, expires_at }))
}

// -----------------------------------------------------------------------------
// 用户管理（管理员）
// -----------------------------------------------------------------------------

pub async fn create_user(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    ensure_admin(&user)?;

    let created = state
        .auth
        .create_user(&request.username, &request.password, request.is_admin)
        .await?;

    info!(
        "User created: {} (is_admin: {}) by admin {}",
        created.username, created.is_admin, user.username
    );

    Ok(Json(UserResponse::from(created)))
}

pub async fn update_user_password(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserPasswordRequest>,
) -> AppResult<Json<UserResponse>> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;

    if user.id != user_id {
        return Err(AppError::Unauthorized(
            "Cannot modify another user's password".to_string(),
        ));
    }

    let updated = state
        .auth
        .change_own_password(&user, &request.current_password, &request.new_password)
        .await?;

    info!("Password updated for user {}", user.username);

    Ok(Json(UserResponse::from(updated)))
}

pub async fn delete_user(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    ensure_admin(&user)?;

    state.auth.delete_user(user_id).await?;
    info!("User {} deleted by admin {}", user_id, user.username);

    Ok(StatusCode::NO_CONTENT)
}

pub async fn extend_jwt_token(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> AppResult<Json<LoginResponse>> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AppError::Auth("Authorization header required".to_string()))?;

    let value = auth_header
        .to_str()
        .map_err(|_| AppError::Auth("Invalid authorization header".to_string()))?;

    if !value.starts_with("Bearer ") {
        return Err(AppError::Auth("Bearer token required".to_string()));
    }

    let token = &value[7..];
    let (new_token, expires_at) = state.auth.extend_jwt_token(token).await?;
    Ok(Json(LoginResponse {
        token: new_token,
        expires_at,
    }))
}

// -----------------------------------------------------------------------------
// API Key 管理（需要 JWT）
// -----------------------------------------------------------------------------

pub async fn create_api_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<CreateApiKeyRequest>,
) -> AppResult<Json<CreateApiKeyResponse>> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    let response = state.auth.create_api_key(&user, request).await?;
    info!("API key created: {} by {}", response.id, user.username);
    Ok(Json(response))
}

pub async fn list_api_keys(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<ApiKeySummary>>> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    let keys = state.auth.list_api_keys(&user).await?;
    let summaries = keys
        .into_iter()
        .map(|k| ApiKeySummary {
            id: k.id,
            name: k.name,
            status: ApiKeyStatus::from_str(&k.status),
            rate_limit_per_minute: k.rate_limit_per_minute,
            failure_count: k.failure_count,
            created_at: k.created_at,
            updated_at: k.updated_at,
        })
        .collect();
    Ok(Json(summaries))
}

pub async fn update_api_key_status(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
    Json(request): Json<UpdateApiKeyStatusRequest>,
) -> AppResult<StatusCode> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    state
        .auth
        .update_api_key_status(&user, key_id, request)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_api_key_rate_limit(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
    Json(request): Json<UpdateApiKeyRateLimitRequest>,
) -> AppResult<StatusCode> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    state
        .auth
        .update_api_key_rate_limit(&user, key_id, request)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reset_api_key_failures(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
    Json(request): Json<ResetApiKeyFailuresRequest>,
) -> AppResult<StatusCode> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    state
        .auth
        .reset_api_key_failures(&user, key_id, request)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_api_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    state.auth.delete_api_key(&user, key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// -----------------------------------------------------------------------------
// 鉴权配置管理（管理员）
// -----------------------------------------------------------------------------

pub async fn get_auth_configs(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> AppResult<Json<AuthConfigResponse>> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    ensure_admin(&user)?;
    let configs = state.auth.get_auth_configs().await?;
    Ok(Json(configs))
}

pub async fn update_auth_configs(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<UpdateAuthConfigRequest>,
) -> AppResult<Json<AuthConfigResponse>> {
    let user = authenticate_user_from_jwt(&headers, &state).await?;
    ensure_admin(&user)?;
    let response = state.auth.update_auth_configs(&user, request).await?;
    Ok(Json(response))
}

// -----------------------------------------------------------------------------
// 消息操作（签名鉴权）
// -----------------------------------------------------------------------------

pub async fn send_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<SendMessageRequest>,
) -> AppResult<Json<MessageResponse>> {
    if request.message.trim().is_empty() {
        return Err(AppError::Validation("Message cannot be empty".to_string()));
    }

    if request.message.len() > 10_000 {
        return Err(AppError::Validation(
            "Message too long (max 10000 characters)".to_string(),
        ));
    }

    let auth_key = authenticate_signed_api_key(&headers, &state, "POST", "/messages/send").await?;

    info!(
        "API key {} sending message to recipient: {}",
        auth_key.key.id, request.recipient
    );

    let recipient_id = state
        .lark
        .verify_recipient(&request.recipient, request.recipient_type.as_deref())
        .await?;

    let Some(actual_recipient) = recipient_id else {
        warn!("Recipient not found for {}", request.recipient);
        state
            .db
            .log_message(
                &SenderType::ApiKey.to_string(),
                &auth_key.key.id,
                &request.recipient,
                &request.message,
                &MessageStatus::Failed.to_string(),
            )
            .await?;
        return Err(AppError::NotFound("Recipient not found".to_string()));
    };

    let result = state
        .lark
        .send_message_to_user(&actual_recipient, &request.message)
        .await;

    let (status, message_id) = match &result {
        Ok(msg_id) => (MessageStatus::Sent, msg_id.clone()),
        Err(err) => {
            error!("Failed to send message to {}: {}", actual_recipient, err);
            (MessageStatus::Failed, None)
        }
    };

    state
        .db
        .log_message(
            &SenderType::ApiKey.to_string(),
            &auth_key.key.id,
            &request.recipient,
            &request.message,
            &status.to_string(),
        )
        .await?;

    match result {
        Ok(_) => Ok(Json(MessageResponse {
            message_id,
            status: status.to_string(),
        })),
        Err(err) => Err(err),
    }
}

pub async fn send_group_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<SendGroupMessageRequest>,
) -> AppResult<Json<MessageResponse>> {
    let auth_key =
        authenticate_signed_api_key(&headers, &state, "POST", "/messages/send-group").await?;

    if request.message.trim().is_empty() {
        return Err(AppError::Validation("Message cannot be empty".to_string()));
    }

    if request.message.len() > 10_000 {
        return Err(AppError::Validation(
            "Message too long (max 10000 characters)".to_string(),
        ));
    }

    info!(
        "API key {} sending group message to recipient: {} (type: {:?})",
        auth_key.key.id, request.recipient, request.recipient_type
    );

    let chat_id = match state
        .lark
        .verify_recipient(&request.recipient, request.recipient_type.as_deref())
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            warn!("Chat not found for recipient {}", request.recipient);
            state
                .db
                .log_message(
                    &SenderType::ApiKey.to_string(),
                    &auth_key.key.id,
                    &request.recipient,
                    &request.message,
                    &MessageStatus::Failed.to_string(),
                )
                .await?;
            return Err(AppError::NotFound(format!(
                "Chat not found: {}",
                request.recipient
            )));
        }
        Err(err) => {
            error!(
                "Failed to verify chat recipient {}: {}",
                request.recipient, err
            );
            return Err(err);
        }
    };

    let result = state
        .lark
        .send_message_to_chat(&chat_id, &request.message)
        .await;

    let (status, message_id) = match &result {
        Ok(msg_id) => (MessageStatus::Sent, msg_id.clone()),
        Err(err) => {
            error!("Failed to send group message to {}: {}", chat_id, err);
            (MessageStatus::Failed, None)
        }
    };

    state
        .db
        .log_message(
            &SenderType::ApiKey.to_string(),
            &auth_key.key.id,
            &request.recipient,
            &request.message,
            &status.to_string(),
        )
        .await?;

    match result {
        Ok(_) => Ok(Json(MessageResponse {
            message_id,
            status: status.to_string(),
        })),
        Err(err) => Err(err),
    }
}

pub async fn verify_recipient(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<VerifyRecipientRequest>,
) -> AppResult<Json<VerifyRecipientResponse>> {
    let _auth_key =
        authenticate_signed_api_key(&headers, &state, "POST", "/recipients/verify").await?;

    let result = state
        .lark
        .verify_recipient(&request.recipient, request.recipient_type.as_deref())
        .await;

    match result {
        Ok(recipient_id) => Ok(Json(VerifyRecipientResponse {
            exists: recipient_id.is_some(),
            recipient_id,
        })),
        Err(err) => {
            error!("Failed to verify recipient: {err}");
            Err(AppError::Lark(format!("Failed to verify recipient: {err}")))
        }
    }
}

// -----------------------------------------------------------------------------
// 辅助函数
// -----------------------------------------------------------------------------

async fn authenticate_user_from_jwt(headers: &HeaderMap, state: &AppState) -> AppResult<User> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AppError::Auth("Authorization header required".to_string()))?;

    let value = auth_header
        .to_str()
        .map_err(|_| AppError::Auth("Invalid authorization header".to_string()))?;

    if !value.starts_with("Bearer ") {
        return Err(AppError::Auth("Bearer token required".to_string()));
    }

    let token = &value[7..];
    state.auth.authenticate_jwt(token).await
}

fn ensure_admin(user: &User) -> AppResult<()> {
    if user.is_admin {
        Ok(())
    } else {
        Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ))
    }
}

async fn authenticate_signed_api_key(
    headers: &HeaderMap,
    state: &AppState,
    method: &str,
    path: &str,
) -> AppResult<AuthenticatedApiKey> {
    let access_key = header_value(headers, HEADER_ACCESS_KEY)?;
    let timestamp = header_value(headers, HEADER_TIMESTAMP)?;
    let nonce = header_value(headers, HEADER_NONCE)?;
    let signature = header_value(headers, HEADER_SIGNATURE)?;

    state
        .auth
        .authenticate_signed_request(access_key, timestamp, nonce, signature, method, path)
        .await
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> AppResult<&'a str> {
    headers
        .get(name)
        .ok_or_else(|| AppError::Auth(format!("Missing header: {}", name)))?
        .to_str()
        .map_err(|_| AppError::Auth(format!("Invalid header: {}", name)))
}
