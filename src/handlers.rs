use crate::auth::{AuthService, AuthenticatedUser};
use crate::database::Database;
use crate::error::{AppError, AppResult};
use crate::lark::LarkClient;
use crate::models::{
    CreateApiKeyRequest, CreateApiKeyResponse, HealthResponse, LoginRequest, LoginResponse,
    MessageResponse, SendGroupMessageRequest, SendMessageRequest, SenderType, MessageStatus,
    VerifyRecipientRequest, VerifyRecipientResponse,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub auth: AuthService,
    pub lark: LarkClient,
}

pub async fn health_check() -> AppResult<Json<HealthResponse>> {
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

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

pub async fn create_api_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<CreateApiKeyRequest>,
) -> AppResult<Json<CreateApiKeyResponse>> {
    let auth_user = authenticate_request(&headers, &state).await?;

    if !auth_user.is_admin() {
        warn!("Non-admin user attempted to create API key: {:?}", auth_user.id());
        return Err(AppError::Unauthorized(
            "Admin privileges required to create API keys".to_string(),
        ));
    }

    let api_key = state.auth.generate_api_key(64);
    let key_hash = state.auth.hash_api_key(&api_key)?;

    let api_key_record = state
        .db
        .create_api_key(&key_hash, &request.name, &request.permissions, &auth_user.id())
        .await?;

    info!(
        "API key created: {} by user {}",
        api_key_record.name,
        auth_user.id()
    );

    Ok(Json(CreateApiKeyResponse {
        key: api_key,
        id: api_key_record.id,
        name: api_key_record.name,
    }))
}

pub async fn revoke_api_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let auth_user = authenticate_request(&headers, &state).await?;

    if !auth_user.is_admin() {
        warn!("Non-admin user attempted to revoke API key: {:?}", auth_user.id());
        return Err(AppError::Unauthorized(
            "Admin privileges required to revoke API keys".to_string(),
        ));
    }

    let revoked = state.db.revoke_api_key(&key_id).await?;

    if !revoked {
        return Err(AppError::NotFound("API key not found or already revoked".to_string()));
    }

    info!("API key revoked: {} by user {}", key_id, auth_user.id());

    Ok(StatusCode::NO_CONTENT)
}

pub async fn send_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<SendMessageRequest>,
) -> AppResult<Json<MessageResponse>> {
    let auth_user = authenticate_request(&headers, &state).await?;

    if !auth_user.can_send_messages() {
        warn!("User without send permission attempted to send message: {:?}", auth_user.id());
        return Err(AppError::Unauthorized(
            "Permission required to send messages".to_string(),
        ));
    }

    if request.message.trim().is_empty() {
        return Err(AppError::Validation("Message cannot be empty".to_string()));
    }

    if request.message.len() > 10000 {
        return Err(AppError::Validation("Message too long (max 10000 characters)".to_string()));
    }

    info!(
        "Sending message from user {} to recipient: {}",
        auth_user.id(),
        request.recipient
    );

    // Verify recipient exists
    let recipient_id = state
        .lark
        .verify_recipient(&request.recipient, request.recipient_type.as_deref())
        .await?;

    if recipient_id.is_none() {
        warn!("Recipient not found: {}", request.recipient);
        let _ = state
            .db
            .log_message(
                &get_sender_type(&auth_user).to_string(),
                &auth_user.id(),
                &request.recipient,
                &request.message,
                &MessageStatus::Failed.to_string(),
            )
            .await;
        return Err(AppError::NotFound("Recipient not found".to_string()));
    }

    let actual_recipient = recipient_id.unwrap();

    // Send the message
    let result = state
        .lark
        .send_message_to_user(&actual_recipient, &request.message)
        .await;

    let (status, message_id) = match &result {
        Ok(msg_id) => (MessageStatus::Sent, msg_id.clone()),
        Err(e) => {
            error!("Failed to send message to {}: {}", actual_recipient, e);
            (MessageStatus::Failed, None)
        }
    };

    // Log the message attempt
    let _ = state
        .db
        .log_message(
            &get_sender_type(&auth_user).to_string(),
            &auth_user.id(),
            &request.recipient,
            &request.message,
            &status.to_string(),
        )
        .await;

    match result {
        Ok(_) => {
            info!(
                "Successfully sent message from {} to {}",
                auth_user.id(),
                request.recipient
            );
            Ok(Json(MessageResponse {
                message_id,
                status: status.to_string(),
            }))
        }
        Err(e) => Err(e),
    }
}

pub async fn send_group_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<SendGroupMessageRequest>,
) -> AppResult<Json<MessageResponse>> {
    let auth_user = authenticate_request(&headers, &state).await?;

    if !auth_user.can_send_messages() {
        warn!("User without send permission attempted to send group message: {:?}", auth_user.id());
        return Err(AppError::Unauthorized(
            "Permission required to send messages".to_string(),
        ));
    }

    if request.message.trim().is_empty() {
        return Err(AppError::Validation("Message cannot be empty".to_string()));
    }

    if request.message.len() > 10000 {
        return Err(AppError::Validation("Message too long (max 10000 characters)".to_string()));
    }

    info!(
        "Sending group message from user {} to chat: {}",
        auth_user.id(),
        request.chat_id
    );

    // Send the message
    let result = state
        .lark
        .send_message_to_chat(&request.chat_id, &request.message)
        .await;

    let (status, message_id) = match &result {
        Ok(msg_id) => (MessageStatus::Sent, msg_id.clone()),
        Err(e) => {
            error!("Failed to send group message to {}: {}", request.chat_id, e);
            (MessageStatus::Failed, None)
        }
    };

    // Log the message attempt
    let _ = state
        .db
        .log_message(
            &get_sender_type(&auth_user).to_string(),
            &auth_user.id(),
            &request.chat_id,
            &request.message,
            &status.to_string(),
        )
        .await;

    match result {
        Ok(_) => {
            info!(
                "Successfully sent group message from {} to {}",
                auth_user.id(),
                request.chat_id
            );
            Ok(Json(MessageResponse {
                message_id,
                status: status.to_string(),
            }))
        }
        Err(e) => Err(e),
    }
}

pub async fn verify_recipient(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<VerifyRecipientRequest>,
) -> AppResult<Json<VerifyRecipientResponse>> {
    let auth_user = authenticate_request(&headers, &state).await?;

    if !auth_user.can_send_messages() {
        warn!("User without permission attempted to verify recipient: {:?}", auth_user.id());
        return Err(AppError::Unauthorized(
            "Permission required to verify recipients".to_string(),
        ));
    }

    info!(
        "Verifying recipient {} for user {}",
        request.recipient,
        auth_user.id()
    );

    let recipient_id = state
        .lark
        .verify_recipient(&request.recipient, request.recipient_type.as_deref())
        .await?;

    Ok(Json(VerifyRecipientResponse {
        exists: recipient_id.is_some(),
        recipient_id,
    }))
}

async fn authenticate_request(
    headers: &HeaderMap,
    state: &AppState,
) -> AppResult<AuthenticatedUser> {
    // Try JWT authentication first
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| AppError::Auth("Invalid authorization header".to_string()))?;

        if auth_str.starts_with("Bearer ") {
            let token = &auth_str[7..];
            return state.auth.authenticate_jwt(token).await;
        }
    }

    // Try API key authentication
    if let Some(api_key_header) = headers.get("x-api-key") {
        let api_key = api_key_header
            .to_str()
            .map_err(|_| AppError::Auth("Invalid API key header".to_string()))?;

        return state.auth.authenticate_api_key(api_key).await;
    }

    Err(AppError::Auth("No valid authentication provided".to_string()))
}

fn get_sender_type(auth_user: &AuthenticatedUser) -> SenderType {
    match auth_user {
        AuthenticatedUser::User { .. } => SenderType::User,
        AuthenticatedUser::Service { .. } => SenderType::Service,
    }
}