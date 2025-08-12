/*!
 * HTTP 请求处理器模块
 * 
 * 包含所有 API 端点的处理逻辑，负责：
 * - 用户认证和授权检查
 * - 请求参数验证
 * - 业务逻辑处理
 * - 错误处理和日志记录
 * - HTTP 响应构造
 * 
 * 支持的 API 端点：
 * - GET  /health - 健康检查
 * - POST /auth/login - 用户登录
 * - POST /auth/api-keys - 创建 API Key（管理员）
 * - DELETE /auth/api-keys/{id} - 撤销 API Key（管理员）
 * - POST /messages/send - 发送个人消息
 * - POST /messages/send-group - 发送群组消息
 * - POST /recipients/verify - 验证接收者
 * 
 * 认证方式：
 * - Authorization: Bearer <JWT_TOKEN> - 用户认证
 * - X-API-Key: <API_KEY> - 服务认证
 */

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

/// 应用程序共享状态
/// 
/// 包含所有 HTTP 处理器需要访问的服务组件
#[derive(Clone)]
pub struct AppState {
    /// 数据库连接
    pub db: Database,
    /// 认证服务
    pub auth: AuthService,
    /// 飞书客户端
    pub lark: LarkClient,
}

/// 系统健康检查
/// 
/// 返回服务的健康状态和基本信息。用于负载均衡器和监控系统。
/// 
/// # HTTP 方法
/// GET /health
/// 
/// # 返回
/// - 服务状态（"healthy"）
/// - 当前时间戳
/// - 应用版本号
/// 
/// # 使用场景
/// - 负载均衡器健康检查
/// - 监控系统状态检查
/// - 容器编排生存探针
pub async fn health_check() -> AppResult<Json<HealthResponse>> {
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

/// 用户登录
/// 
/// 验证用户名和密码，返回 JWT Token。
/// 
/// # HTTP 方法
/// POST /auth/login
/// 
/// # 请求体
/// ```json
/// {
///   "username": "user@example.com",
///   "password": "secure_password"
/// }
/// ```
/// 
/// # 返回
/// ```json
/// {
///   "token": "eyJ0eXAiOiJKV1Qi...",
///   "expires_at": "2024-01-01T12:00:00Z"
/// }
/// ```
/// 
/// # 错误
/// - 401: 用户名或密码错误
/// - 500: 服务器内部错误
/// 
/// # 安全性
/// - 密码使用 Argon2 算法验证
/// - JWT Token 有效期 24 小时
/// - 错误信息不泄露敏感信息
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

/// 创建 API Key
/// 
/// 创建用于服务间认证的 API Key。需要管理员权限。
/// 
/// # HTTP 方法
/// POST /auth/api-keys
/// 
/// # 认证
/// Authorization: Bearer <JWT_TOKEN> (需要 admin 权限)
/// 
/// # 请求体
/// ```json
/// {
///   "name": "Production Service",
///   "permissions": "send_messages,admin"
/// }
/// ```
/// 
/// # 返回
/// ```json
/// {
///   "key": "abcd1234...",
///   "id": "550e8400-e29b-41d4-a716-446655440000",
///   "name": "Production Service"
/// }
/// ```
/// 
/// # 权限系统
/// - `admin`: 管理员权限，可以创建/撤销 API Key
/// - `send_messages`: 发送消息权限
/// - 多个权限用逗号分隔
/// 
/// # 错误
/// - 401: 未认证或无管理员权限
/// - 400: 请求参数错误
/// - 500: 服务器内部错误
/// 
/// # 安全性
/// - API Key 以哈希形式存储
/// - 原始 API Key 只在创建时返回一次
/// - 支持细粒度权限控制
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

/// 撤销 API Key
/// 
/// 撤销指定的 API Key，使其立即失效。需要管理员权限。
/// 
/// # HTTP 方法
/// DELETE /auth/api-keys/{key_id}
/// 
/// # 认证
/// Authorization: Bearer <JWT_TOKEN> (需要 admin 权限)
/// 
/// # 参数
/// - `key_id`: API Key 的 UUID
/// 
/// # 返回
/// - 204 No Content: 撤销成功
/// - 404 Not Found: API Key 不存在或已被撤销
/// 
/// # 错误
/// - 401: 未认证或无管理员权限
/// - 404: API Key 不存在或已被撤销
/// - 500: 服务器内部错误
/// 
/// # 安全性
/// - 软删除机制，保持审计日志完整性
/// - 撤销后的 API Key 立即失效
/// - 不可逆操作
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

/// 发送个人消息
/// 
/// 向飞书用户发送文本消息。支持多种接收者格式的自动识别。
/// 
/// # HTTP 方法
/// POST /messages/send
/// 
/// # 认证
/// - Authorization: Bearer <JWT_TOKEN> (用户认证)
/// - X-API-Key: <API_KEY> (服务认证，需要 send_messages 权限)
/// 
/// # 请求体
/// ```json
/// {
///   "recipient": "user@company.com",
///   "message": "Hello, this is a test message",
///   "recipient_type": "auto"
/// }
/// ```
/// 
/// # 接收者格式
/// - `auto`: 自动识别类型（默认）
/// - `email`: 邮箱地址
/// - `mobile`: 手机号
/// - `user_id`: 飞书用户 ID
/// 
/// # 返回
/// ```json
/// {
///   "message_id": "om_xxx",
///   "status": "sent"
/// }
/// ```
/// 
/// # 消息限制
/// - 消息长度: 1-10000 字符
/// - 不能为空或只包含空白字符
/// 
/// # 错误处理
/// - 401: 未认证或无权限
/// - 400: 参数验证失败
/// - 404: 接收者不存在
/// - 500: 飞书 API 错误或服务器内部错误
/// 
/// # 审计日志
/// 所有消息发送尝试都会记录到数据库，包括失败的尝试
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

/// 发送群组消息
/// 
/// 向飞书群聊发送文本消息。
/// 
/// # HTTP 方法
/// POST /messages/send-group
/// 
/// # 认证
/// - Authorization: Bearer <JWT_TOKEN> (用户认证)
/// - X-API-Key: <API_KEY> (服务认证，需要 send_messages 权限)
/// 
/// # 请求体
/// ```json
/// {
///   "recipient": "oc_1234567890abcdef",
///   "message": "Hello everyone!",
///   "recipient_type": "chat_id"
/// }
/// ```
/// 
/// 或者使用群聊名称：
/// ```json
/// {
///   "recipient": "技术讨论群",
///   "message": "Hello everyone!",
///   "recipient_type": "chat_name"
/// }
/// ```
/// 
/// # 群聊 ID 格式
/// - `oc_xxx`: 普通群聊
/// - `ou_xxx`: 企业群聊
/// 
/// # 返回
/// ```json
/// {
///   "message_id": "om_xxx",
///   "status": "sent"
/// }
/// ```
/// 
/// # 消息限制
/// - 消息长度: 1-10000 字符
/// - 不能为空或只包含空白字符
/// 
/// # 前置条件
/// - 机器人必须已加入目标群聊
/// - 具有群聊发言权限
/// 
/// # 错误处理
/// - 401: 未认证或无权限
/// - 400: 参数验证失败
/// - 404: 群聊不存在或机器人未加入
/// - 500: 飞书 API 错误或服务器内部错误
/// 
/// # 审计日志
/// 所有消息发送尝试都会记录到数据库，包括失败的尝试
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
        "Sending group message from user {} to recipient: {} (type: {:?})",
        auth_user.id(),
        request.recipient,
        request.recipient_type
    );

    // Resolve the recipient to get the actual chat_id
    let chat_id = match state
        .lark
        .verify_recipient(&request.recipient, request.recipient_type.as_deref())
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            warn!("Chat not found for recipient: {}", request.recipient);
            return Err(AppError::NotFound(format!(
                "Chat not found: {}",
                request.recipient
            )));
        }
        Err(e) => {
            error!("Failed to verify chat recipient {}: {}", request.recipient, e);
            return Err(e);
        }
    };

    info!("Resolved chat recipient '{}' to chat_id: {}", request.recipient, chat_id);

    // Send the message
    let result = state
        .lark
        .send_message_to_chat(&chat_id, &request.message)
        .await;

    let (status, message_id) = match &result {
        Ok(msg_id) => (MessageStatus::Sent, msg_id.clone()),
        Err(e) => {
            error!("Failed to send group message to {}: {}", chat_id, e);
            (MessageStatus::Failed, None)
        }
    };

    // Log the message attempt
    let _ = state
        .db
        .log_message(
            &get_sender_type(&auth_user).to_string(),
            &auth_user.id(),
            &chat_id,
            &request.message,
            &status.to_string(),
        )
        .await;

    match result {
        Ok(_) => {
            info!(
                "Successfully sent group message from {} to {} (resolved from '{}')",
                auth_user.id(),
                chat_id,
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

/// 验证接收者
/// 
/// 检查指定的接收者是否存在于飞书系统中。
/// 
/// # HTTP 方法
/// POST /recipients/verify
/// 
/// # 认证
/// - Authorization: Bearer <JWT_TOKEN> (用户认证)
/// - X-API-Key: <API_KEY> (服务认证，需要 send_messages 权限)
/// 
/// # 请求体
/// ```json
/// {
///   "recipient": "user@company.com",
///   "recipient_type": "auto"
/// }
/// ```
/// 
/// # 返回
/// ```json
/// {
///   "exists": true,
///   "recipient_id": "ou_1234567890abcdef"
/// }
/// ```
/// 
/// # 支持的接收者类型
/// - `auto`: 自动识别类型（默认）
/// - `email`: 邮箱地址
/// - `mobile`: 手机号
/// - `user_id`: 飞书用户 ID
/// - `chat_id`: 群聊 ID
/// 
/// # 使用场景
/// - 发送消息前验证接收者
/// - 批量导入用户时验证
/// - 用户界面实时验证
/// 
/// # 错误处理
/// - 401: 未认证或无权限
/// - 400: 参数验证失败
/// - 500: 飞书 API 错误或服务器内部错误
/// 
/// # 性能考虑
/// - 部分验证需要调用飞书 API，可能有较高延迟
/// - 建议在用户界面中使用防抖机制
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