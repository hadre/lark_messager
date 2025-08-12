/*!
 * 飞书（Lark）API 客户端模块
 * 
 * 封装了与飞书开放平台的交互，提供以下功能：
 * - 获取企业访问 Token（tenant_access_token）
 * - 发送消息给个人用户
 * - 发送消息给群聊/聊天室
 * - 通过邮箱查找用户 ID
 * - 通过手机号查找用户 ID
 * - 智能识别接收者类型并验证
 * 
 * 支持的接收者类型：
 * - user_id: 用户开放 ID
 * - email: 邮箱地址（自动转换为 user_id）
 * - mobile: 手机号（自动转换为 user_id）
 * - chat_id: 群聊 ID
 * - auto: 自动识别类型
 * 
 * API 文档: https://open.feishu.cn/document/
 */

use crate::error::{AppError, AppResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

/// 飞书应用配置
/// 
/// 包含访问飞书 API 所需的应用凭据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LarkConfig {
    /// 应用 ID，从飞书开放平台获取
    pub app_id: String,
    /// 应用密钥，从飞书开放平台获取
    pub app_secret: String,
}

/// 获取访问 Token 请求结构体
#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenRequest {
    /// 应用 ID
    app_id: String,
    /// 应用密钥
    app_secret: String,
}

/// 获取访问 Token 响应结构体
#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenResponse {
    /// 错误码，0 表示成功
    code: i32,
    /// 错误消息
    msg: String,
    /// 企业访问 Token
    tenant_access_token: Option<String>,
    /// 过期时间（秒）
    expire: Option<i64>,
}

/// 发送消息请求结构体
#[derive(Debug, Serialize, Deserialize)]
struct SendMessageRequest {
    /// 接收者 ID
    receive_id: String,
    /// 消息类型（text, image, file 等）
    msg_type: String,
    /// 消息内容（JSON 字符串）
    content: String,
}

/// 发送消息响应结构体
#[derive(Debug, Serialize, Deserialize)]
struct SendMessageResponse {
    /// 错误码，0 表示成功
    code: i32,
    /// 错误消息
    msg: String,
    /// 响应数据
    data: Option<SendMessageData>,
}

/// 发送消息响应数据
#[derive(Debug, Serialize, Deserialize)]
struct SendMessageData {
    /// 消息 ID
    message_id: Option<String>,
}

/// 批量获取用户 ID 请求结构体
#[derive(Debug, Serialize, Deserialize)]
struct BatchGetIdRequest {
    /// 邮箱列表
    emails: Option<Vec<String>>,
    /// 手机号列表
    mobiles: Option<Vec<String>>,
}

/// 批量获取用户 ID 响应结构体
#[derive(Debug, Serialize, Deserialize)]
struct BatchGetIdResponse {
    /// 错误码，0 表示成功
    code: i32,
    /// 错误消息
    msg: String,
    /// 响应数据
    data: Option<BatchGetIdData>,
}

/// 批量获取用户 ID 响应数据
#[derive(Debug, Serialize, Deserialize)]
struct BatchGetIdData {
    /// 用户信息列表
    user_list: Option<Vec<UserInfo>>,
}

/// 用户信息结构体
#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    /// 用户 ID
    user_id: String,
    /// 邮箱地址
    email: Option<String>,
    /// 手机号码
    mobile: Option<String>,
}

/// 飞书 API 客户端
/// 
/// 封装了与飞书开放平台的交互，提供统一的 API 调用接口。
/// 自动处理 Token 获取和刷新，管理 HTTP 请求生命周期。
#[derive(Clone)]
pub struct LarkClient {
    /// HTTP 客户端
    client: Client,
    /// 飞书应用配置
    config: LarkConfig,
    /// API 基础 URL
    base_url: String,
}

impl LarkClient {
    /// 创建新的飞书 API 客户端
    /// 
    /// # 参数
    /// - `app_id`: 飞书应用 ID
    /// - `app_secret`: 飞书应用密钥
    /// 
    /// # 说明
    /// 使用飞书中国站的 API 地址（open.feishu.cn）。
    /// 如果需要使用国际站，可修改 base_url 为 open.larksuite.com。
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self {
            client: Client::new(),
            config: LarkConfig { app_id, app_secret },
            base_url: "https://open.feishu.cn".to_string(),
        }
    }

    /// 获取企业访问 Token
    /// 
    /// 使用应用凭据获取企业级别的访问 Token，用于调用飞书 API。
    /// Token 有效期为 2 小时，到期后需要重新获取。
    /// 
    /// # 返回
    /// 成功时返回 tenant_access_token 字符串
    /// 
    /// # 错误
    /// - 网络请求失败
    /// - 应用凭据错误
    /// - 飞书 API 返回错误
    /// 
    /// # API 文档
    /// https://open.feishu.cn/document/ukTMukTMukTM/uIjNz4iM2MjLyYzM
    async fn get_tenant_access_token(&self) -> AppResult<String> {
        let url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            self.base_url
        );

        let request_body = AccessTokenRequest {
            app_id: self.config.app_id.clone(),
            app_secret: self.config.app_secret.clone(),
        };

        debug!("Requesting Lark tenant access token");

        let response = self.client.post(&url).json(&request_body).send().await?;

        if !response.status().is_success() {
            error!("Failed to get access token: HTTP {}", response.status());
            return Err(AppError::Lark(format!("HTTP error: {}", response.status())));
        }

        let token_response: AccessTokenResponse = response.json().await?;

        if token_response.code != 0 {
            error!(
                "Lark API error: {} - {}",
                token_response.code, token_response.msg
            );
            return Err(AppError::Lark(format!(
                "API error: {} - {}",
                token_response.code, token_response.msg
            )));
        }

        let token = token_response
            .tenant_access_token
            .ok_or_else(|| AppError::Lark("No access token in response".to_string()))?;

        debug!("Successfully obtained Lark access token");
        Ok(token)
    }

    /// 发送消息给用户
    /// 
    /// 向指定的飞书用户发送文本消息。
    /// 
    /// # 参数
    /// - `user_id`: 目标用户的 user_id
    /// - `message`: 要发送的消息内容
    /// 
    /// # 返回
    /// 成功时返回消息 ID（可用于追踪和管理）
    /// 
    /// # 错误
    /// - Token 获取失败
    /// - 用户 ID 不存在或无权限发送
    /// - 消息内容过长或包含非法字符
    /// - 网络请求失败
    /// 
    /// # API 文档
    /// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
    pub async fn send_message_to_user(
        &self,
        user_id: &str,
        message: &str,
    ) -> AppResult<Option<String>> {
        let access_token = self.get_tenant_access_token().await?;
        let url = format!("{}/open-apis/im/v1/messages", self.base_url);

        let content = serde_json::json!({
            "text": message
        });

        let request_body = SendMessageRequest {
            receive_id: user_id.to_string(),
            msg_type: "text".to_string(),
            content: content.to_string(),
        };

        info!("Sending message to Lark user: {}", user_id);
        debug!("Message content length: {} characters", message.len());

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json; charset=utf-8")
            .query(&[("receive_id_type", "user_id")])
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            error!("Failed to send message: HTTP {}", response.status());
            return Err(AppError::Lark(format!("HTTP error: {}", response.status())));
        }

        let message_response: SendMessageResponse = response.json().await?;

        if message_response.code != 0 {
            error!(
                "Lark API error: {} - {}",
                message_response.code, message_response.msg
            );
            return Err(AppError::Lark(format!(
                "API error: {} - {}",
                message_response.code, message_response.msg
            )));
        }

        let message_id = message_response.data.and_then(|data| data.message_id);

        info!(
            "Successfully sent message to user: {}, message_id: {:?}",
            user_id, message_id
        );
        Ok(message_id)
    }

    /// 发送消息给群聊
    /// 
    /// 向指定的飞书群聊发送文本消息。
    /// 
    /// # 参数
    /// - `chat_id`: 目标群聊的 chat_id
    /// - `message`: 要发送的消息内容
    /// 
    /// # 返回
    /// 成功时返回消息 ID
    /// 
    /// # 群聊 ID 格式
    /// - 以 "oc_" 开头：普通群聊
    /// - 以 "ou_" 开头：企业群聊
    /// 
    /// # 错误
    /// - Token 获取失败
    /// - 群聊 ID 不存在或无权限发送
    /// - 机器人未被加入群聊
    /// - 消息内容过长或包含非法字符
    /// - 网络请求失败
    pub async fn send_message_to_chat(
        &self,
        chat_id: &str,
        message: &str,
    ) -> AppResult<Option<String>> {
        let access_token = self.get_tenant_access_token().await?;
        let url = format!("{}/open-apis/im/v1/messages", self.base_url);

        let content = serde_json::json!({
            "text": message
        });

        let request_body = SendMessageRequest {
            receive_id: chat_id.to_string(),
            msg_type: "text".to_string(),
            content: content.to_string(),
        };

        info!("Sending message to Lark chat: {}", chat_id);
        debug!("Message content length: {} characters", message.len());

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json; charset=utf-8")
            .query(&[("receive_id_type", "chat_id")])
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            error!("Failed to send message to chat: HTTP {}", response.status());
            return Err(AppError::Lark(format!("HTTP error: {}", response.status())));
        }

        let message_response: SendMessageResponse = response.json().await?;

        if message_response.code != 0 {
            error!(
                "Lark API error: {} - {}",
                message_response.code, message_response.msg
            );
            return Err(AppError::Lark(format!(
                "API error: {} - {}",
                message_response.code, message_response.msg
            )));
        }

        let message_id = message_response.data.and_then(|data| data.message_id);

        info!(
            "Successfully sent message to chat: {}, message_id: {:?}",
            chat_id, message_id
        );
        Ok(message_id)
    }

    /// 通过邮箱获取用户 ID
    /// 
    /// 使用邮箱地址查找对应的飞书用户 ID。
    /// 适用于知道用户邮箱但不知道 user_id 的情况。
    /// 
    /// # 参数
    /// - `email`: 用户的邮箱地址
    /// 
    /// # 返回
    /// - `Some(user_id)`: 找到对应的用户 ID
    /// - `None`: 没有找到对应的用户
    /// 
    /// # 限制
    /// - 只能查找企业内部用户
    /// - 邮箱必须在飞书系统中已验证
    /// - 需要相应的 API 权限
    /// 
    /// # API 文档
    /// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/batch_get_id
    pub async fn get_user_id_by_email(&self, email: &str) -> AppResult<Option<String>> {
        let access_token = self.get_tenant_access_token().await?;
        let url = format!("{}/open-apis/contact/v3/users/batch_get_id", self.base_url);

        let request_body = BatchGetIdRequest {
            emails: Some(vec![email.to_string()]),
            mobiles: None,
        };

        debug!("Looking up Lark user by email: {}", email);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json; charset=utf-8")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            error!("Failed to lookup user by email: HTTP {}", response.status());
            return Err(AppError::Lark(format!("HTTP error: {}", response.status())));
        }

        let lookup_response: BatchGetIdResponse = response.json().await?;

        if lookup_response.code != 0 {
            error!(
                "Lark API error: {} - {}",
                lookup_response.code, lookup_response.msg
            );
            return Err(AppError::Lark(format!(
                "API error: {} - {}",
                lookup_response.code, lookup_response.msg
            )));
        }

        let user_id = lookup_response
            .data
            .and_then(|data| data.user_list)
            .and_then(|users| users.into_iter().next())
            .map(|user| user.user_id);

        debug!("User lookup result for {}: {:?}", email, user_id);
        Ok(user_id)
    }

    /// 通过手机号获取用户 ID
    /// 
    /// 使用手机号查找对应的飞书用户 ID。
    /// 适用于知道用户手机号但不知道 user_id 的情况。
    /// 
    /// # 参数
    /// - `mobile`: 用户的手机号（可包含国家代码）
    /// 
    /// # 返回
    /// - `Some(user_id)`: 找到对应的用户 ID
    /// - `None`: 没有找到对应的用户
    /// 
    /// # 手机号格式
    /// - 支持国际格式：+86138xxxxxxxx
    /// - 支持本地格式：138xxxxxxxx
    /// - 系统会自动识别和匹配
    /// 
    /// # 限制
    /// - 只能查找企业内部用户
    /// - 手机号必须在飞书系统中已验证
    /// - 需要相应的 API 权限
    pub async fn get_user_id_by_mobile(&self, mobile: &str) -> AppResult<Option<String>> {
        let access_token = self.get_tenant_access_token().await?;
        let url = format!("{}/open-apis/contact/v3/users/batch_get_id", self.base_url);

        let request_body = BatchGetIdRequest {
            emails: None,
            mobiles: Some(vec![mobile.to_string()]),
        };

        debug!("Looking up Lark user by mobile: {}", mobile);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json; charset=utf-8")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            error!(
                "Failed to lookup user by mobile: HTTP {}",
                response.status()
            );
            return Err(AppError::Lark(format!("HTTP error: {}", response.status())));
        }

        let lookup_response: BatchGetIdResponse = response.json().await?;

        if lookup_response.code != 0 {
            error!(
                "Lark API error: {} - {}",
                lookup_response.code, lookup_response.msg
            );
            return Err(AppError::Lark(format!(
                "API error: {} - {}",
                lookup_response.code, lookup_response.msg
            )));
        }

        let user_id = lookup_response
            .data
            .and_then(|data| data.user_list)
            .and_then(|users| users.into_iter().next())
            .map(|user| user.user_id);

        debug!("User lookup result for {}: {:?}", mobile, user_id);
        Ok(user_id)
    }

    /// 验证并解析接收者信息
    /// 
    /// 智能识别接收者类型并验证其有效性。支持多种输入格式的自动识别。
    /// 
    /// # 参数
    /// - `recipient`: 接收者标识符
    /// - `recipient_type`: 可选的接收者类型，为 None 时自动识别
    /// 
    /// # 支持的接收者类型
    /// - `user_id`: 用户 ID（直接验证格式）
    /// - `open_id`: 开放用户 ID（直接验证格式）
    /// - `union_id`: 联合用户 ID（直接验证格式）
    /// - `email`: 邮箱地址（通过 API 查找对应的 user_id）
    /// - `mobile`: 手机号（通过 API 查找对应的 user_id）
    /// - `chat_id`: 群聊 ID（验证格式前缀）
    /// - `auto`: 自动识别类型（默认）
    /// 
    /// # 自动识别规则（auto 模式）
    /// 1. 包含 "@" 字符 → 邮箱地址
    /// 2. 全是数字和 "+" → 手机号
    /// 3. 以 "oc_" 或 "ou_" 开头 → 群聊 ID
    /// 4. 长度大于 10 位 → 用户 ID
    /// 5. 其他情况 → 无效
    /// 
    /// # 返回值
    /// - `Some(id)`: 找到有效的接收者 ID
    /// - `None`: 接收者不存在或无效
    /// 
    /// # 错误
    /// - 未知的接收者类型
    /// - API 调用失败（邮箱/手机号查找时）
    /// - 网络连接错误
    /// 
    /// # 使用示例
    /// ```rust
    /// // 自动识别邮箱
    /// let user_id = client.verify_recipient("user@company.com", None).await?;
    /// 
    /// // 自动识别手机号
    /// let user_id = client.verify_recipient("+8613800138000", None).await?;
    /// 
    /// // 指定类型
    /// let user_id = client.verify_recipient("ou_xxx", Some("user_id")).await?;
    /// ```
    pub async fn verify_recipient(
        &self,
        recipient: &str,
        recipient_type: Option<&str>,
    ) -> AppResult<Option<String>> {
        match recipient_type.unwrap_or("auto").to_lowercase().as_str() {
            "user_id" | "open_id" | "union_id" => {
                // Assume these are valid if they look like proper IDs
                if recipient.len() > 10 {
                    Ok(Some(recipient.to_string()))
                } else {
                    Ok(None)
                }
            }
            "email" => self.get_user_id_by_email(recipient).await,
            "mobile" => self.get_user_id_by_mobile(recipient).await,
            "chat_id" => {
                // For chat IDs, we assume they're valid if they start with common prefixes
                if recipient.starts_with("oc_") || recipient.starts_with("ou_") {
                    Ok(Some(recipient.to_string()))
                } else {
                    Ok(None)
                }
            }
            "auto" => {
                // Auto-detect recipient type
                if recipient.contains("@") {
                    self.get_user_id_by_email(recipient).await
                } else if recipient.chars().all(|c| c.is_ascii_digit() || c == '+') {
                    self.get_user_id_by_mobile(recipient).await
                } else if recipient.starts_with("oc_") || recipient.starts_with("ou_") {
                    Ok(Some(recipient.to_string()))
                } else if recipient.len() > 10 {
                    Ok(Some(recipient.to_string()))
                } else {
                    Ok(None)
                }
            }
            _ => Err(AppError::Validation(format!(
                "Unknown recipient type: {}",
                recipient_type.unwrap_or("auto")
            ))),
        }
    }
}
