/*!
 * 飞书（Lark）API 客户端模块
 *
 * 封装了与飞书开放平台的交互，提供以下功能：
 * - 获取企业访问 Token（tenant_access_token）
 * - 发送消息给个人用户
 * - 发送消息给群聊/聊天室
 * - 通过邮箱查找用户 ID
 * - 通过手机号查找用户 ID
 * - 通过群聊名称查找群聊 ID
 * - 智能识别接收者类型并验证
 *
 * 支持的接收者类型：
 * - user_id: 用户开放 ID (open_id)
 * - email: 邮箱地址（自动转换为 open_id）
 * - mobile: 手机号（自动转换为 open_id）
 * - chat_id: 群聊 ID
 * - chat_name: 群聊名称（自动转换为 chat_id）
 * - auto: 自动识别类型
 *
 * API 文档: https://open.feishu.cn/document/
 */

use crate::error::{AppError, AppResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
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

/// 缓存的访问令牌信息
///
/// 存储访问令牌及其过期时间，用于避免频繁获取新令牌
#[derive(Debug, Clone)]
struct CachedToken {
    /// 访问令牌
    token: String,
    /// 过期时间戳（UNIX 时间戳，秒）
    expires_at: u64,
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
    /// 用户开放 ID (open_id)
    user_id: String,
    /// 邮箱地址
    email: Option<String>,
    /// 手机号码
    mobile: Option<String>,
}

/// 获取群聊列表请求结构体
#[derive(Debug, Serialize, Deserialize)]
struct ChatListRequest {
    /// 页面大小（最大 200）
    page_size: Option<i32>,
    /// 页面令牌（用于分页）
    page_token: Option<String>,
}

/// 获取群聊列表响应结构体
#[derive(Debug, Serialize, Deserialize)]
struct ChatListResponse {
    /// 错误码，0 表示成功
    code: i32,
    /// 错误消息
    msg: String,
    /// 响应数据
    data: Option<ChatListData>,
}

/// 获取群聊列表响应数据
#[derive(Debug, Serialize, Deserialize)]
struct ChatListData {
    /// 是否还有更多数据
    has_more: Option<bool>,
    /// 下一页的页面令牌
    page_token: Option<String>,
    /// 群聊列表
    items: Option<Vec<ChatInfo>>,
}

/// 群聊信息结构体
#[derive(Debug, Serialize, Deserialize)]
struct ChatInfo {
    /// 群聊 ID
    chat_id: String,
    /// 群聊名称
    name: Option<String>,
    /// 群聊描述
    description: Option<String>,
    /// 群聊类型
    chat_type: Option<String>,
}

/// 飞书 API 客户端
///
/// 封装了与飞书开放平台的交互，提供统一的 API 调用接口。
/// 自动处理 Token 获取和刷新，管理 HTTP 请求生命周期。
///
/// # 令牌缓存机制
///
/// 客户端会自动缓存获取的 tenant_access_token，避免频繁调用认证 API：
/// - 令牌有效期为 2 小时
/// - 自动检查令牌有效性
/// - 到期前 5 分钟会自动刷新
/// - 多线程安全的缓存访问
#[derive(Clone)]
pub struct LarkClient {
    /// HTTP 客户端
    client: Client,
    /// 飞书应用配置
    config: LarkConfig,
    /// API 基础 URL
    base_url: String,
    /// 缓存的访问令牌（线程安全）
    ///
    /// 使用 RwLock 保证多线程环境下的安全访问：
    /// - 读操作（检查令牌）不会相互阻塞
    /// - 写操作（更新令牌）会独占访问
    /// - Arc 允许多个客户端实例共享同一缓存
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

impl LarkClient {
    /// 创建新的飞书 API 客户端
    ///
    /// # 参数
    /// - `app_id`: 飞书应用 ID
    /// - `app_secret`: 飞书应用密钥
    ///
    /// # 说明
    /// - 使用飞书中国站的 API 地址（open.feishu.cn）
    /// - 如果需要使用国际站，可修改 base_url 为 open.larksuite.com
    /// - 初始化空的令牌缓存，首次使用时会自动获取
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self {
            client: Client::new(),
            config: LarkConfig { app_id, app_secret },
            base_url: "https://open.feishu.cn".to_string(),
            cached_token: Arc::new(RwLock::new(None)),
        }
    }

    /// 获取当前时间戳（秒）
    ///
    /// 返回 UNIX 时间戳，用于比较令牌过期时间
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// 检查缓存的令牌是否仍然有效
    ///
    /// # 参数
    /// - `cached_token`: 缓存的令牌信息
    ///
    /// # 返回
    /// - `true`: 令牌仍然有效（距离过期还有至少 5 分钟）
    /// - `false`: 令牌已过期或即将过期
    ///
    /// # 缓冲时间
    /// 为了避免在令牌即将过期时发送请求失败，我们在过期前 5 分钟
    /// 就认为令牌无效，提前获取新令牌。
    fn is_token_valid(cached_token: &CachedToken) -> bool {
        let current_time = Self::current_timestamp();
        let buffer_time = 300; // 5 分钟缓冲时间

        cached_token.expires_at > current_time + buffer_time
    }

    /// 从飞书 API 获取新的企业访问令牌
    ///
    /// 这是一个内部方法，直接调用飞书 API 获取令牌，不涉及缓存逻辑。
    ///
    /// # 返回
    /// 成功时返回包含令牌和过期时间的元组 (token, expires_at)
    ///
    /// # 错误
    /// - 网络请求失败
    /// - 应用凭据错误  
    /// - 飞书 API 返回错误
    ///
    /// # API 文档
    /// https://open.feishu.cn/document/ukTMukTMukTM/uIjNz4iM2MjLyYzM
    async fn fetch_new_token(&self) -> AppResult<(String, u64)> {
        let url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            self.base_url
        );

        let request_body = AccessTokenRequest {
            app_id: self.config.app_id.clone(),
            app_secret: self.config.app_secret.clone(),
        };

        debug!("Requesting new Lark tenant access token from API");

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

        // 计算过期时间：当前时间 + 过期秒数
        let current_time = Self::current_timestamp();
        let expires_in = token_response.expire.unwrap_or(7200); // 默认 2 小时
        let expires_at = current_time + expires_in as u64;

        debug!(
            "Successfully obtained new Lark access token, expires in {} seconds",
            expires_in
        );

        Ok((token, expires_at))
    }

    /// 获取企业访问 Token（带缓存）
    ///
    /// 智能缓存机制的企业 Token 获取方法：
    /// 1. 首先检查缓存中是否有有效的令牌
    /// 2. 如果有效令牌存在，直接返回（避免 API 调用）
    /// 3. 如果令牌不存在或即将过期，从 API 获取新令牌
    /// 4. 更新缓存并返回新令牌
    ///
    /// # 性能优化
    /// - 避免频繁的 API 调用（2小时内复用同一令牌）
    /// - 多线程安全的缓存访问
    /// - 提前 5 分钟刷新，避免边界情况
    ///
    /// # 缓存策略
    /// - 令牌有效期：2 小时（飞书 API 限制）
    /// - 提前刷新：过期前 5 分钟自动刷新
    /// - 并发安全：读写锁保护缓存访问
    ///
    /// # 返回
    /// 成功时返回有效的 tenant_access_token 字符串
    ///
    /// # 错误
    /// - 网络请求失败
    /// - 应用凭据错误
    /// - 飞书 API 返回错误
    /// - 缓存访问错误
    async fn get_tenant_access_token(&self) -> AppResult<String> {
        // 第一步：尝试从缓存读取有效令牌
        {
            let cached = self.cached_token.read().await;
            if let Some(ref cached_token) = *cached {
                if Self::is_token_valid(cached_token) {
                    debug!("Using cached Lark access token");
                    return Ok(cached_token.token.clone());
                } else {
                    debug!("Cached Lark access token has expired or will expire soon");
                }
            } else {
                debug!("No cached Lark access token found");
            }
        }

        // 第二步：获取新令牌并更新缓存
        let (new_token, expires_at) = self.fetch_new_token().await?;

        {
            let mut cached = self.cached_token.write().await;
            *cached = Some(CachedToken {
                token: new_token.clone(),
                expires_at,
            });

            debug!("Cached new Lark access token, expires at: {}", expires_at);
        }

        Ok(new_token)
    }

    /// 发送消息给用户
    ///
    /// 向指定的飞书用户发送文本消息。
    ///
    /// # 参数
    /// - `user_id`: 目标用户的开放 ID (open_id)
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
            .query(&[("receive_id_type", "open_id")])
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

    /// 通过邮箱获取用户开放 ID
    ///
    /// 使用邮箱地址查找对应的飞书用户开放 ID (open_id)。
    /// 适用于知道用户邮箱但不知道 open_id 的情况。
    ///
    /// # 参数
    /// - `email`: 用户的邮箱地址
    ///
    /// # 返回
    /// - `Some(open_id)`: 找到对应的用户开放 ID
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
            .query(&[("user_id_type", "open_id")])
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

    /// 通过手机号获取用户开放 ID
    ///
    /// 使用手机号查找对应的飞书用户开放 ID (open_id)。
    /// 适用于知道用户手机号但不知道 open_id 的情况。
    ///
    /// # 参数
    /// - `mobile`: 用户的手机号（可包含国家代码）
    ///
    /// # 返回
    /// - `Some(open_id)`: 找到对应的用户开放 ID
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
            .query(&[("user_id_type", "open_id")])
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

    /// 通过群聊名称获取群聊 ID
    /// 
    /// 使用群聊名称查找对应的飞书群聊 ID。
    /// 由于飞书 API 不支持直接按名称搜索，此方法会获取所有群聊列表并在本地进行名称匹配。
    /// 
    /// # 参数
    /// - `chat_name`: 群聊的名称（支持完全匹配和部分匹配）
    /// 
    /// # 返回
    /// - `Some(chat_id)`: 找到匹配的群聊 ID
    /// - `None`: 没有找到匹配的群聊
    /// 
    /// # 匹配规则
    /// 1. 完全匹配：群聊名称完全相同（优先级最高）
    /// 2. 部分匹配：群聊名称包含搜索关键词
    /// 3. 忽略大小写进行匹配
    /// 
    /// # 性能考虑
    /// - 如果群聊较多，此操作可能比较耗时
    /// - 建议在业务层面进行缓存优化
    /// - 对于频繁使用的群聊，可考虑直接使用 chat_id
    /// 
    /// # 限制
    /// - 需要机器人已加入目标群聊
    /// - 需要相应的 API 权限读取群聊列表
    /// - 每次查询都会遍历所有群聊（性能影响）
    /// 
    /// # API 文档
    /// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/chat/list
    pub async fn get_chat_id_by_name(&self, chat_name: &str) -> AppResult<Option<String>> {
        let access_token = self.get_tenant_access_token().await?;
        let url = format!("{}/open-apis/im/v1/chats", self.base_url);

        debug!("Looking up Lark chat by name: {}", chat_name);

        let mut page_token: Option<String> = None;
        let chat_name_lower = chat_name.to_lowercase();

        // 遍历所有页面寻找匹配的群聊
        loop {
            let mut query_params = vec![("page_size", "200")];
            if let Some(ref token) = page_token {
                query_params.push(("page_token", token));
            }

            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", access_token))
                .header("Content-Type", "application/json; charset=utf-8")
                .query(&query_params)
                .send()
                .await?;

            if !response.status().is_success() {
                error!("Failed to get chat list: HTTP {}", response.status());
                return Err(AppError::Lark(format!("HTTP error: {}", response.status())));
            }

            let chat_response: ChatListResponse = response.json().await?;

            if chat_response.code != 0 {
                error!(
                    "Lark API error: {} - {}",
                    chat_response.code, chat_response.msg
                );
                return Err(AppError::Lark(format!(
                    "API error: {} - {}",
                    chat_response.code, chat_response.msg
                )));
            }

            // 检查当前页面的群聊
            if let Some(data) = chat_response.data {
                if let Some(chats) = data.items {
                    // 先寻找完全匹配的群聊名称
                    for chat in &chats {
                        if let Some(ref name) = chat.name {
                            if name.to_lowercase() == chat_name_lower {
                                debug!("Found exact match for chat name '{}': {}", chat_name, chat.chat_id);
                                return Ok(Some(chat.chat_id.clone()));
                            }
                        }
                    }

                    // 如果没有完全匹配，寻找部分匹配
                    for chat in &chats {
                        if let Some(ref name) = chat.name {
                            if name.to_lowercase().contains(&chat_name_lower) {
                                debug!("Found partial match for chat name '{}': {} ({})", 
                                      chat_name, chat.chat_id, name);
                                return Ok(Some(chat.chat_id.clone()));
                            }
                        }
                    }
                }

                // 检查是否还有更多数据
                if data.has_more.unwrap_or(false) {
                    page_token = data.page_token;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        debug!("No chat found with name: {}", chat_name);
        Ok(None)
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
    /// - `chat_name`: 群聊名称（通过 API 查找对应的 chat_id）
    /// - `auto`: 自动识别类型（默认）
    ///
    /// # 自动识别规则（auto 模式）
    /// 1. 包含 "@" 字符 → 邮箱地址
    /// 2. 全是数字和 "+" → 手机号
    /// 3. 以 "oc_" 或 "ou_" 开头 → 群聊 ID
    /// 4. 长度大于 10 位 → 用户 ID
    /// 5. 其他情况 → 群聊名称（尝试查找）
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
    /// // 自动识别群聊名称
    /// let chat_id = client.verify_recipient("技术讨论群", None).await?;
    ///
    /// // 指定类型
    /// let user_id = client.verify_recipient("ou_xxx", Some("user_id")).await?;
    /// let chat_id = client.verify_recipient("开发组", Some("chat_name")).await?;
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
            "chat_name" => self.get_chat_id_by_name(recipient).await,
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
                    // 尝试作为群聊名称查找
                    self.get_chat_id_by_name(recipient).await
                }
            }
            _ => Err(AppError::Validation(format!(
                "Unknown recipient type: {}",
                recipient_type.unwrap_or("auto")
            ))),
        }
    }
}
