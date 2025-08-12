use crate::error::{AppError, AppResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LarkConfig {
    pub app_id: String,
    pub app_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenRequest {
    app_id: String,
    app_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenResponse {
    code: i32,
    msg: String,
    tenant_access_token: Option<String>,
    expire: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SendMessageRequest {
    receive_id: String,
    msg_type: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SendMessageResponse {
    code: i32,
    msg: String,
    data: Option<SendMessageData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SendMessageData {
    message_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BatchGetIdRequest {
    emails: Option<Vec<String>>,
    mobiles: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BatchGetIdResponse {
    code: i32,
    msg: String,
    data: Option<BatchGetIdData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BatchGetIdData {
    user_list: Option<Vec<UserInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    user_id: String,
    email: Option<String>,
    mobile: Option<String>,
}

#[derive(Clone)]
pub struct LarkClient {
    client: Client,
    config: LarkConfig,
    base_url: String,
}

impl LarkClient {
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self {
            client: Client::new(),
            config: LarkConfig { app_id, app_secret },
            base_url: "https://open.feishu.cn".to_string(),
        }
    }

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
