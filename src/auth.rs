/*!
 * 身份认证和授权模块
 *
 * 实现统一的 API Key 鉴权机制，提供：
 * - 用户管理（密码哈希、验证、JWT 管理端口令）
 * - API Key 生成、禁用、失败计数、频率限制
 * - HMAC-SHA256 请求签名校验（包含时间戳与 nonce 防重放）
 * - 运行时可更新的鉴权配置（失败阈值、频率上限、nonce 保留时间）
 */

use crate::database::Database;
use crate::error::{AppError, AppResult};
use crate::models::{
    ApiKey, ApiKeyStatus, AuthConfigEntry, AuthConfigResponse, CreateApiKeyRequest,
    CreateApiKeyResponse, ResetApiKeyFailuresRequest, UpdateApiKeyRateLimitRequest,
    UpdateApiKeyStatusRequest, UpdateAuthConfigRequest, User,
};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use moka::sync::Cache;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::{Mutex, RwLock};
use tracing::warn;
use uuid::Uuid;

const DEFAULT_AUTH_MAX_FAILURES: i32 = 5;
const DEFAULT_MAX_RATE_LIMIT_PER_MINUTE: i32 = 600;
const DEFAULT_NONCE_RETENTION_SECONDS: i64 = 300;
const TIMESTAMP_SKEW_SECONDS: i64 = 300; // 5 minutes
const RATE_LIMIT_CACHE_CAPACITY: u64 = 10_000;
const NONCE_CACHE_CAPACITY: u64 = 100_000;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const DEFAULT_JWT_EXTENSION_SECONDS: i64 = 3600; // 1 hour

type HmacSha256 = Hmac<Sha256>;

/// 缓存的鉴权配置
#[derive(Debug, Clone)]
struct AuthConfigValues {
    auth_max_failures: i32,
    max_rate_limit_per_minute: i32,
    nonce_retention_seconds: i64,
    jwt_extension_seconds: i64,
}

impl AuthConfigValues {
    fn new() -> Self {
        Self {
            auth_max_failures: DEFAULT_AUTH_MAX_FAILURES,
            max_rate_limit_per_minute: DEFAULT_MAX_RATE_LIMIT_PER_MINUTE,
            nonce_retention_seconds: DEFAULT_NONCE_RETENTION_SECONDS,
            jwt_extension_seconds: DEFAULT_JWT_EXTENSION_SECONDS,
        }
    }
}

fn seconds_to_std(secs: i64) -> StdDuration {
    if secs <= 0 {
        StdDuration::from_secs(1)
    } else {
        StdDuration::from_secs(secs as u64)
    }
}

/// nonce 存储，防止 5 分钟窗口内重放
struct NonceCache {
    ttl: StdDuration,
    capacity: u64,
    cache: Cache<(Uuid, String), ()>,
}

impl NonceCache {
    fn new(retention_seconds: i64, capacity: u64) -> Self {
        let ttl = seconds_to_std(retention_seconds);
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl)
            .build();
        Self {
            ttl,
            capacity,
            cache,
        }
    }

    fn update_retention(&mut self, retention_seconds: i64) {
        self.ttl = seconds_to_std(retention_seconds);
        let new_cache = Cache::builder()
            .max_capacity(self.capacity)
            .time_to_live(self.ttl)
            .build();
        for (key, _) in self.cache.iter() {
            new_cache.insert((*key).clone(), ());
        }
        self.cache = new_cache;
    }

    /// 返回 true 表示 nonce 新鲜，可以使用；false 表示重复
    fn check_and_store(&self, key_id: Uuid, nonce: &str) -> bool {
        let key = (key_id, nonce.to_string());
        if self.cache.get(&key).is_some() {
            return false;
        }
        self.cache.insert(key, ());
        true
    }
}

/// 简单的每分钟频率限制器
struct RateLimiter {
    cache: Cache<Uuid, i32>,
}

impl RateLimiter {
    fn new(window: StdDuration, capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(window)
            .build();
        Self { cache }
    }

    fn allow(&self, key_id: Uuid, limit: i32) -> bool {
        let count = self.cache.get(&key_id).unwrap_or(0);
        if count >= limit {
            return false;
        }
        self.cache.insert(key_id, count + 1);
        true
    }

    fn reset(&self, key_id: Uuid) {
        self.cache.invalidate(&key_id);
    }
}

/// API 请求认证后的主体
#[derive(Debug, Clone)]
pub struct AuthenticatedApiKey {
    pub key: ApiKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub username: String,
    pub exp: usize,
    pub iat: usize,
    pub is_admin: bool,
}

/// 认证服务
#[derive(Clone)]
pub struct AuthService {
    jwt_secret: String,
    db: Database,
    config: Arc<RwLock<AuthConfigValues>>,
    nonce_cache: Arc<Mutex<NonceCache>>,
    rate_limiter: Arc<RateLimiter>,
}

impl AuthService {
    pub async fn new(jwt_secret: String, db: Database) -> AppResult<Self> {
        let service = Self {
            jwt_secret,
            db: db.clone(),
            config: Arc::new(RwLock::new(AuthConfigValues::new())),
            nonce_cache: Arc::new(Mutex::new(NonceCache::new(
                DEFAULT_NONCE_RETENTION_SECONDS,
                NONCE_CACHE_CAPACITY,
            ))),
            rate_limiter: Arc::new(RateLimiter::new(
                StdDuration::from_secs(RATE_LIMIT_WINDOW_SECS),
                RATE_LIMIT_CACHE_CAPACITY,
            )),
        };
        service.reload_config_cache().await?;
        Ok(service)
    }

    /// 重新加载数据库中的鉴权配置
    pub async fn reload_config_cache(&self) -> AppResult<()> {
        let configs = self.db.get_configs_by_type("auth").await?;
        let mut current = AuthConfigValues::new();
        for item in configs {
            match item.config_key.as_str() {
                "auth_max_failures" => {
                    if let Ok(v) = item.config_value.parse::<i32>() {
                        current.auth_max_failures = v.max(1);
                    }
                }
                "max_rate_limit_per_minute" => {
                    if let Ok(v) = item.config_value.parse::<i32>() {
                        current.max_rate_limit_per_minute = v.max(1);
                    }
                }
                "nonce_retention_seconds" => {
                    if let Ok(v) = item.config_value.parse::<i64>() {
                        current.nonce_retention_seconds = v.max(0);
                    }
                }
                "jwt_extension_seconds" => {
                    if let Ok(v) = item.config_value.parse::<i64>() {
                        current.jwt_extension_seconds = v.max(0);
                    }
                }
                _ => {}
            }
        }

        {
            let mut guard = self.config.write().await;
            *guard = current.clone();
        }

        {
            let mut nonce_cache = self.nonce_cache.lock().await;
            nonce_cache.update_retention(current.nonce_retention_seconds);
        }

        Ok(())
    }

    fn current_config(&self) -> impl std::future::Future<Output = AuthConfigValues> + '_ {
        async move { self.config.read().await.clone() }
    }

    // ------------------------------------------------------------------
    // 密码处理
    // ------------------------------------------------------------------

    pub fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Failed to hash password: {e}")))?;
        Ok(hash.to_string())
    }

    pub fn verify_password(&self, password: &str, password_hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AppError::Internal(format!("Failed to parse password hash: {e}")))?;
        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> AppResult<User> {
        let user = self
            .db
            .get_user_by_username(username)
            .await?
            .ok_or_else(|| AppError::Auth("User not found".to_string()))?;

        let valid = self.verify_password(password, &user.password_hash)?;
        if !valid {
            return Err(AppError::Auth("Invalid credentials".to_string()));
        }
        Ok(user)
    }

    pub fn generate_jwt_token(&self, user: &User) -> AppResult<(String, DateTime<Utc>)> {
        let now = Utc::now();
        let expires = now + Duration::hours(24);
        let claims = JwtClaims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            exp: expires.timestamp() as usize,
            iat: now.timestamp() as usize,
            is_admin: user.is_admin,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok((token, expires))
    }

    pub async fn extend_jwt_token(&self, token: &str) -> AppResult<(String, DateTime<Utc>)> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;

        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| AppError::Auth("Invalid token subject".to_string()))?;

        let user = self
            .db
            .get_user_by_id(&user_id)
            .await?
            .ok_or_else(|| AppError::Auth("User not found".to_string()))?;

        let config = self.current_config().await;
        if config.jwt_extension_seconds <= 0 {
            return Err(AppError::Validation(
                "JWT extension is disabled by configuration".to_string(),
            ));
        }

        let current_exp = DateTime::<Utc>::from_timestamp(token_data.claims.exp as i64, 0)
            .ok_or_else(|| AppError::Auth("Invalid token expiration".to_string()))?;
        let base = std::cmp::max(current_exp, Utc::now());
        let new_expires = base + Duration::seconds(config.jwt_extension_seconds);

        let new_claims = JwtClaims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            exp: new_expires.timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
            is_admin: user.is_admin,
        };

        let new_token = encode(
            &Header::default(),
            &new_claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok((new_token, new_expires))
    }

    pub async fn authenticate_jwt(&self, token: &str) -> AppResult<User> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;

        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| AppError::Auth("Invalid token subject".to_string()))?;

        let user = self
            .db
            .get_user_by_id(&user_id)
            .await?
            .ok_or_else(|| AppError::Auth("User not found".to_string()))?;

        Ok(user)
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        is_admin: bool,
    ) -> AppResult<User> {
        let password_hash = self.hash_password(password)?;
        self.db
            .create_user(username, &password_hash, is_admin)
            .await
    }

    pub async fn change_own_password(
        &self,
        requester: &User,
        current_password: &str,
        new_password: &str,
    ) -> AppResult<User> {
        if new_password.trim().is_empty() {
            return Err(AppError::Validation(
                "New password cannot be empty".to_string(),
            ));
        }

        let stored_user = self
            .db
            .get_user_by_id(&requester.id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let valid = self.verify_password(current_password, &stored_user.password_hash)?;
        if !valid {
            return Err(AppError::Auth("Current password is incorrect".to_string()));
        }

        if self.verify_password(new_password, &stored_user.password_hash)? {
            return Err(AppError::Validation(
                "New password must differ from current password".to_string(),
            ));
        }

        let password_hash = self.hash_password(new_password)?;
        self.db
            .update_user_password_hash(&requester.id, &password_hash)
            .await?;

        self.db
            .get_user_by_id(&requester.id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))
    }

    pub async fn delete_user(&self, user_id: Uuid) -> AppResult<()> {
        self.db
            .get_user_by_id(&user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        self.db.delete_user(&user_id).await
    }

    pub fn generate_api_key_secret(&self, length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    pub async fn create_api_key(
        &self,
        owner: &User,
        payload: CreateApiKeyRequest,
    ) -> AppResult<CreateApiKeyResponse> {
        let config = self.current_config().await;
        if payload.rate_limit_per_minute > config.max_rate_limit_per_minute {
            return Err(AppError::Validation(format!(
                "Rate limit exceeds configured maximum {}",
                config.max_rate_limit_per_minute
            )));
        }

        let secret = self.generate_api_key_secret(64);
        let api_key = self
            .db
            .create_api_key(
                &owner.id,
                &secret,
                &payload.name,
                payload.rate_limit_per_minute,
            )
            .await?;

        Ok(CreateApiKeyResponse {
            id: api_key.id,
            name: api_key.name,
            secret,
            status: ApiKeyStatus::Enabled,
            rate_limit_per_minute: api_key.rate_limit_per_minute,
        })
    }

    pub async fn list_api_keys(&self, owner: &User) -> AppResult<Vec<ApiKey>> {
        self.db.list_api_keys_for_user(&owner.id).await
    }

    pub async fn update_api_key_status(
        &self,
        owner: &User,
        key_id: Uuid,
        payload: UpdateApiKeyStatusRequest,
    ) -> AppResult<()> {
        let key = self
            .db
            .get_api_key_by_id(&key_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

        if key.user_id != owner.id {
            return Err(AppError::Unauthorized(
                "Cannot modify another user's key".to_string(),
            ));
        }

        let new_status = if payload.enable {
            "enabled"
        } else {
            "disabled"
        };
        self.db.update_api_key_status(&key_id, new_status).await?;

        if payload.enable && key.status != "enabled" {
            self.rate_limiter.reset(key_id);
        }
        Ok(())
    }

    pub async fn delete_api_key(&self, owner: &User, key_id: Uuid) -> AppResult<()> {
        let key = self
            .db
            .get_api_key_by_id(&key_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

        if key.user_id != owner.id {
            return Err(AppError::Unauthorized(
                "Cannot delete another user's key".to_string(),
            ));
        }

        self.db.delete_api_key(&key_id).await?;
        Ok(())
    }

    pub async fn update_api_key_rate_limit(
        &self,
        owner: &User,
        key_id: Uuid,
        payload: UpdateApiKeyRateLimitRequest,
    ) -> AppResult<()> {
        let config = self.current_config().await;
        if payload.rate_limit_per_minute > config.max_rate_limit_per_minute {
            return Err(AppError::Validation(format!(
                "Rate limit exceeds configured maximum {}",
                config.max_rate_limit_per_minute
            )));
        }

        let key = self
            .db
            .get_api_key_by_id(&key_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

        if key.user_id != owner.id {
            return Err(AppError::Unauthorized(
                "Cannot modify another user's key".to_string(),
            ));
        }

        self.db
            .update_api_key_rate_limit(&key_id, payload.rate_limit_per_minute)
            .await?;
        Ok(())
    }

    pub async fn reset_api_key_failures(
        &self,
        owner: &User,
        key_id: Uuid,
        _payload: ResetApiKeyFailuresRequest,
    ) -> AppResult<()> {
        let key = self
            .db
            .get_api_key_by_id(&key_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

        if key.user_id != owner.id {
            return Err(AppError::Unauthorized(
                "Cannot modify another user's key".to_string(),
            ));
        }

        self.db.reset_api_key_failure(&key_id).await?;
        Ok(())
    }

    pub async fn update_auth_configs(
        &self,
        _admin: &User,
        payload: UpdateAuthConfigRequest,
    ) -> AppResult<AuthConfigResponse> {
        for entry in &payload.entries {
            let config_type = if entry.config_type.trim().is_empty() {
                "auth"
            } else {
                entry.config_type.as_str()
            };
            self.db
                .upsert_config_entry(config_type, &entry.key, &entry.value)
                .await?;
        }
        self.reload_config_cache().await?;
        Ok(AuthConfigResponse {
            entries: payload.entries.clone(),
        })
    }

    pub async fn get_auth_configs(&self) -> AppResult<AuthConfigResponse> {
        let configs = self.db.get_configs_by_type("auth").await?;
        let entries = configs
            .into_iter()
            .map(|c| AuthConfigEntry {
                config_type: c.config_type,
                key: c.config_key,
                value: c.config_value,
            })
            .collect();
        Ok(AuthConfigResponse { entries })
    }

    /// 认证带签名的 API 请求
    pub async fn authenticate_signed_request(
        &self,
        key_header: &str,
        timestamp_header: &str,
        nonce_header: &str,
        signature_header: &str,
        method: &str,
        path_with_query: &str,
    ) -> AppResult<AuthenticatedApiKey> {
        let key_id = Uuid::parse_str(key_header)
            .map_err(|_| AppError::Auth("Invalid API key identifier".to_string()))?;

        let timestamp = timestamp_header
            .parse::<i64>()
            .map_err(|_| AppError::Auth("Invalid timestamp".to_string()))?;
        let request_time = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| AppError::Auth("Timestamp out of range".to_string()))?;

        let now = Utc::now();
        let skew = (now - request_time).num_seconds().abs();
        if skew > TIMESTAMP_SKEW_SECONDS {
            warn!("API key {} timestamp skew {}s", key_id, skew);
            self.record_failure(&key_id, "timestamp_skew").await?;
            return Err(AppError::Auth(
                "Timestamp outside allowed window".to_string(),
            ));
        }

        let key = self
            .db
            .get_api_key_by_id(&key_id)
            .await?
            .ok_or_else(|| AppError::Auth("API key not found".to_string()))?;

        if key.status != "enabled" {
            warn!("API key {} disabled attempt", key_id);
            return Err(AppError::Unauthorized("API key disabled".to_string()));
        }

        if !self.rate_limiter.allow(key_id, key.rate_limit_per_minute) {
            warn!("API key {} hit rate limit", key_id);
            self.record_failure(&key_id, "rate_limit").await?;
            return Err(AppError::RateLimit);
        }

        let nonce_ok = {
            let cache = self.nonce_cache.lock().await;
            cache.check_and_store(key_id, nonce_header)
        };
        if !nonce_ok {
            warn!("API key {} replayed nonce", key_id);
            self.record_failure(&key_id, "nonce_replay").await?;
            return Err(AppError::Auth("Nonce already used".to_string()));
        }

        let canonical = format!(
            "{timestamp}\n{nonce}\n{method}\n{path}",
            timestamp = timestamp_header,
            nonce = nonce_header,
            method = method.to_uppercase(),
            path = path_with_query
        );

        let expected_signature = self.compute_signature(&key.key_secret, canonical.as_bytes());
        let provided_signature = signature_header.trim();

        if !constant_time_eq::constant_time_eq(
            expected_signature.as_bytes(),
            provided_signature.as_bytes(),
        ) {
            warn!("API key {} signature mismatch", key_id);
            self.record_failure(&key_id, "signature_mismatch").await?;
            return Err(AppError::Auth("Invalid signature".to_string()));
        }

        Ok(AuthenticatedApiKey { key })
    }

    fn compute_signature(&self, secret: &str, message: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(message);
        let result = mac.finalize().into_bytes();
        hex::encode(result)
    }

    async fn record_failure(&self, key_id: &Uuid, reason: &str) -> AppResult<()> {
        let count = self.db.increment_api_key_failure(key_id).await?;
        let config = self.current_config().await;
        if count >= config.auth_max_failures {
            warn!(
                "API key {} disabled after repeated failures (reason: {})",
                key_id, reason
            );
            self.db
                .update_api_key_status(key_id, ApiKeyStatus::Disabled.to_string().as_str())
                .await?;
        }
        Ok(())
    }
}
