/*!
 * 身份认证和授权模块
 * 
 * 提供完整的双重认证系统：
 * - JWT Token 认证（用户身份认证）
 * - API Key 认证（服务间认证）
 * - 密码哈希和验证（Argon2 算法）
 * - 权限管理和访问控制
 * 
 * 支持以下认证方式：
 * 1. 用户登录 -> JWT Token（24小时有效期）
 * 2. 服务调用 -> API Key（长期有效，可撤销）
 * 
 * 安全特性：
 * - 使用 Argon2 算法进行密码哈希
 * - JWT Token 包含用户信息和过期时间
 * - API Key 支持细粒度权限控制
 * - 所有敏感信息都经过哈希存储
 */

use crate::database::Database;
use crate::error::{AppError, AppResult};
use crate::models::User;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT Token 声明信息
/// 
/// 包含用户身份和令牌元数据，符合 JWT 标准
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// 主题（用户 ID）
    pub sub: String,
    /// 用户名
    pub username: String,
    /// 过期时间（Unix 时间戳）
    pub exp: usize,
    /// 签发时间（Unix 时间戳）
    pub iat: usize,
}

/// 已认证的用户类型
/// 
/// 统一表示通过不同认证方式验证的用户，支持：
/// - 通过 JWT 认证的普通用户
/// - 通过 API Key 认证的服务
#[derive(Debug)]
pub enum AuthenticatedUser {
    /// 普通用户（通过用户名密码登录）
    User { 
        /// 用户 ID
        id: Uuid, 
        /// 用户名
        username: String 
    },
    /// 服务用户（通过 API Key 认证）
    Service { 
        /// 创建该 API Key 的用户 ID
        id: Uuid, 
        /// API Key 的友好名称
        name: String, 
        /// 权限列表
        permissions: Vec<String> 
    },
}

impl AuthenticatedUser {
    /// 获取用户 ID
    /// 
    /// 无论是普通用户还是服务用户，都返回对应的用户 ID
    pub fn id(&self) -> Uuid {
        match self {
            AuthenticatedUser::User { id, .. } => *id,
            AuthenticatedUser::Service { id, .. } => *id,
        }
    }

    /// 检查是否具有管理员权限
    /// 
    /// - 普通用户：默认没有管理员权限
    /// - 服务用户：检查是否具有 "admin" 权限
    pub fn is_admin(&self) -> bool {
        match self {
            AuthenticatedUser::User { .. } => false,
            AuthenticatedUser::Service { permissions, .. } => {
                permissions.contains(&"admin".to_string())
            }
        }
    }

    /// 检查是否可以发送消息
    /// 
    /// - 普通用户：默认可以发送消息
    /// - 服务用户：需要 "send_messages" 或 "admin" 权限
    pub fn can_send_messages(&self) -> bool {
        match self {
            AuthenticatedUser::User { .. } => true,
            AuthenticatedUser::Service { permissions, .. } => {
                permissions.contains(&"send_messages".to_string()) 
                    || permissions.contains(&"admin".to_string())
            }
        }
    }
}

/// 认证服务
/// 
/// 提供统一的认证和授权功能，包括：
/// - 密码哈希和验证
/// - JWT Token 生成和验证
/// - API Key 生成、哈希和验证
/// - 用户认证和授权检查
#[derive(Clone)]
pub struct AuthService {
    /// JWT 签名密钥
    jwt_secret: String,
    /// 数据库连接
    db: Database,
}

impl AuthService {
    /// 创建认证服务实例
    /// 
    /// # 参数
    /// - `jwt_secret`: JWT 签名密钥，必须足够复杂以确保安全性
    /// - `db`: 数据库连接实例
    pub fn new(jwt_secret: String, db: Database) -> Self {
        Self { jwt_secret, db }
    }

    /// 密码哈希
    /// 
    /// 使用 Argon2 算法对密码进行安全哈希。
    /// Argon2 是目前推荐的密码哈希算法，可以抗对各种攻击。
    /// 
    /// # 参数
    /// - `password`: 原始密码字符串
    /// 
    /// # 返回
    /// 哈希后的密码字符串，包含盐值和参数
    /// 
    /// # 安全性
    /// - 自动生成随机盐值
    /// - 使用默认的 Argon2 参数（适合大多数应用）
    /// - 抵抗彩虹表和暴力破解攻击
    pub fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?;

        Ok(password_hash.to_string())
    }

    /// 验证密码
    /// 
    /// 校验用户输入的密码是否与存储的哈希匹配。
    /// 
    /// # 参数
    /// - `password`: 用户输入的原始密码
    /// - `password_hash`: 数据库中存储的密码哈希
    /// 
    /// # 返回
    /// - `true`: 密码正确
    /// - `false`: 密码错误
    /// 
    /// # 安全性
    /// - 使用常量时间比较，防止时间攻击
    /// - 错误不会泄露具体的失败原因
    pub fn verify_password(&self, password: &str, password_hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AppError::Internal(format!("Failed to parse password hash: {}", e)))?;
        
        let argon2 = Argon2::default();
        
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// 生成 JWT Token
    /// 
    /// 为用户创建一个有效期为 24 小时的 JWT Token。
    /// Token 中包含用户 ID、用户名和过期时间。
    /// 
    /// # 参数
    /// - `user`: 用户对象，包含用户信息
    /// 
    /// # 返回
    /// 返回元组：(JWT Token 字符串, 过期时间)
    /// 
    /// # JWT 结构
    /// - Header: 默认算法 (HS256)
    /// - Payload: 用户 ID、用户名、过期时间、签发时间
    /// - Signature: 使用配置的密钥签名
    pub fn generate_jwt_token(&self, user: &User) -> AppResult<(String, DateTime<Utc>)> {
        let expiration = Utc::now() + Duration::hours(24);
        
        let claims = Claims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            exp: expiration.timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )?;

        Ok((token, expiration))
    }

    /// 验证 JWT Token
    /// 
    /// 解析并验证 JWT Token 的有效性，包括：
    /// - 签名验证（防止篡改）
    /// - 过期时间检查
    /// - 格式正确性验证
    /// 
    /// # 参数
    /// - `token`: 要验证的 JWT Token 字符串
    /// 
    /// # 返回
    /// 解析后的声明信息，包含用户 ID 和用户名
    /// 
    /// # 错误
    /// - Token 格式错误
    /// - 签名验证失败
    /// - Token 已过期
    pub fn verify_jwt_token(&self, token: &str) -> AppResult<Claims> {
        let token_data: TokenData<Claims> = decode(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }

    /// 生成随机 API Key
    /// 
    /// 创建一个指定长度的随机字符串，用作 API Key。
    /// 使用大小写字母和数字的组合，避免歧义字符。
    /// 
    /// # 参数
    /// - `length`: 生成的 API Key 长度，建议不少于 32 位
    /// 
    /// # 返回
    /// 随机生成的 API Key 字符串
    /// 
    /// # 安全性
    /// - 使用加密安全的随机数生成器
    /// - 字符集包含 62 个字符，熔量足够大
    /// - 结果不可预测且难以暴力破解
    pub fn generate_api_key(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789";
        
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// API Key 哈希
    /// 
    /// 使用与密码相同的 Argon2 算法对 API Key 进行哈希。
    /// 这样可以防止 API Key 在数据库中以明文存储。
    /// 
    /// # 参数
    /// - `api_key`: 原始的 API Key 字符串
    /// 
    /// # 返回
    /// 哈希后的 API Key，包含盐值和参数
    /// 
    /// # 安全性
    /// - 与密码哈希使用相同的安全标准
    /// - 无法从哈希反推原始 API Key
    /// - 可以安全地存储在日志和数据库中
    pub fn hash_api_key(&self, api_key: &str) -> AppResult<String> {
        use argon2::password_hash::rand_core::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let key_hash = argon2
            .hash_password(api_key.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Failed to hash API key: {}", e)))?;

        Ok(key_hash.to_string())
    }

    /// 验证 API Key
    /// 
    /// 校验 API Key 是否与存储的哈希值匹配。
    /// 使用与密码验证相同的安全机制。
    /// 
    /// # 参数
    /// - `api_key`: 用户提供的原始 API Key
    /// - `key_hash`: 数据库中存储的 API Key 哈希
    /// 
    /// # 返回
    /// - `true`: API Key 正确
    /// - `false`: API Key 错误
    /// 
    /// # 安全性
    /// - 使用常量时间比较，防止时间攻击
    /// - 错误不会泄露具体的失败原因
    pub fn verify_api_key(&self, api_key: &str, key_hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(key_hash)
            .map_err(|e| AppError::Internal(format!("Failed to parse API key hash: {}", e)))?;
        
        let argon2 = Argon2::default();
        
        match argon2.verify_password(api_key.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// 解析权限字符串
    /// 
    /// 将逗号分隔的权限字符串转换为权限列表。
    /// 自动过滤空白和空权限。
    /// 
    /// # 参数
    /// - `permissions_str`: 权限字符串，格式如 "admin,send_messages,view_logs"
    /// 
    /// # 返回
    /// 解析后的权限列表
    /// 
    /// # 示例
    /// ```rust
    /// let perms = auth.parse_permissions("admin, send_messages , view_logs");
    /// assert_eq!(perms, vec!["admin", "send_messages", "view_logs"]);
    /// ```
    pub fn parse_permissions(&self, permissions_str: &str) -> Vec<String> {
        permissions_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// 用户身份认证
    /// 
    /// 验证用户名和密码组合的有效性。用于用户登录流程。
    /// 
    /// # 参数
    /// - `username`: 用户名
    /// - `password`: 原始密码
    /// 
    /// # 返回
    /// 认证成功时返回用户对象
    /// 
    /// # 错误
    /// - 用户不存在
    /// - 密码错误
    /// - 数据库连接失败
    /// 
    /// # 安全性
    /// - 用户名和密码错误使用相同的错误信息，防止用户枚举
    /// - 密码验证使用安全的 Argon2 算法
    pub async fn authenticate_user(&self, username: &str, password: &str) -> AppResult<User> {
        let user = self.db.get_user_by_username(username)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid username or password".to_string()))?;

        if !self.verify_password(password, &user.password_hash)? {
            return Err(AppError::Auth("Invalid username or password".to_string()));
        }

        Ok(user)
    }

    /// JWT Token 认证
    /// 
    /// 验证 JWT Token 并返回认证用户信息。
    /// 用于保护需要用户身份验证的 API 端点。
    /// 
    /// # 参数
    /// - `token`: JWT Token 字符串
    /// 
    /// # 返回
    /// 认证成功时返回 `AuthenticatedUser::User`
    /// 
    /// # 验证流程
    /// 1. 解析和验证 Token 签名
    /// 2. 检查 Token 是否过期
    /// 3. 提取用户 ID
    /// 4. 从数据库查询用户信息
    /// 5. 返回认证结果
    /// 
    /// # 错误
    /// - Token 格式错误
    /// - Token 签名无效
    /// - Token 已过期
    /// - 用户不存在（可能已被删除）
    pub async fn authenticate_jwt(&self, token: &str) -> AppResult<AuthenticatedUser> {
        let claims = self.verify_jwt_token(token)?;
        
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Auth("Invalid user ID in token".to_string()))?;

        let user = self.db.get_user_by_id(&user_id)
            .await?
            .ok_or_else(|| AppError::Auth("User not found".to_string()))?;

        Ok(AuthenticatedUser::User {
            id: user.id,
            username: user.username,
        })
    }

    /// API Key 认证
    /// 
    /// 验证 API Key 并返回服务用户信息，包含权限列表。
    /// 用于保护需要服务间认证的 API 端点。
    /// 
    /// # 参数
    /// - `api_key`: API Key 字符串
    /// 
    /// # 返回
    /// 认证成功时返回 `AuthenticatedUser::Service`，包含权限信息
    /// 
    /// # 验证流程
    /// 1. 从数据库获取所有活跃的 API Key 哈希
    /// 2. 逐一验证输入的 API Key 与存储的哈希
    /// 3. 检查 API Key 是否被撤销
    /// 4. 解析权限字符串为权限列表
    /// 5. 返回服务用户认证结果
    /// 
    /// # 权限系统
    /// - `admin`: 管理员权限，可以创建/撤销 API Key
    /// - `send_messages`: 发送消息权限
    /// - 可扩展其他自定义权限
    /// 
    /// # 错误
    /// - API Key 无效或不存在
    /// - API Key 已被撤销
    /// - 数据库连接失败
    /// 
    /// # 安全性
    /// - API Key 以哈希形式存储，不可逆向
    /// - 支持细粒度权限控制
    /// - 可以随时撤销而无需更改代码
    pub async fn authenticate_api_key(&self, api_key: &str) -> AppResult<AuthenticatedUser> {
        // Use the new verification method that works with hashed keys
        let api_key_record = self.db.find_api_key_by_verification(api_key, self)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid API key".to_string()))?;

        if api_key_record.revoked_at.is_some() {
            return Err(AppError::Auth("API key has been revoked".to_string()));
        }

        let permissions = self.parse_permissions(&api_key_record.permissions);

        Ok(AuthenticatedUser::Service {
            id: api_key_record.created_by,
            name: api_key_record.name,
            permissions,
        })
    }
}