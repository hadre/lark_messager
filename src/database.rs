/*!
 * 数据库操作模块
 * 
 * 提供对 MySQL 数据库的完整操作接口，包括：
 * - 用户管理（创建、查询用户）
 * - API Key 管理（创建、查询、撤销）
 * - 消息日志记录和查询
 * - 数据库迁移和初始化
 * 
 * 使用 SQLx 作为异步数据库驱动，支持连接池和预编译查询。
 * 所有操作都是类型安全的，避免了 SQL 注入风险。
 */

use crate::error::AppResult;
use crate::models::{ApiKey, MessageLog, User};
use chrono::Utc;
use sqlx::{MySql, MySqlPool, Pool, Row};
use uuid::Uuid;

/// 数据库连接管理器
/// 
/// 封装 MySQL 连接池，提供对数据库的高级操作接口。
/// 使用连接池机制确保高并发下的性能和资源管理。
#[derive(Clone)]
pub struct Database {
    /// MySQL 连接池
    pool: Pool<MySql>,
}

impl Database {
    /// 创建新的数据库连接实例
    /// 
    /// 仅连接到 MySQL 数据库，不执行迁移操作。
    /// 建议在应用启动时显式调用 `migrate()` 方法。
    /// 
    /// # 参数
    /// - `database_url`: MySQL 连接字符串，格式：mysql://user:pass@host:port/db
    /// 
    /// # 错误
    /// - 数据库连接失败
    /// - URL 格式错误
    /// 
    /// # 使用示例
    /// ```rust
    /// let db = Database::new(&database_url).await?;
    /// db.migrate().await?; // 显式执行迁移
    /// ```
    pub async fn new(database_url: &str) -> AppResult<Self> {
        let pool = MySqlPool::connect(database_url).await?;
        Ok(Database { pool })
    }

    /// 创建新的数据库连接实例并自动执行迁移
    /// 
    /// 连接到 MySQL 数据库并自动执行数据库迁移。
    /// 这是一个便利方法，适用于开发环境或单实例部署。
    /// 
    /// # 参数
    /// - `database_url`: MySQL 连接字符串，格式：mysql://user:pass@host:port/db
    /// 
    /// # 错误
    /// - 数据库连接失败
    /// - 数据库迁移失败
    /// - URL 格式错误
    /// 
    /// # 生产环境建议
    /// 在生产环境中，建议使用 `new()` + 显式 `migrate()` 的方式，
    /// 或者使用独立的迁移工具（如 `sqlx migrate run`）。
    pub async fn new_with_migrations(database_url: &str) -> AppResult<Self> {
        let pool = MySqlPool::connect(database_url).await?;
        let db = Database { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// 执行数据库迁移
    /// 
    /// 自动执行 migrations 目录下的所有迁移脚本，确保数据库结构是最新的。
    /// SQLx 会跟踪已执行的迁移，避免重复执行。
    /// 
    /// # 安全性
    /// - 使用事务确保迁移的原子性
    /// - 自动跟踪已执行的迁移，避免重复
    /// - 支持并发安全的迁移执行
    /// 
    /// # 最佳实践
    /// - 开发环境：可以在应用启动时调用
    /// - 生产环境：建议使用独立的部署脚本或工具执行
    /// - 容器环境：可以使用 init 容器执行迁移
    /// 
    /// # 错误处理
    /// 如果迁移失败，应用应该停止启动，避免在不一致的数据库状态下运行。
    pub async fn migrate(&self) -> AppResult<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// 创建新用户
    /// 
    /// 在数据库中插入新的用户记录。用户名必须唯一。
    /// 
    /// # 参数
    /// - `username`: 用户名，必须唯一
    /// - `password_hash`: 使用 Argon2 算法加密的密码哈希
    /// 
    /// # 返回
    /// 创建的用户对象，包含生成的 UUID 和时间戳
    /// 
    /// # 错误
    /// - 用户名已存在（重复键错误）
    /// - 数据库写入失败
    pub async fn create_user(&self, username: &str, password_hash: &str) -> AppResult<User> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(username)
        .bind(password_hash)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(User {
            id,
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            created_at: now,
            updated_at: now,
        })
    }

    /// 根据用户名查找用户
    /// 
    /// 用于用户登录时的身份验证。
    /// 
    /// # 参数
    /// - `username`: 要查找的用户名
    /// 
    /// # 返回
    /// - `Some(User)`: 找到用户时返回用户信息
    /// - `None`: 用户不存在
    pub async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(User {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                username: row.get("username"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })),
            None => Ok(None),
        }
    }

    /// 根据用户 ID 查找用户
    /// 
    /// 用于 JWT token 验证后获取用户详细信息。
    /// 
    /// # 参数
    /// - `user_id`: 用户的 UUID 标识符
    /// 
    /// # 返回
    /// - `Some(User)`: 找到用户时返回用户信息
    /// - `None`: 用户不存在（可能已被删除）
    pub async fn get_user_by_id(&self, user_id: &Uuid) -> AppResult<Option<User>> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE id = ?",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(User {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                username: row.get("username"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })),
            None => Ok(None),
        }
    }

    /// 创建新的 API Key
    /// 
    /// 生成一个用于服务间认证的 API Key。存储的是加密后的哈希值，
    /// 原始密钥不会被保存。
    /// 
    /// # 参数
    /// - `key_hash`: API Key 的哈希值
    /// - `name`: API Key 的友好名称
    /// - `permissions`: 权限字符串，逗号分隔
    /// - `created_by`: 创建者的用户 ID
    /// 
    /// # 返回
    /// 创建的 API Key 对象
    /// 
    /// # 错误
    /// - 数据库写入失败
    /// - 用户 ID 不存在（外键约束失败）
    pub async fn create_api_key(
        &self,
        key_hash: &str,
        name: &str,
        permissions: &str,
        created_by: &Uuid,
    ) -> AppResult<ApiKey> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO api_keys (id, key_hash, name, permissions, created_by, created_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
            "#,
        )
        .bind(id.to_string())
        .bind(key_hash)
        .bind(name)
        .bind(permissions)
        .bind(created_by.to_string())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(ApiKey {
            id,
            key_hash: key_hash.to_string(),
            name: name.to_string(),
            permissions: permissions.to_string(),
            created_by: *created_by,
            created_at: now,
            revoked_at: None,
        })
    }

    /// 根据哈希值查找 API Key
    /// 
    /// 用于 API Key 认证时验证密钥的有效性。只返回未被撤销的 API Key。
    /// 
    /// # 参数
    /// - `key_hash`: API Key 的哈希值
    /// 
    /// # 返回
    /// - `Some(ApiKey)`: 找到有效的 API Key
    /// - `None`: API Key 不存在或已被撤销
    /// 
    /// # 注意
    /// 这个方法已被废弃，建议使用 `find_api_key_by_verification` 方法
    pub async fn get_api_key_by_hash(&self, key_hash: &str) -> AppResult<Option<ApiKey>> {
        let row = sqlx::query(
            r#"
            SELECT id, key_hash, name, permissions, created_by, created_at, revoked_at
            FROM api_keys 
            WHERE key_hash = ? AND revoked_at IS NULL
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(ApiKey {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                key_hash: row.get("key_hash"),
                name: row.get("name"),
                permissions: row.get("permissions"),
                created_by: Uuid::parse_str(row.get::<String, _>("created_by").as_str()).unwrap(),
                created_at: row.get("created_at"),
                revoked_at: row.get("revoked_at"),
            })),
            None => Ok(None),
        }
    }

    /// 撤销 API Key
    /// 
    /// 通过设置撤销时间来禁用 API Key，而不是物理删除。
    /// 这样可以保持审计日志的完整性。
    /// 
    /// # 参数
    /// - `key_id`: 要撤销的 API Key 的 UUID
    /// 
    /// # 返回
    /// - `true`: 成功撤销
    /// - `false`: API Key 不存在或已被撤销
    pub async fn revoke_api_key(&self, key_id: &Uuid) -> AppResult<bool> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(key_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 记录消息发送日志
    /// 
    /// 为所有消息发送操作创建审计日志，用于追踪和调试。
    /// 记录发送者、接收者、消息内容和发送状态。
    /// 
    /// # 参数
    /// - `sender_type`: 发送者类型（"user" 或 "service"）
    /// - `sender_id`: 发送者的 UUID
    /// - `recipient`: 接收者标识
    /// - `message`: 消息内容
    /// - `status`: 发送状态（"sent", "failed", "pending"）
    /// 
    /// # 返回
    /// 创建的消息日志记录
    /// 
    /// # 注意
    /// 此方法应在消息发送尝试后立即调用，无论成功还是失败
    pub async fn log_message(
        &self,
        sender_type: &str,
        sender_id: &Uuid,
        recipient: &str,
        message: &str,
        status: &str,
    ) -> AppResult<MessageLog> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO message_logs (id, sender_type, sender_id, recipient, message, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(sender_type)
        .bind(sender_id.to_string())
        .bind(recipient)
        .bind(message)
        .bind(status)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(MessageLog {
            id,
            sender_type: sender_type.to_string(),
            sender_id: *sender_id,
            recipient: recipient.to_string(),
            message: message.to_string(),
            status: status.to_string(),
            timestamp: now,
        })
    }

    /// 获取消息发送日志
    /// 
    /// 查询消息发送的历史记录，支持按发送者过滤和限制返回数量。
    /// 结果按发送时间降序排列（最新的在前）。
    /// 
    /// # 参数
    /// - `sender_id`: 可选，特定发送者的 UUID，为 None 时返回所有日志
    /// - `limit`: 可选，返回的最大记录数，默认为 100
    /// 
    /// # 返回
    /// 按时间降序排列的消息日志列表
    /// 
    /// # 使用场景
    /// - 管理员查看所有消息发送记录
    /// - 用户查看自己的消息发送历史
    /// - 系统调试和问题排查
    pub async fn get_message_logs(
        &self,
        sender_id: Option<Uuid>,
        limit: Option<i64>,
    ) -> AppResult<Vec<MessageLog>> {
        let limit = limit.unwrap_or(100);

        let rows = match sender_id {
            Some(id) => {
                sqlx::query(
                    r#"
                    SELECT id, sender_type, sender_id, recipient, message, status, timestamp
                    FROM message_logs 
                    WHERE sender_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    "#,
                )
                .bind(id.to_string())
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    r#"
                    SELECT id, sender_type, sender_id, recipient, message, status, timestamp
                    FROM message_logs 
                    ORDER BY timestamp DESC
                    LIMIT ?
                    "#,
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };

        let logs = rows
            .into_iter()
            .map(|row| MessageLog {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                sender_type: row.get("sender_type"),
                sender_id: Uuid::parse_str(row.get::<String, _>("sender_id").as_str()).unwrap(),
                recipient: row.get("recipient"),
                message: row.get("message"),
                status: row.get("status"),
                timestamp: row.get("timestamp"),
            })
            .collect();

        Ok(logs)
    }

    /// 通过密码验证查找 API Key
    /// 
    /// 由于 API Key 存储的是哈希值，需要逐一验证所有活跃的 API Key。
    /// 这是更安全的认证方式，可以防止网络窃听和日志泄露。
    /// 
    /// # 参数
    /// - `api_key`: 原始的 API Key 字符串
    /// - `auth_service`: 认证服务实例，用于密码验证
    /// 
    /// # 返回
    /// - `Some(ApiKey)`: 找到匹配的有效 API Key
    /// - `None`: 没有找到匹配的 API Key
    /// 
    /// # 性能考虑
    /// 此方法会查询所有活跃的 API Key 并逐一验证，
    /// 在 API Key 数量很多时可能影响性能。建议配置缓存。
    pub async fn find_api_key_by_verification(&self, api_key: &str, auth_service: &crate::auth::AuthService) -> AppResult<Option<ApiKey>> {
        // Get all active API keys for verification
        let rows = sqlx::query(
            r#"
            SELECT id, key_hash, name, permissions, created_by, created_at, revoked_at
            FROM api_keys 
            WHERE revoked_at IS NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        for row in rows {
            let key_hash: String = row.get("key_hash");
            if auth_service.verify_api_key(api_key, &key_hash).unwrap_or(false) {
                return Ok(Some(ApiKey {
                    id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                    key_hash: row.get("key_hash"),
                    name: row.get("name"),
                    permissions: row.get("permissions"),
                    created_by: Uuid::parse_str(row.get::<String, _>("created_by").as_str()).unwrap(),
                    created_at: row.get("created_at"),
                    revoked_at: row.get("revoked_at"),
                }));
            }
        }
        Ok(None)
    }
}