/*!
 * 数据库操作模块
 *
 * 提供 MySQL 数据库的操作接口：
 * - 用户管理
 * - API Key 管理
 * - 配置项管理
 * - 消息日志记录
 */

use crate::error::AppResult;
use crate::models::{
    ApiKey, AuthConfig, MessageLog, MessageLogFilters, MessageLogRecord, OperationLog,
    OperationLogFilters, OperationLogRecord, User,
};
use chrono::{DateTime, Utc};
use sqlx::{MySql, MySqlPool, Pool, QueryBuilder, Row};
use tracing::warn;
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: Pool<MySql>,
}

impl Database {
    pub async fn new(database_url: &str) -> AppResult<Self> {
        let pool = MySqlPool::connect(database_url).await?;
        Ok(Database { pool })
    }

    pub async fn new_with_migrations(database_url: &str) -> AppResult<Self> {
        let pool = MySqlPool::connect(database_url).await?;
        let db = Database { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> AppResult<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // 用户管理
    // ---------------------------------------------------------------------

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        is_admin: bool,
    ) -> AppResult<User> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO auth_users (
                id, username, password_hash, is_admin, is_super_admin, created_at, updated_at, last_login_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(username)
        .bind(password_hash)
        .bind(is_admin)
        .bind(false)
        .bind(now)
        .bind(now)
        .bind(Option::<DateTime<Utc>>::None)
        .execute(&self.pool)
        .await?;

        Ok(User {
            id,
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            is_admin,
            is_super_admin: false,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, is_admin, is_super_admin, last_login_at, created_at, updated_at
            FROM auth_users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| User {
            id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            is_admin: row.get::<i8, _>("is_admin") != 0,
            is_super_admin: row.get::<i8, _>("is_super_admin") != 0,
            last_login_at: row.get::<Option<DateTime<Utc>>, _>("last_login_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    pub async fn get_user_by_id(&self, user_id: &Uuid) -> AppResult<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, is_admin, is_super_admin, last_login_at, created_at, updated_at
            FROM auth_users
            WHERE id = ?
            "#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| User {
            id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            is_admin: row.get::<i8, _>("is_admin") != 0,
            is_super_admin: row.get::<i8, _>("is_super_admin") != 0,
            last_login_at: row.get::<Option<DateTime<Utc>>, _>("last_login_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    pub async fn update_user_password_hash(
        &self,
        user_id: &Uuid,
        password_hash: &str,
    ) -> AppResult<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE auth_users
            SET password_hash = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(password_hash)
        .bind(now)
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_user_last_login(
        &self,
        user_id: &Uuid,
        last_login_at: DateTime<Utc>,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            UPDATE auth_users
            SET last_login_at = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(last_login_at)
        .bind(last_login_at)
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_user(&self, user_id: &Uuid) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM auth_api_keys WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM auth_users WHERE id = ?")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // API Key 管理
    // ---------------------------------------------------------------------

    pub async fn create_api_key(
        &self,
        user_id: &Uuid,
        key_secret: &str,
        name: &str,
        rate_limit_per_minute: i32,
    ) -> AppResult<ApiKey> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO auth_api_keys (
                id, user_id, key_secret, name, status, failure_count, last_failed_at,
                rate_limit_per_minute, disabled_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'enabled', 0, NULL, ?, NULL, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .bind(key_secret)
        .bind(name)
        .bind(rate_limit_per_minute)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(ApiKey {
            id,
            user_id: *user_id,
            key_secret: key_secret.to_string(),
            name: name.to_string(),
            status: "enabled".to_string(),
            failure_count: 0,
            last_failed_at: None,
            rate_limit_per_minute,
            disabled_at: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_api_key_by_id(&self, key_id: &Uuid) -> AppResult<Option<ApiKey>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, key_secret, name, status, failure_count, last_failed_at,
                   rate_limit_per_minute, disabled_at, created_at, updated_at
            FROM auth_api_keys
            WHERE id = ?
            "#,
        )
        .bind(key_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| ApiKey {
            id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
            user_id: Uuid::parse_str(row.get::<String, _>("user_id").as_str()).unwrap(),
            key_secret: row.get("key_secret"),
            name: row.get("name"),
            status: row.get("status"),
            failure_count: row.get("failure_count"),
            last_failed_at: row.get("last_failed_at"),
            rate_limit_per_minute: row.get("rate_limit_per_minute"),
            disabled_at: row.get("disabled_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    pub async fn list_api_keys_for_user(&self, user_id: &Uuid) -> AppResult<Vec<ApiKey>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, key_secret, name, status, failure_count, last_failed_at,
                   rate_limit_per_minute, disabled_at, created_at, updated_at
            FROM auth_api_keys
            WHERE user_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| ApiKey {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                user_id: Uuid::parse_str(row.get::<String, _>("user_id").as_str()).unwrap(),
                key_secret: row.get("key_secret"),
                name: row.get("name"),
                status: row.get("status"),
                failure_count: row.get("failure_count"),
                last_failed_at: row.get("last_failed_at"),
                rate_limit_per_minute: row.get("rate_limit_per_minute"),
                disabled_at: row.get("disabled_at"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect())
    }

    pub async fn update_api_key_status(&self, key_id: &Uuid, status: &str) -> AppResult<()> {
        let now = Utc::now();
        let disabled_at = if status == "disabled" {
            Some(now)
        } else {
            None
        };

        sqlx::query(
            r#"
            UPDATE auth_api_keys
            SET status = ?, disabled_at = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(disabled_at)
        .bind(now)
        .bind(key_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn increment_api_key_failure(&self, key_id: &Uuid) -> AppResult<i32> {
        let now = Utc::now();
        let rec = sqlx::query(
            r#"
            UPDATE auth_api_keys
            SET failure_count = failure_count + 1,
                last_failed_at = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(key_id.to_string())
        .execute(&self.pool)
        .await?;

        if rec.rows_affected() == 0 {
            return Ok(0);
        }

        let row = sqlx::query("SELECT failure_count FROM auth_api_keys WHERE id = ?")
            .bind(key_id.to_string())
            .fetch_one(&self.pool)
            .await?;

        Ok(row.get("failure_count"))
    }

    pub async fn reset_api_key_failure(&self, key_id: &Uuid) -> AppResult<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE auth_api_keys
            SET failure_count = 0,
                last_failed_at = NULL,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(now)
        .bind(key_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_api_key_rate_limit(
        &self,
        key_id: &Uuid,
        rate_limit_per_minute: i32,
    ) -> AppResult<()> {
        let now = Utc::now();

        sqlx::query(
            r#"
            UPDATE auth_api_keys
            SET rate_limit_per_minute = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(rate_limit_per_minute)
        .bind(now)
        .bind(key_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_api_key(&self, key_id: &Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM auth_api_keys WHERE id = ?")
            .bind(key_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // 配置项管理
    // ---------------------------------------------------------------------

    pub async fn get_configs_by_type(&self, config_type: &str) -> AppResult<Vec<AuthConfig>> {
        let rows = sqlx::query(
            r#"
            SELECT config_type, config_key, config_value, updated_at
            FROM app_configs
            WHERE config_type = ?
            "#,
        )
        .bind(config_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| AuthConfig {
                config_type: row.get("config_type"),
                config_key: row.get("config_key"),
                config_value: row.get("config_value"),
                updated_at: row.get("updated_at"),
            })
            .collect())
    }

    pub async fn upsert_config_entry(
        &self,
        config_type: &str,
        key: &str,
        value: &str,
    ) -> AppResult<()> {
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO app_configs (config_type, config_key, config_value, updated_at)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value), updated_at = VALUES(updated_at)
            "#,
        )
        .bind(config_type)
        .bind(key)
        .bind(value)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ---------------------------------------------------------------------
    // 消息日志
    // ---------------------------------------------------------------------

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

    pub async fn list_message_logs(
        &self,
        filters: MessageLogFilters,
    ) -> AppResult<Vec<MessageLogRecord>> {
        let mut query_builder = QueryBuilder::<MySql>::new(
            "SELECT m.id, m.sender_type, m.sender_id, k.name AS sender_name, u.username AS owner_username, m.recipient, m.message, m.status, m.timestamp FROM message_logs m LEFT JOIN auth_api_keys k ON m.sender_id = k.id LEFT JOIN auth_users u ON k.user_id = u.id WHERE 1 = 1",
        );

        if let Some(sender_id) = filters.sender_id {
            query_builder
                .push(" AND m.sender_id = ")
                .push_bind(sender_id.to_string());
        }

        if let Some(sender_type) = &filters.sender_type {
            query_builder
                .push(" AND m.sender_type = ")
                .push_bind(sender_type);
        }

        if let Some(status) = &filters.status {
            query_builder.push(" AND m.status = ").push_bind(status);
        }

        if let Some(sender_name) = &filters.sender_name {
            query_builder.push(" AND k.name = ").push_bind(sender_name);
        }

        if let Some(owner_username) = &filters.owner_username {
            query_builder
                .push(" AND u.username = ")
                .push_bind(owner_username);
        }

        if let Some(start_time) = filters.start_time {
            query_builder
                .push(" AND m.timestamp >= ")
                .push_bind(start_time);
        }

        if let Some(end_time) = filters.end_time {
            query_builder
                .push(" AND m.timestamp <= ")
                .push_bind(end_time);
        }

        let limit = filters.limit.unwrap_or(100).max(1).min(1000);
        query_builder
            .push(" ORDER BY m.timestamp DESC LIMIT ")
            .push_bind(limit);

        let query = query_builder.build();
        let rows = query.fetch_all(&self.pool).await?;

        Ok(rows
            .into_iter()
            .map(|row| MessageLogRecord {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                sender_type: row.get("sender_type"),
                sender_id: Uuid::parse_str(row.get::<String, _>("sender_id").as_str()).unwrap(),
                sender_name: row.get("sender_name"),
                owner_username: row.get("owner_username"),
                recipient: row.get("recipient"),
                message: row.get("message"),
                status: row.get("status"),
                timestamp: row.get("timestamp"),
            })
            .collect())
    }

    // ---------------------------------------------------------------------
    // 操作日志
    // ---------------------------------------------------------------------

    pub async fn record_operation_log(
        &self,
        user_id: Option<Uuid>,
        operation_type: &str,
        detail: &str,
    ) -> AppResult<OperationLog> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO operation_logs (id, user_id, operation_type, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(user_id.map(|value| value.to_string()))
        .bind(operation_type)
        .bind(detail)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(OperationLog {
            id,
            user_id,
            operation_type: operation_type.to_string(),
            detail: detail.to_string(),
            created_at: now,
        })
    }

    /// 异步记录操作日志，不阻塞调用方
    pub fn log_operation_async(
        &self,
        user_id: Option<Uuid>,
        operation_type: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let db = self.clone();
        let operation_type = operation_type.into();
        let detail = detail.into();

        tokio::spawn(async move {
            if let Err(err) = db
                .record_operation_log(user_id, &operation_type, &detail)
                .await
            {
                warn!("Failed to record operation log: {}", err);
            }
        });
    }

    pub async fn list_operation_logs(
        &self,
        filters: OperationLogFilters,
    ) -> AppResult<Vec<OperationLogRecord>> {
        let mut query_builder = QueryBuilder::<MySql>::new(
            "SELECT o.id, o.user_id, u.username, u.is_admin, u.is_super_admin, o.operation_type, o.detail, o.created_at FROM operation_logs o LEFT JOIN auth_users u ON o.user_id = u.id WHERE 1 = 1",
        );

        if let Some(username) = &filters.username {
            query_builder.push(" AND u.username = ").push_bind(username);
        }

        if let Some(operation_type) = &filters.operation_type {
            query_builder
                .push(" AND o.operation_type = ")
                .push_bind(operation_type);
        }

        if let Some(start_time) = filters.start_time {
            query_builder
                .push(" AND o.created_at >= ")
                .push_bind(start_time);
        }

        if let Some(end_time) = filters.end_time {
            query_builder
                .push(" AND o.created_at <= ")
                .push_bind(end_time);
        }

        let limit = filters.limit.unwrap_or(100).max(1).min(1000);
        query_builder
            .push(" ORDER BY o.created_at DESC LIMIT ")
            .push_bind(limit);

        let query = query_builder.build();
        let rows = query.fetch_all(&self.pool).await?;

        Ok(rows
            .into_iter()
            .map(|row| OperationLogRecord {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap(),
                user_id: row
                    .get::<Option<String>, _>("user_id")
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                username: row.get("username"),
                is_admin: row.get::<Option<i8>, _>("is_admin").map(|flag| flag != 0),
                is_super_admin: row
                    .get::<Option<i8>, _>("is_super_admin")
                    .map(|flag| flag != 0),
                operation_type: row.get("operation_type"),
                detail: row.get("detail"),
                created_at: row.get("created_at"),
            })
            .collect())
    }
}
