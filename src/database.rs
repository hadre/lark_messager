use crate::error::AppResult;
use crate::models::{ApiKey, MessageLog, User};
use chrono::Utc;
use sqlx::{MySql, MySqlPool, Pool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: Pool<MySql>,
}

impl Database {
    pub async fn new(database_url: &str) -> AppResult<Self> {
        let pool = MySqlPool::connect(database_url).await?;
        let db = Database { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> AppResult<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

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