-- Initial schema: unified authentication and configuration

-- 用户基础信息，存储登录凭证及管理员标记
CREATE TABLE auth_users (
    id VARCHAR(36) PRIMARY KEY COMMENT '用户唯一ID（UUID）',
    username VARCHAR(255) UNIQUE NOT NULL COMMENT '登录用户名，唯一',
    password_hash VARCHAR(255) NOT NULL COMMENT '使用 Argon2 哈希后的密码',
    is_admin BOOLEAN NOT NULL DEFAULT FALSE COMMENT '是否为管理员账号',
    created_at DATETIME NOT NULL COMMENT '创建时间',
    updated_at DATETIME NOT NULL COMMENT '最后更新时间',
    disabled_at DATETIME NULL COMMENT '禁用时间，NULL 表示启用'
) COMMENT='系统用户表';

-- API Key 元数据及安全控制
CREATE TABLE auth_api_keys (
    id VARCHAR(36) PRIMARY KEY COMMENT 'API Key 主键（UUID）',
    user_id VARCHAR(36) NOT NULL COMMENT '归属用户ID',
    key_secret VARCHAR(128) NOT NULL COMMENT 'API Key 明文密钥（仅存储哈希或指纹）',
    name VARCHAR(255) NOT NULL COMMENT 'API Key 友好名称',
    status VARCHAR(20) NOT NULL COMMENT '当前状态: enabled/disabled',
    failure_count INT NOT NULL DEFAULT 0 COMMENT '连续失败计数',
    last_failed_at DATETIME NULL COMMENT '最近失败时间',
    rate_limit_per_minute INT NOT NULL COMMENT '每分钟调用限额',
    disabled_at DATETIME NULL COMMENT '禁用时间',
    created_at DATETIME NOT NULL COMMENT '创建时间',
    updated_at DATETIME NOT NULL COMMENT '最后更新时间',
    FOREIGN KEY (user_id) REFERENCES auth_users(id)
) COMMENT='API Key 管理表';

-- 消息发送审计日志
CREATE TABLE message_logs (
    id VARCHAR(36) PRIMARY KEY COMMENT '日志记录ID',
    sender_type VARCHAR(50) NOT NULL COMMENT '发送者类型: api_key 等',
    sender_id VARCHAR(36) NOT NULL COMMENT '发送者标识',
    recipient VARCHAR(500) NOT NULL COMMENT '接收者信息',
    message TEXT NOT NULL COMMENT '发送的消息内容',
    status VARCHAR(50) NOT NULL COMMENT '消息状态: sent/failed/pending',
    timestamp DATETIME NOT NULL COMMENT '消息时间戳'
) COMMENT='消息发送日志表';

-- 应用级配置存储
CREATE TABLE app_configs (
    config_type VARCHAR(50) NOT NULL COMMENT '配置类别',
    config_key VARCHAR(100) NOT NULL COMMENT '配置键',
    config_value VARCHAR(255) NOT NULL COMMENT '配置值',
    updated_at DATETIME NOT NULL COMMENT '最后更新时间',
    PRIMARY KEY (config_type, config_key)
) COMMENT='应用配置表';

-- Seed authentication defaults
INSERT INTO app_configs (config_type, config_key, config_value, updated_at) VALUES
    ('auth', 'auth_max_failures', '5', NOW()),
    ('auth', 'max_rate_limit_per_minute', '600', NOW()),
    ('auth', 'nonce_retention_seconds', '300', NOW());

-- Indexes to support lookups and auditing
CREATE UNIQUE INDEX idx_auth_users_username ON auth_users(username);
CREATE UNIQUE INDEX idx_auth_api_keys_secret ON auth_api_keys(key_secret);
CREATE INDEX idx_auth_api_keys_user_status ON auth_api_keys(user_id, status);
CREATE INDEX idx_message_logs_sender ON message_logs(sender_id, timestamp);
CREATE INDEX idx_message_logs_timestamp ON message_logs(timestamp);
