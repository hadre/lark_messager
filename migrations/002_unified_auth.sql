-- New tables for unified authentication and configuration
CREATE TABLE auth_users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    disabled_at DATETIME NULL
);

CREATE TABLE auth_api_keys (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    key_secret VARCHAR(128) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL,
    failure_count INT NOT NULL DEFAULT 0,
    last_failed_at DATETIME NULL,
    rate_limit_per_minute INT NOT NULL,
    disabled_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES auth_users(id),
    INDEX idx_auth_api_keys_user_status(user_id, status)
);

CREATE TABLE app_configs (
    config_type VARCHAR(50) NOT NULL,
    config_key VARCHAR(100) NOT NULL,
    config_value VARCHAR(255) NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (config_type, config_key)
);

INSERT INTO app_configs (config_type, config_key, config_value, updated_at) VALUES
    ('auth', 'auth_max_failures', '5', NOW()),
    ('auth', 'max_rate_limit_per_minute', '600', NOW()),
    ('auth', 'nonce_retention_seconds', '300', NOW());
