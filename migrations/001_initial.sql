-- Create users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- Create api_keys table
CREATE TABLE api_keys (
    id VARCHAR(36) PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    permissions VARCHAR(500) NOT NULL,
    created_by VARCHAR(36) NOT NULL,
    created_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Create message_logs table
CREATE TABLE message_logs (
    id VARCHAR(36) PRIMARY KEY,
    sender_type VARCHAR(50) NOT NULL,
    sender_id VARCHAR(36) NOT NULL,
    recipient VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(50) NOT NULL,
    timestamp DATETIME NOT NULL
);

-- Create indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE UNIQUE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_active ON api_keys(revoked_at);
CREATE INDEX idx_message_logs_sender ON message_logs(sender_id, timestamp);
CREATE INDEX idx_message_logs_timestamp ON message_logs(timestamp);