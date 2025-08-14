# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based Lark (Feishu) messaging bot API service that provides secure message sending capabilities. The service acts as a proxy between authenticated clients and the Lark Bot API, offering user authentication, message validation, and comprehensive logging.

### Core Functionality
- **REST API Service**: Web server providing HTTP endpoints for message operations
- **User Authentication**: JWT-based authentication with local database storage
- **Lark Integration**: Send messages via Lark Bot API to individuals and groups
- **Message Validation**: Verify recipient existence before sending messages
- **Comprehensive Logging**: Request logging, error tracking, and debug information
- **Docker Deployment**: Containerized deployment support

### Target Use Cases
- Send notifications to Lark users/groups from authenticated applications
- Centralized message dispatching with audit trails
- Secure API gateway for Lark messaging operations

## Project Structure

- `lark_messager/` - Main Rust application for Lark messaging
  - `src/main.rs` - Entry point with basic "Hello, world!" implementation
  - `Cargo.toml` - Project configuration and dependencies
  - `Cargo.lock` - Dependency lock file
  - `target/` - Build artifacts (generated)

## Development Commands

### Building and Running
```bash
cd lark_messager
cargo build                                    # Build all binaries
cargo build --release                          # Build optimized release version
cargo run                                      # Build and run main application
cargo run --bin generate_credentials           # Run credential generation tool
```

### Testing and Quality
```bash
cd lark_messager
cargo test            # Run all tests
cargo check           # Quick syntax/type checking without building
cargo clippy          # Run Rust linter
cargo fmt             # Format code
```

### Dependencies
```bash
cd lark_messager
cargo add <package>   # Add a new dependency
cargo update          # Update dependencies
```

## Technical Architecture

### Core Components
- **Web Server**: HTTP server handling REST API requests (using Axum/Warp)
- **Dual Authentication System**: JWT for users + API Key for services
- **Database Layer**: Local database for user credentials, API keys, and audit logs
- **Lark Client**: HTTP client for Lark Bot API integration
- **Logging System**: Structured logging to local files
- **Message Validator**: Recipient verification and message format validation

### Authentication Architecture

#### 1. JWT Authentication (User Scenario)
- Target: Frontend applications, personal tools, interactive clients
- Flow: User login → JWT token issued → Token in Authorization header
- Expiration: Short-lived tokens (configurable, default 24h)
- Use case: Individual users sending messages through web/mobile apps

#### 2. API Key Authentication (Service-to-Service)
- Target: Trusted services, automation scripts, scheduled tasks
- Flow: Pre-issued API key → Key in X-API-Key header
- Expiration: Long-lived or permanent (manual revocation)
- Use case: Backend services, monitoring systems, batch processors

#### Authentication Headers
```
# JWT Authentication
Authorization: Bearer <jwt_token>

# API Key Authentication  
X-API-Key: <api_key>
```

### API Design
- `POST /auth/login` - User authentication, returns JWT token
- `POST /auth/api-keys` - Create new API key (requires admin API key, NOT user token)
- `DELETE /auth/api-keys/{key_id}` - Revoke API key (requires admin API key, NOT user token)
- `POST /messages/send` - Send message to individual user
- `POST /messages/send-group` - Send message to group
- `GET /recipients/verify` - Verify recipient existence
- `GET /health` - Service health check

### Message Recipients Support
#### Individual Messages
- Open ID (obtained from email/mobile lookup)
- Email address (automatically converted to open_id)
- Phone number (automatically converted to open_id)

#### Group Messages  
- Chat ID (oc_xxx, ou_xxx format)
- Chat name (automatically converted to chat_id)

### Permission Levels
- **User Level**: Can send messages, verify recipients
- **Service Level**: Same as user + batch operations
- **Admin Level**: User management, API key management

## Development Principles

### Code Documentation Requirements
- **Always Write Comments**: During code development, comprehensive comments must be included alongside the implementation
- **Comment Standards**: Comments should explain the "why" behind complex logic, not just the "what"
- **Documentation Consistency**: Maintain consistent commenting style throughout the codebase
- **API Documentation**: All public functions, structs, and modules must include proper Rust documentation comments (`///`)

### Session Logging Requirements
- **Prompt and Execution Logging**: After each user prompt execution, record the session in `prompts/prompt_records.md`
- **Log Format**:
  ```markdown
  # [YYYY-MM-DD HH:MM:SS][Prompt Summary]
  ## Prompt内容
  [Original prompt content]
  ## 执行内容总结
  [Summary of execution and changes made]
  ```

### Security and Git Management Rules
- **Environment File Security**: Before creating or modifying any files containing sensitive information (API keys, passwords, database credentials), always ensure they are added to `.gitignore`
- **Sensitive File Detection**: When working with configuration files, environment variables, or secrets, proactively remind about .gitignore requirements
- **Template Files Only**: Keep only example/template files (`.env.example`, `.env.test.example`) in version control
- **Security Review**: When adding new configuration files or modifying existing ones, review whether they contain or might contain sensitive information

## Development Requirements

### Dependencies to Add
- Web framework (Axum recommended)
- JWT handling (jsonwebtoken crate)
- Database ORM (SQLx or Diesel)
- HTTP client (reqwest)
- Logging (tracing + tracing-subscriber)
- Serialization (serde)
- UUID generation (uuid crate)
- Password hashing (argon2 or bcrypt)

### Environment Variables
- `LARK_APP_ID` - Lark application ID
- `LARK_APP_SECRET` - Lark application secret
- `JWT_SECRET` - JWT signing secret
- `DATABASE_URL` - Database connection string
- `LOG_LEVEL` - Logging level configuration
- `API_KEY_LENGTH` - Generated API key length (default: 64)
- `AUTO_MIGRATE` - Whether to run database migrations on startup (default: true)

### Database Schema (MySQL)
```sql
-- Users table (for JWT authentication)
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- API Keys table (for service authentication)
CREATE TABLE api_keys (
    id VARCHAR(36) PRIMARY KEY,
    key_hash TEXT UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    permissions TEXT NOT NULL,
    created_by VARCHAR(36) NOT NULL,
    created_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Message logs table
CREATE TABLE message_logs (
    id VARCHAR(36) PRIMARY KEY,
    sender_type VARCHAR(50) NOT NULL,
    sender_id VARCHAR(36) NOT NULL,
    recipient VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(50) NOT NULL,
    timestamp DATETIME NOT NULL
);
```

### Deployment

#### Database Migration Best Practices
- **Development Environment**: Set `AUTO_MIGRATE=true` for automatic schema updates
- **Production Environment**: Set `AUTO_MIGRATE=false` and use dedicated migration tools:
  ```bash
  # Option 1: Use sqlx CLI
  sqlx migrate run --database-url $DATABASE_URL
  
  # Option 2: Use init container in Kubernetes
  # Option 3: Use Database::migrate() in deployment script
  ```
- **Container Deployment**: Use init containers or separate migration jobs
- **High Availability**: Run migrations before deploying new application versions

#### General Deployment
- Docker containerization for easy deployment
- Environment-based configuration
- Volume mounting for persistent logs and database
- Health check endpoints for container orchestration

### Security Considerations
- Hash API keys in database (never store plain text)
- Implement rate limiting per authentication type
- Audit logging for all authentication attempts
- Secure JWT token expiration and refresh mechanism
- Input validation and sanitization
- Never log sensitive information (tokens, secrets, message content)
- **Environment File Security**: Always add sensitive configuration files to .gitignore:
  - `.env` - Production environment variables
  - `.env.local` - Local development overrides
  - `.env.test` - Test environment configuration
  - Any files containing real API keys, passwords, or secrets
  - Keep only `.env.example` or `.env.test.example` files in version control as templates