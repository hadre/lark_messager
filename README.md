# Lark Messager

A Rust-based Lark (Feishu) messaging bot API service that provides secure message sending capabilities with dual authentication support.

## Features

- **Dual Authentication**: JWT for users + API Key for services
- **Lark Integration**: Send messages to users and groups via Lark Bot API
- **Message Validation**: Verify recipient existence before sending
- **Comprehensive Logging**: Request logging, error tracking, and debug information
- **Docker Support**: Containerized deployment with Docker Compose
- **Database Support**: SQLite with automatic migrations
- **Rate Limiting Ready**: Architecture supports rate limiting implementation

## Quick Start

### Prerequisites

- Rust 1.75+ 
- Lark App credentials (App ID and App Secret)
- MySQL 8.0+ database

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd lark_messager
```

2. Copy environment configuration:
```bash
cp .env.example .env
```

3. Update `.env` with your Lark App credentials:
```env
LARK_APP_ID=your-lark-app-id
LARK_APP_SECRET=your-lark-app-secret
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
```

4. Build and run:
```bash
cargo build
cargo run
```

The server will start on `http://localhost:8080`.

### Docker Deployment

1. Build and start with Docker Compose:
```bash
docker-compose up -d
```

2. Check service health:
```bash
curl http://localhost:8080/health
```

## API Documentation

### Authentication

#### User Authentication (JWT)
```bash
# Login to get JWT token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "password"}'

# Use JWT token in subsequent requests
curl -H "Authorization: Bearer <jwt_token>" \
  http://localhost:8080/messages/send
```

#### Service Authentication (API Key)
```bash
# Use API key in requests
curl -H "X-API-Key: <api_key>" \
  http://localhost:8080/messages/send
```

### Endpoints

#### Health Check
```bash
GET /health
```

#### Authentication
```bash
POST /auth/login                    # User login
POST /auth/api-keys                 # Create API key (admin only)
DELETE /auth/api-keys/{id}          # Revoke API key (admin only)
```

#### Messages
```bash
POST /messages/send                 # Send message to user
POST /messages/send-group           # Send message to group
POST /recipients/verify             # Verify recipient exists
```

### Example Usage

#### Send Message to User
```bash
curl -X POST http://localhost:8080/messages/send \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "user@example.com",
    "message": "Hello from Lark Messager!",
    "recipient_type": "email"
  }'
```

#### Send Message to Group
```bash
# Using chat_id
curl -X POST http://localhost:8080/messages/send-group \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "oc_xxxxxxxxxx",
    "message": "Hello everyone!",
    "recipient_type": "chat_id"
  }'

# Using chat name
curl -X POST http://localhost:8080/messages/send-group \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "技术讨论群",
    "message": "Hello everyone!",
    "recipient_type": "chat_name"
  }'
```

#### Verify Recipient
```bash
curl -X POST http://localhost:8080/recipients/verify \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "user@example.com",
    "recipient_type": "email"
  }'
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | MySQL database connection URL | `mysql://root:password@localhost:3306/lark_messager` | No |
| `JWT_SECRET` | JWT signing secret | - | Yes |
| `LARK_APP_ID` | Lark application ID | - | Yes |
| `LARK_APP_SECRET` | Lark application secret | - | Yes |
| `SERVER_HOST` | Server bind address | `127.0.0.1` | No |
| `SERVER_PORT` | Server port | `8080` | No |
| `LOG_LEVEL` | Logging level | `info` | No |
| `API_KEY_LENGTH` | Generated API key length | `64` | No |

### Recipient Types

The service supports multiple recipient identification methods:

#### For Individual Messages (`/messages/send`)
- `user_id`: Lark user open_id (obtained from email/mobile lookup)
- `email`: Email address (automatically converted to open_id)
- `mobile`: Phone number (automatically converted to open_id)
- `auto`: Auto-detect based on format (default)

#### For Group Messages (`/messages/send-group`)
- `chat_id`: Group chat ID (oc_xxx, ou_xxx)
- `chat_name`: Group chat name (automatically converted to chat_id)
- `auto`: Auto-detect based on format (default)

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_login_success

# Run with output
cargo test -- --nocapture
```

### Database Setup

1. Create a MySQL database:
```sql
CREATE DATABASE lark_messager;
CREATE USER 'lark_user'@'%' IDENTIFIED BY 'lark_password';
GRANT ALL PRIVILEGES ON lark_messager.* TO 'lark_user'@'%';
FLUSH PRIVILEGES;
```

2. Database migrations are automatically applied on startup. Migration files are located in the `migrations/` directory.

### Adding New Features

1. Update models in `src/models.rs`
2. Add database operations in `src/database.rs`
3. Implement handlers in `src/handlers.rs`
4. Add routes in `src/routes.rs`
5. Write tests in `tests/`

## Architecture

### Core Components

- **Web Server**: Axum-based HTTP server
- **Authentication**: JWT + API Key dual authentication
- **Database**: MySQL with SQLx ORM
- **Lark Client**: HTTP client for Lark Bot API
- **Logging**: Structured logging with tracing

### Security Features

- Password hashing with Argon2
- API key hashing in database
- JWT token expiration
- Input validation and sanitization
- Request logging and audit trails
- CORS support

## Troubleshooting

### Common Issues

1. **"JWT_SECRET is required"**
   - Ensure JWT_SECRET is set in environment or .env file

2. **"Invalid Lark credentials"**
   - Verify LARK_APP_ID and LARK_APP_SECRET are correct
   - Check Lark app permissions

3. **Database migration errors**
   - Ensure write permissions to database directory
   - Check SQLite installation

4. **Port already in use**
   - Change SERVER_PORT in environment
   - Kill existing process: `pkill lark_messager`

### Logs

- Application logs: `lark_messager.log`
- Docker logs: `docker-compose logs -f`

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run tests: `cargo test`
5. Submit pull request

## License

This project is licensed under the MIT License.