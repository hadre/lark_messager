# 测试指南

本项目包含单元测试和集成测试，所有测试都使用 MySQL 数据库。

## 前置要求

- Docker 和 Docker Compose
- Rust 和 Cargo
- MySQL 客户端工具（可选，用于调试）

## 快速运行测试

使用提供的脚本自动启动测试数据库并运行所有测试：

```bash
./scripts/run_tests.sh
```

这个脚本会：
1. 启动测试用的 MySQL 容器（端口 3307）
2. 等待数据库就绪
3. 运行所有测试
4. 清理测试环境

## 手动运行测试

### 1. 启动测试数据库

```bash
docker-compose -f docker-compose.test.yml up -d test-mysql
```

### 2. 等待数据库就绪

```bash
# 检查数据库是否就绪
docker exec $(docker-compose -f docker-compose.test.yml ps -q test-mysql) mysqladmin ping -h "localhost"
```

### 3. 设置环境变量

```bash
export TEST_DATABASE_URL="mysql://root:password@localhost:3307/test_lark_messager"
```

### 4. 运行测试

```bash
# 运行所有测试
cargo test

# 只运行单元测试
cargo test --test unit_tests

# 只运行集成测试
cargo test --test integration_tests

# 运行特定测试
cargo test test_database_user_operations
```

### 5. 清理环境

```bash
docker-compose -f docker-compose.test.yml down
```

## 测试数据库配置

测试数据库配置：
- **主机**: localhost
- **端口**: 3307 (避免与开发数据库冲突)
- **数据库名**: test_lark_messager
- **用户名**: root
- **密码**: password

## 测试类型

### 单元测试 (`tests/unit_tests.rs`)

测试各个模块的功能：
- 数据库操作（用户、API Key、消息日志）
- 认证服务（密码哈希、JWT、API Key 验证）
- 错误处理
- Lark 客户端基础功能

### 集成测试 (`tests/integration_tests.rs`)

测试完整的 HTTP API：
- 健康检查端点
- 用户登录 API
- 消息发送 API
- API Key 管理
- 认证中间件
- CORS 处理

## 故障排除

### 数据库连接失败

1. 确认 Docker 容器正在运行：
   ```bash
   docker ps | grep test-mysql
   ```

2. 检查数据库日志：
   ```bash
   docker-compose -f docker-compose.test.yml logs test-mysql
   ```

3. 手动测试数据库连接：
   ```bash
   mysql -h 127.0.0.1 -P 3307 -u root -ppassword test_lark_messager
   ```

### 端口冲突

如果端口 3307 被占用，可以修改 `docker-compose.test.yml` 中的端口映射。

### 权限问题

确保测试脚本有执行权限：
```bash
chmod +x scripts/run_tests.sh
```

## 注意事项

1. **数据隔离**: 每个测试都使用独立的测试数据库，避免测试间相互影响
2. **清理策略**: 测试运行后会自动清理数据库状态
3. **并发测试**: 测试设计为可以并发运行，但共享同一个测试数据库实例
4. **环境变量**: 可以通过 `TEST_DATABASE_URL` 环境变量自定义数据库连接