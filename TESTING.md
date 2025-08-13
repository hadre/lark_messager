# 测试指南

本项目包含单元测试和集成测试，所有测试都使用 MySQL 数据库。

## 前置要求

- Rust 和 Cargo
- 可访问的 MySQL 数据库实例
- MySQL 客户端工具（可选，用于调试）

## 环境配置

### 1. 准备测试数据库

确保您有一个可用的 MySQL 数据库用于测试。建议创建一个专门的测试数据库：

```sql
CREATE DATABASE test_lark_messager;
-- 或者使用您现有的测试数据库
```

### 2. 设置环境变量

方式一：直接设置环境变量
```bash
export TEST_DATABASE_URL="mysql://username:password@hostname:port/database_name"
```

方式二：使用环境配置文件
```bash
# 复制示例配置文件
cp .env.test.example .env.test
# 编辑配置文件，设置您的数据库连接信息
# 然后在运行测试前加载配置
source .env.test
```

例如：
```bash
export TEST_DATABASE_URL="mysql://root:password@localhost:3306/test_lark_messager"
```

## 运行测试

### 快速运行测试

使用提供的脚本运行所有测试：

```bash
./scripts/run_tests.sh
```

### 手动运行测试

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

1. 检查环境变量是否正确设置：
   ```bash
   echo $TEST_DATABASE_URL
   ```

2. 手动测试数据库连接：
   ```bash
   mysql -h hostname -P port -u username -ppassword database_name
   ```

3. 确认数据库服务正在运行：
   ```bash
   # 检查 MySQL 服务状态
   mysqladmin -h hostname -P port -u username -ppassword ping
   ```

### 权限问题

1. 确保测试脚本有执行权限：
   ```bash
   chmod +x scripts/run_tests.sh
   ```

2. 确认数据库用户有足够权限：
   - CREATE/DROP 数据库权限
   - CREATE/DROP 表权限
   - INSERT/UPDATE/DELETE 权限

### 数据库迁移问题

如果遇到迁移相关错误，可以手动重置测试数据库：
```sql
DROP DATABASE IF EXISTS test_lark_messager;
CREATE DATABASE test_lark_messager;
```

## 注意事项

1. **数据隔离**: 建议使用专门的测试数据库，避免与开发/生产数据混合
2. **清理策略**: 测试会自动清理创建的数据，但不会删除数据库本身
3. **并发测试**: 测试设计为可以并发运行，但请确保数据库支持并发连接
4. **环境变量**: 必须正确设置 `TEST_DATABASE_URL` 环境变量才能运行测试