/*!
 * HTTP 服务器模块
 *
 * 负责启动和运行 HTTP 服务器，协调所有组件的初始化：
 * - 日志系统初始化
 * - 数据库连接和迁移
 * - 认证服务配置
 * - 飞书客户端初始化
 * - 路由和中间件配置
 * - HTTP 服务器启动
 */

use crate::auth::AuthService;
use crate::config::Config;
use crate::database::Database;
use crate::error::AppResult;
use crate::handlers::AppState;
use crate::lark::LarkClient;
use crate::logging;
use crate::routes::create_router;
use axum::serve;
use tokio::net::TcpListener;
use tracing::info;

/// HTTP 服务器结构体
///
/// 封装服务器配置和启动逻辑
pub struct Server {
    /// 应用配置
    config: Config,
}

impl Server {
    /// 创建新的服务器实例
    ///
    /// # 参数
    /// - `config`: 应用程序配置，包含数据库、认证、服务器等设置
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// 启动并运行服务器
    ///
    /// 执行完整的服务器启动流程：
    /// 1. 初始化日志系统
    /// 2. 连接数据库并执行迁移
    /// 3. 初始化认证服务
    /// 4. 初始化飞书客户端
    /// 5. 创建应用状态和路由
    /// 6. 绑定地址并启动 HTTP 服务器
    ///
    /// # 启动流程说明
    ///
    /// ## 1. 日志系统初始化
    /// 配置双重日志输出（控制台 + 文件），设置日志级别
    ///
    /// ## 2. 数据库初始化
    /// - 连接 MySQL 数据库
    /// - 自动执行数据库迁移
    /// - 创建必需的表和索引
    ///
    /// ## 3. 服务组件初始化
    /// - 认证服务：配置 JWT 和 API Key 认证
    /// - 飞书客户端：配置 API 凭据
    ///
    /// ## 4. HTTP 服务器启动
    /// - 绑定指定的主机和端口
    /// - 配置路由和中间件
    /// - 开始监听 HTTP 请求
    ///
    /// # 错误处理
    /// 启动过程中的任何错误都会导致服务器停止启动：
    /// - 日志系统初始化失败
    /// - 数据库连接失败
    /// - 端口绑定失败
    /// - 配置错误
    ///
    /// # 生产环境注意事项
    /// - 确保数据库服务可用
    /// - 验证飞书 API 凭据有效
    /// - 确保端口未被占用
    /// - 检查文件系统权限（日志文件写入）
    pub async fn run(&self) -> AppResult<()> {
        // 第一步：初始化日志系统
        // 必须首先配置日志，以便后续步骤的日志能够正确输出
        logging::init_logging(&self.config.log_level).map_err(|e| {
            crate::error::AppError::Config(format!("Failed to initialize logging: {}", e))
        })?;

        // 输出启动信息
        info!(
            "Starting Lark Messager Server v{}",
            env!("CARGO_PKG_VERSION")
        );
        info!("Log level: {}", self.config.log_level);

        // 第二步：初始化数据库连接
        // 连接数据库并执行迁移脚本
        info!(
            "Connecting to database: {}",
            // 隐藏密码信息，仅显示主机和数据库名
            self.config.database_url.split('@').last().unwrap_or("***")
        );
        let db = Database::new(&self.config.database_url, self.config.timezone_offset()).await?;
        info!("Database connection established");

        // 根据配置决定是否执行数据库迁移
        if self.config.auto_migrate {
            info!("Running database migrations (AUTO_MIGRATE=true)...");
            db.migrate().await?;
            info!("Database migrations completed successfully");
        } else {
            info!("Skipping database migrations (AUTO_MIGRATE=false)");
            info!("Note: Please ensure database schema is up-to-date before starting");
        }

        // 第三步：初始化认证服务
        // 配置 JWT 和 API Key 双重认证机制
        let auth = AuthService::new(self.config.jwt_secret.clone(), db.clone()).await?;
        info!("Authentication service initialized");

        // 第四步：初始化飞书客户端
        // 配置飞书 API 访问凭据
        let lark = LarkClient::new(
            self.config.lark_app_id.clone(),
            self.config.lark_app_secret.clone(),
        );
        info!("Lark client initialized");

        // 第五步：创建应用状态
        // 将所有服务组件组合到共享状态中
        let state = AppState { db, auth, lark };

        // 第六步：创建路由器
        // 配置所有 API 端点和中间件
        let app = create_router(state);

        // 第七步：绑定网络地址
        // 使用配置中的主机地址和端口
        let addr = format!("{}:{}", self.config.server_host, self.config.server_port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            crate::error::AppError::Config(format!("Failed to bind to address {}: {}", addr, e))
        })?;

        // 输出服务器启动信息和 API 文档
        info!("Server listening on http://{}", addr);
        info!("API Documentation:");
        info!("  POST /auth/login - User authentication");
        info!("  POST /auth/api-keys - Create API key (admin only)");
        info!("  DELETE /auth/api-keys/{{id}} - Revoke API key (admin only)");
        info!("  POST /messages/send - Send message to user");
        info!("  POST /messages/send-group - Send message to group");
        info!("  POST /recipients/verify - Verify recipient exists");
        info!("  GET /auth/configs - View auth configuration (admin)");
        info!("  PATCH /auth/configs - Update auth configuration (admin)");
        info!("  GET /health - Health check");

        // 第八步：启动 HTTP 服务器
        // 开始监听和处理客户端请求
        serve(listener, app)
            .await
            .map_err(|e| crate::error::AppError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }
}
