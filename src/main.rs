/*!
 * Lark Messager - 飞书消息机器人 API 服务
 * 
 * 这是应用程序的主入口点，负责：
 * - 加载环境配置
 * - 初始化服务器
 * - 启动 HTTP 服务
 * 
 * 服务提供双重认证机制：
 * - JWT 认证（用于用户）
 * - API Key 认证（用于服务间调用）
 */

use lark_messager::{config::Config, server::Server, AppResult};

/// 应用程序主入口点
/// 
/// 执行以下步骤：
/// 1. 从环境变量加载配置
/// 2. 创建服务器实例
/// 3. 启动异步服务器运行
/// 
/// # 错误处理
/// 如果配置加载或服务器启动失败，将返回相应的错误
#[tokio::main]
async fn main() -> AppResult<()> {
    // 从环境变量加载配置，如果失败则返回错误
    let config = Config::from_env()?;
    
    // 使用配置创建服务器实例
    let server = Server::new(config);
    
    // 启动服务器并运行直到收到停止信号
    server.run().await
}
