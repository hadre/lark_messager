/*!
 * 日志系统配置模块
 * 
 * 配置结构化日志记录，支持同时输出到控制台和文件。
 * 使用 tracing 框架提供高性能的异步日志记录能力。
 * 
 * # 日志配置特性
 * - 双重输出：控制台（带颜色）+ 文件（无颜色）
 * - 结构化日志：包含时间戳、级别、目标模块、线程 ID
 * - 可配置级别：支持环境变量和参数控制日志级别
 * - 文件轮转：追加写入到 lark_messager.log 文件
 */

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};
use std::fs::OpenOptions;
use std::io;
use tracing_subscriber::fmt;

/// 初始化日志系统
/// 
/// 配置双重日志输出：
/// 1. 控制台输出：带 ANSI 颜色，适合开发和调试
/// 2. 文件输出：纯文本格式，适合生产环境日志分析
/// 
/// # 参数
/// - `log_level`: 日志级别字符串，支持 "trace", "debug", "info", "warn", "error"
/// 
/// # 日志格式
/// 每条日志包含以下信息：
/// - 时间戳：ISO 8601 格式
/// - 日志级别：ERROR, WARN, INFO, DEBUG, TRACE
/// - 目标模块：代码模块路径
/// - 线程 ID：用于多线程调试
/// - 日志内容：实际的日志消息
/// 
/// # 环境变量
/// 可以通过 `RUST_LOG` 环境变量覆盖默认日志级别：
/// ```bash
/// RUST_LOG=debug cargo run
/// ```
/// 
/// # 错误处理
/// 如果日志文件创建失败，将返回错误。在生产环境中应该确保：
/// - 应用有创建日志文件的权限
/// - 磁盘空间充足
/// - 日志目录存在
/// 
/// # 使用示例
/// ```rust
/// use tracing::{info, warn, error};
/// 
/// // 在应用启动时初始化
/// logging::init_logging("info")?;
/// 
/// // 在代码中使用
/// info!("Server started on port 8080");
/// warn!("Rate limit exceeded for user: {}", user_id);
/// error!("Failed to connect to database: {}", error);
/// ```
pub fn init_logging(log_level: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 创建或打开日志文件，追加模式写入
    let log_file = OpenOptions::new()
        .create(true)        // 如果文件不存在则创建
        .write(true)         // 允许写入
        .append(true)        // 追加模式，不覆盖已有内容
        .open("lark_messager.log")?;

    // 配置日志级别过滤器
    // 优先使用环境变量 RUST_LOG，如果没有则使用传入的参数
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    // 配置控制台输出层
    // 包含 ANSI 颜色代码，适合终端显示
    let stdout_layer = fmt::layer()
        .with_target(true)      // 显示日志来源模块
        .with_thread_ids(true)  // 显示线程 ID
        .with_level(true)       // 显示日志级别
        .with_ansi(true)        // 启用 ANSI 颜色
        .with_writer(io::stdout);

    // 配置文件输出层
    // 纯文本格式，适合日志分析工具处理
    let file_layer = fmt::layer()
        .with_target(true)      // 显示日志来源模块
        .with_thread_ids(true)  // 显示线程 ID
        .with_level(true)       // 显示日志级别
        .with_ansi(false)       // 禁用 ANSI 颜色（文件输出）
        .with_writer(log_file);

    // 初始化全局日志订阅器
    // 组合过滤器和两个输出层
    Registry::default()
        .with(env_filter)      // 应用日志级别过滤
        .with(stdout_layer)    // 添加控制台输出
        .with(file_layer)      // 添加文件输出
        .init();               // 设置为全局默认

    Ok(())
}