/*!
 * Lark Messager 库模块
 *
 * 这个库提供了一个完整的飞书消息机器人 API 服务，包含以下核心功能：
 * - 双重认证系统（JWT + API Key）
 * - 飞书 API 集成
 * - MySQL 数据库支持
 * - RESTful API 端点
 * - 结构化日志记录
 * - Docker 部署支持
 *
 * # 模块组织
 *
 * - `auth`: 认证和授权系统
 * - `config`: 配置管理
 * - `database`: 数据库操作和模型
 * - `error`: 错误类型定义
 * - `handlers`: HTTP 请求处理器
 * - `lark`: 飞书 API 客户端
 * - `logging`: 日志系统配置
 * - `models`: 数据模型定义
 * - `routes`: 路由配置
 * - `server`: HTTP 服务器实现
 */

/// 认证和授权模块
/// 提供 JWT 和 API Key 双重认证机制
pub mod auth;

/// 配置管理模块
/// 从环境变量加载应用配置
pub mod config;

/// 数据库操作模块
/// 提供 MySQL 数据库的 CRUD 操作
pub mod database;

/// 错误处理模块
/// 定义应用程序的错误类型和处理机制
pub mod error;

/// HTTP 请求处理器模块
/// 实现各个 API 端点的业务逻辑
pub mod handlers;

/// 飞书 API 客户端模块
/// 封装与飞书开放平台的交互
pub mod lark;

/// 日志系统模块
/// 配置结构化日志输出
pub mod logging;

/// 数据模型模块
/// 定义数据库表对应的结构体和请求/响应模型
pub mod models;

/// 路由配置模块
/// 定义 HTTP 路由和中间件
pub mod routes;

/// HTTP 服务器模块
/// 实现服务器的启动和运行逻辑
pub mod server;

// 导出常用的错误类型供外部使用
pub use error::{AppError, AppResult};
