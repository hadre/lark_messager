/*!
 * 配置管理模块
 * 
 * 负责从环境变量加载应用程序配置，包括数据库连接、认证密钥、
 * 飞书 API 凭据等。支持通过 .env 文件和系统环境变量进行配置。
 */

use crate::error::{AppError, AppResult};
use std::env;

/// 应用程序配置结构体
/// 
/// 包含运行应用程序所需的所有配置参数
#[derive(Clone, Debug)]
pub struct Config {
    /// MySQL 数据库连接 URL
    /// 格式：mysql://username:password@host:port/database
    pub database_url: String,
    
    /// JWT 签名密钥
    /// 用于生成和验证 JWT token，必须是强密钥
    pub jwt_secret: String,
    
    /// 飞书应用 ID
    /// 从飞书开放平台获取的应用标识符
    pub lark_app_id: String,
    
    /// 飞书应用密钥
    /// 从飞书开放平台获取的应用密钥
    pub lark_app_secret: String,
    
    /// HTTP 服务器绑定地址
    /// 默认为 0.0.0.0 监听所有网络接口
    pub server_host: String,
    
    /// HTTP 服务器端口
    /// 默认为 8080
    pub server_port: u16,
    
    /// 日志级别
    /// 支持：trace, debug, info, warn, error
    pub log_level: String,
    
    /// 生成的 API Key 长度
    /// 用于控制自动生成的 API Key 的字符数
    pub api_key_length: usize,
    
    /// 是否在启动时自动执行数据库迁移
    /// 默认为 true（开发环境友好），生产环境建议设为 false
    pub auto_migrate: bool,
}

impl Config {
    /// 从环境变量加载配置
    /// 
    /// 首先尝试加载 .env 文件，然后从环境变量读取配置。
    /// 某些配置项（如 JWT_SECRET）是必需的，缺失会返回错误。
    /// 其他配置项有合理的默认值。
    /// 
    /// # 必需的环境变量
    /// - `JWT_SECRET`: JWT 签名密钥
    /// - `LARK_APP_ID`: 飞书应用 ID
    /// - `LARK_APP_SECRET`: 飞书应用密钥
    /// 
    /// # 可选的环境变量（有默认值）
    /// - `DATABASE_URL`: 数据库连接 URL
    /// - `SERVER_HOST`: 服务器地址
    /// - `SERVER_PORT`: 服务器端口
    /// - `LOG_LEVEL`: 日志级别
    /// - `API_KEY_LENGTH`: API Key 长度
    /// - `AUTO_MIGRATE`: 是否自动执行数据库迁移
    /// 
    /// # 错误
    /// 如果必需的环境变量缺失或格式错误，将返回 `AppError::Config`
    pub fn from_env() -> AppResult<Self> {
        // 尝试加载 .env 文件（忽略失败）
        dotenvy::dotenv().ok();

        Ok(Config {
            // 数据库配置
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "mysql://root:password@localhost:3306/lark_messager".to_string()),
            
            // 认证配置（必需）
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| AppError::Config("JWT_SECRET is required".to_string()))?,
            
            // 飞书 API 配置（必需）
            lark_app_id: env::var("LARK_APP_ID")
                .map_err(|_| AppError::Config("LARK_APP_ID is required".to_string()))?,
            lark_app_secret: env::var("LARK_APP_SECRET")
                .map_err(|_| AppError::Config("LARK_APP_SECRET is required".to_string()))?,
            
            // 服务器配置
            server_host: env::var("SERVER_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .map_err(|_| AppError::Config("Invalid SERVER_PORT".to_string()))?,
            
            // 日志配置
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            
            // API Key 配置
            api_key_length: env::var("API_KEY_LENGTH")
                .unwrap_or_else(|_| "64".to_string())
                .parse()
                .map_err(|_| AppError::Config("Invalid API_KEY_LENGTH".to_string()))?,
            
            // 数据库迁移配置
            auto_migrate: env::var("AUTO_MIGRATE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| AppError::Config("Invalid AUTO_MIGRATE (expected true/false)".to_string()))?,
        })
    }
}