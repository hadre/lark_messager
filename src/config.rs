use crate::error::{AppError, AppResult};
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub lark_app_id: String,
    pub lark_app_secret: String,
    pub server_host: String,
    pub server_port: u16,
    pub log_level: String,
    pub api_key_length: usize,
}

impl Config {
    pub fn from_env() -> AppResult<Self> {
        dotenvy::dotenv().ok();

        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "mysql://root:password@localhost:3306/lark_messager".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| AppError::Config("JWT_SECRET is required".to_string()))?,
            lark_app_id: env::var("LARK_APP_ID")
                .map_err(|_| AppError::Config("LARK_APP_ID is required".to_string()))?,
            lark_app_secret: env::var("LARK_APP_SECRET")
                .map_err(|_| AppError::Config("LARK_APP_SECRET is required".to_string()))?,
            server_host: env::var("SERVER_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .map_err(|_| AppError::Config("Invalid SERVER_PORT".to_string()))?,
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            api_key_length: env::var("API_KEY_LENGTH")
                .unwrap_or_else(|_| "64".to_string())
                .parse()
                .map_err(|_| AppError::Config("Invalid API_KEY_LENGTH".to_string()))?,
        })
    }
}