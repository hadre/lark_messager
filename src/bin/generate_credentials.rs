#!/usr/bin/env cargo

//! Standalone utility for generating user credentials and API keys
//!
//! This utility helps initialize the system by generating:
//! - Admin user with hashed password
//! - API keys for service-to-service authentication
//!
//! Usage:
//!   cargo run --bin generate_credentials -- --user admin --password mypassword
//!   cargo run --bin generate_credentials -- --api-key --name "monitoring-service"

use lark_messager::auth::AuthService;
use lark_messager::config::Config;
use lark_messager::database::Database;
use std::env;
use uuid::Uuid;

/// Configuration for credential generation
#[derive(Debug)]
struct CredentialConfig {
    /// Username for new user
    username: Option<String>,
    /// Password for new user
    password: Option<String>,
    /// Generate API key instead of user
    generate_api_key: bool,
    /// Name/description for the API key
    api_key_name: Option<String>,
    /// Length of generated API key (default: 64)
    api_key_length: usize,
    /// Created by user ID (for API keys)
    created_by_user_id: Option<String>,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            generate_api_key: false,
            api_key_name: None,
            api_key_length: 64,
            created_by_user_id: None,
        }
    }
}

/// Generate user credentials and save to database
async fn generate_user_credentials(
    config: &CredentialConfig,
    auth_service: &AuthService,
    database: &Database,
) -> Result<(), String> {
    let username = config.username.as_ref().unwrap();
    let password = config.password.as_ref().unwrap();

    // Hash password using the project's auth service
    let password_hash = auth_service
        .hash_password(password)
        .map_err(|e| format!("Failed to hash password: {}", e))?;

    // Create user in database
    let user = database
        .create_user(username, &password_hash)
        .await
        .map_err(|e| format!("Failed to create user: {}", e))?;

    println!("=== Generated User Credentials ===");
    println!("User ID: {}", user.id);
    println!("Username: {}", user.username);
    println!("Password Hash: {}", user.password_hash);
    println!("Created At: {}", user.created_at);
    println!();
    println!("✅ User successfully created in database!");
    println!();
    println!("You can now use these credentials to:");
    println!("1. Login via POST /auth/login with username and password");
    println!("2. Use this user ID to create API keys");

    Ok(())
}

/// Generate API key credentials and save to database
async fn generate_api_key_credentials(
    config: &CredentialConfig,
    auth_service: &AuthService,
    database: &Database,
) -> Result<(), String> {
    let name = config.api_key_name.as_ref().unwrap();

    // Parse created_by user ID
    let created_by = if let Some(user_id_str) = &config.created_by_user_id {
        Uuid::parse_str(user_id_str).map_err(|_| {
            "Invalid user ID format. Use UUID format like: 12345678-1234-1234-1234-123456789012"
                .to_string()
        })?
    } else {
        return Err("API key creation requires --created-by parameter with user ID".to_string());
    };

    // Generate API key using the project's auth service
    let api_key = auth_service.generate_api_key(config.api_key_length);

    // Hash API key using the project's auth service
    let key_hash = auth_service
        .hash_api_key(&api_key)
        .map_err(|e| format!("Failed to hash API key: {}", e))?;

    // Default permissions for API keys
    let permissions = "send_message,verify_recipient";

    // Create API key in database
    let api_key_record = database
        .create_api_key(&key_hash, name, permissions, &created_by)
        .await
        .map_err(|e| format!("Failed to create API key: {}", e))?;

    println!("=== Generated API Key ===");
    println!("API Key ID: {}", api_key_record.id);
    println!("API Key Name: {}", api_key_record.name);
    println!("API Key (SAVE THIS - it won't be shown again): {}", api_key);
    println!("Key Hash: {}", api_key_record.key_hash);
    println!("Permissions: {}", api_key_record.permissions);
    println!("Created By: {}", api_key_record.created_by);
    println!("Created At: {}", api_key_record.created_at);
    println!();
    println!("✅ API key successfully created in database!");
    println!();
    println!("⚠️  IMPORTANT: Save the API key above securely. It cannot be retrieved later!");
    println!();
    println!("You can now use this API key to:");
    println!("1. Authenticate requests with X-API-Key header");
    println!("2. Send messages via POST /messages/send");
    println!("3. Verify recipients via GET /recipients/verify");

    Ok(())
}

/// Parse command line arguments
fn parse_args() -> CredentialConfig {
    let args: Vec<String> = env::args().collect();
    let mut config = CredentialConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--user" | "-u" => {
                if i + 1 < args.len() {
                    config.username = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --user requires a username");
                    std::process::exit(1);
                }
            }
            "--password" | "-p" => {
                if i + 1 < args.len() {
                    config.password = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --password requires a password");
                    std::process::exit(1);
                }
            }
            "--api-key" => {
                config.generate_api_key = true;
                i += 1;
            }
            "--name" | "-n" => {
                if i + 1 < args.len() {
                    config.api_key_name = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --name requires a name");
                    std::process::exit(1);
                }
            }
            "--created-by" => {
                if i + 1 < args.len() {
                    config.created_by_user_id = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --created-by requires a user ID");
                    std::process::exit(1);
                }
            }
            "--length" | "-l" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<usize>() {
                        Ok(length) if length >= 32 => {
                            config.api_key_length = length;
                            i += 2;
                        }
                        _ => {
                            eprintln!("Error: --length must be a number >= 32");
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("Error: --length requires a number");
                    std::process::exit(1);
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Error: Unknown argument '{}'", args[i]);
                print_help();
                std::process::exit(1);
            }
        }
    }

    config
}

/// Print help message
fn print_help() {
    println!("Lark Messager Credential Generator");
    println!();
    println!("USAGE:");
    println!("    cargo run --bin generate_credentials [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -u, --user <USERNAME>         Generate user credentials with this username");
    println!("    -p, --password <PASSWORD>     Password for the user");
    println!("        --api-key                 Generate an API key instead of user credentials");
    println!("    -n, --name <NAME>             Name/description for the API key");
    println!(
        "        --created-by <USER_ID>    User ID who creates the API key (required for API keys)"
    );
    println!("    -l, --length <LENGTH>         Length of API key (default: 64, minimum: 32)");
    println!("    -h, --help                    Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate admin user credentials");
    println!("    cargo run --bin generate_credentials -- --user admin --password mypassword");
    println!();
    println!("    # Generate API key for monitoring service (requires existing user ID)");
    println!("    cargo run --bin generate_credentials -- --api-key --name \"monitoring-service\" --created-by \"12345678-1234-1234-1234-123456789012\"");
    println!();
    println!("    # Generate longer API key");
    println!("    cargo run --bin generate_credentials -- --api-key --name \"batch-processor\" --created-by \"12345678-1234-1234-1234-123456789012\" --length 128");
    println!();
    println!("ENVIRONMENT VARIABLES:");
    println!("    DATABASE_URL    MySQL connection string (required)");
    println!("    JWT_SECRET      JWT signing secret (required)");
    println!();
    println!("NOTE: This tool connects to the database and creates records directly.");
    println!(
        "      Make sure your .env file is properly configured with DATABASE_URL and JWT_SECRET."
    );
}

/// Validate configuration
fn validate_config(config: &CredentialConfig) -> Result<(), String> {
    if config.generate_api_key {
        if config.api_key_name.is_none() {
            return Err("API key generation requires --name parameter".to_string());
        }
        if config.created_by_user_id.is_none() {
            return Err(
                "API key generation requires --created-by parameter with user ID".to_string(),
            );
        }
    } else {
        if config.username.is_none() || config.password.is_none() {
            return Err(
                "User generation requires both --user and --password parameters".to_string(),
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    // Load environment variables
    dotenvy::dotenv().ok();

    let config = parse_args();

    // Validate configuration
    if let Err(err) = validate_config(&config) {
        eprintln!("Error: {}", err);
        println!();
        print_help();
        std::process::exit(1);
    }

    // Load application configuration
    let app_config =
        Config::from_env().map_err(|e| format!("Failed to load configuration: {}", e))?;

    // Initialize database connection
    let database = Database::new_with_migrations(&app_config.database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;

    // Initialize auth service
    let auth_service = AuthService::new(app_config.jwt_secret.clone(), database.clone());

    // Generate credentials based on configuration
    if config.generate_api_key {
        generate_api_key_credentials(&config, &auth_service, &database).await?;
    } else {
        generate_user_credentials(&config, &auth_service, &database).await?;
    }

    Ok(())
}
