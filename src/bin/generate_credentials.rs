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

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use chrono;
use rand::{distributions::Alphanumeric, Rng};
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
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            generate_api_key: false,
            api_key_name: None,
            api_key_length: 64,
        }
    }
}

/// Generate a secure random API key
fn generate_api_key(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Hash a password using Argon2
fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Password hashing failed: {}", e))?;
    Ok(password_hash.to_string())
}

/// Hash an API key using Argon2 (for secure storage)
fn hash_api_key(api_key: &str) -> Result<String, String> {
    hash_password(api_key)
}

/// Escape a string for safe SQL insertion
/// Escapes single quotes and backslashes to prevent SQL injection
fn escape_sql_string(input: &str) -> String {
    input.replace('\\', "\\\\").replace('\'', "''")
}

/// Generate user credentials (username + hashed password)
fn generate_user_credentials(username: &str, password: &str) -> Result<(), String> {
    let user_id = Uuid::new_v4();
    let password_hash = hash_password(password)?;
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");

    println!("=== Generated User Credentials ===");
    println!("User ID: {}", user_id);
    println!("Username: {}", username);
    println!("Password Hash: {}", password_hash);
    println!("Created At: {}", now);
    println!();
    println!("SQL Insert Statement:");
    println!(
        "INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES ('{}', '{}', '{}', '{}', '{}');",
        user_id, escape_sql_string(username), escape_sql_string(&password_hash), now, now
    );
    println!();

    Ok(())
}

/// Generate API key credentials
fn generate_api_key_credentials(name: &str, length: usize) -> Result<(), String> {
    let api_key_id = Uuid::new_v4();
    let api_key = generate_api_key(length);
    let key_hash = hash_api_key(&api_key)?;
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
    // Default permissions for API keys
    let permissions = "send_message,verify_recipient";

    println!("=== Generated API Key ===");
    println!("API Key ID: {}", api_key_id);
    println!("API Key Name: {}", name);
    println!("API Key (SAVE THIS - it won't be shown again): {}", api_key);
    println!("Key Hash: {}", key_hash);
    println!("Permissions: {}", permissions);
    println!("Created At: {}", now);
    println!();
    println!(
        "SQL Insert Statement (you'll need to replace <CREATED_BY_USER_ID> with actual user ID):"
    );
    println!(
        "INSERT INTO api_keys (id, key_hash, name, permissions, created_by, created_at, revoked_at) VALUES ('{}', '{}', '{}', '{}', '<CREATED_BY_USER_ID>', '{}', NULL);",
        api_key_id, escape_sql_string(&key_hash), escape_sql_string(name), escape_sql_string(permissions), now
    );
    println!();
    println!("⚠️  IMPORTANT: Save the API key above securely. It cannot be retrieved later!");

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
    println!("    -u, --user <USERNAME>       Generate user credentials with this username");
    println!("    -p, --password <PASSWORD>   Password for the user");
    println!("        --api-key               Generate an API key instead of user credentials");
    println!("    -n, --name <NAME>           Name/description for the API key");
    println!("    -l, --length <LENGTH>       Length of API key (default: 64, minimum: 32)");
    println!("    -h, --help                  Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate admin user credentials");
    println!("    cargo run --bin generate_credentials -- --user admin --password mypassword");
    println!();
    println!("    # Generate API key for monitoring service");
    println!("    cargo run --bin generate_credentials -- --api-key --name \"monitoring-service\"");
    println!();
    println!("    # Generate longer API key");
    println!("    cargo run --bin generate_credentials -- --api-key --name \"batch-processor\" --length 128");
}

/// Validate configuration
fn validate_config(config: &CredentialConfig) -> Result<(), String> {
    if config.generate_api_key {
        if config.api_key_name.is_none() {
            return Err("API key generation requires --name parameter".to_string());
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

fn main() -> Result<(), String> {
    let config = parse_args();

    // Validate configuration
    if let Err(err) = validate_config(&config) {
        eprintln!("Error: {}", err);
        println!();
        print_help();
        std::process::exit(1);
    }

    // Generate credentials based on configuration
    if config.generate_api_key {
        let name = config.api_key_name.as_ref().unwrap();
        generate_api_key_credentials(name, config.api_key_length)?;
    } else {
        let username = config.username.as_ref().unwrap();
        let password = config.password.as_ref().unwrap();
        generate_user_credentials(username, password)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key() {
        let key1 = generate_api_key(64);
        let key2 = generate_api_key(64);

        assert_eq!(key1.len(), 64);
        assert_eq!(key2.len(), 64);
        assert_ne!(key1, key2); // Should be different

        // Should only contain alphanumeric characters
        assert!(key1.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_hash_password() {
        use argon2::{PasswordHash, PasswordVerifier};

        let password = "test_password_123";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Hashes should be different due to salt
        assert_ne!(hash1, hash2);

        // Both should verify against original password
        let argon2 = Argon2::default();
        let parsed_hash1 = PasswordHash::new(&hash1).unwrap();
        let parsed_hash2 = PasswordHash::new(&hash2).unwrap();

        assert!(argon2
            .verify_password(password.as_bytes(), &parsed_hash1)
            .is_ok());
        assert!(argon2
            .verify_password(password.as_bytes(), &parsed_hash2)
            .is_ok());
    }

    #[test]
    fn test_hash_api_key() {
        use argon2::{PasswordHash, PasswordVerifier};

        let api_key = "test_api_key_abc123";
        let hash = hash_api_key(api_key).unwrap();

        // Should be a valid Argon2 hash
        let parsed_hash = PasswordHash::new(&hash).unwrap();
        let argon2 = Argon2::default();
        assert!(argon2
            .verify_password(api_key.as_bytes(), &parsed_hash)
            .is_ok());
    }

    #[test]
    fn test_escape_sql_string() {
        // Test single quote escaping
        assert_eq!(escape_sql_string("test'value"), "test''value");
        
        // Test backslash escaping
        assert_eq!(escape_sql_string("test\\value"), "test\\\\value");
        
        // Test both combined
        assert_eq!(escape_sql_string("test'value\\path"), "test''value\\\\path");
        
        // Test normal string without special characters
        assert_eq!(escape_sql_string("normal_string"), "normal_string");
        
        // Test Argon2 hash-like string with $ characters (no escaping needed for $)
        let argon2_like = "$argon2id$v=19$m=4096,t=3,p=1$salt$hash";
        assert_eq!(escape_sql_string(argon2_like), argon2_like);
        
        // Test complex case with multiple types of quotes and backslashes
        assert_eq!(
            escape_sql_string("It's a 'test' with\\back\\slashes"),
            "It''s a ''test'' with\\\\back\\\\slashes"
        );
    }
}
