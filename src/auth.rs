use crate::database::Database;
use crate::error::{AppError, AppResult};
use crate::models::User;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (user id)
    pub username: String,
    pub exp: usize, // Expiration time
    pub iat: usize, // Issued at
}

#[derive(Debug)]
pub enum AuthenticatedUser {
    User { id: Uuid, username: String },
    Service { id: Uuid, name: String, permissions: Vec<String> },
}

impl AuthenticatedUser {
    pub fn id(&self) -> Uuid {
        match self {
            AuthenticatedUser::User { id, .. } => *id,
            AuthenticatedUser::Service { id, .. } => *id,
        }
    }

    pub fn is_admin(&self) -> bool {
        match self {
            AuthenticatedUser::User { .. } => false,
            AuthenticatedUser::Service { permissions, .. } => {
                permissions.contains(&"admin".to_string())
            }
        }
    }

    pub fn can_send_messages(&self) -> bool {
        match self {
            AuthenticatedUser::User { .. } => true,
            AuthenticatedUser::Service { permissions, .. } => {
                permissions.contains(&"send_messages".to_string()) 
                    || permissions.contains(&"admin".to_string())
            }
        }
    }
}

#[derive(Clone)]
pub struct AuthService {
    jwt_secret: String,
    db: Database,
}

impl AuthService {
    pub fn new(jwt_secret: String, db: Database) -> Self {
        Self { jwt_secret, db }
    }

    pub fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?;

        Ok(password_hash.to_string())
    }

    pub fn verify_password(&self, password: &str, password_hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AppError::Internal(format!("Failed to parse password hash: {}", e)))?;
        
        let argon2 = Argon2::default();
        
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn generate_jwt_token(&self, user: &User) -> AppResult<(String, DateTime<Utc>)> {
        let expiration = Utc::now() + Duration::hours(24);
        
        let claims = Claims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            exp: expiration.timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )?;

        Ok((token, expiration))
    }

    pub fn verify_jwt_token(&self, token: &str) -> AppResult<Claims> {
        let token_data: TokenData<Claims> = decode(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }

    pub fn generate_api_key(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789";
        
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    pub fn hash_api_key(&self, api_key: &str) -> AppResult<String> {
        use argon2::password_hash::rand_core::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let key_hash = argon2
            .hash_password(api_key.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Failed to hash API key: {}", e)))?;

        Ok(key_hash.to_string())
    }

    pub fn verify_api_key(&self, api_key: &str, key_hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(key_hash)
            .map_err(|e| AppError::Internal(format!("Failed to parse API key hash: {}", e)))?;
        
        let argon2 = Argon2::default();
        
        match argon2.verify_password(api_key.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn parse_permissions(&self, permissions_str: &str) -> Vec<String> {
        permissions_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> AppResult<User> {
        let user = self.db.get_user_by_username(username)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid username or password".to_string()))?;

        if !self.verify_password(password, &user.password_hash)? {
            return Err(AppError::Auth("Invalid username or password".to_string()));
        }

        Ok(user)
    }

    pub async fn authenticate_jwt(&self, token: &str) -> AppResult<AuthenticatedUser> {
        let claims = self.verify_jwt_token(token)?;
        
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Auth("Invalid user ID in token".to_string()))?;

        let user = self.db.get_user_by_id(&user_id)
            .await?
            .ok_or_else(|| AppError::Auth("User not found".to_string()))?;

        Ok(AuthenticatedUser::User {
            id: user.id,
            username: user.username,
        })
    }

    pub async fn authenticate_api_key(&self, api_key: &str) -> AppResult<AuthenticatedUser> {
        // Use the new verification method that works with hashed keys
        let api_key_record = self.db.find_api_key_by_verification(api_key, self)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid API key".to_string()))?;

        if api_key_record.revoked_at.is_some() {
            return Err(AppError::Auth("API key has been revoked".to_string()));
        }

        let permissions = self.parse_permissions(&api_key_record.permissions);

        Ok(AuthenticatedUser::Service {
            id: api_key_record.created_by,
            name: api_key_record.name,
            permissions,
        })
    }
}