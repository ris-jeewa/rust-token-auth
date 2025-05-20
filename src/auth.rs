use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{Duration, Utc};
use bcrypt::verify;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user id
    pub exp: i64,     // expiration time
    pub role: String, // user role
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone)]
pub struct AuthState {
    pub db: PgPool,
    pub jwt_secret: String,
}

impl AuthState {
    pub fn new(db: PgPool, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
    }

    pub async fn authenticate(&self, credentials: &Credentials) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, password_hash, role FROM users WHERE username = $1",
            credentials.username
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(user) = user {
            if verify(&credentials.password, &user.password_hash).unwrap_or(false) {
                return Ok(Some(user));
            }
        }

        Ok(None)
    }

    pub fn create_token(&self, user: &User) -> Result<String, jsonwebtoken::errors::Error> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(1)) // Access token expires in 1 hour
            .expect("valid timestamp")
            .timestamp();

        let claims = Claims {
            sub: user.id.to_string(),
            exp: expiration,
            role: user.role.clone(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
    }

    pub async fn create_refresh_token(&self, user_id: Uuid) -> Result<String, sqlx::Error> {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::days(30); // Refresh token expires in 30 days

        sqlx::query!(
            "INSERT INTO refresh_tokens (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)",
            Uuid::new_v4(),
            user_id,
            token,
            expires_at
        )
        .execute(&self.db)
        .await?;

        Ok(token)
    }

    pub async fn verify_refresh_token(&self, token: &str) -> Result<Option<User>, sqlx::Error> {
        let now = Utc::now();
        
        // Start a transaction
        let mut tx = self.db.begin().await?;
        
        // Get the user and delete the token in one transaction
        let user = sqlx::query_as!(
            User,
            r#"
            WITH deleted_token AS (
                DELETE FROM refresh_tokens 
                WHERE token = $1 AND expires_at > $2
                RETURNING user_id
            )
            SELECT u.id, u.username, u.password_hash, u.role
            FROM users u
            JOIN deleted_token dt ON u.id = dt.user_id
            "#,
            token,
            now
        )
        .fetch_optional(&mut *tx)
        .await?;

        // Commit the transaction
        tx.commit().await?;

        Ok(user)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map(|data| data.claims)
    }
}

#[derive(Debug)]
pub struct AuthUser(pub User);

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        info!("Processing authentication request");
        
        // Extract and validate Authorization header
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| {
                error!("Missing or invalid Authorization header");
                (StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header").into_response()
            })?;

        info!("Found Authorization header");

        // Get auth state from extensions
        let auth_state = parts
            .extensions
            .get::<Arc<AuthState>>()
            .ok_or_else(|| {
                error!("Auth state not found in extensions");
                (StatusCode::INTERNAL_SERVER_ERROR, "Auth state not found").into_response()
            })?;

        info!("Found auth state in extensions");

        // Verify token
        let claims = auth_state.verify_token(auth_header).map_err(|e| {
            error!("Token verification failed: {:?}", e);
            (StatusCode::UNAUTHORIZED, "Invalid token").into_response()
        })?;

        info!("Token verified successfully");

        // Parse user ID from claims
        let user_id = Uuid::parse_str(&claims.sub).map_err(|e| {
            error!("Failed to parse user ID: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Invalid user ID format").into_response()
        })?;

        info!("Parsed user ID: {}", user_id);

        // Fetch user from database
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, password_hash, role FROM users WHERE id = $1",
            user_id
        )
        .fetch_optional(&auth_state.db)
        .await
        .map_err(|e| {
            error!("Database error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
        })?
        .ok_or_else(|| {
            error!("User not found in database");
            (StatusCode::UNAUTHORIZED, "User not found").into_response()
        })?;

        info!("User found: {}", user.username);
        Ok(AuthUser(user))
    }
} 