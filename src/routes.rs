use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid;

use crate::auth::{AuthUser, Credentials, RefreshTokenRequest, TokenResponse};
use crate::rbac::{RequirePermission, check_permission};
use crate::AppState;

#[derive(Deserialize)]
pub struct RegisterUser {
    username: String,
    password: String,
    role: String,
}

pub async fn home() -> &'static str {
    "Welcome to the API!"
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(user): Json<RegisterUser>,
) -> impl IntoResponse {
    // Check if the registering user has permission to create users
    if let Err(response) = check_permission(&state.rbac, "admin", "/register", "POST").await {
        return response;
    }

    let password_hash = bcrypt::hash(user.password.as_bytes(), bcrypt::DEFAULT_COST)
        .expect("Failed to hash password");

    let user_id = uuid::Uuid::new_v4();

    match sqlx::query!(
        "INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)",
        user_id,
        user.username,
        password_hash,
        user.role
    )
    .execute(&state.auth.db)
    .await
    {
        Ok(_) => (StatusCode::CREATED, "User registered successfully").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to register user").into_response(),
    }
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(credentials): Json<Credentials>,
) -> impl IntoResponse {
    match state.auth.authenticate(&credentials).await {
        Ok(Some(user)) => {
            match state.auth.create_token(&user) {
                Ok(access_token) => {
                    match state.auth.create_refresh_token(user.id).await {
                        Ok(refresh_token) => {
                            let response = TokenResponse {
                                access_token,
                                refresh_token,
                            };
                            (StatusCode::OK, Json(response)).into_response()
                        }
                        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create refresh token").into_response(),
                    }
                }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create access token").into_response(),
            }
        }
        Ok(None) => (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Authentication failed").into_response(),
    }
}

pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RefreshTokenRequest>,
) -> impl IntoResponse {
    match state.auth.verify_refresh_token(&request.refresh_token).await {
        Ok(Some(user)) => {
            match state.auth.create_token(&user) {
                Ok(access_token) => {
                    match state.auth.create_refresh_token(user.id).await {
                        Ok(refresh_token) => {
                            let response = TokenResponse {
                                access_token,
                                refresh_token,
                            };
                            (StatusCode::OK, Json(response)).into_response()
                        }
                        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create refresh token").into_response(),
                    }
                }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create access token").into_response(),
            }
        }
        Ok(None) => (StatusCode::UNAUTHORIZED, "Invalid refresh token").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Token refresh failed").into_response(),
    }
}

pub async fn protected(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    permission: RequirePermission,
) -> impl IntoResponse {
    // Check if the user has permission to access the protected route
    if let Err(response) = check_permission(
        &state.rbac,
        &auth_user.0.role,
        &permission.object,
        &permission.action,
    ).await {
        return response;
    }

    (StatusCode::OK, format!("Protected route accessed by {}", auth_user.0.username)).into_response()
} 