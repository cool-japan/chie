//! JWT authentication for the coordinator API.

use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// JWT claims structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID).
    pub sub: uuid::Uuid,
    /// User's peer ID (if they're a node operator).
    pub peer_id: Option<String>,
    /// User role.
    pub role: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at time (Unix timestamp).
    pub iat: i64,
}

/// JWT configuration.
#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "chie-dev-secret-change-me".to_string()),
            expiration_hours: 24,
        }
    }
}

/// JWT encoder/decoder.
#[derive(Clone)]
pub struct JwtAuth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    config: JwtConfig,
}

impl JwtAuth {
    /// Create a new JWT auth instance.
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());
        Self {
            encoding_key,
            decoding_key,
            config,
        }
    }

    /// Generate a JWT token for a user.
    pub fn generate_token(
        &self,
        user_id: uuid::Uuid,
        peer_id: Option<String>,
        role: &str,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.config.expiration_hours);

        let claims = Claims {
            sub: user_id,
            peer_id,
            role: role.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenCreation(e.to_string()))
    }

    /// Verify and decode a JWT token.
    pub fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        Ok(token_data.claims)
    }
}

/// Authentication errors.
#[derive(Debug, Clone)]
pub enum AuthError {
    /// Missing authorization header.
    MissingAuth,
    /// Invalid token format.
    InvalidFormat,
    /// Token creation failed.
    TokenCreation(String),
    /// Invalid token.
    InvalidToken(String),
    /// Token expired.
    Expired,
    /// Insufficient permissions.
    #[allow(dead_code)]
    InsufficientPermissions,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::MissingAuth => (StatusCode::UNAUTHORIZED, "Missing authorization header"),
            Self::InvalidFormat => (StatusCode::UNAUTHORIZED, "Invalid authorization format"),
            Self::TokenCreation(ref e) => {
                tracing::error!("Token creation error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Token creation failed")
            }
            Self::InvalidToken(_) => (StatusCode::UNAUTHORIZED, "Invalid token"),
            Self::Expired => (StatusCode::UNAUTHORIZED, "Token expired"),
            Self::InsufficientPermissions => (StatusCode::FORBIDDEN, "Insufficient permissions"),
        };

        let body = serde_json::json!({
            "error": message,
        });

        (status, Json(body)).into_response()
    }
}

/// Authenticated user extracted from request.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: uuid::Uuid,
    pub peer_id: Option<String>,
    pub role: String,
}

/// Application state that includes auth.
pub type SharedJwtAuth = Arc<JwtAuth>;

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get JWT auth from extensions
        let jwt_auth = parts
            .extensions
            .get::<SharedJwtAuth>()
            .cloned()
            .ok_or(AuthError::MissingAuth)?;

        // Get authorization header
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or(AuthError::MissingAuth)?;

        // Extract bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidFormat)?;

        // Verify token
        let claims = jwt_auth.verify_token(token)?;

        // Check expiration
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(AuthError::Expired);
        }

        Ok(AuthenticatedUser {
            user_id: claims.sub,
            peer_id: claims.peer_id,
            role: claims.role,
        })
    }
}

/// Middleware layer for adding JWT auth to request extensions.
#[allow(dead_code)]
pub fn auth_layer(jwt_auth: SharedJwtAuth) -> axum::Extension<SharedJwtAuth> {
    axum::Extension(jwt_auth)
}
