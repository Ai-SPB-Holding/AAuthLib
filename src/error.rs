use thiserror::Error;

/// Errors returned by this SDK (configuration, HTTP, OAuth, JSON).
#[derive(Debug, Error)]
pub enum SdkError {
    /// Invalid or inconsistent env / [`crate::config::ClientConfig`].
    #[error("configuration: {0}")]
    Config(String),

    /// Transport-level failure from `reqwest`.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Non-success HTTP status with response body (best-effort).
    #[error("HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },

    /// OAuth 2.0 error payload from the token endpoint (`error` / `error_description`).
    #[error("OAuth/token endpoint error: {0}")]
    OAuth(String),

    /// Failed to parse JSON from a response body.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid URL string.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Server rejected `grant_type` (e.g. `client_credentials` on AuthService).
    #[error("unsupported grant_type from server (AuthService token endpoint allows authorization_code, refresh_token, password, embedded_session only): {0}")]
    UnsupportedGrantType(String),

    /// PKCE verifier was not found for the OAuth `state` (Axum helper).
    #[error("PKCE state was missing or expired")]
    PkceStateMissing,

    /// Generic message wrapper.
    #[error("{0}")]
    Msg(String),
}

impl SdkError {
    pub fn config(msg: impl Into<String>) -> Self {
        SdkError::Config(msg.into())
    }

    pub fn msg(msg: impl Into<String>) -> Self {
        SdkError::Msg(msg.into())
    }
}
