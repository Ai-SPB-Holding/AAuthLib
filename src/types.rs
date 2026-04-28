use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Successful access token response (subset of fields returned by AuthService `TokenPair` + `token_type`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default)]
    pub id_token: Option<String>,
}

/// Password grant may return tokens or an MFA / enrollment payload instead.
#[derive(Debug, Clone)]
pub enum PasswordGrantResult {
    Tokens(TokenSet),
    Other(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub aud: Option<String>,
}
