//! Axum-oriented helpers: OAuth redirect callback + PKCE verifier lookup.

use async_trait::async_trait;
use serde::Deserialize;

use crate::config::ClientConfig;
use crate::error::SdkError;
use crate::oauth2::OAuth2Client;
use crate::types::TokenSet;

/// Query parameters on `redirect_uri` after successful `/oauth2/authorize`.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

/// Holds PKCE `code_verifier` keyed by OAuth `state` (remove on use).
#[async_trait]
pub trait PkceStateStore: Send + Sync {
    async fn take_code_verifier(&self, oauth_state: &str) -> Result<Option<String>, SdkError>;
}

/// In-memory store for development only (not suitable for multi-instance production).
pub struct MemoryPkceStateStore {
    inner: tokio::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl Default for MemoryPkceStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryPkceStateStore {
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub async fn insert(&self, oauth_state: String, code_verifier: String) {
        let mut g = self.inner.lock().await;
        g.insert(oauth_state, code_verifier);
    }
}

#[async_trait]
impl PkceStateStore for MemoryPkceStateStore {
    async fn take_code_verifier(&self, oauth_state: &str) -> Result<Option<String>, SdkError> {
        Ok(self.inner.lock().await.remove(oauth_state))
    }
}

/// Completes authorization-code flow: loads verifier via [`PkceStateStore`], exchanges code at `/oauth2/token`.
pub async fn exchange_authorization_code_with_pkce_store<S: PkceStateStore + ?Sized>(
    oauth: &OAuth2Client,
    client: &ClientConfig,
    store: &S,
    callback: &OAuthCallbackQuery,
    redirect_uri: &str,
    audience: Option<&str>,
) -> Result<TokenSet, SdkError> {
    let verifier = store
        .take_code_verifier(&callback.state)
        .await?
        .ok_or(SdkError::PkceStateMissing)?;
    oauth
        .exchange_authorization_code(client, &callback.code, &verifier, redirect_uri, audience)
        .await
}
