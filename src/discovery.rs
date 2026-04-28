use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::RwLock;

use crate::error::SdkError;

/// OIDC discovery document (fields required for this SDK; unknown keys are ignored).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

/// Fetches and caches [`OidcDiscoveryDocument`] from `SERVER_METADATA_URL`.
#[derive(Clone)]
pub struct DiscoveryClient {
    http: reqwest::Client,
    metadata_url: String,
    ttl: Duration,
    cache: std::sync::Arc<RwLock<Option<(Instant, OidcDiscoveryDocument)>>>,
}

impl DiscoveryClient {
    pub fn new(http: reqwest::Client, metadata_url: impl Into<String>) -> Self {
        Self::with_ttl(http, metadata_url, Duration::from_secs(600))
    }

    pub fn with_ttl(http: reqwest::Client, metadata_url: impl Into<String>, ttl: Duration) -> Self {
        Self {
            http,
            metadata_url: metadata_url.into(),
            ttl,
            cache: std::sync::Arc::new(RwLock::new(None)),
        }
    }

    /// Clears the in-memory cache (e.g. after rotation or failed requests).
    pub async fn invalidate(&self) {
        let mut g = self.cache.write().await;
        *g = None;
    }

    async fn fetch_uncached(&self) -> Result<OidcDiscoveryDocument, SdkError> {
        let resp = self.http.get(&self.metadata_url).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(SdkError::HttpStatus {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Returns cached metadata when younger than `ttl`, otherwise refetches.
    pub async fn get(&self) -> Result<OidcDiscoveryDocument, SdkError> {
        {
            let r = self.cache.read().await;
            if let Some((t, doc)) = r.as_ref() {
                if t.elapsed() < self.ttl {
                    return Ok(doc.clone());
                }
            }
        }
        let doc = self.fetch_uncached().await?;
        let mut w = self.cache.write().await;
        *w = Some((Instant::now(), doc.clone()));
        Ok(doc)
    }
}
