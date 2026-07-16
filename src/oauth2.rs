//! OAuth2 calls against AuthService `/oauth2/*` endpoints.

use reqwest::header::CONTENT_TYPE;
use secrecy::ExposeSecret;
use serde_json::{json, Value};

use crate::client_auth::ResolvedClientAuth;
use crate::config::{ClientConfig, Config};
use crate::discovery::{DiscoveryClient, OidcDiscoveryDocument};
use crate::error::SdkError;
use crate::types::{IntrospectResponse, PasswordGrantResult, TokenSet};
use uuid::Uuid;

/// HTTP client for the token, userinfo, introspection, and revoke endpoints
/// (URLs from [`OidcDiscoveryDocument`] via [`Self::metadata`](OAuth2Client::metadata)).
#[derive(Clone)]
pub struct OAuth2Client {
    pub http: reqwest::Client,
    pub discovery: DiscoveryClient,
    pub default_audience: Option<String>,
}

impl OAuth2Client {
    pub fn new(http: reqwest::Client, server_metadata_url: impl Into<String>) -> Self {
        Self {
            http: http.clone(),
            discovery: DiscoveryClient::new(http, server_metadata_url),
            default_audience: None,
        }
    }

    pub fn from_config(http: reqwest::Client, config: &Config) -> Self {
        Self {
            http: http.clone(),
            discovery: DiscoveryClient::new(http, config.server_metadata_url.clone()),
            default_audience: config.default_audience.clone(),
        }
    }

    pub async fn metadata(&self) -> Result<OidcDiscoveryDocument, SdkError> {
        self.discovery.get().await
    }

    fn effective_audience<'a>(&'a self, audience: Option<&'a str>) -> Option<&'a str> {
        audience.or(self.default_audience.as_deref())
    }

    /// `grant_type=authorization_code` at [`OidcDiscoveryDocument::token_endpoint`].
    pub async fn exchange_authorization_code(
        &self,
        client: &ClientConfig,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        audience: Option<&str>,
    ) -> Result<TokenSet, SdkError> {
        let doc = self.metadata().await?;
        let auth = ResolvedClientAuth::resolve(client)?;
        let aud = self.effective_audience(audience);
        let mut pairs = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];
        if let Some(a) = aud {
            pairs.push(("audience".to_string(), a.to_string()));
        }
        let v = self
            .post_token_form(&doc.token_endpoint, &auth, pairs)
            .await?;
        parse_token_set(&v)
    }

    /// `grant_type=refresh_token`
    pub async fn refresh(
        &self,
        client: &ClientConfig,
        refresh_token: &str,
        audience: Option<&str>,
    ) -> Result<TokenSet, SdkError> {
        let doc = self.metadata().await?;
        let auth = ResolvedClientAuth::resolve(client)?;
        let aud = self.effective_audience(audience);
        let mut pairs = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
        ];
        if let Some(a) = aud {
            pairs.push(("audience".to_string(), a.to_string()));
        }
        let v = self
            .post_token_form(&doc.token_endpoint, &auth, pairs)
            .await?;
        parse_token_set(&v)
    }

    /// `grant_type=embedded_session` (BFF exchanges a one-time code from `POST /api/session-code`).
    pub async fn exchange_embedded_session(
        &self,
        client: &ClientConfig,
        code: &str,
        audience: Option<&str>,
    ) -> Result<TokenSet, SdkError> {
        let doc = self.metadata().await?;
        let auth = ResolvedClientAuth::resolve(client)?;
        let aud = self.effective_audience(audience).ok_or_else(|| {
            SdkError::config(
                "audience is required for embedded_session (set DEFAULT_AUDIENCE or pass audience)",
            )
        })?;
        let pairs = vec![
            ("grant_type".to_string(), "embedded_session".to_string()),
            ("code".to_string(), code.to_string()),
            ("audience".to_string(), aud.to_string()),
        ];
        let v = self
            .post_token_form(&doc.token_endpoint, &auth, pairs)
            .await?;
        parse_token_set(&v)
    }

    /// `grant_type=password` (only if `AUTH__ALLOW_RESOURCE_OWNER_PASSWORD_GRANT=true` on the server).
    pub async fn password_grant(
        &self,
        client: &ClientConfig,
        tenant_id: Uuid,
        email: &str,
        password: &str,
        audience: Option<&str>,
    ) -> Result<PasswordGrantResult, SdkError> {
        let doc = self.metadata().await?;
        let auth = ResolvedClientAuth::resolve(client)?;
        let aud = self.effective_audience(audience).ok_or_else(|| {
            SdkError::config(
                "audience is required for password grant (set DEFAULT_AUDIENCE or pass audience)",
            )
        })?;
        let pairs = vec![
            ("grant_type".to_string(), "password".to_string()),
            ("tenant_id".to_string(), tenant_id.to_string()),
            ("email".to_string(), email.to_string()),
            ("password".to_string(), password.to_string()),
            ("audience".to_string(), aud.to_string()),
        ];
        let v = self
            .post_token_form(&doc.token_endpoint, &auth, pairs)
            .await?;
        if v.get("access_token").and_then(|x| x.as_str()).is_some() {
            return Ok(PasswordGrantResult::Tokens(parse_token_set(&v)?));
        }
        Ok(PasswordGrantResult::Other(v))
    }

    /// `grant_type=client_credentials` for confidential machine clients (Mail Sync, user admin SDK, …).
    pub async fn client_credentials(
        &self,
        client: &ClientConfig,
        scope: Option<&str>,
        audience: Option<&str>,
    ) -> Result<TokenSet, SdkError> {
        let doc = self.metadata().await?;
        let auth = ResolvedClientAuth::resolve(client)?;
        let aud = self.effective_audience(audience);
        let mut pairs = vec![("grant_type".to_string(), "client_credentials".to_string())];
        if let Some(s) = scope {
            pairs.push(("scope".to_string(), s.to_string()));
        }
        if let Some(a) = aud {
            pairs.push(("audience".to_string(), a.to_string()));
        }
        let v = self
            .post_token_form(&doc.token_endpoint, &auth, pairs)
            .await?;
        parse_token_set(&v)
    }

    /// `GET` [`OidcDiscoveryDocument::userinfo_endpoint`] with `Authorization: Bearer`.
    pub async fn userinfo(&self, access_token: &str) -> Result<Value, SdkError> {
        let doc = self.metadata().await?;
        let url = doc
            .userinfo_endpoint
            .ok_or_else(|| SdkError::msg("discovery document has no userinfo_endpoint"))?;
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token.trim()))
            .send()
            .await?;
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

    /// RFC 7662 introspection at `/oauth2/introspect` (form POST).
    pub async fn introspect(
        &self,
        client: &ClientConfig,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<IntrospectResponse, SdkError> {
        let doc = self.metadata().await?;
        let url = doc
            .introspection_endpoint
            .ok_or_else(|| SdkError::msg("discovery document has no introspection_endpoint"))?;
        let auth = ResolvedClientAuth::resolve(client)?;
        let mut pairs = vec![("token".to_string(), token.to_string())];
        if let Some(h) = token_type_hint {
            pairs.push(("token_type_hint".to_string(), h.to_string()));
        }
        auth.extend_form_for_introspect_revoke(&mut pairs);
        let v = self.post_form(&url, &auth, pairs).await?;
        Ok(serde_json::from_value(v)?)
    }

    /// Token revocation at `/oauth2/revoke` (form POST).
    pub async fn revoke(&self, client: &ClientConfig, token: &str) -> Result<(), SdkError> {
        let doc = self.metadata().await?;
        let url = doc
            .revocation_endpoint
            .ok_or_else(|| SdkError::msg("discovery document has no revocation_endpoint"))?;
        let auth = ResolvedClientAuth::resolve(client)?;
        let mut pairs = vec![("token".to_string(), token.to_string())];
        auth.extend_form_for_introspect_revoke(&mut pairs);
        let resp = self.post_form_raw(&url, &auth, pairs).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SdkError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    async fn post_token_form(
        &self,
        token_endpoint: &str,
        auth: &ResolvedClientAuth,
        mut pairs: Vec<(String, String)>,
    ) -> Result<Value, SdkError> {
        auth.extend_form_for_token_endpoint(&mut pairs);
        self.post_form(token_endpoint, auth, pairs).await
    }

    async fn post_form(
        &self,
        url: &str,
        auth: &ResolvedClientAuth,
        pairs: Vec<(String, String)>,
    ) -> Result<Value, SdkError> {
        let resp = self.post_form_raw(url, auth, pairs).await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        let body = String::from_utf8_lossy(&bytes).into_owned();
        let v: Value =
            serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw": body.clone() }));
        if !status.is_success() {
            return Err(token_endpoint_error(status.as_u16(), &body, &v));
        }
        // OAuth 2.0 error JSON on 200 is unusual; handle anyway.
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return Err(SdkError::OAuth(format!(
                "{}: {}",
                err,
                v.get("error_description")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
            )));
        }
        Ok(v)
    }

    async fn post_form_raw(
        &self,
        url: &str,
        auth: &ResolvedClientAuth,
        pairs: Vec<(String, String)>,
    ) -> Result<reqwest::Response, SdkError> {
        // Encode in a sync helper so `url::form_urlencoded::Serializer` is not stored in the
        // generated async state machine across `.await` (it is not `Send` / thread-safe).
        let body = encode_x_www_form_urlencoded(&pairs);
        let mut req = self
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body);
        req = match auth {
            ResolvedClientAuth::Basic { client_id, secret } => {
                req.basic_auth(client_id, Some(secret.expose_secret()))
            }
            _ => req,
        };
        Ok(req.send().await?)
    }
}

fn encode_x_www_form_urlencoded(pairs: &[(String, String)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

#[cfg(test)]
mod encode_tests {
    use super::encode_x_www_form_urlencoded;

    #[test]
    fn encodes_pairs() {
        let out = encode_x_www_form_urlencoded(&[
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), "rt".into()),
        ]);
        assert!(out.contains("grant_type=refresh_token"));
        assert!(out.contains("refresh_token=rt"));
    }
}

fn parse_token_set(v: &Value) -> Result<TokenSet, SdkError> {
    serde_json::from_value(v.clone()).map_err(|e| {
        tracing::debug!(error = %e, body = %v, "token response parse");
        SdkError::msg(format!("unexpected token response shape: {e}"))
    })
}

fn token_endpoint_error(status: u16, raw: &str, parsed: &Value) -> SdkError {
    if raw.contains("unsupported grant_type") {
        return SdkError::UnsupportedGrantType(raw.to_string());
    }
    if let Some(err) = parsed.get("error").and_then(|e| e.as_str()) {
        return SdkError::OAuth(format!(
            "{}: {}",
            err,
            parsed
                .get("error_description")
                .and_then(|x| x.as_str())
                .unwrap_or(raw)
        ));
    }
    SdkError::HttpStatus {
        status,
        body: raw.to_string(),
    }
}
