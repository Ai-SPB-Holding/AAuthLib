//! Tenant-scoped user admin API (`/api/service/v1/users*`) for confidential OAuth clients.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client_auth::ResolvedClientAuth;
use crate::config::{ClientConfig, Config};
use crate::error::SdkError;
use crate::oauth2::OAuth2Client;

/// User row returned by `/api/service/v1/users*`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceUser {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub is_active: bool,
    pub is_locked: bool,
    pub email_verified: bool,
    pub registration_source: String,
    pub created_at: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListUsersParams {
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateServiceUserRequest {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_ids: Vec<Uuid>,
}

#[derive(Debug, Default, Serialize)]
pub struct PatchServiceUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SetUserRolesRequest {
    pub role_ids: Vec<Uuid>,
}

/// HTTP client for machine user admin (Basic client secret or Bearer from `client_credentials`).
#[derive(Clone)]
pub struct ServiceUserAdminClient {
    http: reqwest::Client,
    api_base: String,
    client: ClientConfig,
    bearer: Option<String>,
}

impl ServiceUserAdminClient {
    /// Build from [`Config`]; API base is derived from `SERVER_METADATA_URL` origin.
    pub fn from_config(http: reqwest::Client, config: &Config) -> Result<Self, SdkError> {
        config.client.validate()?;
        if config.client.client_secret.is_none() {
            return Err(SdkError::config(
                "CLIENT_SECRET is required for service user admin API",
            ));
        }
        Ok(Self {
            http,
            api_base: api_base_from_metadata(&config.server_metadata_url)?,
            client: config.client.clone(),
            bearer: None,
        })
    }

    /// Use OAuth2 `client_credentials` once and cache the access token for subsequent calls.
    pub async fn with_client_credentials(
        mut self,
        oauth: &OAuth2Client,
        scope: Option<&str>,
        audience: Option<&str>,
    ) -> Result<Self, SdkError> {
        let tokens = oauth
            .client_credentials(&self.client, scope, audience)
            .await?;
        self.bearer = Some(tokens.access_token);
        Ok(self)
    }

    pub async fn list_users(
        &self,
        params: ListUsersParams,
    ) -> Result<Vec<ServiceUser>, SdkError> {
        let mut url = format!("{}/api/service/v1/users", self.api_base);
        let mut qs = Vec::new();
        if let Some(q) = params.q.as_deref().filter(|s| !s.is_empty()) {
            qs.push(format!("q={}", urlencoding(q)));
        }
        if let Some(limit) = params.limit {
            qs.push(format!("limit={limit}"));
        }
        if let Some(offset) = params.offset {
            qs.push(format!("offset={offset}"));
        }
        if !qs.is_empty() {
            url.push('?');
            url.push_str(&qs.join("&"));
        }
        self.get_json(&url).await
    }

    pub async fn get_user(&self, user_id: Uuid) -> Result<ServiceUser, SdkError> {
        let url = format!("{}/api/service/v1/users/{user_id}", self.api_base);
        self.get_json(&url).await
    }

    pub async fn create_user(
        &self,
        req: CreateServiceUserRequest,
    ) -> Result<ServiceUser, SdkError> {
        let url = format!("{}/api/service/v1/users", self.api_base);
        self.post_json(&url, &req).await
    }

    pub async fn update_user(
        &self,
        user_id: Uuid,
        req: PatchServiceUserRequest,
    ) -> Result<ServiceUser, SdkError> {
        let url = format!("{}/api/service/v1/users/{user_id}", self.api_base);
        self.patch_json(&url, &req).await
    }

    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), SdkError> {
        let url = format!("{}/api/service/v1/users/{user_id}", self.api_base);
        let resp = self.http.delete(&url).headers(self.auth_headers()?).send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(SdkError::HttpStatus {
            status: status.as_u16(),
            body,
        })
    }

    pub async fn set_user_roles(
        &self,
        user_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<(), SdkError> {
        let url = format!("{}/api/service/v1/users/{user_id}/roles", self.api_base);
        let req = SetUserRolesRequest {
            role_ids: role_ids.to_vec(),
        };
        let _: serde_json::Value = self.put_json(&url, &req).await?;
        Ok(())
    }

    fn auth_headers(&self) -> Result<reqwest::header::HeaderMap, SdkError> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = self.bearer.as_deref() {
            headers.insert(
                AUTHORIZATION,
                format!("Bearer {token}")
                    .parse()
                    .map_err(|e: reqwest::header::InvalidHeaderValue| SdkError::msg(e.to_string()))?,
            );
            return Ok(headers);
        }
        let auth = ResolvedClientAuth::resolve(&self.client)?;
        if let ResolvedClientAuth::Basic { client_id, secret } = auth {
            let raw = format!("{}:{}", client_id, secret.expose_secret());
            let b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                raw.as_bytes(),
            );
            headers.insert(
                AUTHORIZATION,
                format!("Basic {b64}")
                    .parse()
                    .map_err(|e: reqwest::header::InvalidHeaderValue| SdkError::msg(e.to_string()))?,
            );
        } else {
            return Err(SdkError::config(
                "service user admin requires confidential client (Basic auth or bearer token)",
            ));
        }
        Ok(headers)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, SdkError> {
        let resp = self.http.get(url).headers(self.auth_headers()?).send().await?;
        parse_json_response(resp).await
    }

    async fn post_json<T, B: Serialize>(&self, url: &str, body: &B) -> Result<T, SdkError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let resp = self
            .http
            .post(url)
            .headers(self.auth_headers()?)
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await?;
        parse_json_response(resp).await
    }

    async fn patch_json<T, B: Serialize>(&self, url: &str, body: &B) -> Result<T, SdkError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let resp = self
            .http
            .patch(url)
            .headers(self.auth_headers()?)
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await?;
        parse_json_response(resp).await
    }

    async fn put_json<T, B: Serialize>(&self, url: &str, body: &B) -> Result<T, SdkError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let resp = self
            .http
            .put(url)
            .headers(self.auth_headers()?)
            .header(CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .await?;
        parse_json_response(resp).await
    }
}

fn api_base_from_metadata(server_metadata_url: &str) -> Result<String, SdkError> {
    let mut u = url::Url::parse(server_metadata_url)
        .map_err(|e| SdkError::config(format!("invalid SERVER_METADATA_URL: {e}")))?;
    u.set_path("");
    u.set_query(None);
    u.set_fragment(None);
    let s = u.to_string();
    Ok(s.trim_end_matches('/').to_string())
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn parse_json_response<T: for<'de> Deserialize<'de>>(
    resp: reqwest::Response,
) -> Result<T, SdkError> {
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

/// Convenience: `client_credentials` + user admin client in one step.
pub async fn service_user_admin_from_config(
    http: reqwest::Client,
    config: &Config,
    scope: Option<&str>,
    audience: Option<&str>,
) -> Result<ServiceUserAdminClient, SdkError> {
    let oauth = OAuth2Client::from_config(http.clone(), config);
    ServiceUserAdminClient::from_config(http, config)?
        .with_client_credentials(&oauth, scope, audience)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_base_strips_well_known_path() {
        let base = api_base_from_metadata("https://auth.example/.well-known/openid-configuration")
            .unwrap();
        assert_eq!(base, "https://auth.example");
    }
}
