use secrecy::SecretString;
use std::env;

use crate::error::SdkError;

/// How to send `client_id` / `client_secret` to `/oauth2/token` (must match DB `token_endpoint_auth_method`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
    /// If `client_secret` is set → `client_secret_basic`, else `none` (public client).
    #[default]
    Auto,
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    pub fn parse(s: &str) -> Result<Self, SdkError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            "basic" | "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "post" | "client_secret_post" => Ok(Self::ClientSecretPost),
            other => Err(SdkError::config(format!(
                "unknown TOKEN_ENDPOINT_AUTH_METHOD: {other}"
            ))),
        }
    }
}

/// OAuth client settings (typically from environment variables).
#[derive(Clone)]
pub struct ClientConfig {
    pub client_id: String,
    pub redirect_uri: String,
    pub client_secret: Option<SecretString>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
}

impl ClientConfig {
    /// Validate logical consistency (public clients must not ship secrets; confidential need one).
    pub fn validate(&self) -> Result<(), SdkError> {
        url::Url::parse(&self.redirect_uri).map_err(|e| SdkError::config(e.to_string()))?;
        match self.token_endpoint_auth_method {
            TokenEndpointAuthMethod::None => {
                if self.client_secret.is_some() {
                    return Err(SdkError::config(
                        "CLIENT_SECRET is set but TOKEN_ENDPOINT_AUTH_METHOD is none",
                    ));
                }
            }
            TokenEndpointAuthMethod::ClientSecretBasic
            | TokenEndpointAuthMethod::ClientSecretPost => {
                if self.client_secret.is_none() {
                    return Err(SdkError::config(
                        "CLIENT_SECRET is required for token_endpoint_auth_method basic/post",
                    ));
                }
            }
            TokenEndpointAuthMethod::Auto => {}
        }
        Ok(())
    }

    /// Load [`ClientConfig`] from environment variables:
    /// - `CLIENT_ID` (required)
    /// - `REDIRECT_URL` (required)
    /// - `CLIENT_SECRET` (optional)
    /// - `TOKEN_ENDPOINT_AUTH_METHOD` (optional; default `auto`)
    pub fn from_env() -> Result<Self, SdkError> {
        let client_id = env::var("CLIENT_ID").map_err(|_| {
            SdkError::config("CLIENT_ID is required (environment variable missing)")
        })?;
        let redirect_uri = env::var("REDIRECT_URL").map_err(|_| {
            SdkError::config("REDIRECT_URL is required (environment variable missing)")
        })?;
        let client_secret = env::var("CLIENT_SECRET")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| SecretString::new(s.into()));
        let token_endpoint_auth_method = env::var("TOKEN_ENDPOINT_AUTH_METHOD")
            .ok()
            .map(|s| TokenEndpointAuthMethod::parse(&s))
            .transpose()?
            .unwrap_or_default();
        let c = Self {
            client_id,
            redirect_uri,
            client_secret,
            token_endpoint_auth_method,
        };
        c.validate()?;
        Ok(c)
    }
}

/// Environment-backed settings for discovery + optional defaults.
#[derive(Clone)]
pub struct Config {
    pub client: ClientConfig,
    /// `/.well-known/openid-configuration` URL for this AuthService deployment.
    pub server_metadata_url: String,
    /// Optional default `audience` for `/oauth2/token` when the server would otherwise use its admin default.
    pub default_audience: Option<String>,
}

impl Config {
    /// Required env:
    /// - `CLIENT_ID`, `REDIRECT_URL`, `SERVER_METADATA_URL`
    ///
    /// Optional:
    /// - `CLIENT_SECRET`, `TOKEN_ENDPOINT_AUTH_METHOD`, `DEFAULT_AUDIENCE`
    pub fn from_env() -> Result<Self, SdkError> {
        let server_metadata_url = env::var("SERVER_METADATA_URL").map_err(|_| {
            SdkError::config("SERVER_METADATA_URL is required (environment variable missing)")
        })?;
        url::Url::parse(&server_metadata_url).map_err(|e| SdkError::config(e.to_string()))?;
        let default_audience = env::var("DEFAULT_AUDIENCE")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let client = ClientConfig::from_env()?;
        Ok(Self {
            client,
            server_metadata_url,
            default_audience,
        })
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{ClientConfig, Config, TokenEndpointAuthMethod};
    use crate::error::SdkError;

    #[test]
    fn parse_auth_method_aliases() {
        assert_eq!(
            TokenEndpointAuthMethod::parse("CLIENT_SECRET_BASIC").unwrap(),
            TokenEndpointAuthMethod::ClientSecretBasic
        );
        assert_eq!(
            TokenEndpointAuthMethod::parse("post").unwrap(),
            TokenEndpointAuthMethod::ClientSecretPost
        );
        assert!(matches!(
            TokenEndpointAuthMethod::parse("unknown"),
            Err(SdkError::Config(_))
        ));
    }

    #[test]
    fn validate_public_none_without_secret_ok() {
        let c = ClientConfig {
            client_id: "cid".into(),
            redirect_uri: "http://localhost/cb".into(),
            client_secret: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        };
        c.validate().unwrap();
    }

    #[test]
    fn validate_none_rejects_secret() {
        let c = ClientConfig {
            client_id: "cid".into(),
            redirect_uri: "http://localhost/cb".into(),
            client_secret: Some(SecretString::new("s".into())),
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        };
        assert!(matches!(c.validate(), Err(SdkError::Config(_))));
    }

    #[test]
    fn validate_basic_requires_secret() {
        let c = ClientConfig {
            client_id: "cid".into(),
            redirect_uri: "http://localhost/cb".into(),
            client_secret: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        };
        assert!(matches!(c.validate(), Err(SdkError::Config(_))));
    }

    #[test]
    fn config_urls_must_parse() {
        let ok = Config {
            client: ClientConfig {
                client_id: "cid".into(),
                redirect_uri: "http://localhost/cb".into(),
                client_secret: None,
                token_endpoint_auth_method: TokenEndpointAuthMethod::Auto,
            },
            server_metadata_url: "http://127.0.0.1/.well-known/openid-configuration".into(),
            default_audience: None,
        };
        url::Url::parse(&ok.server_metadata_url).unwrap();
        ok.client.validate().unwrap();
    }
}
