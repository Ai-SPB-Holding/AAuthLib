use secrecy::{ExposeSecret, SecretString};

use crate::config::{ClientConfig, TokenEndpointAuthMethod};
use crate::error::SdkError;

/// Resolved auth style for a single HTTP request to the token (or introspect/revoke) endpoint.
#[derive(Clone, Debug)]
pub(crate) enum ResolvedClientAuth {
    None {
        client_id: String,
    },
    Basic {
        client_id: String,
        secret: SecretString,
    },
    Post {
        client_id: String,
        secret: SecretString,
    },
}

impl ResolvedClientAuth {
    pub fn resolve(config: &ClientConfig) -> Result<Self, SdkError> {
        let client_id = config.client_id.clone();
        match config.token_endpoint_auth_method {
            TokenEndpointAuthMethod::Auto => {
                if let Some(ref sec) = config.client_secret {
                    Ok(ResolvedClientAuth::Basic {
                        client_id,
                        secret: sec.clone(),
                    })
                } else {
                    Ok(ResolvedClientAuth::None { client_id })
                }
            }
            TokenEndpointAuthMethod::None => Ok(ResolvedClientAuth::None { client_id }),
            TokenEndpointAuthMethod::ClientSecretBasic => {
                let secret = config.client_secret.clone().ok_or_else(|| {
                    SdkError::config("CLIENT_SECRET required for client_secret_basic")
                })?;
                Ok(ResolvedClientAuth::Basic { client_id, secret })
            }
            TokenEndpointAuthMethod::ClientSecretPost => {
                let secret = config.client_secret.clone().ok_or_else(|| {
                    SdkError::config("CLIENT_SECRET required for client_secret_post")
                })?;
                Ok(ResolvedClientAuth::Post { client_id, secret })
            }
        }
    }

    /// Append `client_id` / `client_secret` to form body when auth is not HTTP Basic.
    /// When [`ResolvedClientAuth::Basic`], credentials go only in `Authorization: Basic`.
    pub fn extend_form_for_token_endpoint(&self, pairs: &mut Vec<(String, String)>) {
        match self {
            ResolvedClientAuth::None { client_id } => {
                pairs.push(("client_id".to_string(), client_id.clone()));
            }
            ResolvedClientAuth::Post { client_id, secret } => {
                pairs.push(("client_id".to_string(), client_id.clone()));
                pairs.push((
                    "client_secret".to_string(),
                    secret.expose_secret().to_string(),
                ));
            }
            ResolvedClientAuth::Basic { .. } => {}
        }
    }

    /// Introspection/revoke merge rules match [`crate::oauth2::OAuth2Client`]: `token`/`client_id` may appear in form.
    pub fn extend_form_for_introspect_revoke(&self, pairs: &mut Vec<(String, String)>) {
        self.extend_form_for_token_endpoint(pairs);
    }
}
