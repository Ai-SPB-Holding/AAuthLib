//! PKCE (RFC 7636) code verifier / S256 challenge generation.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};

/// PKCE pair using `S256` (`code_challenge_method=S256`).
#[derive(Debug, Clone)]
pub struct PkceS256 {
    pub code_verifier: String,
    pub code_challenge: String,
}

impl PkceS256 {
    /// Random URL-safe verifier (~64 chars) and derived S256 challenge.
    pub fn generate() -> Self {
        let verifier = random_verifier(64);
        let challenge = compute_challenge_s256(&verifier);
        Self {
            code_verifier: verifier,
            code_challenge: challenge,
        }
    }
}

fn random_verifier(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

pub(crate) fn compute_challenge_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Build browser redirect URL for AuthService `GET /oauth2/authorize`.
pub fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkceS256,
    scope: Option<&str>,
    state: Option<&str>,
    nonce: Option<&str>,
) -> Result<url::Url, crate::error::SdkError> {
    let mut u = url::Url::parse(authorization_endpoint)
        .map_err(crate::error::SdkError::UrlParse)?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("code_challenge", &pkce.code_challenge);
        q.append_pair("code_challenge_method", "S256");
        if let Some(s) = scope {
            q.append_pair("scope", s);
        }
        if let Some(s) = state {
            q.append_pair("state", s);
        }
        if let Some(n) = nonce {
            q.append_pair("nonce", n);
        }
    }
    Ok(u)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pkce_s256_matches_sha256_base64url_nopad() {
        // Same verifier string as RFC 7636 appendix B (challenge text in some RFC copies is inconsistent).
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            super::compute_challenge_s256(v),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
