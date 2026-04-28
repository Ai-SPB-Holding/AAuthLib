//! Exchange one-time embedded iframe `code` at `/oauth2/token` (`grant_type=embedded_session`).

use authservice_sdk::{Config, OAuth2Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_demo_env_if_missing();

    let mut cfg = Config::from_env()?;
    if cfg.default_audience.is_none() {
        cfg.default_audience = Some("your-api-audience".to_string());
    }

    let http = reqwest::Client::builder().build()?;
    let oauth = OAuth2Client::from_config(http, &cfg);

    let code = "one-time-code-from-post-api-session-code";
    let result = oauth
        .exchange_embedded_session(&cfg.client, code, cfg.default_audience.as_deref())
        .await;

    println!("embedded_session exchange (expects running AuthService): {result:?}");
    Ok(())
}

fn load_demo_env_if_missing() {
    use std::env;
    if env::var("CLIENT_ID").is_err() {
        env::set_var("CLIENT_ID", "demo-client");
    }
    if env::var("REDIRECT_URL").is_err() {
        env::set_var("REDIRECT_URL", "http://127.0.0.1:8080/callback");
    }
    if env::var("SERVER_METADATA_URL").is_err() {
        env::set_var(
            "SERVER_METADATA_URL",
            "http://127.0.0.1/.well-known/openid-configuration",
        );
    }
}
