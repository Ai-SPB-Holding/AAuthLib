//! Calls `grant_type=client_credentials` (confidential clients only).

use authservice_sdk::{Config, OAuth2Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_demo_env_if_missing();

    let cfg = Config::from_env()?;
    let http = reqwest::Client::builder().build()?;
    let oauth = OAuth2Client::from_config(http, &cfg);

    let tokens = oauth
        .client_credentials(&cfg.client, Some("users.read"), cfg.default_audience.as_deref())
        .await?;

    println!(
        "access_token prefix: {}…",
        &tokens.access_token[..tokens.access_token.len().min(24)]
    );
    println!("expires_in: {}", tokens.expires_in);

    Ok(())
}

fn load_demo_env_if_missing() {
    use std::env;
    if env::var("CLIENT_ID").is_err() {
        env::set_var("CLIENT_ID", "demo-client");
    }
    if env::var("CLIENT_SECRET").is_err() {
        env::set_var("CLIENT_SECRET", "demo-secret");
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
