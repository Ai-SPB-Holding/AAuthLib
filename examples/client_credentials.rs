//! Calls `grant_type=client_credentials`. AuthService currently rejects this grant — demonstrates [`authservice_sdk::SdkError::UnsupportedGrantType`].

use authservice_sdk::{Config, OAuth2Client, SdkError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_demo_env_if_missing();

    let cfg = Config::from_env()?;
    let http = reqwest::Client::builder().build()?;
    let oauth = OAuth2Client::from_config(http, &cfg);

    let result = oauth
        .client_credentials(&cfg.client, Some("read"), cfg.default_audience.as_deref())
        .await;

    match result {
        Ok(_) => println!("unexpected success"),
        Err(SdkError::UnsupportedGrantType(msg)) => println!("Expected unsupported grant:\n{msg}"),
        Err(e) => println!("Other error (e.g. connection): {e:?}"),
    }

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
