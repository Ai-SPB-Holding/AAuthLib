//! Build `/oauth2/authorize` URL with PKCE and complete callback exchange (Axum-oriented helpers).
//!
//! Run with real AuthService URLs:
//! ```text
//! SERVER_METADATA_URL=https://auth.example/.well-known/openid-configuration \
//! CLIENT_ID=... REDIRECT_URL=https://app/callback \
//! cargo run -p authservice-sdk --example bff_auth_code --features axum
//! ```

use authservice_sdk::{
    build_authorize_url, exchange_authorization_code_with_pkce_store, Config, MemoryPkceStateStore,
    OAuth2Client, OAuthCallbackQuery, PkceS256,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_demo_env_if_missing();

    let cfg = Config::from_env()?;
    let http = reqwest::Client::builder().build()?;
    let oauth = OAuth2Client::from_config(http, &cfg);

    let meta = oauth.metadata().await?;
    let pkce = PkceS256::generate();
    let state = uuid::Uuid::new_v4().to_string();

    let store = MemoryPkceStateStore::new();
    store
        .insert(state.clone(), pkce.code_verifier.clone())
        .await;

    let auth_url = build_authorize_url(
        &meta.authorization_endpoint,
        &cfg.client.client_id,
        &cfg.client.redirect_uri,
        &pkce,
        Some("openid profile email"),
        Some(&state),
        None,
    )?;

    println!("Open in browser (after idp_session cookie / login flow):\n{auth_url}\n");

    // Simulated redirect callback:
    let callback = OAuthCallbackQuery {
        code: "would-come-from-query".to_string(),
        state,
    };

    let result = exchange_authorization_code_with_pkce_store(
        &oauth,
        &cfg.client,
        &store,
        &callback,
        &cfg.client.redirect_uri,
        cfg.default_audience.as_deref(),
    )
    .await;

    println!("Exchange result (expected failure without real code): {result:?}");

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
