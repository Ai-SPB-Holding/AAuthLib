//! Tenant user admin via confidential client + `users.manage` scope.

use authservice_sdk::{
    Config, CreateServiceUserRequest, ListUsersParams, OAuth2Client, ServiceUserAdminClient,
};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_demo_env_if_missing();

    let cfg = Config::from_env()?;
    let http = reqwest::Client::builder().build()?;
    let oauth = OAuth2Client::from_config(http.clone(), &cfg);

    let admin = ServiceUserAdminClient::from_config(http, &cfg)?
        .with_client_credentials(&oauth, Some("users.manage"), cfg.default_audience.as_deref())
        .await?;

    let users = admin.list_users(ListUsersParams::default()).await?;
    println!("Existing users: {}", users.len());

    let email = format!("sdk-user-{}@example.test", Uuid::new_v4().as_simple());
    let created = admin
        .create_user(CreateServiceUserRequest {
            email: email.clone(),
            password: "SecurePass!2026".into(),
            email_verified: Some(true),
            role_ids: vec![],
        })
        .await?;
    println!("Created user {} ({})", created.email, created.id);

    admin.delete_user(created.id).await?;
    println!("Deleted user {}", created.id);

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
