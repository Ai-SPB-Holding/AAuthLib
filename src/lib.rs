#![forbid(unsafe_code)]

//! AuthService Rust SDK — OAuth2/OIDC helpers for backend (BFF) integrations.
//!
//! ## Configuration
//!
//! Load [`Config::from_env`](config::Config::from_env) after setting at least `CLIENT_ID`,
//! `REDIRECT_URL`, and `SERVER_METADATA_URL`. Use `CLIENT_SECRET` and
//! [`TokenEndpointAuthMethod`](config::TokenEndpointAuthMethod) when the OAuth client is confidential;
//! see the crate README for a full variable table.
//!
//! ## Main types
//!
//! - [`OAuth2Client`] — token, userinfo, introspect, revoke.
//! - [`DiscoveryClient`] — cached OIDC discovery document.
//! - Optional **feature `axum`** — PKCE state store and authorization-code callback helper.
//!
//! HTTP contracts aligned with the server are documented in **`CONTRACTS.md`** in this crate directory.

pub mod client_auth;
pub mod config;
pub mod discovery;
pub mod error;
pub mod oauth2;
pub mod pkce;
pub mod types;
pub mod user_admin;

#[cfg(feature = "axum")]
pub mod axum;

pub use config::{ClientConfig, Config};
pub use discovery::{DiscoveryClient, OidcDiscoveryDocument};
pub use error::SdkError;
pub use oauth2::OAuth2Client;
pub use pkce::{build_authorize_url, PkceS256};
pub use types::{IntrospectResponse, PasswordGrantResult, TokenSet};
pub use user_admin::{
    CreateServiceUserRequest, ListUsersParams, PatchServiceUserRequest, ServiceUser,
    ServiceUserAdminClient,
};

#[cfg(feature = "axum")]
pub use axum::{
    exchange_authorization_code_with_pkce_store, MemoryPkceStateStore, OAuthCallbackQuery,
    PkceStateStore,
};
