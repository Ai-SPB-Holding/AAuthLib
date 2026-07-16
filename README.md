# authservice-sdk

Rust library for backend (BFF) integrations with **AuthService**: OIDC discovery, OAuth2 `/oauth2/token` flows (authorization code + PKCE, refresh, embedded session exchange, optional password grant), `userinfo` / `introspect` / `revoke`, and optional **Axum** helpers.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CLIENT_ID` | yes | OAuth `client_id` from the admin UI |
| `REDIRECT_URL` | yes | Registered redirect URI (must match the client allowlist) |
| `SERVER_METADATA_URL` | yes | Full URL to `/.well-known/openid-configuration` for this deployment |
| `CLIENT_SECRET` | see below | Optional for **public** (PKCE) clients; **required** for confidential clients when using `client_secret_basic` or `client_secret_post` in the database |
| `TOKEN_ENDPOINT_AUTH_METHOD` | no | `auto` (default), `none`, `basic` / `client_secret_basic`, `post` / `client_secret_post` — must match the client’s `token_endpoint_auth_method` in AuthService |
| `DEFAULT_AUDIENCE` | no | Default `audience` for token calls when you omit per-call audience (`embedded_session`, `password`, `refresh`, etc.) |

### When is `CLIENT_SECRET` needed?

- **`TOKEN_ENDPOINT_AUTH_METHOD=auto` (default):** if `CLIENT_SECRET` is set (non-empty), the SDK uses HTTP Basic toward `/oauth2/token` when the server expects a confidential client; if unset, it behaves as a public client (`client_id` in form where applicable).
- **`none`:** must **not** set `CLIENT_SECRET` (public client).
- **`basic` / `post`:** must set `CLIENT_SECRET` and align with how the client is registered in AuthService.

## Cargo dependency

**Path** (monorepo checkout):

```toml
authservice-sdk = { path = "AAuthLib/authservice-sdk" }
```

**Git** (subset of the monorepo; Cargo 1.64+; replace `OWNER` / branch):

```toml
[dependencies]
authservice-sdk = { git = "https://github.com/OWNER/AuthService.git", branch = "main", subdirectory = "AAuthLib/authservice-sdk" }
```

After **crates.io** publication, prefer `authservice-sdk = "0.1"` (or the current semver).

Before publishing, set the real `repository` URL in this crate’s [`Cargo.toml`](Cargo.toml) (placeholder `OWNER`).

### Features

- **TLS:** default `rustls-tls`; optional `native-tls`
- **`axum`:** PKCE state store + `exchange_authorization_code_with_pkce_store`

```toml
authservice-sdk = { path = "AAuthLib/authservice-sdk", features = ["axum"] }
```

## Quick usage

```rust
use authservice_sdk::{build_authorize_url, Config, OAuth2Client, PkceS256};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let http = reqwest::Client::builder().build()?;
let cfg = Config::from_env()?;
let oauth = OAuth2Client::from_config(http, &cfg);
let meta = oauth.metadata().await?;

let pkce = PkceS256::generate();
let auth_url = build_authorize_url(
    &meta.authorization_endpoint,
    &cfg.client.client_id,
    &cfg.client.redirect_uri,
    &pkce,
    Some("openid profile email"),
    Some("opaque-state"),
    None,
)?;

// Redirect user to `auth_url`. After callback:
let _tokens = oauth.exchange_authorization_code(
    &cfg.client,
    "authorization-code-from-query",
    &pkce.code_verifier,
    &cfg.client.redirect_uri,
    cfg.default_audience.as_deref(),
).await?;
# Ok(())
# }
```

See [`CONTRACTS.md`](CONTRACTS.md) for request/response fields aligned with the server.

## Examples

```bash
cargo run -p authservice-sdk --example bff_auth_code --features axum
cargo run -p authservice-sdk --example bff_embedded_session
cargo run -p authservice-sdk --example client_credentials
cargo run -p authservice-sdk --example service_user_admin
```

Confidential clients with `users.read` / `users.write` / `users.delete` / `users.manage` scopes can manage tenant users via [`ServiceUserAdminClient`](src/user_admin.rs) (HTTP Basic or `client_credentials` bearer).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).
