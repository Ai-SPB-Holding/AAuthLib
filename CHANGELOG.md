# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0

### Added

- Initial release: OIDC discovery (cached), OAuth2 token flows (`authorization_code`, `refresh_token`, `embedded_session`, `password`), `userinfo`, `introspect`, `revoke`.
- `Config` / `ClientConfig` from environment; `TokenEndpointAuthMethod` and `ResolvedClientAuth` for public vs confidential clients.
- Optional `axum` feature: PKCE state store and authorization-code exchange helper.
- `client_credentials` helper that surfaces `SdkError::UnsupportedGrantType` when the server rejects the grant (current AuthService behavior).
