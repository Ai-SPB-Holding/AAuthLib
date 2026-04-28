# AuthService HTTP contracts (SDK reference)

Sources: `backend/src/http/handlers/oauth2.rs`, `oidc.rs`, `embedded_login.rs`.

## Discovery

- `GET /.well-known/openid-configuration` — JSON; uses `token_endpoint`, `authorization_endpoint`, `userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`, `jwks_uri`.

## Token endpoint

`POST /oauth2/token` — `Content-Type: application/x-www-form-urlencoded`.

Supported **`grant_type`** values:

| `grant_type`          | Required fields (typical) |
|-----------------------|---------------------------|
| `authorization_code`| `code`, `redirect_uri`, `code_verifier`, `client_id` (or Basic auth); optional `audience` |
| `refresh_token`      | `refresh_token`; optional `audience` |
| `password`           | `tenant_id`, `email`, `password`, `audience`; optional `client_id` — **only if** `AUTH__ALLOW_RESOURCE_OWNER_PASSWORD_GRANT=true` |
| `embedded_session`   | `code`, `audience`, `client_id` (or Basic auth) |

**Not implemented on `/oauth2/token`:** `client_credentials` — server responds with validation / unsupported `grant_type`.

Client authentication:

- Public clients: `client_id` in body (no secret).
- Confidential: HTTP Basic (`Authorization: Basic …`) or `client_secret_post` (`client_id` + `client_secret` in body), per DB `token_endpoint_auth_method`.

Successful token JSON matches `TokenPair` style:

- `access_token`, `refresh_token`, `token_type`, `expires_in`, optional `id_token` (if `openid` scope).

## Userinfo / introspect / revoke

- `GET /oauth2/userinfo` — `Authorization: Bearer <access_token>` → JSON claims.
- `POST /oauth2/introspect` — form: `token`, optional `token_type_hint`, plus client auth.
- `POST /oauth2/revoke` — form: `token`, plus client auth.

## Embedded → BFF

1. Iframe: `POST /api/session-code` with short-lived iframe access token → returns one-time `code`.
2. BFF: `POST /oauth2/token` with `grant_type=embedded_session`, `code`, `audience`, `client_id` (+ secret if confidential).
