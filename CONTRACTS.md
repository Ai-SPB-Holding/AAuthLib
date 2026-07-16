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
| `client_credentials` | confidential client auth; optional `audience` |

Machine clients (e.g. Mail Sync Provider workers) should use scopes such as `mail.sync.read`, `mail.sync.write`, `mail.send` on the OAuth client record.

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

## Service key introspect (MailService integration)

`POST /api/service-keys/introspect` — `Content-Type: application/x-www-form-urlencoded`.

Used by MailService to resolve tenant context for opaque universal keys (`auk_*`). AuthService does **not** validate the opaque key itself; MailService validates `auk_*` locally. This endpoint authenticates a **confidential** OAuth client and returns tenant/scopes from the client record.

| Field | Required | Notes |
|-------|----------|-------|
| `key` | yes | Universal key string (contract + stable `key_id` tracing) |
| `client_id` | yes* | OAuth client id (*or HTTP Basic) |
| `client_secret` | yes* | Required for confidential clients (*or HTTP Basic) |

Successful JSON:

```json
{
  "active": true,
  "key_id": "uuid",
  "tenant_id": "uuid",
  "scopes": ["mail.send"],
  "status": "active"
}
```

Client must include `mail.send` in its configured OAuth `scopes`; otherwise `403`.

## Service user admin (tenant-scoped machine API)

Confidential OAuth clients with user-admin scopes can manage users in **their own tenant** via:

`GET|POST /api/service/v1/users`, `GET|PATCH|DELETE /api/service/v1/users/{id}`, `PUT /api/service/v1/users/{id}/roles`.

Authentication (one of):

1. HTTP Basic (`client_id:client_secret`) on each request, or
2. `Authorization: Bearer` from `grant_type=client_credentials`.

Required OAuth client scopes (space-separated in client record):

| Scope | Operations |
|-------|------------|
| `users.read` | list, get |
| `users.write` | create, update, set roles |
| `users.delete` | delete |
| `users.manage` | all of the above |

`tenant_id` is taken from the client record only; callers cannot target another tenant.

SDK: [`ServiceUserAdminClient`](src/user_admin.rs) in this crate (`examples/service_user_admin.rs`).

## Tenant manager panel API

Human managers assigned in `tenant_managers` log in at `POST /api/tenant-manager/v1/session` and use `/api/tenant-manager/v1/*` with Bearer JWT (`aud` = `AUTH__TENANT_MANAGER_API_AUDIENCE`, role `tenant_manager`). Same user CRUD semantics as above but scoped to the manager's tenant (all users, not only `registration_source` = client_id).
