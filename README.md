# Sésame

> OAuth 2.1 + OIDC server for AdonisJS

Sésame turns your AdonisJS application into a full-featured OAuth 2.1 authorization server. This guide covers:

- Installing and configuring the package
- Registering OAuth and discovery routes
- Protecting your API with the OAuth guard and scope checking
- Managing tokens (refresh, revoke, introspect)
- Enabling OpenID Connect (OIDC) for `id_token` emission, `/userinfo`, and JWKS
- Using the Client Credentials grant for machine-to-machine authentication
- Dynamic client registration and MCP support

## Overview

Modern applications need a reliable way to delegate authorization. Sésame implements the OAuth 2.1 specification on top of AdonisJS, giving you an authorization code flow with PKCE, refresh token rotation with replay detection, token introspection, revocation, and dynamic client registration out of the box.

When you need identity claims on top of authorization, Sésame supports OpenID Connect. You provide an RSA key pair, wire up a user provider, and the server starts issuing signed `id_token` JWTs alongside access tokens.

## Installation

```bash
node ace add @julr/sesame
```

This will publish the configuration file to `config/sesame.ts`, create six database migration files, and register the service provider and commands. Then run the migrations:

```bash
node ace migration:run
```

## Configuration

The configuration file lives at `config/sesame.ts`. You define your issuer URL, available scopes, grant types, token lifetimes, and page redirects for the authorization flow.

```ts title="config/sesame.ts"
import env from '#start/env'
import { defineConfig } from '@julr/sesame'
import type { InferScopes } from '@julr/sesame/types'

const sesameConfig = defineConfig({
  issuer: env.get('APP_URL'),

  scopes: {
    read: 'Read access',
    write: 'Write access',
  },

  defaultScopes: ['read'],

  grantTypes: ['authorization_code', 'refresh_token'],

  accessTokenTtl: '1h',
  refreshTokenTtl: '30d',
  authorizationCodeTtl: '10m',

  loginPage: '/login',
  consentPage: '/oauth/consent',

  allowDynamicRegistration: false,
  allowPublicRegistration: false,
})

export default sesameConfig

declare module '@julr/sesame/types' {
  interface SesameScopes extends InferScopes<typeof sesameConfig> {}
}
```

The `SesameScopes` module augmentation gives you type-safe scope names throughout your application. When you reference a scope in middleware or guard calls, TypeScript will autocomplete and validate against the scopes you declared.

## Routes

You must register OAuth routes from your `start/routes.ts` file. The OAuth endpoints go inside a prefix group, and the discovery endpoints go at the root level so they remain at `/.well-known/...`.

```ts title="start/routes.ts"
import sesame from '@julr/sesame/services/main'

// OAuth endpoints under /oauth
router
  .group(() => {
    sesame.registerRoutes()
  })
  .prefix('/oauth')

// Discovery + JWKS endpoints at root
sesame.registerDiscoveryRoutes()
```

This registers the following endpoints:

| Method     | Path                                      | Description                              |
| ---------- | ----------------------------------------- | ---------------------------------------- |
| `POST`     | `/oauth/token`                            | Token endpoint (RFC 6749 §3.2)           |
| `GET`      | `/oauth/authorize`                        | Authorization endpoint (RFC 6749 §3.1)   |
| `POST`     | `/oauth/consent`                          | Consent submission                       |
| `POST`     | `/oauth/introspect`                       | Token introspection (RFC 7662)           |
| `POST`     | `/oauth/revoke`                           | Token revocation (RFC 7009)              |
| `POST`     | `/oauth/register`                         | Dynamic client registration (RFC 7591)   |
| `GET`      | `/oauth/client-info`                      | Public client information                |
| `GET/POST` | `/oauth/userinfo`                         | OpenID Connect UserInfo (OIDC Core §5.3) |
| `GET`      | `/.well-known/oauth-authorization-server` | Server metadata (RFC 8414)               |
| `GET`      | `/.well-known/openid-configuration`       | OIDC discovery                           |
| `GET`      | `/.well-known/oauth-protected-resource`   | Protected resource metadata (RFC 9728)   |
| `GET`      | `/jwks`                                   | JSON Web Key Set (RFC 7517)              |

The JWKS path defaults to `/jwks`. You can customize it:

```ts title="start/routes.ts"
sesame.registerDiscoveryRoutes({ jwksPath: '/.well-known/jwks.json' })
```

## Authorization Code Flow

The authorization code flow works in three steps. All clients must use PKCE with S256 (mandatory per OAuth 2.1).

1. The consuming app redirects the user to `GET /oauth/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, and `code_challenge_method=S256`. If the user is not logged in, they are sent to your `loginPage`. Once authenticated, they see the consent screen (your `consentPage`). If the user has already approved the requested scopes, consent is skipped and the code is issued directly.

2. After the user approves, they are redirected back to the `redirect_uri` with a `code` and `state` parameter. The consuming app exchanges the code at `POST /oauth/token` with `grant_type=authorization_code`, the `code`, `redirect_uri`, client credentials, and the PKCE `code_verifier`. The response contains an `access_token`, `refresh_token` (when the `refresh_token` grant is enabled), `token_type`, `expires_in`, and `scope`. The `iss` parameter is included in all redirect responses per RFC 9207.

3. The consuming app passes the access token as a `Bearer` token in the `Authorization` header when calling your API.

## Authentication Guard

Sésame provides an OAuth guard for `@adonisjs/auth` that verifies opaque Bearer tokens against the database, checks revocation and expiry, and resolves the user model. Configure it in `config/auth.ts`:

```ts title="config/auth.ts"
import { defineConfig } from '@adonisjs/auth'
import { oauthGuard, oauthUserProvider } from '@julr/sesame/guard'

const authConfig = defineConfig({
  default: 'web',
  guards: {
    // ...your other guards
    oauth: oauthGuard({
      provider: oauthUserProvider({ model: () => import('#models/user') }),
    }),
  },
})
```

Then use the guard in your controllers. After authentication, you have access to the user, the granted scopes, and the client ID.

```ts title="app/controllers/api_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'

export default class ApiController {
  async index({ auth }: HttpContext) {
    const guard = auth.use('oauth')
    await guard.authenticate()

    const user = auth.user!
    const scopes = guard.scopes // e.g. ['read', 'write']
    const clientId = guard.clientId // e.g. 'my-app-client-id'

    return { user, scopes, clientId }
  }
}
```

## Scopes

### Scope Middleware

Two named middleware are available for checking scopes on authenticated requests. Use `scopes` when the client must have **all** listed scopes, and `anyScope` when having **at least one** is sufficient.

```ts title="start/routes.ts"
// Requires ALL listed scopes
router.get('/admin', [AdminController]).use(middleware.scopes({ scopes: ['admin', 'write'] }))

// Requires AT LEAST ONE of the listed scopes
router.get('/data', [DataController]).use(middleware.anyScope({ scopes: ['read', 'write'] }))
```

Important: these middleware are `TransientToken`-like. If the request carries an OAuth Bearer token, scopes are enforced against that token. If there is no Bearer token but the request is already authenticated through a session/web guard, the middleware lets the request through instead of rejecting on missing OAuth scopes.

Use these middleware on routes that are allowed to accept either:

- a scoped OAuth access token
- or a first-party session-authenticated user

If you want to require OAuth scopes strictly, authenticate with `auth.use('oauth').authenticate()` in your controller or route pipeline and check scopes on that guard explicitly.

### Programmatic Scope Checking

You can also check scopes directly in your controller logic using `hasScope()` and `hasAnyScope()` on the guard instance. This is useful when you need conditional behavior based on scopes rather than a hard reject.

```ts title="app/controllers/posts_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'

export default class PostsController {
  async index({ auth }: HttpContext) {
    const guard = auth.use('oauth')
    await guard.authenticate()

    // Check if the token has a specific scope
    if (guard.hasScope('write')) {
      return { posts: await Post.all(), canEdit: true }
    }

    return { posts: await Post.all(), canEdit: false }
  }
}
```

`hasScope()` requires **all** provided scopes. `hasAnyScope()` requires **at least one**.

## Managing Tokens

### Refreshing tokens

The consuming app sends `POST /oauth/token` with `grant_type=refresh_token`, the `refresh_token`, and client credentials to get a new token pair. Sésame uses **refresh token rotation**: every refresh returns a new refresh token and the old one is revoked immediately. If an attacker replays a revoked refresh token, all tokens for that client+user pair are nuked as a security measure. The client can request a narrower set of scopes by passing a `scope` parameter, but cannot request scopes that were not in the original grant.

### Revoking tokens

The consuming app can call `POST /oauth/revoke` with the `token`, optional `token_type_hint`, and client credentials. The endpoint always returns HTTP 200, even if the token was not found (to prevent information leakage per RFC 7009). When revoking a refresh token, the associated access token is also revoked automatically.

On the server side, you can revoke all tokens for a user at once. This is useful when a user is deleted or deactivated.

```ts
import sesame from '@julr/sesame/services/main'

await sesame.revokeAllForUser(user.id)
```

### Introspecting tokens

Resource servers can verify a token's state by calling `POST /oauth/introspect` with the `token`, optional `token_type_hint`, and client credentials. The response is `{ "active": true, "token_type": "Bearer", "client_id": "...", "sub": "...", "scope": "...", ... }` for valid tokens, or `{ "active": false }` for invalid, expired, or revoked tokens. This is useful when a separate service needs to validate tokens without sharing database access.

## OpenID Connect (OIDC)

Sésame supports OpenID Connect on top of OAuth 2.1. When OIDC is enabled, the server issues signed `id_token` JWTs alongside access tokens, exposes a `/userinfo` endpoint for retrieving user claims, and publishes a JWKS so relying parties can verify token signatures.

OIDC is opt-in. You need two things: an RSA key pair (JWK) for signing ID tokens, and a user provider so the server can resolve user claims.

### Generating a JWK

You need an RSA private key in JWK format. Generate one with Node.js:

```bash
node -e "
  const { generateKeyPair, exportJWK } = require('jose');
  generateKeyPair('RS256', { extractable: true })
    .then(({ privateKey }) => exportJWK(privateKey))
    .then((jwk) => console.log(JSON.stringify(jwk)))
"
```

Store the output in an environment variable (e.g. `OIDC_JWK`). Never commit the private key to your repository.

### Configuration

Pass the JWK and a user provider to `defineConfig`. The `oidcProvider` uses the same `oauthUserProvider` helper you configure for the auth guard.

```ts title="config/sesame.ts"
import env from '#start/env'
import { defineConfig } from '@julr/sesame'
import { oauthUserProvider } from '@julr/sesame/guard'

const sesameConfig = defineConfig({
  issuer: env.get('APP_URL'),

  scopes: {
    read: 'Read access',
    write: 'Write access',
  },

  loginPage: '/login',
  consentPage: '/oauth/consent',

  // OIDC configuration
  jwk: JSON.parse(env.get('OIDC_JWK')),
  oidcProvider: oauthUserProvider({ model: () => import('#models/user') }),
  idTokenTtl: '1h',
})
```

Both `jwk` and `oidcProvider` must be set for OIDC to be active. If either is missing, the server works as a pure OAuth 2.1 server and OIDC endpoints return 404.

### User Claims

When the `openid` scope is granted, Sésame calls `getOidcClaims()` on your User model to populate the `id_token` and `/userinfo` response with user-specific claims. If the method is not implemented, only protocol-level claims (`sub`, `iss`, `aud`, `exp`, `iat`) are included.

Implement the `OidcSubject` interface and use the `collectOidcClaims` helper for a type-safe, declarative mapping of scopes to claims:

```ts title="app/models/user.ts"
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { collectOidcClaims } from '@julr/sesame/types'
import type { OidcSubject, Scope } from '@julr/sesame/types'

export default class User extends BaseModel implements OidcSubject {
  @column({ isPrimary: true })
  declare id: number

  @column()
  declare fullName: string

  @column()
  declare email: string

  /**
   * Return OIDC claims based on the granted scopes.
   * Protocol-managed claims (sub, iss, aud, exp, iat, nonce, at_hash)
   * are filtered out automatically so you cannot accidentally override them.
   */
  getOidcClaims(scopes: Scope[]) {
    return collectOidcClaims(scopes, {
      profile: { name: this.fullName },
      email: { email: this.email },
    })
  }
}
```

### OIDC Scopes

Three scopes are OIDC-specific: `openid`, `profile`, and `email`. They are recognized by the server without needing to be declared in your `scopes` config.

- `openid` triggers `id_token` emission. The `profile` and `email` scopes are only valid when `openid` is also requested.
- If a client requests `openid` but OIDC is not configured, the authorization endpoint rejects the request with `invalid_scope`.

### How `id_token` Is Issued

When the `openid` scope is present in the authorization code or refresh token exchange, the token response includes an `id_token` field alongside `access_token` and `refresh_token`:

```json
{
  "access_token": "oat_...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "ort_...",
  "id_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

The `id_token` is a signed JWT containing `iss`, `sub`, `aud`, `iat`, `exp`, `at_hash`, and any claims returned by `getOidcClaims()`. When the authorization request included a `nonce` parameter, it is echoed in the `id_token` payload. On refresh token exchanges, the `nonce` is omitted per OIDC Core §12.2.

### UserInfo Endpoint

The `/userinfo` endpoint (GET and POST) returns claims about the authenticated user. It requires a valid access token with the `openid` scope. The token can be passed as a `Bearer` header or as an `access_token` body parameter.

```bash
curl -H "Authorization: Bearer oat_..." https://auth.example.com/oauth/userinfo
```

```json
{
  "sub": "42",
  "name": "Julien Ripouteau",
  "email": "julien@example.com"
}
```

### JWKS Endpoint

The `/jwks` endpoint serves the public key(s) used to sign ID tokens. Relying parties use this to verify `id_token` signatures without needing the private key. The response includes a `Cache-Control` header (`public, max-age=900`) so clients can cache the key set.

## Client Credentials Grant

For machine-to-machine (M2M) authentication, enable the `client_credentials` grant. This allows a confidential client to send `POST /oauth/token` with `grant_type=client_credentials`, its credentials (via Basic auth or POST body), and the requested `scope`. No refresh token is issued.

```ts title="config/sesame.ts"
const sesameConfig = defineConfig({
  // ...
  grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
  clientCredentialsAccessTokenTtl: '2h',
})
```

User-centric scopes (`openid`, `profile`, `email`, `offline_access`) are rejected for client credentials since they are meaningless in an M2M context. The client must be associated with a user (`userId` on the client record) and must be confidential (not public).

## Dynamic Client Registration

Sésame supports RFC 7591 dynamic client registration. Clients send their metadata (`redirect_uris`, `client_name`, `grant_types`, `scope`, `token_endpoint_auth_method`) to `POST /oauth/register` and receive a `client_id` and `client_secret` in return. Set `token_endpoint_auth_method` to `"none"` for public clients (no secret issued). Requested scopes and grant types are validated against your server config.

```ts title="config/sesame.ts"
const sesameConfig = defineConfig({
  // ...
  allowDynamicRegistration: true,
  allowPublicRegistration: true, // allows unauthenticated registration
})
```

## MCP Support

For MCP (Model Context Protocol) servers, you can register per-resource discovery endpoints following RFC 9728. This tells MCP clients which authorization server protects a given resource.

```ts title="start/routes.ts"
sesame.registerProtectedResource({
  resource: '/api/mcp',
  scopes: ['read:mcp'],
})
```

This creates a `/.well-known/oauth-protected-resource/api/mcp` endpoint. MCP clients that support the latest spec will discover this automatically.

MCP clients typically need to self-register, so you will want to enable dynamic client registration with public access (see the [Dynamic Client Registration](#dynamic-client-registration) section above).

## Events

The OAuth guard emits events during authentication that you can listen to for logging, analytics, or custom behavior.

| Event                                 | When                                                                   |
| ------------------------------------- | ---------------------------------------------------------------------- |
| `oauth_auth:authentication_attempted` | A bearer token has been received and authentication starts             |
| `oauth_auth:authentication_succeeded` | The token is valid and the user has been resolved                      |
| `oauth_auth:authentication_failed`    | The token is invalid, expired, revoked, or the user cannot be resolved |

```ts title="start/events.ts"
import emitter from '@adonisjs/core/services/emitter'

emitter.on('oauth_auth:authentication_failed', (event) => {
  logger.warn({ guardName: event.guardName, err: event.error }, 'OAuth authentication failed')
})
```

## Testing

The OAuth guard implements `authenticateAsClient`, which integrates with Japa's `loginAs` helper. This automatically creates a test OAuth client and access token in the database, so your tests can make authenticated API requests without going through the full authorization flow.

```ts title="tests/functional/api.spec.ts"
import { test } from '@japa/runner'
import User from '#models/user'

test.group('API', () => {
  test('returns user data for authenticated request', async ({ client }) => {
    const user = await User.find(1)

    const response = await client.get('/api/me').loginAs(user, 'oauth')

    response.assertStatus(200)
    response.assertBodyContains({ id: user.id })
  })
})
```

The test client is created with `defaultScopes` from your config. The token is scoped to a `__test_client__` OAuth client that gets auto-created on first use.

## Token Cleanup

Expired and revoked tokens accumulate over time. Purge them with the Ace command:

```bash
node ace sesame:purge
node ace sesame:purge --revoked-only
node ace sesame:purge --expired-only
node ace sesame:purge --retention-hours=168
```

The `--retention-hours` flag (default: 168, i.e. 7 days) controls how long expired tokens are kept for audit purposes before deletion.

You can also call it programmatically:

```ts
import sesame from '@julr/sesame/services/main'

const result = await sesame.purgeTokens({ retentionHours: 168 })
// => { accessTokens: 42, refreshTokens: 12, authorizationCodes: 3, pendingRequests: 7 }
```

## Security

- All tokens (access tokens, refresh tokens, authorization codes, client secrets) are stored as **SHA-256 hashes**. Raw values are never persisted in the database.
- PKCE with **S256** is mandatory for all clients (OAuth 2.1).
- Refresh tokens use **rotation**. The old token is revoked immediately on use.
- **Replay detection**: if a revoked refresh token is presented, all tokens for that client+user pair are revoked to mitigate stolen token reuse.
- Client secret verification uses **timing-safe comparison**.
- ID tokens are signed with **RS256** using the configured JWK. The JWKS endpoint only exposes public key components.
- Protocol-managed claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `at_hash`) cannot be overridden by `getOidcClaims()`.
- OAuth errors follow the standard JSON format with proper HTTP status codes and `WWW-Authenticate` headers.

## License

MIT
