# Sésame

<p align="center">
  <img src="docs/assets/sesame-logo-readme.png" alt="Sésame" width="560" />
</p>

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

`@adonisjs/auth` is required, including when you use Kysely without Lucid. If your Lucid application does not already have Auth configured, run `node ace add @adonisjs/auth --guard=session` first. This registers Auth's provider and initialization middleware in addition to installing the package. Keep your existing Auth setup if it is already configured.

```bash title="Terminal"
node ace add @julr/sesame
```

By default, this publishes `config/sesame.ts`, creates six Lucid migrations, and registers the service provider and commands. Make sure `@adonisjs/lucid` is installed in your application, then run the migrations:

```bash title="Terminal"
node ace migration:run
```

### Kysely installation

You can use Sésame in a Kysely application without installing Lucid. The installer publishes a configuration file and a migration, but it does not connect to the database or create tables automatically.

If Auth is not already configured, install `@adonisjs/auth` with `pnpm add @adonisjs/auth`, add `() => import('@adonisjs/auth/auth_provider')` to the `providers` array in `adonisrc.ts`, and add `router.use([() => import('@adonisjs/auth/initialize_auth_middleware')])` to `start/kernel.ts`. Do not run `node ace add @adonisjs/auth` for this path: its bundled installer currently generates a Lucid user model and migration. For the interactive authorization flow, configure `@adonisjs/session` in your application and use a session guard as the default; the OAuth guard authenticates Bearer tokens, not browser login sessions.

```bash title="Terminal"
pnpm add kysely
node ace add @julr/sesame --store=kysely
```

The generated `config/sesame.ts` selects the Kysely driver. Its `#services/kysely` import is a placeholder. Replace it with the module that exports your application's existing Kysely connection. For example, if that module exports `appDb` from `#services/database`, configure the store like this:

```ts title="config/sesame.ts"
import env from '#start/env'
import { defineConfig, stores } from '@julr/sesame'
import type { InferScopes } from '@julr/sesame/types'

const sesameConfig = defineConfig({
  issuer: env.get('APP_URL'),
  store: stores.kysely({
    connection: async () => {
      const { appDb } = await import('#services/database')
      return appDb
    },
  }),
  scopes: {},
  defaultScopes: [],
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

> [!WARNING]
> The generated config reads `APP_URL`. Your `start/env.ts` must validate that variable, and its value must be the public URL of the OAuth server, not the frontend URL or a `0.0.0.0` bind address. If your application already validates another public API URL, use that variable for `issuer` instead. Without a validated value, `env.get('APP_URL')` can be `undefined` and TypeScript will reject the config.

The installer writes the complete migration to `database/kysely_migrations/create_oauth_tables.ts`. Keep that generated file in your application as a schema snapshot. When you already have a Kysely migrator, move it into that migrator's `migrationFolder`, give it a filename that sorts after your existing migrations, and run your usual migration command. For example, an application whose migrator reads `database/migrations` should put the file there. Do not pass it to Lucid's `node ace migration:run`.

If Sésame uses its own migration folder, configure a separate [Kysely migrator](https://kysely-org.github.io/kysely-apidoc/classes/migration.Migrator.html) for `database/kysely_migrations` and call `migrateToLatest()` explicitly. Give that migrator unique `migrationTableName` and `migrationLockTableName` values when your application already has another Kysely migrator on the same database. Commit the generated migration so future Sésame upgrades cannot alter a migration you already applied.

The Kysely driver supports SQLite, PostgreSQL, and MySQL. For a custom Kysely dialect backed by one of these databases, pass its `dialect` explicitly to `stores.kysely()`.

Sésame configures one `store` at a time. It must be an AdonisJS `ConfigProvider<SesameStore>`; the service provider resolves it with the application before creating the manager. Choose `stores.lucid()`, `stores.kysely()`, or a custom driver. To add a custom driver, implement `SesameStore` from `@julr/sesame/types` and wrap it with `configProvider.create()`. The store interface exposes OAuth operations rather than generic CRUD queries. Its `exchangeAuthorizationCode`, `rotateRefreshToken`, and `issueTokenPair` methods must use real database transactions; the first two return `false` when another request consumed the credential first. `purgeUnusedClients` should also run in a transaction and re-check client usage in its `DELETE`.

Upgrading an existing Lucid application from 0.6.0 requires config and import changes. Follow the [0.6.0 to 0.7.0 migration guide](docs/migration-0.6-to-0.7.md).

## Configuration

The configuration file lives at `config/sesame.ts`. You define your issuer URL, available scopes, grant types, token lifetimes, and page redirects for the authorization flow.

```ts title="config/sesame.ts"
import env from '#start/env'
import { defineConfig, stores } from '@julr/sesame'
import type { InferScopes } from '@julr/sesame/types'

const sesameConfig = defineConfig({
  issuer: env.get('APP_URL'),

  store: stores.lucid(),

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
import router from '@adonisjs/core/services/router'
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

### Consent page

Sésame redirects authenticated users to your `consentPage` with the original authorize query parameters plus an `auth_token`. Use `findPendingAuthorizationRequest` to display the stored request: always render the client and scopes from the stored record, never from the editable query string.

The simplest consent page posts a form to the built-in `POST /oauth/consent` route:

| Field        | Description                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------ |
| `auth_token` | Required. The raw token received by the consent page                                                   |
| `accept`     | Any truthy value approves. Omit it (or send JSON `false`) to deny                                      |
| `scope`      | Optional. Space-delimited string or array of scopes to grant. Must be a subset of the requested scopes |

When `scope` is omitted, every requested scope is granted. With checkboxes, an unchecked box is simply not sent: if the user can uncheck everything, handle the decision in your own controller as shown below rather than posting an empty form.

### Handling consent in your own controller

When you need more control (granting fewer scopes than requested, an Inertia page, extra checks before approving), call `approveAuthorization` and `denyAuthorization` from your own controller. Both consume the pending request atomically and return the client redirect URL instead of redirecting, so you can use `response.redirect()` or `inertia.location()`.

```ts title="app/controllers/oauth_consent_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'
import sesame from '@julr/sesame/services/main'

export default class OauthConsentController {
  async show({ auth, request, response, view }: HttpContext) {
    const authToken = request.input('auth_token')
    const userId = String(auth.getUserOrFail().id)

    const pending = await sesame.findPendingAuthorizationRequest({ token: authToken, userId })
    if (!pending) return response.badRequest('Authorization request not found or expired')

    const client = await sesame.findClient(pending.clientId)

    return view.render('oauth/consent', { authToken, client, scopes: pending.scopes })
  }

  async decide({ auth, request, response }: HttpContext) {
    const authToken = request.input('auth_token')
    const userId = String(auth.getUserOrFail().id)

    if (request.input('decision') !== 'approve') {
      const { redirectUrl } = await sesame.denyAuthorization({ authToken, userId })
      return response.redirect(redirectUrl)
    }

    const readOnly = request.input('read_only') === 'on'
    const { redirectUrl } = await sesame.approveAuthorization({
      authToken,
      userId,
      scopes: readOnly ? ['read'] : undefined,
    })

    return response.redirect(redirectUrl)
  }
}
```

`approveAuthorization` returns `{ redirectUrl, clientId, scopes }`, where `scopes` lists the scopes actually granted. The authorization code only carries those scopes, and the token endpoint returns them in its `scope` field so the client knows what it received (OAuth 2.1 §1.4.1). `denyAuthorization` returns the same shape with an `access_denied` redirect URL and an empty `scopes` list.

Both methods throw the standard Sésame OAuth errors, which render as JSON when left uncaught:

- `E_INVALID_GRANT` when the request is unknown, expired, already used, or belongs to another user
- `E_INVALID_SCOPE` when `scopes` is empty, contains a scope that was not requested, or contains `profile`/`email` without `openid`. These checks run before the request is consumed, so the user can still submit a valid decision
- `E_INVALID_CLIENT` when the client was deleted or disabled in the meantime

Approved scopes are remembered per client and user, and merged with previously approved ones. Future requests covered by the remembered scopes skip the consent page, unless the client sends `prompt=consent`. Denying a request does not change the remembered consent.

### The `prompt` parameter

Sésame supports two values of the OpenID Connect `prompt` parameter, with or without the `openid` scope, and advertises them in `prompt_values_supported`:

- `prompt=consent` always shows the consent page, even when the user already approved the requested scopes.
- `prompt=none` never shows a page. Sésame redirects back to the client with `error=login_required` when the user is not logged in, or `error=consent_required` when the requested scopes are not covered by a remembered consent. Combining `none` with another value returns `error=invalid_request`.

Other values (`login`, `select_account`, `create`) and `max_age` are ignored.

## Authentication Guard

Sésame provides an OAuth guard for `@adonisjs/auth` that verifies opaque Bearer tokens against the database, checks revocation and expiry, and resolves the user. In a Lucid application configured with the session guard, add the OAuth guard while keeping `web` as the default. Sésame uses that default guard to identify the logged-in user during authorization and consent:

```ts title="config/auth.ts"
import { defineConfig } from '@adonisjs/auth'
import { sessionGuard, sessionUserProvider } from '@adonisjs/auth/session'
import type { InferAuthenticators, InferAuthEvents, Authenticators } from '@adonisjs/auth/types'
import { oauthGuard } from '@julr/sesame/guard'
import { oauthUserProvider } from '@julr/sesame/guard/lucid'

const authConfig = defineConfig({
  default: 'web',
  guards: {
    web: sessionGuard({
      useRememberMeTokens: false,
      provider: sessionUserProvider({ model: () => import('#models/user') }),
    }),
    oauth: oauthGuard({
      provider: oauthUserProvider({ model: () => import('#models/user') }),
    }),
  },
})

export default authConfig

declare module '@adonisjs/auth/types' {
  interface Authenticators extends InferAuthenticators<typeof authConfig> {}
}

declare module '@adonisjs/core/types' {
  interface EventsList extends InferAuthEvents<Authenticators> {}
}
```

### Kysely user provider

The Kysely store handles OAuth records, not your application's users. In a Lucid-free app, provide a user lookup for the OAuth guard and OIDC. This example assumes that your existing `appDb` connection has a `users` table with string `id` and `email` columns. Adapt the query and identifier conversion to your schema:

```ts title="app/auth/kysely_oauth_user_provider.ts"
import { symbols } from '@adonisjs/auth'
import type { OAuthGuardUser, OAuthUserProviderContract } from '@julr/sesame/guard'
import { appDb } from '#services/database'

type User = {
  id: string
  email: string
  getOidcClaims(scopes: string[]): Record<string, unknown>
}

export class KyselyOAuthUserProvider implements OAuthUserProviderContract<User> {
  declare [symbols.PROVIDER_REAL_USER]: User

  async createUserForGuard(user: User): Promise<OAuthGuardUser<User>> {
    return { getId: () => user.id, getOriginal: () => user }
  }

  async findById(identifier: string | number | BigInt): Promise<OAuthGuardUser<User> | null> {
    const row = await appDb
      .selectFrom('users')
      .select(['id', 'email'])
      .where('id', '=', String(identifier))
      .executeTakeFirst()

    if (!row) return null

    const user: User = {
      id: row.id,
      email: row.email,
      getOidcClaims(scopes) {
        return scopes.includes('email') ? { email: row.email } : {}
      },
    }

    return this.createUserForGuard(user)
  }
}

export const kyselyOAuthUserProvider = new KyselyOAuthUserProvider()
```

Configure this provider for both the default session guard (browser login) and the OAuth guard (Bearer tokens). This assumes `@adonisjs/session` is installed and configured and your `/login` page signs users into the `web` guard:

```ts title="config/auth.ts"
import { defineConfig } from '@adonisjs/auth'
import { sessionGuard } from '@adonisjs/auth/session'
import type { InferAuthenticators, InferAuthEvents, Authenticators } from '@adonisjs/auth/types'
import { oauthGuard } from '@julr/sesame/guard'
import { kyselyOAuthUserProvider } from '../app/auth/kysely_oauth_user_provider.js'

const authConfig = defineConfig({
  default: 'web',
  guards: {
    web: sessionGuard({ useRememberMeTokens: false, provider: kyselyOAuthUserProvider }),
    oauth: oauthGuard({ provider: kyselyOAuthUserProvider }),
  },
})

export default authConfig

declare module '@adonisjs/auth/types' {
  interface Authenticators extends InferAuthenticators<typeof authConfig> {}
}

declare module '@adonisjs/core/types' {
  interface EventsList extends InferAuthEvents<Authenticators> {}
}
```

Use the same `kyselyOAuthUserProvider` as `oidcProvider` in `config/sesame.ts` if you enable OIDC. The `getOidcClaims()` method above includes the email claim when the client has the `email` scope.

Then use the guard in your controllers. After authentication, you have access to the user, the granted scopes, the client ID, and the access token that authenticated the request.

```ts title="app/controllers/api_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'

export default class ApiController {
  async index({ auth }: HttpContext) {
    const guard = auth.use('oauth')
    await guard.authenticate()

    const user = auth.user!
    const scopes = guard.scopes // e.g. ['read', 'write']
    const clientId = guard.clientId // e.g. 'my-app-client-id'
    const tokenId = guard.accessToken!.id // e.g. '0b6f…' (access token record id)

    return { user, scopes, clientId, tokenId }
  }
}
```

`guard.accessToken` holds `id`, `clientId`, `userId`, `scopes`, `expiresAt`, and `createdAt`. It never contains the token value or its hash. Use the `id` to correlate audit logs with a token.

Sésame does not track a "last used" date. Access tokens are short-lived and rotated on refresh, and writing on every request has a cost. If you need it, listen to `oauth_auth:authentication_succeeded` (see [Events](#events)) and record usage in your app, ideally throttled.

## Scopes

### Scope Middleware

Two named middleware are available for checking scopes on authenticated requests. Use `scopes` when the client must have **all** listed scopes, and `anyScope` when having **at least one** is sufficient.

```ts title="start/routes.ts"
import router from '@adonisjs/core/services/router'
import { middleware } from '#start/kernel'

// Requires ALL listed scopes
router
  .get('/admin', async () => ({ ok: true }))
  .use(middleware.scopes({ scopes: ['read', 'write'] }))

// Requires AT LEAST ONE of the listed scopes
router
  .get('/data', async () => ({ ok: true }))
  .use(middleware.anyScope({ scopes: ['read', 'write'] }))
```

Important: these middleware are `TransientToken`-like. If the request carries an OAuth Bearer token, scopes are enforced against that token. If there is no Bearer token but the request is already authenticated through a session/web guard, the middleware lets the request through instead of rejecting on missing OAuth scopes.

Use these middleware on routes that are allowed to accept either:

- a scoped OAuth access token
- or a first-party session-authenticated user

If you want to require OAuth scopes strictly, authenticate with `auth.use('oauth').authenticate()` in your controller or route pipeline and check scopes on that guard explicitly.

### Scope challenges

When a request is rejected, the `WWW-Authenticate` header tells the client which scopes to request (RFC 6750, MCP authorization spec):

- **401** (missing, invalid, or expired token): `scope` lists the scopes declared for the guard's resource with `registerProtectedResource()` plus the scopes required by the route middleware. A route using `anyScope` adds nothing when the resource scopes already satisfy it. When both lists are empty, `scope` is omitted and clients fall back to `scopes_supported` from the protected resource metadata.
- **403** (`insufficient_scope`): `scope` lists the scopes already granted to the token plus the required ones, so a client re-authorizing with that list does not lose its current permissions. The header also carries `resource_metadata`.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/mcp", scope="read"
```

The route scopes can only be advertised when the scope middleware raises the 401. It also works when the guard already ran without them earlier in the request (for example `ctx.auth.check()` with `oauth` as the default guard): the challenge is rewritten. However, if an `auth` middleware such as `middleware.auth({ guards: ['oauth'] })` runs before `middleware.scopes()` and rejects the request, the scope middleware never runs and the 401 only lists the resource scopes. The scope middleware authenticates OAuth requests by itself, so drop the `auth` middleware on those routes, or declare the scopes on the resource with `registerProtectedResource()`.

To advertise route scopes when calling the guard yourself, pass them to `authenticate()`:

```ts
await auth.use('oauth').authenticate({ scopes: ['read', 'write'] })
```

To reject with a 403 challenge from your own code, throw `guard.insufficientScopeError(['write'])`.

### Programmatic Scope Checking

You can also check scopes directly in your controller logic using `hasScope()` and `hasAnyScope()` on the guard instance. This is useful when you need conditional behavior based on scopes rather than a hard reject.

```ts title="app/controllers/posts_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'

export default class PostsController {
  async index({ auth }: HttpContext) {
    const guard = auth.use('oauth')
    await guard.authenticate()

    if (guard.hasScope('write')) return { canEdit: true }

    return { canEdit: false }
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

```ts title="app/controllers/users_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'
import sesame from '@julr/sesame/services/main'

export default class UsersController {
  async revokeTokens({ params }: HttpContext) {
    await sesame.revokeAllForUser(String(params.id))

    return { revoked: true }
  }
}
```

### Introspecting tokens

Resource servers can verify a token's state by calling `POST /oauth/introspect` with the `token`, optional `token_type_hint`, and client credentials. The response is `{ "active": true, "token_type": "Bearer", "client_id": "...", "sub": "...", "scope": "...", ... }` for valid tokens, or `{ "active": false }` for invalid, expired, or revoked tokens. This is useful when a separate service needs to validate tokens without sharing database access.

## OpenID Connect (OIDC)

Sésame supports OpenID Connect on top of OAuth 2.1. When OIDC is enabled, the server issues signed `id_token` JWTs alongside access tokens, exposes a `/userinfo` endpoint for retrieving user claims, and publishes a JWKS so relying parties can verify token signatures.

OIDC is opt-in. You need two things: an RSA key pair (JWK) for signing ID tokens, and a user provider so the server can resolve user claims.

### Generating a JWK

You need an RSA private key in JWK format. The easiest way is to write it directly to your `.env` file:

```bash title="Terminal"
node ace sesame:key --write-env
```

This generates a JWK and adds (or replaces) `OIDC_JWK` in your `.env` file. Never commit the private key to your repository.

You can also output the raw JSON for piping to a secret manager or file:

```bash title="Terminal"
node ace sesame:key --raw > jwk.json
```

Or run `node ace sesame:key` without flags to see the key with usage instructions.

### Configuration

Pass the JWK and a user provider to `defineConfig`. With Lucid, `oidcProvider` can use the same `oauthUserProvider` helper as the auth guard. With Kysely, pass your `KyselyOAuthUserProvider` instead and keep `stores.kysely()` as the store. The example declares `profile` and `email` in `scopes` so the `Scope` type also accepts them in the claims example below; they do not need to be declared for runtime validation.

```ts title="config/sesame.ts"
import env from '#start/env'
import { defineConfig, stores } from '@julr/sesame'
import { oauthUserProvider } from '@julr/sesame/guard/lucid'
import type { InferScopes } from '@julr/sesame/types'

const sesameConfig = defineConfig({
  issuer: env.get('APP_URL'),

  store: stores.lucid(),

  scopes: {
    read: 'Read access',
    write: 'Write access',
    profile: 'Basic profile information',
    email: 'Email address',
  },

  loginPage: '/login',
  consentPage: '/oauth/consent',

  // OIDC configuration
  jwk: JSON.parse(env.get('OIDC_JWK')),
  oidcProvider: oauthUserProvider({ model: () => import('#models/user') }),
  idTokenTtl: '1h',
})

export default sesameConfig

declare module '@julr/sesame/types' {
  interface SesameScopes extends InferScopes<typeof sesameConfig> {}
}
```

Both `jwk` and `oidcProvider` must be set for OIDC to be active. If either is missing, the server works as a pure OAuth 2.1 server. OIDC discovery and JWKS return 404; an access token without the `openid` scope cannot retrieve user claims from `/userinfo`.

### User Claims

When the `openid` scope is granted, Sésame calls `getOidcClaims()` on the user returned by `oidcProvider` to populate the `id_token` and `/userinfo` response with user-specific claims. Without this method, the ID token still contains its protocol claims (`sub`, `iss`, `aud`, `exp`, `iat`, `at_hash`), while `/userinfo` returns only `sub`.

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

```json title="Token response"
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

```bash title="Terminal"
curl -H "Authorization: Bearer oat_..." https://auth.example.com/oauth/userinfo
```

```json title="UserInfo response"
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

Add `client_credentials` to `grantTypes` in `config/sesame.ts` and optionally set `clientCredentialsAccessTokenTtl: '2h'` there. Keep your existing store, issuer, and page settings.

User-centric scopes (`openid`, `profile`, `email`, `offline_access`) are rejected for client credentials since they are meaningless in an M2M context. The client must be associated with a user (`userId` on the client record) and must be confidential (not public).

## Dynamic Client Registration

Sésame supports RFC 7591 dynamic client registration. Clients send their metadata (`redirect_uris`, `client_name`, `grant_types`, `scope`, `token_endpoint_auth_method`) to `POST /oauth/register` and receive a `client_id` and `client_secret` in return. Set `token_endpoint_auth_method` to `"none"` for public clients (no secret issued). Requested scopes and grant types are validated against your server config.

Set `allowDynamicRegistration: true` in `config/sesame.ts`. Also set `allowPublicRegistration: true` only if unauthenticated clients should be able to register.

Registered clients store `registration: 'dynamic'` in their `metadata` (not returned in the registration response), then `first_authorized_at` once they first obtain tokens. With public registration, clients that register but never complete an authorization pile up; delete them with `node ace sesame:purge --clients` (see [Token Cleanup](#token-cleanup)).

## Managing Clients

### Creating clients from the CLI

The `sesame:client` Ace command creates a new OAuth client interactively. It prompts for a name, redirect URIs, and client type, then outputs the generated credentials.

```bash title="Terminal"
node ace sesame:client
```

You can also pass flags to skip the prompts:

```bash title="Terminal"
node ace sesame:client --name "My App" --redirect-uris https://app.example.com/callback
node ace sesame:client --name "SPA" --public --redirect-uris https://spa.example.com/callback
node ace sesame:client --name "M2M Service" --grant-types client_credentials --user-id 42
```

The client secret is displayed once at creation time and cannot be retrieved later (it is stored as a SHA-256 hash).

### Programmatic client management

The `SesameManager` exposes methods for managing clients from your application code. This is useful for admin panels, seeding scripts, or any workflow where you need to create and manage clients without the CLI or dynamic registration.

```ts title="database/seeders/oauth_clients_seeder.ts"
import sesame from '@julr/sesame/services/main'

// Create a confidential client
const { client, clientSecret } = await sesame.createClient({
  name: 'Partner App',
  redirectUris: ['https://partner.example.com/callback'],
  scopes: ['read', 'write'],
  grantTypes: ['authorization_code', 'refresh_token'],
})

// Create a public client (no secret)
const { client: spa } = await sesame.createClient({
  name: 'SPA',
  redirectUris: ['https://spa.example.com/callback'],
  isPublic: true,
})
```

`createClient` returns a plain client record and the raw secret. The secret is only available at creation time. Client records returned by the public management methods do not serialize the stored `clientSecret` hash.

To find, list, update, or delete clients:

```ts title="database/seeders/oauth_clients_seeder.ts"
import sesame from '@julr/sesame/services/main'

// Find by public client_id
const client = await sesame.findClient('a1b2c3...')

// List all clients (optionally filtered by owner)
const allClients = await sesame.listClients()
const userClients = await sesame.listClients({ userId: '42' })

// Update specific fields
await sesame.updateClient('a1b2c3...', {
  name: 'New Name',
  redirectUris: ['https://new.example.com/callback'],
  isDisabled: true,
})

// Delete a client and all its tokens, codes, and consents
await sesame.deleteClient('a1b2c3...')
```

To rotate a confidential client's secret (e.g. after a suspected leak):

```ts title="database/seeders/oauth_clients_seeder.ts"
import sesame from '@julr/sesame/services/main'

const newSecret = await sesame.rotateClientSecret('a1b2c3...')
// Returns the new raw secret, or null if the client is public or not found
```

## MCP Support

For MCP (Model Context Protocol) servers, you can register per-resource discovery endpoints following RFC 9728. This tells MCP clients which authorization server protects a given resource.

```ts title="start/routes.ts"
import sesame from '@julr/sesame/services/main'

sesame.registerProtectedResource({
  resource: '/api/mcp',
  scopes: ['read'],
})
```

This creates a `/.well-known/oauth-protected-resource/api/mcp` endpoint. MCP clients that support the latest spec will discover this automatically.

Point the OAuth guard at the same resource with `oauthGuard({ provider, resource: '/api/mcp' })`. Its 401 responses then reference this metadata URL and advertise the declared `scopes` in the `WWW-Authenticate` header (see [Scope challenges](#scope-challenges)).

MCP clients typically need to self-register, so you will want to enable dynamic client registration with public access (see the [Dynamic Client Registration](#dynamic-client-registration) section above).

The official MCP TypeScript SDK sends `prompt=consent` whenever it requests the `offline_access` scope, and adds `offline_access` itself when it is advertised (Sésame always advertises it). Since Sésame honors `prompt=consent`, these clients show your consent page on every new connection, even if the user approved them before. Token refreshes are not affected.

## Events

The OAuth guard emits events during authentication that you can listen to for logging, analytics, or custom behavior.

| Event                                 | When                                                                   |
| ------------------------------------- | ---------------------------------------------------------------------- |
| `oauth_auth:authentication_attempted` | A bearer token has been received and authentication starts             |
| `oauth_auth:authentication_succeeded` | The token is valid and the user has been resolved                      |
| `oauth_auth:authentication_failed`    | The token is invalid, expired, revoked, or the user cannot be resolved |

```ts title="start/events.ts"
import emitter from '@adonisjs/core/services/emitter'
import logger from '@adonisjs/core/services/logger'

emitter.on('oauth_auth:authentication_failed', (event) => {
  logger.warn({ guardName: event.guardName, err: event.error }, 'OAuth authentication failed')
})
```

The `oauth_auth:authentication_succeeded` payload also includes `accessToken`, the same object as `guard.accessToken`:

```ts title="start/events.ts"
emitter.on('oauth_auth:authentication_succeeded', (event) => {
  logger.info(
    { tokenId: event.accessToken.id, clientId: event.accessToken.clientId },
    'OAuth request authenticated'
  )
})
```

## Testing

The OAuth guard implements `authenticateAsClient`, which integrates with Japa's `loginAs` helper. This automatically creates a test OAuth client and access token in the database, so your tests can make authenticated API requests without going through the full authorization flow.

```ts title="tests/functional/api.spec.ts"
import { test } from '@japa/runner'
import User from '#models/user'

test.group('API', () => {
  test('returns user data for authenticated request', async ({ client }) => {
    const user = await User.findOrFail(1)

    const response = await client.get('/api/me').loginAs(user, 'oauth')

    response.assertStatus(200)
    response.assertBodyContains({ id: user.id })
  })
})
```

The test client is created with `defaultScopes` from your config. The token is scoped to a `__test_client__` OAuth client that gets auto-created on first use.

## Token Cleanup

Expired and revoked tokens accumulate over time. Purge them with the Ace command:

```bash title="Terminal"
node ace sesame:purge
node ace sesame:purge --revoked
node ace sesame:purge --expired
node ace sesame:purge --hours=168
```

The `--hours` flag (default: 168, i.e. 7 days) controls how long expired tokens are kept for audit purposes before deletion. The programmatic option is named `retentionHours`.

You can also call it programmatically:

```ts title="app/services/token_cleanup.ts"
import sesame from '@julr/sesame/services/main'

const result = await sesame.purgeTokens({ retentionHours: 168 })
// => { accessTokens: 42, refreshTokens: 12, authorizationCodes: 3, pendingRequests: 7 }
```

### Unused clients

Dynamic client registration lets any client create a record, so `oauth_clients` grows over time. Pass `--clients` to also delete dynamically registered clients that were never used:

```bash title="Terminal"
node ace sesame:purge --clients
node ace sesame:purge --clients --client-days=7
```

A client is deleted when all of these are true:

- it was created more than `--client-days` days ago (default: 30; must be an integer of at least 1, like `olderThanDays`)
- it was dynamically registered: its `metadata` has `registration: 'dynamic'`, or `token_endpoint_auth_method` for clients registered before this marker existed
- it was never authorized: its `metadata` has no `first_authorized_at`
- no access token, refresh token, authorization code, consent, or pending authorization request references it

Sésame writes `first_authorized_at` in the client's `metadata` the first time the client obtains tokens (authorization code exchange, client credentials, or a refresh for clients registered before this marker existed). The marker survives token purges and `revokeAllForUser()`, so a client that was used once is never deleted, even after all its tokens are gone. The purge therefore targets clients that registered and never obtained a token.

Clients created with `sesame.createClient()` or `node ace sesame:client` are never deleted. Tokens are purged first, then clients. The flag is opt-in, so an existing `sesame:purge` schedule keeps its current behavior.

```ts title="app/services/token_cleanup.ts"
import sesame from '@julr/sesame/services/main'

const deleted = await sesame.purgeUnusedClients({ olderThanDays: 30 })
// => 12
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
