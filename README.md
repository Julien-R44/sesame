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

Upgrading an existing Lucid application from 0.6.0 requires config and import changes. Follow the [0.6.0 to 0.7.0 migration guide](docs/migration-0.6-to-0.7.md). Upgrading from 0.7.0 requires a database migration published by `node ace sesame:upgrade 0.8`; follow the [0.7.0 to 0.8.0 migration guide](docs/migration-0.7-to-0.8.md).

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

1. The consuming app redirects the user to `GET /oauth/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, and `code_challenge_method=S256`. If the user is not logged in, they are sent to your `loginPage`. Once authenticated, they see the consent screen (your `consentPage`). If the user already has an active [grant](#grants) without context covering the requested scopes, consent is skipped and the code is issued directly.

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

Declining `offline_access` does not prevent a refresh token: Sésame issues one whenever the `refresh_token` grant is enabled, regardless of that scope (RFC 6749 §5.1). The scope is only removed from the granted list. To stop issuing refresh tokens, remove `refresh_token` from `grantTypes`.

Every approval creates a [grant](#grants) holding the granted scopes. Future requests whose scopes are covered by the user's active grants for that client skip the consent page, unless the client sends `prompt=consent` or the grants carry a context. Denying a request does not touch existing grants.

#### Attaching application context

Pass `context` to `approveAuthorization` to store application data on the grant, for example the team the user picked on your consent page. The OAuth guard exposes it on every request authenticated with a token issued from that grant, and refresh token rotation keeps it.

```ts title="app/controllers/oauth_consent_controller.ts"
const member = await TeamMember.findByOrFail({ userId: user.id, teamId: request.input('team_id') })

const { redirectUrl } = await sesame.approveAuthorization({
  authToken,
  userId: String(user.id),
  context: { teamMemberId: member.id, projectIds: request.input('project_ids') },
})
```

The context must be a plain JSON object. It is stored as-is in the database, so do not put secrets in it, and it is never exposed to the client (token response, introspection). The built-in `POST /oauth/consent` route never reads a context from the request body. A grant with a context never skips the consent page: the user picks the context again on each authorization.

Type it once with module augmentation:

```ts title="config/sesame.ts"
declare module '@julr/sesame/types' {
  interface SesameGrantContext {
    teamMemberId: number
    projectIds: number[]
  }
}
```

### The `prompt` parameter

Sésame supports two values of the OpenID Connect `prompt` parameter, with or without the `openid` scope, and advertises them in `prompt_values_supported`:

- `prompt=consent` always shows the consent page, even when the user already approved the requested scopes.
- `prompt=none` never shows a page. Sésame redirects back to the client with `error=login_required` when the user is not logged in, or `error=consent_required` when the requested scopes are not covered by an active grant without context. Combining `none` with another value returns `error=invalid_request`.

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

Then use the guard in your controllers. After authentication, you have access to the user, the granted scopes, the client ID, the access token that authenticated the request, and the [grant](#grants) it was issued from with its context.

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
    const grantId = guard.grantId // undefined for client_credentials tokens
    const context = guard.context // e.g. { teamMemberId: 12, projectIds: [3] } or null
    const audience = guard.audience // e.g. 'https://app.com/api/mcp', or null

    return { user, scopes, clientId, tokenId, grantId, context, audience }
  }
}
```

`guard.accessToken` holds `id`, `clientId`, `userId`, `scopes`, `expiresAt`, `createdAt`, `grantId`, and `context`. It never contains the token value or its hash. Use the `id` to correlate audit logs with a token.

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

Both middleware authenticate with the guard named `oauth`. Pass the `guard` option to use another OAuth guard, for example the guard of an [MCP resource](#mcp-support):

```ts title="start/routes.ts"
router.post('/api/mcp', [McpController]).use(middleware.scopes({ scopes: ['read'], guard: 'mcp' }))
```

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

The consuming app sends `POST /oauth/token` with `grant_type=refresh_token`, the `refresh_token`, and client credentials to get a new token pair. Sésame uses **refresh token rotation**: every refresh returns a new refresh token and the old one is revoked immediately. If an attacker replays a revoked refresh token, its whole [grant](#grants) is revoked as a security measure: every token issued from that authorization stops working, while other grants of the same user and client (another device, another context) keep working. The client can request a narrower set of scopes by passing a `scope` parameter, but cannot request scopes that were not in the original grant.

### Revoking tokens

The consuming app can call `POST /oauth/revoke` with the `token`, optional `token_type_hint`, and client credentials. The endpoint always returns HTTP 200, even if the token was not found (to prevent information leakage per RFC 7009). Revoking a refresh token revokes its whole [grant](#grants), including every access token issued from it (RFC 7009 §2.1). Revoking an access token only revokes that token.

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

### Grants

A grant is one authorization a user gave to a client. Every completed authorization creates one, and its authorization code, access tokens, and rotated refresh tokens all reference it. A user can hold several grants for the same client: one per device, per reconnection, or per [context](#attaching-application-context). A grant stays active as long as its latest refresh token, and expired grants are removed by [token cleanup](#token-cleanup).

Use the grant API to build a "connected applications" page:

```ts title="app/controllers/connected_apps_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'
import sesame from '@julr/sesame/services/main'

export default class ConnectedAppsController {
  async index({ auth, view }: HttpContext) {
    const grants = await sesame.listGrants({ userId: String(auth.getUserOrFail().id) })
    const apps = Object.groupBy(grants, (grant) => grant.clientId)

    return view.render('settings/connected_apps', { apps })
  }

  async disconnect({ auth, params }: HttpContext) {
    await sesame.revokeGrants({
      userId: String(auth.getUserOrFail().id),
      clientId: params.clientId,
    })
  }

  async revoke({ auth, params }: HttpContext) {
    await sesame.revokeGrant({ grantId: params.id, userId: String(auth.getUserOrFail().id) })
  }
}
```

| Method                                       | Description                                                                                    |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `listGrants({ userId, clientId? })`          | Active grants, newest first. Each includes its public `client` record                          |
| `findGrant(grantId)`                         | One grant, or `null`                                                                           |
| `revokeGrant({ grantId, userId? })`          | Revokes the grant and all its tokens. With `userId`, only revokes a grant owned by that user   |
| `revokeGrants({ userId, clientId? })`        | Revokes every grant of a user, optionally for one client. Returns the number of revoked grants |
| `updateGrant({ grantId, context, userId? })` | Replaces the context. The guard reads it on every request, so the change applies immediately   |

`revokeAllForUser()` and `deleteClient()` also remove the related grants.

### Introspecting tokens

Resource servers can verify a token's state by calling `POST /oauth/introspect` with the `token`, optional `token_type_hint`, and client credentials. The response is `{ "active": true, "token_type": "Bearer", "client_id": "...", "sub": "...", "scope": "...", ... }` for valid tokens, or `{ "active": false }` for invalid, expired, or revoked tokens. Tokens bound to a resource also include it as `aud` (see [Resource indicators](#resource-indicators-and-token-audience)). This is useful when a separate service needs to validate tokens without sharing database access.

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

## Client ID Metadata Documents

The MCP specification (2025-11-25) recommends [Client ID Metadata Documents](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) (CIMD) over dynamic client registration. Instead of registering, the client uses an HTTPS URL as its `client_id`, and that URL serves a JSON document describing the client. Claude Code (`https://claude.ai/oauth/claude-code-client-metadata`) and VS Code (`https://vscode.dev/oauth/client-metadata.json`) work this way.

The feature is disabled by default because it makes your server fetch URLs chosen by the client. Enable it in `config/sesame.ts`:

```ts title="config/sesame.ts"
const sesameConfig = defineConfig({
  // ...
  clientIdMetadataDocuments: true,
})
```

Pass an object to customize the policy. Every option is optional:

```ts title="config/sesame.ts"
const sesameConfig = defineConfig({
  // ...
  clientIdMetadataDocuments: {
    // Only accept documents served by these hosts. A leading `*.` matches subdomains.
    // When omitted, any public HTTPS host is accepted.
    allowedHosts: ['claude.ai', 'vscode.dev', '*.example.com'],

    // Bounds applied to the document's Cache-Control / Expires headers.
    cache: { minTtl: '5m', maxTtl: '24h' },

    fetchTimeout: '5s',
    maxResponseSize: 5120,
  },
})
```

Once enabled, the authorization server metadata advertises `client_id_metadata_document_supported: true`, and MCP clients that support CIMD stop using `/oauth/register`. Keep dynamic registration enabled if you also need older clients.

### How it works

When `/oauth/authorize` receives a `client_id` starting with `https://`, Sésame:

1. Validates the URL. It must use `https`, have a path other than `/`, be in canonical form, and have no query, fragment, userinfo, or IP address host. It must not exceed 255 characters, the size of the `oauth_clients.client_id` column.
2. Checks `allowedHosts`.
3. Fetches the document if no fresh copy is stored, then validates it. The rules are listed below.
4. Stores the client in `oauth_clients` as a public client with mandatory PKCE, but only once the user is authenticated. Anonymous requests are validated without writing anything.

The token, introspection, and revocation endpoints use the stored client and never fetch the document. The stored client is reused until the cache lifetime expires, then refreshed on the next authorization request. The cache lifetime is the remaining freshness of the response (`Cache-Control: max-age` or `Expires`, minus its age from the `Age` and `Date` headers, as defined by RFC 9111), clamped to `[minTtl, maxTtl]`. Responses with `no-store`, `no-cache`, no freshness information, or that are already stale use `minTtl`. If the document can no longer be fetched or validated, the authorization request fails even when a stored copy exists. Each refresh overwrites the client's name, redirect URIs, scopes, grant types, and document-derived metadata (`client_uri`, `logo_uri`, etc.). Only `isDisabled` and the custom `metadata` keys you added survive, so changes such as `sesame.updateClient(url, { scopes })` are undone at the next refresh.

Any failure returns an `invalid_client` error to the browser. Sésame does not redirect to the `redirect_uri` because it cannot be trusted yet. Network errors are reported as `Unable to fetch client metadata document`: the details (connection refused, timeout, TLS error, blocked address, etc.) are only logged with the request logger under the `err` key, so the endpoint cannot be used to scan ports. Validation errors keep a precise description to help client developers.

Anonymous resolutions are not persisted, so they are kept in a bounded in-memory cache (500 entries, per process): successful resolutions for `minTtl`, failures for 5 seconds. Repeated anonymous requests for the same `client_id` therefore do not trigger repeated fetches.

A document must:

- Contain a `client_id` that is exactly the URL it was fetched from
- Contain a non-empty `client_name` and at least one `redirect_uris` entry. Redirect URIs follow the same rules as dynamic registration.
- Omit `token_endpoint_auth_method` or set it to `none`. Shared-secret methods are forbidden by the specification. `private_key_jwt` is not supported yet.
- Not contain `client_secret` or `client_secret_expires_at`
- Include `code` in `response_types` when that field is present

Grant types default to `authorization_code` and `refresh_token`. Unsupported grant types listed by the document (such as the device code grant) are ignored. The document's `scope` is intersected with your configured scopes; without it, the client gets `defaultScopes`. `client_uri`, `logo_uri`, `tos_uri`, and `policy_uri` must be HTTPS URLs and are stored in the client `metadata` for display.

### Security

Fetching a URL supplied by a client exposes the server to SSRF. Sésame applies the protections required by the specification:

- Every IP address the host resolves to is checked at connection time. Loopback, private, link-local, carrier-grade NAT, multicast, documentation, and other special-use ranges (RFC 6890) are refused, including IPv4-mapped IPv6 addresses. Checking at connection time also prevents DNS rebinding.
- Redirects are never followed, and any status other than `200` is an error.
- The response must be served as `application/json` (or `application/*+json`) without content encoding, within `fetchTimeout` and `maxResponseSize`.
- URLs inside the document, such as `logo_uri`, are never fetched by Sésame.

Outbound proxies configured through `HTTPS_PROXY` are not used.

Client ids are always compared exactly. With their default collations, MySQL and MariaDB compare `client_id` case-insensitively, so `https://host/~Alice/client.json` and `https://host/~alice/client.json` would hit the same row. Sésame rejects such a variant with `invalid_client` instead of using or updating the other client. Two clients that only differ by case therefore cannot coexist. To support them, use a binary collation such as `utf8mb4_bin` on `oauth_clients.client_id` and on every `client_id` foreign key column:

```sql
ALTER TABLE oauth_clients MODIFY client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
-- Repeat for client_id in oauth_access_tokens, oauth_refresh_tokens, oauth_authorization_codes,
-- oauth_consents and oauth_pending_authorization_requests (drop and recreate the foreign keys around it).
```

Use `allowedHosts` on servers that should only accept known clients. To block a single client, disable it. It stays disabled when its document is refreshed:

```ts
await sesame.updateClient('https://claude.ai/oauth/claude-code-client-metadata', {
  isDisabled: true,
})
```

Turning `clientIdMetadataDocuments` off rejects every URL `client_id` on all endpoints (authorize, consent, token, introspection, revocation, client info), even clients already stored. Removing a host from `allowedHosts` does the same for that host's clients. Access tokens that were already issued stay valid until they expire. Call `sesame.deleteClient(url)` to delete a client together with its tokens.

### Consent screen

Anyone can reuse a public client's metadata URL. On desktop clients that use loopback redirect URIs, a local process could also claim to be that client. Your consent page should show:

- the host serving the document
- the host of the `redirect_uri`
- a warning when the redirect URI is a loopback address

Read the values from the pending request rather than from the query string:

```ts title="app/controllers/oauth_consent_controller.ts"
import type { HttpContext } from '@adonisjs/core/http'
import sesame from '@julr/sesame/services/main'

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]']

export default class OAuthConsentController {
  async show({ request, auth, view }: HttpContext) {
    const user = auth.getUserOrFail()
    const pending = await sesame.findPendingAuthorizationRequest({
      token: request.qs().auth_token,
      userId: String(user.id),
    })
    if (!pending) return view.render('oauth/expired')

    const client = await sesame.findClient(pending.clientId)
    const redirectUri = new URL(pending.redirectUri)
    const isMetadataDocument = pending.clientId.startsWith('https://')

    return view.render('oauth/consent', {
      authToken: request.qs().auth_token,
      scopes: pending.scopes,
      clientName: client?.name,
      logoUri: client?.metadata?.logo_uri,
      clientHost: isMetadataDocument ? new URL(pending.clientId).host : null,
      redirectHost: redirectUri.host,
      isLoopbackRedirect: LOOPBACK_HOSTS.includes(redirectUri.hostname),
    })
  }
}
```

`GET /oauth/client-info` also returns `client_uri`, `logo_uri`, `tos_uri`, `policy_uri`, `client_id_metadata_document`, and `client_id_host` for metadata document clients. Sésame does not proxy logos: rendering `logo_uri` directly lets the client's host see when the consent screen is displayed.

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

// Delete a client and all its tokens, codes, and grants
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

Declare the same path as `resource` on the guard that protects your MCP routes. Without it, the guard does not check the token audience, and a token issued for another resource of your application is accepted:

```ts title="config/auth.ts"
mcp: oauthGuard({
  provider: oauthUserProvider({ model: () => import('#models/user') }),
  resource: '/api/mcp',
}),
```

The guard also points MCP clients to `/.well-known/oauth-protected-resource/api/mcp` in its `WWW-Authenticate` 401 responses and advertises the declared `scopes` there (see [Scope challenges](#scope-challenges)), so clients request tokens for that resource.

When the MCP route uses the `scopes` or `anyScope` middleware, pass that guard with the `guard` option. Without it, the middleware authenticates with the `oauth` guard: its 401 challenge points to the metadata of another resource, and it rejects tokens issued for `/api/mcp` when the `oauth` guard declares another `resource`. Each resource of your application gets its own guard:

```ts title="config/auth.ts"
guards: {
  web: sessionGuard({ ... }),
  oauth: oauthGuard({ provider: userProvider }),
  mcp: oauthGuard({ provider: userProvider, resource: '/api/mcp' }),
  mcpAdmin: oauthGuard({ provider: userProvider, resource: '/api/admin/mcp' }),
}
```

```ts title="start/routes.ts"
sesame.registerProtectedResource({ resource: '/api/mcp', scopes: ['read'] })
sesame.registerProtectedResource({ resource: '/api/admin/mcp', scopes: ['admin'] })

router.post('/api/mcp', [McpController]).use(middleware.scopes({ scopes: ['read'], guard: 'mcp' }))

router
  .post('/api/admin/mcp', [AdminMcpController])
  .use(middleware.scopes({ scopes: ['admin'], guard: 'mcpAdmin' }))
```

In the controller, read the authenticated token from the same guard, for example `auth.use('mcp').context`.

### Resource indicators and token audience

MCP clients send a `resource` parameter ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)) to `/oauth/authorize` and `/oauth/token` to name the server they will call. Sésame binds the issued tokens to that resource:

- The resource must be an absolute `http(s)` URI without a fragment, whitespace, control characters, or backslashes. It is mapped to the most specific resource served by Sésame on the issuer's origin: a path registered with `registerProtectedResource()`, or the issuer itself. For example, `https://app.com/api/mcp/` and `https://app.com/api/mcp/tools` both map to `https://app.com/api/mcp`, while `https://app.com/other` maps to the issuer `https://app.com` because no registered path covers it.
- A malformed value, a resource on another origin (scheme, host, or port), or a repeated `resource` parameter is rejected with an `invalid_target` error.
- The authorization code, the access token, and the refresh token store the resource. A refresh keeps it, and requesting another resource at the token endpoint than the one granted is rejected with `invalid_target`.
- Requests without `resource` (regular OAuth clients, older MCP clients) still work and produce tokens that are not bound to any resource. Tokens issued before the upgrade are also unbound; the first refresh that sends a `resource` binds the new tokens to it.
- The consent page receives the resolved `resource` query parameter, and `sesame.findPendingAuthorizationRequest()` exposes it as `resource`, so you can show which server the client wants to access.

A guard with a `resource` rejects tokens bound to another resource with a `401 invalid_token`. Unbound tokens are accepted by default for backward compatibility. Set `requireAudience: true` to reject them as well, as the MCP specification requires once all your clients send `resource`:

```ts title="config/auth.ts"
mcp: oauthGuard({
  provider: oauthUserProvider({ model: () => import('#models/user') }),
  resource: '/api/mcp',
  requireAudience: true,
}),
```

After authentication, `guard.audience` contains the resource the token is bound to, or `null`. Guards without `resource` never check the audience. In tests, `loginAs()` binds its token to the guard's resource.

A guard compares tokens with its `resource` mapped the same way as the `resource` parameter. Register the guard path with `registerProtectedResource()`: otherwise it maps to the closest registered resource (often the issuer), the guard accepts tokens issued for that broader resource, and Sésame logs a warning once.

MCP clients identify themselves through [Client ID Metadata Documents](#client-id-metadata-documents) (preferred by the MCP specification) or by self-registering. Enable `clientIdMetadataDocuments`, and keep dynamic client registration with public access for clients that do not support metadata documents yet (see [Dynamic Client Registration](#dynamic-client-registration)).

The official MCP TypeScript SDK requests the scopes listed in the `scope` of the `WWW-Authenticate` challenge, and only falls back to `scopes_supported` of the protected resource metadata when the challenge has none. The OAuth guard lists the resource and route scopes in its 401 challenge (see [Scope challenges](#scope-challenges)), so the SDK requests exactly those scopes. It does not add `offline_access`, and since it only sends `prompt=consent` together with `offline_access`, it does not send `prompt=consent` either. A returning user whose grants without context already cover these scopes skips your consent page. Sésame still issues a refresh token whenever the `refresh_token` grant type is enabled, with or without `offline_access`. When the challenge has no `scope` (no scopes declared on the resource nor on the route), the SDK requests `scopes_supported`, which includes `offline_access`, and sends `prompt=consent`: your consent page is then shown on every new connection.

When a tool needs a scope the token lacks, reject the request with `guard.insufficientScopeError(['write'])`. The 403 challenge lists the scopes to request, and Sésame handles the new authorization like any other. However, the current MCP TypeScript SDK first refreshes its token on a 403, which cannot add scopes, then gives up when the server answers 403 again. With that SDK, the client must drop its tokens (for example by reconnecting the server) to obtain the wider scopes.

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

    const response = await client.get('/api/me').withGuard('oauth').loginAs(user)

    response.assertStatus(200)
    response.assertBodyContains({ id: user.id })
  })
})
```

The test client is created with `defaultScopes` from your config. The token is scoped to a `__test_client__` OAuth client that gets auto-created on first use, and belongs to its own grant. Pass options to choose the scopes or the grant context:

```ts title="tests/functional/api.spec.ts"
await client
  .get('/mcp')
  .withGuard('oauth')
  .loginAs(user, { scopes: ['read'], context: { teamMemberId: 1 } })
```

## Token Cleanup

Expired and revoked tokens accumulate over time. Purge them with the Ace command:

```bash title="Terminal"
node ace sesame:purge
node ace sesame:purge --revoked
node ace sesame:purge --expired
node ace sesame:purge --hours=168
```

The `--hours` flag (default: 168, i.e. 7 days) controls how long expired tokens, authorization codes, and grants are kept for audit purposes before deletion. The programmatic option is named `retentionHours`. Revoked refresh tokens are also kept for that period, so replaying a recently rotated refresh token is still detected. Revoked access tokens are deleted immediately.

You can also call it programmatically:

```ts title="app/services/token_cleanup.ts"
import sesame from '@julr/sesame/services/main'

const result = await sesame.purgeTokens({ retentionHours: 168 })
// => { accessTokens: 42, refreshTokens: 12, authorizationCodes: 3, pendingRequests: 7, grants: 5 }
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
- no access token, refresh token, authorization code, grant, or pending authorization request references it

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
- Redirect URIs are matched exactly. Loopback redirect URIs (`http://127.0.0.1`, `http://[::1]`, `http://localhost`) accept any port at request time, so native and CLI clients can bind an ephemeral port (RFC 8252 §7.3).
- Refresh tokens use **rotation**. The old token is revoked immediately on use.
- **Replay detection**: if a revoked refresh token or an already exchanged authorization code is presented, its whole grant is revoked to mitigate stolen token reuse (OAuth 2.1 §4.1.3 and §4.3.1).
- Client secret verification uses **timing-safe comparison**.
- Client ID Metadata Documents are opt-in and fetched with **SSRF protections**: special-use IP ranges are refused at connection time, redirects are not followed, and responses are bounded in time and size.
- ID tokens are signed with **RS256** using the configured JWK. The JWKS endpoint only exposes public key components.
- Protocol-managed claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `at_hash`) cannot be overridden by `getOidcClaims()`.
- OAuth errors follow the standard JSON format with proper HTTP status codes and `WWW-Authenticate` headers.

## License

MIT
