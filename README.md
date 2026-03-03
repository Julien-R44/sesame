# Sésame

> OAuth 2.1 + OIDC server for AdonisJS

Sésame is an AdonisJS package that turns your application into a full-featured OAuth 2.1 authorization server. It implements the core OAuth 2.1 specification along with OIDC discovery, token introspection, dynamic client registration, and MCP (Model Context Protocol) support.

## Features

- **Authorization Code Grant** with PKCE (S256)
- **Refresh Token Rotation** with replay detection
- **Token Introspection** (RFC 7662) and **Revocation** (RFC 7009)
- **Dynamic Client Registration** (RFC 7591)
- **OIDC Discovery** (`/.well-known/openid-configuration`)
- **OAuth Server Metadata** (RFC 8414)
- **Protected Resource Metadata** (RFC 9728) for MCP servers
- **Type-safe scopes** via module augmentation
- **OAuth guard** for `@adonisjs/auth` with scope-checking middleware
- **Token cleanup** via `sesame:purge` Ace command

## Installation

```bash
node ace add @julr/sesame
```

This will:
- Publish the configuration file to `config/sesame.ts`
- Publish database migrations (6 tables)
- Register the service provider and commands

Then run the migrations:

```bash
node ace migration:run
```

## Configuration

The configuration file lives at `config/sesame.ts`:

```ts
import env from '#start/env'
import { defineConfig } from '@julr/sesame'
import type { InferScopes } from '@julr/sesame/types'

const sesameConfig = defineConfig({
  issuer: env.get('APP_URL'),

  scopes: {
    'read': 'Read access',
    'write': 'Write access',
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

The `SesameScopes` augmentation gives you type-safe scope names throughout your application.

## Routes

Register OAuth routes from your `start/routes.ts` file:

```ts
import sesame from '@julr/sesame/services/main'

// OAuth endpoints under /oauth
router.group(() => {
  sesame.registerRoutes(router)
}).prefix('/oauth')

// Discovery endpoints at the root
sesame.registerWellKnownRoutes(router)
```

This registers the following endpoints:

| Method | Path                                      | Description                            |
| ------ | ----------------------------------------- | -------------------------------------- |
| `POST` | `/oauth/token`                            | Token endpoint                         |
| `GET`  | `/oauth/authorize`                        | Authorization endpoint                 |
| `POST` | `/oauth/consent`                          | Consent submission                     |
| `POST` | `/oauth/introspect`                       | Token introspection (RFC 7662)         |
| `POST` | `/oauth/revoke`                           | Token revocation (RFC 7009)            |
| `POST` | `/oauth/register`                         | Dynamic client registration (RFC 7591) |
| `GET`  | `/oauth/client-info`                      | Public client info                     |
| `GET`  | `/.well-known/oauth-authorization-server` | Server metadata (RFC 8414)             |
| `GET`  | `/.well-known/openid-configuration`       | OIDC discovery                         |

## Authentication Guard

Sésame provides an OAuth guard for `@adonisjs/auth`. Configure it in `config/auth.ts`:

```ts
import { oauthGuard, oauthUserProvider } from '@julr/sesame/guard'
import User from '#models/user'

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

Then use it in your controllers:

```ts
export default class ApiController {
  async index({ auth }: HttpContext) {
    const guard = auth.use('oauth')
    await guard.authenticate()

    const user = auth.user!
    const scopes = guard.scopes
  }
}
```

## Scope Middleware

Two named middleware are available for checking scopes on authenticated requests:

```ts
// Requires ALL listed scopes
router
  .get('/admin', [AdminController])
  .use(middleware.scopes({ scopes: ['admin', 'write'] }))

// Requires AT LEAST ONE of the listed scopes
router
  .get('/data', [DataController])
  .use(middleware.anyScope({ scopes: ['read', 'write'] }))
```

## MCP Support

For MCP (Model Context Protocol) servers, register per-resource discovery:

```ts
sesame.registerProtectedResource(router, {
  resource: '/api/mcp',
  scopes: ['read:mcp'],
})
```

This creates a `/.well-known/oauth-protected-resource/api/mcp` endpoint following RFC 9728.

You can also enable public client registration for MCP clients:

```ts
const sesameConfig = defineConfig({
  // ...
  allowDynamicRegistration: true,
  allowPublicRegistration: true,
})
```

## Token Cleanup

Purge expired and revoked tokens with the Ace command:

```bash
node ace sesame:purge
node ace sesame:purge --revoked-only
node ace sesame:purge --expired-only
node ace sesame:purge --retention-hours=168
```

You can also call it programmatically:

```ts
import sesame from '@julr/sesame/services/main'

const result = await sesame.purgeTokens({ retentionHours: 168 })
```

## Security

- Tokens (access, refresh, authorization codes, client secrets) are stored as **SHA-256 hashes** — raw values are never persisted
- PKCE with **S256** is required for public clients
- Refresh tokens use **rotation** — the old token is revoked on each use
- **Replay detection**: if a revoked refresh token is reused, all tokens for that client+user pair are revoked
- Client secret verification uses **timing-safe comparison**
- OAuth errors follow the standard JSON format with proper HTTP status codes and `WWW-Authenticate` headers

## License

MIT
