# Migrate from Sésame 0.7.0 to 0.8.0

This guide covers the changes needed in an existing AdonisJS application using Sésame 0.7.0. Each section below describes one change and whether it requires action.

## Guard challenges and unused client purge

This release adds `scope` to the `WWW-Authenticate` challenges of the OAuth guard, exposes the authenticating access token on `guard.accessToken`, and lets `sesame:purge` delete dynamically registered clients that were never used. These changes do not alter the database schema; the [Grants](#grants) section below does.

### Custom stores must implement `purgeUnusedClients`

Applications using `stores.lucid()` or `stores.kysely()` have nothing to do. If you wrote a custom `SesameStore`, add the new method:

```ts title="app/oauth/my_store.ts"
import type { PurgeUnusedClientsOptions, SesameStore } from '@julr/sesame/types'

export class MyStore implements SesameStore {
  // ...existing methods

  async purgeUnusedClients(options: PurgeUnusedClientsOptions): Promise<number> {
    // Delete the clients that match all of these conditions, then return how many were deleted:
    // - created before options.createdBefore
    // - dynamically registered: metadata.registration === 'dynamic',
    //   or metadata.token_endpoint_auth_method is set (clients registered before 0.8.0)
    // - never authorized: metadata.first_authorized_at is not set
    // - no access token, refresh token, authorization code, grant,
    //   or pending authorization request references the client
  }
}
```

Run the existence checks again in the `DELETE` statement, inside a transaction, so a client that creates a token, code, or pending request between the lookup and the delete is kept. The purge takes no lock: an authorization request that already loaded the client can still race with the delete. Its insert then hits the foreign key and Sésame answers `invalid_client`, as for an unknown client. A custom store must let that foreign key error propagate (Postgres `23503`, MySQL/MariaDB `ER_NO_REFERENCED_ROW_2`, SQLite `SQLITE_CONSTRAINT_FOREIGNKEY`).

### Header changes

- 401 responses from the OAuth guard may now include `scope`, listing the scopes declared with `registerProtectedResource()` and the scopes required by the `scopes`/`anyScope` middleware.
- 403 `insufficient_scope` responses now include `resource_metadata`, and their `scope` lists the scopes already granted to the token plus the required ones. Previously it only listed the required scopes.

Update tests that compare these headers exactly.

### Dynamic registrations are marked

Clients created through `POST /oauth/register` now store `registration: 'dynamic'` in their `metadata`. The marker is not returned in the registration response. The first time such a client obtains tokens, Sésame also writes `first_authorized_at` in its `metadata`; clients with this marker are never purged. Clients registered before 0.8.0 get the marker on their next code exchange or refresh. Clients created with `sesame.createClient()` or `node ace sesame:client` are never purged; do not add `registration` or `token_endpoint_auth_method` to their `metadata`.

## Consent and the `prompt` parameter

Sésame 0.8.0 lets your application drive consent and honors the OpenID Connect `prompt` parameter. These changes need no config change. Remembered consent is now derived from grants, which require the database migration described in [Grants](#grants).

### New: approve or deny from your own controller

`sesame.approveAuthorization({ authToken, userId, scopes? })` and `sesame.denyAuthorization({ authToken, userId })` complete a pending authorization request and return `{ redirectUrl, clientId, scopes }`. Pass `scopes` to grant a subset of the requested scopes, for example read-only access. See [Handling consent in your own controller](../README.md#handling-consent-in-your-own-controller).

The built-in `POST /oauth/consent` route also accepts an optional `scope` field (space-delimited string or array) with the same rules. Requests without `scope` keep granting every requested scope.

### Behavior change: `scope` on `POST /oauth/consent` is no longer ignored

In 0.7.0, a `scope` field posted to `/oauth/consent` was ignored. It is now the list of granted scopes. If your consent form posts a `scope` field, for example a hidden input copied from the query string, make sure it only contains scopes from the pending request. Otherwise the submission fails with `invalid_scope`. Remove the field to keep granting everything that was requested.

### Behavior change: `prompt=consent` always shows the consent page

Previously, Sésame ignored `prompt` and skipped the consent page whenever a remembered consent covered the requested scopes. Requests with `prompt=consent` now always show the consent page.

The official MCP TypeScript SDK requests the scopes listed in the `scope` of the 401 challenge, which the OAuth guard now includes (see [Header changes](#header-changes)). With 0.7.0, the challenge had no `scope`, so the SDK requested `scopes_supported` from the protected resource metadata, including `offline_access`, and sent `prompt=consent` along with it. With 0.8.0, it requests only the challenge scopes, without `offline_access` nor `prompt=consent`, so a returning user whose grants without context cover these scopes skips the consent page. Sésame still issues a refresh token whenever the `refresh_token` grant type is enabled. Tokens issued to these clients no longer list `offline_access` in their `scope`.

The SDK still sends `prompt=consent` when the challenge has no `scope`, that is when neither the resource nor the route declares scopes. See [MCP Support](../README.md#mcp-support) for the step-up limitation of the current SDK.

### Behavior change: `prompt=none` returns errors to the client

Requests with `prompt=none` no longer redirect to your login or consent page:

- When the user is not logged in, Sésame redirects to the client with `error=login_required`.
- When the requested scopes are not covered by the user's active grants without context, Sésame redirects to the client with `error=consent_required`.
- `prompt=none` combined with another value returns `error=invalid_request`.

Other `prompt` values (`login`, `select_account`, `create`) are still ignored. Discovery documents now include `prompt_values_supported: ["none", "consent"]`. The authorization server metadata (`/.well-known/oauth-authorization-server`) also lists `scopes_supported` (RFC 8414), with the same values as the OpenID Connect discovery document.

## Grants

Sésame 0.8.0 records every authorization a user gives to a client as a **grant**. Authorization codes, access tokens, and refresh tokens reference the grant they were issued from, so a whole authorization can be listed, revoked, or carry application context. This change requires a database migration. Custom stores must also be updated.

### 1. Publish and run the upgrade migrations

One command publishes every 0.8.0 migration for your store: the grants migration below and the [resource indicators](#resource-indicators-and-token-audience) migration. Run them before starting the application with 0.8.0:

```bash title="Terminal"
# Lucid
node ace sesame:upgrade 0.8
node ace migration:run

# Kysely
node ace sesame:upgrade 0.8 --store=kysely
```

The Kysely migrations are written to `database/kysely_migrations/` as `sesame_v000800_add_oauth_grants.ts` and `sesame_v000800_add_oauth_resource_columns.ts`: the zero-padded version keeps them sorted after `create_oauth_tables.ts` and before the migrations of later Sésame versions. Move them next to the `create_oauth_tables.ts` migration you applied for 0.7.0, keep their filenames, and run them with your Kysely migrator.

The migrations:

- create the `oauth_grants` table;
- add a nullable, indexed `grant_id` column to `oauth_authorization_codes`, `oauth_access_tokens`, and `oauth_refresh_tokens`, and a `consumed_at` column to `oauth_authorization_codes`;
- drop the `oauth_consents` table;
- add a nullable `resource` text column to `oauth_pending_authorization_requests`, `oauth_authorization_codes`, `oauth_access_tokens`, and `oauth_refresh_tokens`.

Rolling them back drops the `resource` columns and recreates an empty `oauth_consents` table.

### 2. Existing tokens and remembered consents

No data is copied. Instead:

- Existing access and refresh tokens keep working without a grant. The guard exposes `grantId` as `undefined` and `context` as `null` for them.
- An existing refresh token is attached to a new grant the next time it is used, together with its access token, so active clients appear in `listGrants()` after their next refresh. Replaying that refresh token afterwards revokes the new grant and every token issued from it. The same applies to an authorization code issued before the upgrade and exchanged after it.
- Replaying a refresh token that was rotated before the upgrade, and therefore never got a grant, revokes the grant-less refresh and access tokens of the same client and user. Tokens already attached to a grant are not affected. This applies even within `refreshTokenRotationGracePeriod`: a refresh token rotated before the upgrade gets no grace period, so it cannot be attached to a second grant next to its successor.
- Remembered consents are dropped. Each user sees your consent page once more the next time a client starts a new authorization. Token refreshes are not affected.

### 3. Behavior changes

- **Remembered consent follows grants.** The consent page is skipped when the user's active grants without context cover the requested scopes. Revoking every grant of a client, or letting them expire, shows the consent page again. A grant with a context never skips the consent page.
- **Every authorization creates a grant.** A user who connects the same client twice, for example from two devices sharing a [Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) `client_id`, now holds two grants.
- **Refresh token replay only revokes the replayed grant.** Previously, every token of the client and user pair was revoked, which logged out other devices and contexts. The grant itself is now deleted, so that authorization has to be approved again (OAuth 2.1 §4.3.1).
- **Reusing an authorization code revokes its grant.** Exchanged codes are kept with `consumed_at` instead of being deleted. A second exchange returns `invalid_grant` with `Authorization code has already been consumed` and revokes the tokens issued from the first exchange (OAuth 2.1 §4.1.3). This includes two concurrent exchanges of the same code: the slower one revokes the tokens of the faster one.
- **Introspection and userinfo check the grant.** Tokens whose grant was revoked or has expired are reported as `active: false` and rejected by `/oauth/userinfo`, like the OAuth guard already does.
- **`POST /oauth/revoke` with a refresh token revokes its whole grant**, including every access token issued from it (RFC 7009 §2.1). Revoking an access token still only revokes that token.
- **Purge keeps revoked refresh tokens for the retention period** (`--hours`, 168 by default) instead of deleting them immediately, so a replay is still detected after a purge. Expired grants are purged too, and `purgeTokens()` returns an additional `grants` count.
- **`revokeAllForUser()` and `deleteClient()`** delete grants instead of consents.

### 4. Code changes

- **Lucid models:** `OAuthConsent` is no longer exported from `@julr/sesame/drivers/lucid`. Use `OAuthGrant` instead.
- **Records:** `OAuthAccessTokenRecord`, `OAuthRefreshTokenRecord`, and `OAuthAuthorizationCodeRecord` gain `grantId: string | null`, and authorization codes gain `consumedAt`. `OAuthConsentRecord` is replaced by `OAuthGrantRecord`.
- **Custom stores:** update your `SesameStore` implementation. Both bundled stores (`src/storage/drivers/lucid.ts` and `src/storage/drivers/kysely.ts`) can serve as references.
  - Remove `findConsent()` and `grantConsent()`.
  - Rename `revokeTokenFamily()` to `revokeLegacyTokenFamily()`. It must only touch tokens whose `grant_id` is null.
  - Add `createGrant()`, `findGrant()`, `listGrants()`, `updateGrant()`, `revokeGrant()`, and `revokeGrants()`.
  - `findAccessToken()` returns the token joined with its `grant` (or `null`) in a single query.
  - `exchangeAuthorizationCode()` receives `consumedAt` and must mark the code consumed instead of deleting it.
  - `exchangeAuthorizationCode()`, `rotateRefreshToken()`, and `issueTokenPair()` receive an optional `grant` write to apply in the same transaction:
    - `extend` must lock the grant (`SELECT ... FOR UPDATE` where supported), fail the whole issuance when the grant no longer exists or has expired, and never move its expiry backwards;
    - `create` inserts the grant and sets `grant_id` on the `adopt` rows (code, refresh token, access token) whose `grant_id` is still null.
  - These three methods return `false` when the issuance fails because of an inactive grant, so `issueTokenPair()` now returns a boolean.
  - `revokeGrant()` and `revokeGrants()` should delete the grant before its tokens, so an issuance waiting on the grant lock cannot leave tokens behind.
  - `purgeTokens()` must keep revoked refresh tokens until the cutoff, delete expired grants, and return a `grants` count.

### 5. New: grant context and grant management

- Pass `context` to `approveAuthorization()` to store application data on the grant, and read it with `auth.use('oauth').context`. See [Attaching application context](../README.md#attaching-application-context).
- Build a "connected applications" page with `listGrants()`, `revokeGrant()`, `revokeGrants()`, and `updateGrant()`. See [Grants](../README.md#grants).
- `withGuard('oauth').loginAs(user, { scopes, context })` authenticates test requests with custom scopes and context.
- `guard.accessToken` (and the `accessToken` of the `oauth_auth:authentication_succeeded` event) gains `grantId` and `context`, also available as `guard.grantId` and `guard.context`.

## Resource indicators and token audience

Sésame 0.8.0 supports the `resource` parameter ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)), which MCP clients send to name the server a token is for. Authorization codes, access tokens, and refresh tokens are bound to that resource, and a guard that declares a `resource` rejects tokens issued for another resource. The `resource` columns are added by the upgrade migrations of [Grants](#1-publish-and-run-the-upgrade-migrations); no other migration is needed.

### Existing tokens

Existing codes and tokens keep a `null` resource: they are not bound to any resource and remain valid until they expire. The first refresh that sends a `resource` binds the new tokens to it, including when the refresh token is attached to a new grant.

### How `resource` values are resolved

A `resource` value is mapped to the most specific path registered with `registerProtectedResource()` on the issuer's origin, or to the issuer itself when no registered path covers it. For example, without a registered `/api/mcp`, a client requesting `https://app.com/api/mcp` gets a token bound to `https://app.com`. Only malformed values (relative URIs, fragments, whitespace, control characters, or backslashes), resources on another origin, and repeated `resource` parameters fail with `invalid_target`, where 0.7.0 ignored the parameter.

Requesting another resource than the one granted, at the token endpoint or on refresh, fails with `invalid_target`. Requests without `resource` keep working and produce unbound tokens.

### Declare `resource` on the guard of each MCP server

Without a `resource`, a guard keeps the 0.7.0 behavior and accepts tokens bound to any resource. To reject tokens issued for another resource of your application, pass the path you registered with `registerProtectedResource()` to the guard that protects it:

```ts title="config/auth.ts"
import { oauthGuard } from '@julr/sesame/guard'
import { oauthUserProvider } from '@julr/sesame/guard/lucid'

const userProvider = oauthUserProvider({ model: () => import('#models/user') })

guards: {
  web: sessionGuard({ ... }),
  oauth: oauthGuard({ provider: userProvider }),
  mcp: oauthGuard({ provider: userProvider, resource: '/api/mcp' }),
}
```

The `scopes` and `anyScope` middleware authenticate with the guard named `oauth` unless you pass the new `guard` option. Pass it on the routes of each resource, so the middleware checks the audience of that resource and its 401 challenge points to the right protected resource metadata:

```ts title="start/routes.ts"
sesame.registerProtectedResource({ resource: '/api/mcp', scopes: ['read'] })

router
  .post('/api/mcp', [McpController])
  .use(middleware.scopes({ scopes: ['read'], guard: 'mcp' }))
```

Tokens that are not bound to a resource are still accepted by default. Once your clients send `resource`, set `requireAudience: true` on the guard to reject them, as the MCP specification requires.

### Behavior and code changes

- **Guards that already declared `resource` in 0.7.0 now check the token audience.** In 0.7.0, `resource` only built the `WWW-Authenticate` header. Check that each such path is registered with `registerProtectedResource()`. If it is not, the guard keeps working but matches tokens against the closest registered resource (usually the issuer), so it also accepts tokens issued for the whole application, and Sésame logs a warning once. Register the path to restrict the guard to tokens issued for it.
- **Introspection** returns the resource of bound tokens as `aud`.
- **Records:** `OAuthAccessTokenRecord`, `OAuthRefreshTokenRecord`, `OAuthAuthorizationCodeRecord`, and `OAuthPendingAuthorizationRequestRecord` gain `resource: string | null`. Custom stores must persist and return it; no store method signature changed. A store that drops the field returns tokens as unbound.
- **Scope middleware:** `scopes` and `anyScope` accept a `guard` option naming the OAuth guard to use. It defaults to `oauth`, the only guard they used in 0.7.0.
- **Guard:** `guard.audience` and `guard.accessToken.resource` expose the resource of the authenticating token. Code that instantiates `OAuthGuard` directly must pass the resource as an options object: `new OAuthGuard(name, ctx, emitter, provider, manager, { resource: '/api/mcp' })` instead of a string.

## Loopback redirect URIs accept any port

Redirect URIs on `http://127.0.0.1`, `http://[::1]` and `http://localhost` now match regardless of the port used in the authorization request, as required by OAuth 2.1 and RFC 8252 §7.3. Host, path and query must still match exactly. This allows native and CLI clients to bind an ephemeral port.

No action is required. If you relied on the port to distinguish two loopback redirect URIs, register different paths instead.

## Client ID Metadata Documents (opt-in)

Sésame can now resolve HTTPS `client_id` URLs through [Client ID Metadata Documents](../README.md#client-id-metadata-documents), the registration method preferred by the MCP specification. The feature is disabled by default. Enable it in `config/sesame.ts`:

```ts title="config/sesame.ts"
const sesameConfig = defineConfig({
  // ...
  clientIdMetadataDocuments: true,
})
```

No migration is needed. Metadata document clients are stored in the existing `oauth_clients` table. Keep in mind:

- `client_id` URLs longer than 255 characters are rejected, matching the `oauth_clients.client_id` column size. If you need longer URLs, widen that column and the `client_id` foreign key columns yourself.
- While the feature is disabled, any `client_id` starting with `https://` is rejected with `invalid_client`. Sésame never generates such ids.
- Update your consent page to display the document host and the redirect URI host (see [Consent screen](../README.md#consent-screen)). `GET /oauth/client-info` returns new fields for this: `client_uri`, `logo_uri`, `tos_uri`, `policy_uri`, `client_id_metadata_document`, and `client_id_host`.
- Custom `SesameStore` implementations need no change. Sésame only uses `findClient`, `createClient`, and `updateClient`. When two requests insert the same client concurrently, `createClient` must throw, as with the unique `client_id` constraint.
