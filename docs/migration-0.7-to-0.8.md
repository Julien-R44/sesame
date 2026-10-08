# Migrate from Sésame 0.7.0 to 0.8.0

This guide covers the changes needed in an existing AdonisJS application using Sésame 0.7.0. Each section below describes one change and whether it requires action.

## Guard challenges and unused client purge

This release adds `scope` to the `WWW-Authenticate` challenges of the OAuth guard, exposes the authenticating access token on `guard.accessToken`, and lets `sesame:purge` delete dynamically registered clients that were never used. The database schema does not change.

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
    // - no access token, refresh token, authorization code, consent,
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

Sésame 0.8.0 lets your application drive consent and honors the OpenID Connect `prompt` parameter. No database migration, config change, or custom store change is required.

### New: approve or deny from your own controller

`sesame.approveAuthorization({ authToken, userId, scopes? })` and `sesame.denyAuthorization({ authToken, userId })` complete a pending authorization request and return `{ redirectUrl, clientId, scopes }`. Pass `scopes` to grant a subset of the requested scopes, for example read-only access. See [Handling consent in your own controller](../README.md#handling-consent-in-your-own-controller).

The built-in `POST /oauth/consent` route also accepts an optional `scope` field (space-delimited string or array) with the same rules. Requests without `scope` keep granting every requested scope.

### Behavior change: `scope` on `POST /oauth/consent` is no longer ignored

In 0.7.0, a `scope` field posted to `/oauth/consent` was ignored. It is now the list of granted scopes. If your consent form posts a `scope` field, for example a hidden input copied from the query string, make sure it only contains scopes from the pending request. Otherwise the submission fails with `invalid_scope`. Remove the field to keep granting everything that was requested.

### Behavior change: `prompt=consent` always shows the consent page

Previously, Sésame ignored `prompt` and skipped the consent page whenever a remembered consent covered the requested scopes. Requests with `prompt=consent` now always show the consent page.

The official MCP TypeScript SDK sends `prompt=consent` whenever it requests `offline_access`, and adds `offline_access` itself because Sésame advertises it. Users of these clients will see your consent page on every new connection, even for a client they approved before. Token refreshes are not affected.

### Behavior change: `prompt=none` returns errors to the client

Requests with `prompt=none` no longer redirect to your login or consent page:

- When the user is not logged in, Sésame redirects to the client with `error=login_required`.
- When the requested scopes are not covered by a remembered consent, Sésame redirects to the client with `error=consent_required`.
- `prompt=none` combined with another value returns `error=invalid_request`.

Other `prompt` values (`login`, `select_account`, `create`) are still ignored. Discovery documents now include `prompt_values_supported: ["none", "consent"]`.
