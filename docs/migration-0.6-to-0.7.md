# Migrate from Sésame 0.6.0 to 0.7.0

This guide covers the changes needed in an existing AdonisJS application using Sésame 0.6.0. You will:

- Configure the new storage driver while keeping your Lucid database
- Update the Lucid-specific imports
- Adapt code that expects client-management methods to return Lucid models
- Check your dependency and migration setup before deploying

## Overview

Sésame 0.7.0 adds a storage-driver system so applications can use Lucid, Kysely, or a custom store. Existing Lucid applications can keep their database and OAuth tables. The upgrade requires changes to application configuration and some imports, but it does not require a new Lucid migration.

Complete the steps below before starting the application with 0.7.0. An unchanged 0.6.0 config fails because `store` is now required.

## 1. Update your dependencies

`@adonisjs/auth` is now a required peer dependency. Keep `@adonisjs/lucid` installed when using the Lucid store. Upgrade Sésame and add Auth if your application does not already depend on it:

```bash title="Terminal"
pnpm add @julr/sesame@^0.7.0 @adonisjs/auth@^10
```

Do not rerun `node ace add @julr/sesame` in an existing application. That command publishes installation stubs, not an upgrade of your existing config or migrations.

## 2. Select the Lucid store in your config

Import `stores` alongside `defineConfig`, then add `store: stores.lucid()` to your existing `config/sesame.ts`. Keep your current issuer, scopes, grant types, pages, and OIDC settings. This complete example shows where the new field belongs:

```ts title="config/sesame.ts"
import env from '#start/env'
import { defineConfig, stores } from '@julr/sesame'
import type { InferScopes } from '@julr/sesame/types'

const sesameConfig = defineConfig({
  issuer: env.get('APP_URL'),
  store: stores.lucid(),
  scopes: {
    read: 'Read access',
  },
  defaultScopes: ['read'],
  loginPage: '/login',
  consentPage: '/oauth/consent',
})

export default sesameConfig

declare module '@julr/sesame/types' {
  interface SesameScopes extends InferScopes<typeof sesameConfig> {}
}
```

Your `start/env.ts` must continue to validate `APP_URL` (or whichever public issuer URL your existing config uses).

> [!WARNING]
> Do not run the new Kysely create-table migration against a database that already contains the OAuth tables. Selecting `stores.lucid()` uses your existing Lucid tables and data; no table recreation is needed for this upgrade. Moving existing data to another database or schema is a separate migration.

## 3. Update Lucid-specific imports

The five OAuth models previously exported from `@julr/sesame` now live under `@julr/sesame/drivers/lucid`. Change imports of `OAuthClient`, `OAuthAccessToken`, `OAuthRefreshToken`, `OAuthAuthorizationCode`, and `OAuthConsent` if your application uses them directly. For example:

```ts title="app/services/oauth_clients.ts"
import { OAuthClient } from '@julr/sesame/drivers/lucid'

export async function findOAuthClient(clientId: string) {
  return OAuthClient.query().where('clientId', clientId).first()
}
```

The Lucid user-provider helper has also moved. Whether you previously imported `oauthUserProvider` from the package root or `@julr/sesame/guard`, import it from `@julr/sesame/guard/lucid` now. `oauthGuard` remains available from `@julr/sesame/guard` and the package root. Keep your guard definitions and default guard unchanged. Apply the same user-provider import change wherever you configure `oidcProvider`.

If you imported `OAuthLucidUserProvider` from the package root or `@julr/sesame/guard`, import it from `@julr/sesame/guard/lucid` instead. The same path exports the `OAuthLucidUserProviderOptions` type.

Import types from `@julr/sesame/types`, not the package root. This includes the previously root-exported `CreateClientOptions`, `CreateClientResult`, and `UpdateClientOptions`, as well as the new `SesameStore` and OAuth record types.

## 4. Adapt client-management results

`createClient`, `findClient`, `listClients`, and `updateClient` now return plain `OAuthClientRecord` objects instead of Lucid model instances. Their data fields remain available, but methods such as `.save()`, `.delete()`, and `.serialize()` are not. Use Sésame's management methods to update or delete clients. Fetch the Lucid model explicitly only when you need Lucid-specific behavior:

```ts title="app/services/rename_oauth_client.ts"
import sesame from '@julr/sesame/services/main'

export async function renameOAuthClient(clientId: string, name: string) {
  const client = await sesame.findClient(clientId)
  if (!client) return null

  return sesame.updateClient(client.clientId, { name })
}
```

The `clientSecret` field still contains a hash, not the raw secret. It is non-enumerable on records returned by the public management methods, so JSON serialization omits it. The raw secret remains available only in the separate `clientSecret` value returned by `createClient` or `rotateClientSecret`.

If your tests or integrations instantiate `SesameManager` directly, its constructor now also requires the resolved store as a third argument. For a Lucid test setup, import `lucidStore` from `@julr/sesame/drivers/lucid` and construct it with `new SesameManager(config, router, lucidStore())`. Normal AdonisJS applications should continue resolving the manager through the service provider.

## 5. Verify the upgrade

Run your application's type check and tests, then verify one existing client and token against the same database. Exercise any authorization-code or refresh-token flow that your application uses. Existing OAuth tables and data should remain in place when staying on Lucid.

For a new Kysely installation, see the [Kysely installation section](../README.md#kysely-installation). Switching an existing Lucid application to Kysely is optional and is not part of the 0.6.0 to 0.7.0 upgrade.
