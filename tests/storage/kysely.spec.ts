import { test } from '@japa/runner'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'
import { IgnitorFactory } from '@adonisjs/core/factories'
import Database from 'better-sqlite3'
import { Kysely, SqliteDialect } from 'kysely'
import { DateTime } from 'luxon'
import { defineConfig } from '../../src/define_config.ts'
import { SesameManager } from '../../src/sesame_manager.ts'
import { stores } from '../../src/stores.ts'
import { ClientService } from '../../src/services/client_service.ts'
import { TokenService } from '../../src/services/token_service.ts'
import { ExchangeAuthorizationCodeAction } from '../../src/actions/exchange_authorization_code.ts'
import { ExchangeClientCredentialsAction } from '../../src/actions/exchange_client_credentials.ts'
import { ExchangeRefreshTokenAction } from '../../src/actions/exchange_refresh_token.ts'
import { OAuthGuard } from '../../src/guard/guard.ts'
import { kyselyStore } from '../../src/storage/drivers/kysely.ts'
import { up } from '../../src/storage/migrations/kysely.ts'
import { createPkce } from '../helpers/create_pkce.ts'
import { createFakeEmitter, FakeUserProvider } from '../helpers/fakes.ts'

async function createKyselyManager() {
  const db = new Kysely<any>({ dialect: new SqliteDialect({ database: new Database(':memory:') }) })
  await up(db)

  const manager = new SesameManager(
    defineConfig({
      issuer: 'https://auth.example.com',
      scopes: { read: 'Read access' },
      defaultScopes: ['read'],
      loginPage: '/login',
      consentPage: '/consent',
      store: stores.kysely({ connection: db }),
    }),
    {} as any,
    kyselyStore({ db })
  )

  return { db, manager }
}

test.group('Kysely store | OAuth flows', () => {
  test('resolves the store through the AdonisJS provider without Lucid', async ({ assert }) => {
    const db = new Kysely<any>({
      dialect: new SqliteDialect({ database: new Database(':memory:') }),
    })
    await up(db)
    let connectionResolutions = 0
    let resolvedApp: unknown

    const config = defineConfig({
      issuer: 'https://auth.example.com',
      scopes: { read: 'Read access' },
      loginPage: '/login',
      consentPage: '/consent',
      store: stores.kysely({
        connection: async (app) => {
          connectionResolutions++
          resolvedApp = app
          return db
        },
      }),
    })
    const ignitor = new IgnitorFactory()
      .withCoreProviders()
      .withCoreConfig()
      .merge({
        rcFileContents: { providers: [() => import('../../providers/sesame_provider.ts')] },
        config: { sesame: config },
      })
      .create(new URL('../', import.meta.url))
    const app = ignitor.createApp('web')

    try {
      await app.init()
      await app.boot()

      const manager = await app.container.make(SesameManager)
      assert.equal(connectionResolutions, 1)
      assert.strictEqual(resolvedApp, app)
      assert.isFunction(manager.store.findClient)
      assert.equal(
        (await manager.createClient({ name: 'Provider App', redirectUris: [] })).client.name,
        'Provider App'
      )
    } finally {
      await db.destroy()
    }
  })

  test('manages clients through Kysely store operations', async ({ assert }) => {
    const { db, manager } = await createKyselyManager()

    try {
      const { client } = await manager.createClient({
        name: 'Original',
        redirectUris: ['https://app.example.com/callback'],
        scopes: ['read'],
        userId: 'owner-1',
      })
      await manager.createClient({
        name: 'Other owner',
        redirectUris: [],
        userId: 'owner-2',
      })

      await db
        .updateTable('oauth_clients')
        .set({ updated_at: '2000-01-01T00:00:00.000Z' })
        .where('client_id', '=', client.clientId)
        .execute()

      const updated = await manager.updateClient(client.clientId, {
        name: 'Renamed',
        metadata: { contact: 'owner-1' },
      })
      assert.equal(updated?.name, 'Renamed')
      assert.deepEqual(updated?.metadata, { contact: 'owner-1' })
      assert.isAbove(updated!.updatedAt.toMillis(), DateTime.fromISO('2000-01-01').toMillis())
      assert.deepEqual(
        (await manager.listClients({ userId: 'owner-1' })).map((item) => item.clientId),
        [client.clientId]
      )

      assert.isTrue(await manager.deleteClient(client.clientId))
      assert.isFalse(await manager.deleteClient(client.clientId))
      assert.isNull(await manager.findClient(client.clientId))
    } finally {
      await db.destroy()
    }
  })

  test('merges consent and consumes a pending request once', async ({ assert }) => {
    const { db, manager } = await createKyselyManager()

    try {
      const { client } = await manager.createClient({ name: 'Consent App', redirectUris: [] })
      const store = manager.store
      const identity = { clientId: client.clientId, userId: 'user-1' }
      await store.grantConsent({ ...identity, scopes: ['read'] })
      await store.grantConsent({ ...identity, scopes: ['write', 'read'] })
      assert.deepEqual((await store.findConsent(identity))?.scopes, ['read', 'write'])

      const concurrentIdentity = { clientId: client.clientId, userId: 'user-2' }
      await Promise.all([
        store.grantConsent({ ...concurrentIdentity, scopes: ['read'] }),
        store.grantConsent({ ...concurrentIdentity, scopes: ['write'] }),
      ])
      assert.sameMembers((await store.findConsent(concurrentIdentity))!.scopes, ['read', 'write'])

      await store.createPendingAuthorizationRequest({
        id: crypto.randomUUID(),
        token: 'pending-hash',
        ...identity,
        redirectUri: 'https://app.example.com/callback',
        scopes: ['read'],
        expiresAt: DateTime.now().plus({ minutes: 5 }),
      })
      const request = { token: 'pending-hash', userId: 'user-1', now: DateTime.now() }
      assert.isNotNull(await store.consumePendingAuthorizationRequest(request))
      assert.isNull(await store.consumePendingAuthorizationRequest(request))
    } finally {
      await db.destroy()
    }
  })

  test('preserves UTC instants and milliseconds in SQLite records', async ({ assert }) => {
    const { db, manager } = await createKyselyManager()

    try {
      const { client } = await manager.createClient({ name: 'Date App', redirectUris: [] })
      const expiresAt = DateTime.utc(2030, 1, 2, 3, 4, 5, 678)
      await manager.store.createAuthorizationCode({
        id: crypto.randomUUID(),
        code: 'utc-code',
        clientId: client.clientId,
        userId: 'user-1',
        scopes: [],
        redirectUri: 'https://app.example.com/callback',
        expiresAt,
      })

      const stored = await manager.store.findAuthorizationCode({
        code: 'utc-code',
        clientId: client.clientId,
      })
      assert.equal(stored?.expiresAt.toMillis(), expiresAt.toMillis())
    } finally {
      await db.destroy()
    }
  })

  test('authenticates a client, exchanges a code once, and rotates its refresh token', async ({
    assert,
  }) => {
    const { db, manager } = await createKyselyManager()

    try {
      const { client, clientSecret } = await manager.createClient({
        name: 'Kysely App',
        redirectUris: ['https://app.example.com/callback'],
        scopes: ['read'],
        grantTypes: ['authorization_code', 'refresh_token'],
      })
      const authenticated = await new ClientService(manager).authenticateClient({
        bodyClientId: client.clientId,
        bodyClientSecret: clientSecret!,
      })
      assert.equal(authenticated.clientId, client.clientId)
      assert.isUndefined(JSON.parse(JSON.stringify(client)).clientSecret)

      const store = manager.store
      const tokenService = new TokenService(manager)
      const rawCode = tokenService.generateOpaqueToken()
      const { codeVerifier, codeChallenge } = createPkce()
      await store.createAuthorizationCode({
        id: crypto.randomUUID(),
        code: tokenService.hashToken(rawCode),
        clientId: client.clientId,
        userId: 'user-1',
        scopes: ['read'],
        redirectUri: 'https://app.example.com/callback',
        codeChallenge,
        codeChallengeMethod: 'S256',
        nonce: null,
        expiresAt: DateTime.now().plus({ minutes: 10 }),
      })

      const exchange = new ExchangeAuthorizationCodeAction()
      const input = {
        client: authenticated,
        code: rawCode,
        redirectUri: 'https://app.example.com/callback',
        codeVerifier,
      }
      const results = await Promise.allSettled([
        exchange.execute(manager, input),
        exchange.execute(manager, input),
      ])
      assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
      assert.equal(results.filter((result) => result.status === 'rejected').length, 1)

      const first = results.find((result) => result.status === 'fulfilled')
      if (!first || first.status !== 'fulfilled') throw new Error('Code exchange did not succeed')
      const refreshed = await new ExchangeRefreshTokenAction().execute(manager, {
        client: authenticated,
        refreshToken: first.value.refresh_token!,
      })
      assert.isDefined(refreshed.access_token)
      assert.notEqual(refreshed.refresh_token, first.value.refresh_token)
      assert.lengthOf(await db.selectFrom('oauth_access_tokens').selectAll().execute(), 2)
      assert.lengthOf(await db.selectFrom('oauth_refresh_tokens').selectAll().execute(), 2)

      assert.isTrue(await manager.deleteClient(client.clientId))
      assert.lengthOf(await db.selectFrom('oauth_access_tokens').selectAll().execute(), 0)
      assert.lengthOf(await db.selectFrom('oauth_refresh_tokens').selectAll().execute(), 0)
    } finally {
      await db.destroy()
    }
  })

  test('rolls back token writes when a transaction fails', async ({ assert }) => {
    const { db, manager } = await createKyselyManager()

    try {
      const { client } = await manager.createClient({
        name: 'Rollback App',
        redirectUris: [],
      })
      const store = manager.store
      const accessTokenId = crypto.randomUUID()
      const refreshTokenId = crypto.randomUUID()
      const expiresAt = DateTime.now().plus({ hours: 1 })
      await store.issueTokenPair({
        accessToken: {
          id: accessTokenId,
          tokenHash: 'first-token',
          clientId: client.clientId,
          userId: 'user-1',
          scopes: ['read'],
          expiresAt,
        },
        refreshToken: {
          id: refreshTokenId,
          token: 'first-refresh',
          accessTokenId,
          clientId: client.clientId,
          userId: 'user-1',
          scopes: ['read'],
          expiresAt,
        },
      })

      await assert.rejects(() =>
        store.issueTokenPair({
          accessToken: {
            id: crypto.randomUUID(),
            tokenHash: 'rollback-test',
            clientId: client.clientId,
            userId: 'user-1',
            scopes: ['read'],
            expiresAt,
          },
          refreshToken: {
            id: refreshTokenId,
            token: 'duplicate-refresh',
            accessTokenId,
            clientId: client.clientId,
            userId: 'user-1',
            scopes: ['read'],
            expiresAt,
          },
        })
      )
      assert.lengthOf(await db.selectFrom('oauth_access_tokens').selectAll().execute(), 1)
    } finally {
      await db.destroy()
    }
  })

  test('authenticates and revokes an access token without Lucid models', async ({ assert }) => {
    const { db, manager } = await createKyselyManager()

    try {
      const { client } = await manager.createClient({
        name: 'Service App',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        userId: 'user-1',
      })
      const result = await new ExchangeClientCredentialsAction().execute(manager, {
        client,
        scope: 'read',
      })
      const request = new RequestFactory().merge({ url: '/' }).create()
      request.request.headers.authorization = `Bearer ${result.access_token}`
      const ctx = new HttpContextFactory().merge({ request }).create()
      const provider = new FakeUserProvider([{ id: 'user-1', name: 'Service Account' }])
      const guard = new OAuthGuard('oauth', ctx, createFakeEmitter(), provider, manager)

      assert.deepEqual(await guard.authenticate(), { id: 'user-1', name: 'Service Account' })
      assert.deepEqual(guard.scopes, ['read'])

      await manager.revokeAllForUser('user-1')
      const revokedGuard = new OAuthGuard('oauth', ctx, createFakeEmitter(), provider, manager)
      await assert.rejects(() => revokedGuard.authenticate())
    } finally {
      await db.destroy()
    }
  })
})
