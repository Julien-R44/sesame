import { test } from '@japa/runner'
import type { Assert } from '@japa/assert'
import { Kysely, MysqlDialect, PostgresDialect } from 'kysely'
import { DateTime } from 'luxon'
import { createPool } from 'mysql2'
import { Pool } from 'pg'
import { kyselyStore } from '../../src/storage/drivers/kysely.ts'
import { up, down } from '../../src/storage/migrations/kysely.ts'
import type { SesameStore } from '../../src/storage/types.ts'

/**
 * These tests use dedicated databases supplied through SESAME_TEST_POSTGRES_URL
 * and SESAME_TEST_MYSQL_URL. Run `pnpm test:sql` to provision both with Docker.
 */

type SqlDialect = 'postgres' | 'mysql'

/**
 * Connect to an isolated database supplied by the integration-test environment.
 */
function createDatabase(dialect: SqlDialect, connectionUrl: string): Kysely<any> {
  if (dialect === 'postgres') {
    return new Kysely<any>({
      dialect: new PostgresDialect({ pool: new Pool({ connectionString: connectionUrl }) }),
    })
  }

  const url = new URL(connectionUrl)
  return new Kysely<any>({
    dialect: new MysqlDialect({
      pool: createPool({
        host: url.hostname,
        port: Number(url.port || 3306),
        user: decodeURIComponent(url.username),
        password: decodeURIComponent(url.password),
        database: url.pathname.slice(1),
        connectionLimit: 4,
      }),
    }),
  })
}

/**
 * Exercise JSON, boolean, nullable, and timestamp conversion for client records.
 */
async function testClientRecords(store: SesameStore, assert: Assert) {
  const clientId = `client-${crypto.randomUUID()}`
  const client = await store.createClient({
    id: crypto.randomUUID(),
    clientId,
    name: 'SQL dialect test',
    clientSecret: 'hashed-secret',
    redirectUris: ['https://app.example.com/callback'],
    scopes: ['read'],
    grantTypes: ['authorization_code', 'refresh_token'],
    isPublic: false,
    isDisabled: false,
    requirePkce: true,
    metadata: { owner: 'test' },
    userId: 'user-1',
  })

  assert.equal(client.clientId, clientId)
  assert.deepEqual(client.redirectUris, ['https://app.example.com/callback'])
  assert.deepEqual(client.metadata, { owner: 'test' })
  assert.isFalse(client.isPublic)
  assert.isTrue(client.requirePkce)
  assert.isTrue(DateTime.isDateTime(client.createdAt))

  await store.updateClient({
    id: client.id,
    data: { scopes: ['read', 'write'], requirePkce: false, metadata: { owner: 'updated' } },
  })
  const updated = await store.findClient(clientId)
  assert.deepEqual(updated?.scopes, ['read', 'write'])
  assert.deepEqual(updated?.metadata, { owner: 'updated' })
  assert.isFalse(updated?.requirePkce)
  assert.equal((await store.listClients({ userId: 'user-1' }))[0]?.clientId, clientId)

  return clientId
}

/**
 * Verify consent merging and one-time consumption of a pending request.
 */
async function testConsent(store: SesameStore, clientId: string, assert: Assert) {
  const identity = { clientId, userId: 'user-1' }
  await store.grantConsent({ ...identity, scopes: ['read'] })
  await store.grantConsent({ ...identity, scopes: ['write', 'read'] })
  assert.deepEqual((await store.findConsent(identity))?.scopes, ['read', 'write'])

  const concurrentIdentity = { clientId, userId: 'user-2' }
  await Promise.all([
    store.grantConsent({ ...concurrentIdentity, scopes: ['read'] }),
    store.grantConsent({ ...concurrentIdentity, scopes: ['write'] }),
  ])
  assert.sameMembers((await store.findConsent(concurrentIdentity))!.scopes, ['read', 'write'])

  await Promise.all([
    store.grantConsent({ ...concurrentIdentity, scopes: ['profile'] }),
    store.grantConsent({ ...concurrentIdentity, scopes: ['email'] }),
  ])
  assert.sameMembers((await store.findConsent(concurrentIdentity))!.scopes, [
    'read',
    'write',
    'profile',
    'email',
  ])

  const token = `pending-${crypto.randomUUID()}`
  await store.createPendingAuthorizationRequest({
    id: crypto.randomUUID(),
    token,
    ...identity,
    redirectUri: 'https://app.example.com/callback',
    scopes: ['read'],
    expiresAt: DateTime.now().plus({ minutes: 5 }),
  })

  const request = { token, userId: identity.userId, now: DateTime.now() }
  assert.isNotNull(await store.consumePendingAuthorizationRequest(request))
  assert.isNull(await store.consumePendingAuthorizationRequest(request))
}

/**
 * Verify single-use code exchange and refresh rotation on a real SQL server.
 */
async function testTokenExchange(store: SesameStore, clientId: string, assert: Assert) {
  const codeId = crypto.randomUUID()
  const code = `code-${crypto.randomUUID()}`
  const accessTokenId = crypto.randomUUID()
  const accessHash = `access-${crypto.randomUUID()}`
  const refreshTokenId = crypto.randomUUID()
  const refreshHash = `refresh-${crypto.randomUUID()}`

  await store.createAuthorizationCode({
    id: codeId,
    code,
    clientId,
    userId: 'user-1',
    scopes: ['read'],
    redirectUri: 'https://app.example.com/callback',
    expiresAt: DateTime.now().plus({ minutes: 5 }),
  })
  assert.equal((await store.findAuthorizationCode({ code, clientId }))?.id, codeId)

  const exchange = {
    codeId,
    accessToken: {
      id: accessTokenId,
      tokenHash: accessHash,
      clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    },
    refreshToken: {
      id: refreshTokenId,
      token: refreshHash,
      accessTokenId,
      clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 1 }),
    },
  }
  assert.isTrue(await store.exchangeAuthorizationCode(exchange))
  assert.isFalse(await store.exchangeAuthorizationCode(exchange))
  assert.isTrue(DateTime.isDateTime((await store.findAccessToken({ hash: accessHash }))?.expiresAt))

  const newAccessTokenId = crypto.randomUUID()
  const newAccessHash = `access-${crypto.randomUUID()}`
  const newRefreshHash = `refresh-${crypto.randomUUID()}`
  const rotation = {
    oldRefreshTokenId: refreshTokenId,
    oldAccessTokenId: accessTokenId,
    revokedAt: DateTime.now(),
    accessToken: {
      ...exchange.accessToken,
      id: newAccessTokenId,
      tokenHash: newAccessHash,
    },
    refreshToken: {
      ...exchange.refreshToken,
      id: crypto.randomUUID(),
      token: newRefreshHash,
      accessTokenId: newAccessTokenId,
    },
  }
  assert.isTrue(await store.rotateRefreshToken(rotation))
  assert.isFalse(await store.rotateRefreshToken(rotation))
  assert.isNotNull((await store.findRefreshToken({ hash: refreshHash, clientId }))?.revokedAt)
  assert.isNotNull((await store.findAccessToken({ hash: accessHash }))?.revokedAt)

  await store.revokeRefreshToken({ hash: newRefreshHash, clientId, now: DateTime.now() })
  assert.isNotNull((await store.findAccessToken({ hash: newAccessHash }))?.revokedAt)
}

/**
 * Verify rollback, conditional revocation, cleanup counts, and client deletion.
 */
async function testCleanup(store: SesameStore, clientId: string, assert: Assert) {
  const accessTokenId = crypto.randomUUID()
  const refreshTokenId = crypto.randomUUID()
  const expiresAt = DateTime.now().plus({ hours: 1 })
  await store.issueTokenPair({
    accessToken: {
      id: accessTokenId,
      tokenHash: `extra-access-${crypto.randomUUID()}`,
      clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt,
    },
    refreshToken: {
      id: refreshTokenId,
      token: `extra-refresh-${crypto.randomUUID()}`,
      accessTokenId,
      clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt,
    },
  })

  const failedHash = `rollback-${crypto.randomUUID()}`
  await assert.rejects(() =>
    store.issueTokenPair({
      accessToken: {
        id: crypto.randomUUID(),
        tokenHash: failedHash,
        clientId,
        userId: 'user-1',
        scopes: ['read'],
        expiresAt,
      },
      refreshToken: {
        id: refreshTokenId,
        token: `duplicate-${crypto.randomUUID()}`,
        accessTokenId,
        clientId,
        userId: 'user-1',
        scopes: ['read'],
        expiresAt,
      },
    })
  )
  assert.isNull(await store.findAccessToken({ hash: failedHash }))

  const revokeHash = `revocable-${crypto.randomUUID()}`
  await store.createAccessToken({
    id: crypto.randomUUID(),
    tokenHash: revokeHash,
    clientId,
    userId: 'user-1',
    scopes: ['read'],
    expiresAt,
  })
  assert.isTrue(await store.revokeAccessToken({ hash: revokeHash, clientId, now: DateTime.now() }))
  assert.isFalse(await store.revokeAccessToken({ hash: revokeHash, clientId, now: DateTime.now() }))

  const counts = await store.purgeTokens({
    purgeRevoked: true,
    purgeExpired: false,
    cutoff: DateTime.now(),
    now: DateTime.now(),
  })
  assert.isAtLeast(counts.accessTokens, 3)
  assert.isAtLeast(counts.refreshTokens, 2)
  assert.isTrue(await store.deleteClient(clientId))
  assert.isFalse(await store.deleteClient(clientId))
  assert.isNull(await store.findClient(clientId))
}

for (const dialect of ['postgres', 'mysql'] as const) {
  const connectionUrl = process.env[`SESAME_TEST_${dialect.toUpperCase()}_URL`]
  const sqlTest = test(`Kysely ${dialect} | migration and OAuth persistence`, async ({
    assert,
  }) => {
    const db = createDatabase(dialect, connectionUrl!)

    try {
      await up(db)
      const store = kyselyStore({ db })
      const clientId = await testClientRecords(store, assert)
      await testConsent(store, clientId, assert)
      await testTokenExchange(store, clientId, assert)
      await testCleanup(store, clientId, assert)
      await down(db)
    } finally {
      await db.destroy()
    }
  })

  if (!connectionUrl) sqlTest.skip()
}
