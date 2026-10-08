import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'
import {
  createManager,
  createTestConfig,
  setupHttpGroup,
  setupIntegrationGroup,
} from './helpers/app.ts'
import { createTestAccessToken } from './helpers/create_test_access_token.ts'
import { createAuthCodeExchange } from './helpers/create_auth_code_exchange.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestGrant } from './helpers/create_test_grant.ts'
import { createTestRefreshToken } from './helpers/create_test_refresh_token.ts'
import { createPkce } from './helpers/create_pkce.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { FakeUserProvider, createFakeEmitter, getTestJwk } from './helpers/fakes.ts'
import { TokenService } from '../src/services/token_service.ts'
import { lucidStore } from '../src/storage/drivers/lucid.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import type { OAuthGrantRecord, SesameStore } from '../src/storage/types.ts'
import { OAuthGuard } from '../src/guard/guard.ts'
import { AuthorizeAction } from '../src/actions/authorize.ts'
import { ExchangeAuthorizationCodeAction } from '../src/actions/exchange_authorization_code.ts'
import { ExchangeRefreshTokenAction } from '../src/actions/exchange_refresh_token.ts'
import { OAuthGrant } from '../src/models/oauth_grant.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { testGrantRecords, testGrantRevocation } from './storage/grant_store_contract.ts'

const REDIRECT_URI = 'https://app.example.com/callback'
const testJwk = await getTestJwk()

type AuthorizeOptions = {
  scopes?: string[]
  context?: Record<string, unknown> | null
  userId?: string
}

/**
 * Run a full authorization: pending request, approval with an optional
 * context, then code exchange. Returns the issued tokens.
 */
async function authorize(manager: SesameManager, options?: AuthorizeOptions) {
  const userId = options?.userId ?? 'user-1'
  const authToken = `auth-token-${crypto.randomUUID()}`
  const { codeVerifier, codeChallenge } = createPkce()
  await manager.store.createPendingAuthorizationRequest({
    id: crypto.randomUUID(),
    token: new TokenService(manager).hashToken(authToken),
    clientId: 'test-client',
    userId,
    redirectUri: REDIRECT_URI,
    scopes: options?.scopes ?? ['read'],
    codeChallenge,
    codeChallengeMethod: 'S256',
    expiresAt: DateTime.now().plus({ minutes: 5 }),
  })

  const decision = await manager.approveAuthorization({
    authToken,
    userId,
    context: options?.context,
  })
  const code = new URL(decision.redirectUrl).searchParams.get('code')!
  const client = (await manager.store.findClient('test-client'))!

  return new ExchangeAuthorizationCodeAction().execute(manager, {
    client,
    code,
    redirectUri: REDIRECT_URI,
    codeVerifier,
  })
}

/**
 * Build a guard for a bearer token.
 */
function buildGuard(manager: SesameManager, bearerToken: string) {
  const request = new RequestFactory().merge({ url: '/' }).create()
  request.request.headers.authorization = `Bearer ${bearerToken}`
  const ctx = new HttpContextFactory().merge({ request }).create()
  const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])

  return new OAuthGuard('oauth', ctx, createFakeEmitter(), provider, manager)
}

/**
 * Find the grant behind an access token.
 */
async function grantIdOf(manager: SesameManager, accessToken: string) {
  const record = await manager.store.findAccessToken({
    hash: new TokenService(manager).hashToken(accessToken),
  })

  return record?.grantId ?? null
}

test.group('Grants | Lucid store', (group) => {
  setupIntegrationGroup(group)

  test('persists, lists, joins, and revokes grants', async ({ assert }) => {
    const client = await createTestClient()

    await testGrantRecords(lucidStore(), client.clientId, assert)
    await testGrantRevocation(lucidStore(), client.clientId, assert)
  })
})

test.group('Grants | Authorization', (group) => {
  setupIntegrationGroup(group)

  test('creates one grant per authorization with its context', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    const first = await authorize(manager, { context: { teamId: 1 } })
    const second = await authorize(manager, { context: { teamId: 2 } })

    const firstGrantId = await grantIdOf(manager, first.access_token)
    const secondGrantId = await grantIdOf(manager, second.access_token)
    assert.isString(firstGrantId)
    assert.notEqual(firstGrantId, secondGrantId)
    assert.deepEqual((await manager.findGrant(firstGrantId!))?.context, { teamId: 1 })
    assert.deepEqual((await manager.findGrant(secondGrantId!))?.context, { teamId: 2 })

    const refreshExpiry = DateTime.now().plus({ hours: 30 * 24 })
    const grant = await manager.findGrant(firstGrantId!)
    assert.isBelow(Math.abs(grant!.expiresAt.diff(refreshExpiry).as('minutes')), 1)
  })

  test('rejects a context that is not a plain object', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    await assert.rejects(
      () => authorize(manager, { context: ['team-1'] as any }),
      'Grant context must be a plain object or null'
    )
  })

  test('skips consent only for active grants without context', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const { codeChallenge } = createPkce()
    const input = {
      clientId: 'test-client',
      responseType: 'code',
      redirectUri: REDIRECT_URI,
      scope: 'read',
      codeChallenge,
      codeChallengeMethod: 'S256',
      userId: 'user-1',
    }

    await createTestGrant({ scopes: ['read'], context: { teamId: 1 } })
    await createTestGrant({ scopes: ['read'], expiresAt: DateTime.now().minus({ minutes: 1 }) })
    assert.equal((await new AuthorizeAction().execute(manager, input)).type, 'consent_required')
    assert.deepEqual(await new AuthorizeAction().execute(manager, { ...input, prompt: 'none' }), {
      type: 'redirect_error',
      error: 'consent_required',
      description: 'The user must consent to the requested scopes',
    })

    const remembered = await createTestGrant({ scopes: ['read'] })
    const result = await new AuthorizeAction().execute(manager, input)
    assert.equal(result.type, 'authorized')

    const code = await OAuthAuthorizationCode.query().firstOrFail()
    assert.isString(code.grantId)
    assert.notEqual(code.grantId, remembered.id)
    assert.isNull((await manager.findGrant(code.grantId!))?.context)
  })

  test('revoking one authorization keeps the others of the same client', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const laptop = await authorize(manager)
    const desktop = await authorize(manager)
    assert.lengthOf(await manager.listGrants({ userId: 'user-1' }), 2)

    await manager.revokeGrant({ grantId: (await grantIdOf(manager, desktop.access_token))! })

    await assert.rejects(() => buildGuard(manager, desktop.access_token).authenticate())
    assert.isNotNull(await buildGuard(manager, laptop.access_token).authenticate())
  })
})

test.group('Grants | Refresh tokens', (group) => {
  setupIntegrationGroup(group)

  test('rotation keeps the grant and extends its expiry', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const { rawRefreshToken, grantId } = await createTestRefreshToken({ scopes: ['read'] })
    await OAuthGrant.query()
      .where('id', grantId!)
      .update({ expiresAt: DateTime.now().plus({ days: 1 }).toSQL() })

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
    })

    assert.equal(await grantIdOf(manager, result.access_token), grantId)
    const grant = await manager.findGrant(grantId!)
    assert.isAbove(grant!.expiresAt.diff(DateTime.now()).as('days'), 29)
  })

  test('replay revokes only the replayed grant', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const replayed = await createTestRefreshToken({
      scopes: ['read'],
      revokedAt: DateTime.now().minus({ minutes: 5 }),
    })
    const sibling = await createTestRefreshToken({ scopes: ['read'] })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: replayed.rawRefreshToken,
        }),
      'invalid_grant'
    )

    assert.isNull(await manager.findGrant(replayed.grantId!))
    assert.isNotNull(await manager.findGrant(sibling.grantId!))
    assert.lengthOf(await OAuthRefreshToken.query().where('grantId', replayed.grantId!), 0)
    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: sibling.rawRefreshToken,
    })
    assert.isString(result.access_token)
  })

  test('rejects a refresh token whose grant was revoked or expired', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const revoked = await createTestRefreshToken({ scopes: ['read'] })
    const expired = await createTestRefreshToken({ scopes: ['read'] })
    await OAuthGrant.query().where('id', revoked.grantId!).delete()
    await OAuthGrant.query()
      .where('id', expired.grantId!)
      .update({ expiresAt: DateTime.now().minus({ minutes: 1 }).toSQL() })

    for (const token of [revoked, expired]) {
      await assertOAuthError(
        assert,
        () =>
          new ExchangeRefreshTokenAction().execute(manager, {
            client,
            refreshToken: token.rawRefreshToken,
          }),
        'invalid_grant'
      )
    }
  })

  test('adopts legacy refresh tokens into a new grant', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const { rawRefreshToken } = await createTestRefreshToken({ scopes: ['read'], grantId: null })

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
    })

    const grantId = await grantIdOf(manager, result.access_token)
    const grant = await manager.findGrant(grantId!)
    assert.deepEqual(grant?.scopes, ['read'])
    assert.isNull(grant?.context)
    assert.equal(grant?.userId, 'user-1')
  })

  test('legacy replay keeps grants of the same client and user', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const legacy = await createTestRefreshToken({
      scopes: ['read'],
      grantId: null,
      revokedAt: DateTime.now().minus({ minutes: 5 }),
    })
    const granted = await createTestRefreshToken({ scopes: ['read'] })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: legacy.rawRefreshToken,
        }),
      'invalid_grant'
    )

    assert.lengthOf(await OAuthRefreshToken.query().whereNull('grantId'), 0)
    assert.lengthOf(await OAuthRefreshToken.query().where('grantId', granted.grantId!), 1)
  })
})

test.group('Grants | Guard', (group) => {
  setupIntegrationGroup(group)

  test('exposes the grant id and context', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const tokens = await authorize(manager, { context: { teamId: 7 } })

    const guard = buildGuard(manager, tokens.access_token)
    await guard.authenticate()

    assert.equal(guard.grantId, await grantIdOf(manager, tokens.access_token))
    assert.deepEqual(guard.context, { teamId: 7 })
    assert.equal(guard.accessToken?.grantId, guard.grantId)
    assert.deepEqual(guard.accessToken?.context, { teamId: 7 })
  })

  test('reads an updated context on the next request', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const tokens = await authorize(manager, { context: { teamId: 7 } })
    const grantId = await grantIdOf(manager, tokens.access_token)

    await manager.updateGrant({ grantId: grantId!, context: { teamId: 8 } })

    const guard = buildGuard(manager, tokens.access_token)
    await guard.authenticate()
    assert.deepEqual(guard.context, { teamId: 8 })
  })

  test('rejects tokens whose grant was revoked or expired', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const revoked = await authorize(manager)
    const expired = await authorize(manager)
    await OAuthGrant.query()
      .where('id', (await grantIdOf(manager, revoked.access_token))!)
      .delete()
    await OAuthGrant.query()
      .where('id', (await grantIdOf(manager, expired.access_token))!)
      .update({ expiresAt: DateTime.now().minus({ minutes: 1 }).toSQL() })

    await assert.rejects(() => buildGuard(manager, revoked.access_token).authenticate())
    await assert.rejects(() => buildGuard(manager, expired.access_token).authenticate())
  })

  test('accepts tokens without grant and exposes no context', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const accessToken = 'legacy-access-token'
    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: new TokenService(manager).hashToken(accessToken),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const guard = buildGuard(manager, accessToken)
    await guard.authenticate()
    assert.isUndefined(guard.grantId)
    assert.isNull(guard.context)
  })

  test('loginAs creates a grant with the given scopes and context', async ({ assert }) => {
    const manager = createManager()
    const request = new RequestFactory().merge({ url: '/' }).create()
    const ctx = new HttpContextFactory().merge({ request }).create()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const loginGuard = new OAuthGuard('oauth', ctx, createFakeEmitter(), provider, manager)

    const { headers } = await loginGuard.authenticateAsClient(
      { id: 'user-1', name: 'Test User' },
      { scopes: ['write'], context: { teamId: 3 } }
    )

    const guard = buildGuard(manager, headers!.authorization.replace('Bearer ', ''))
    await guard.authenticate()
    assert.deepEqual(guard.scopes, ['write'])
    assert.deepEqual(guard.context, { teamId: 3 })
    assert.isString(guard.grantId)
  })
})

test.group('Grants | Manager API', (group) => {
  setupIntegrationGroup(group)

  test('lists active grants with their client, newest first', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    await createTestClient({ clientId: 'other-client', name: 'Other App' })
    const older = await createTestGrant({ context: { teamId: 1 } })
    await new Promise((resolve) => setTimeout(resolve, 5))
    const newer = await createTestGrant({ clientId: 'other-client' })
    await createTestGrant({ expiresAt: DateTime.now().minus({ minutes: 1 }) })
    await createTestGrant({ userId: 'user-2' })

    const grants = await manager.listGrants({ userId: 'user-1' })
    assert.deepEqual(
      grants.map((grant) => grant.id),
      [newer.id, older.id]
    )
    assert.equal(grants[0].client.name, 'Other App')
    assert.notProperty(JSON.parse(JSON.stringify(grants[0])).client, 'clientSecret')
    assert.deepEqual(grants[1].context, { teamId: 1 })

    const forClient = await manager.listGrants({ userId: 'user-1', clientId: 'test-client' })
    assert.deepEqual(
      forClient.map((grant) => grant.id),
      [older.id]
    )
  })

  test('revokes a grant only for its owner', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const grant = await createTestGrant()

    assert.isFalse(await manager.revokeGrant({ grantId: grant.id, userId: 'user-2' }))
    assert.isNotNull(await manager.findGrant(grant.id))
    assert.isTrue(await manager.revokeGrant({ grantId: grant.id, userId: 'user-1' }))
    assert.isFalse(await manager.revokeGrant({ grantId: grant.id }))
  })

  test('revokes every grant of a user for one client', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    await createTestClient({ clientId: 'other-client' })
    await createTestGrant()
    await createTestGrant()
    const kept = await createTestGrant({ clientId: 'other-client' })

    assert.equal(await manager.revokeGrants({ userId: 'user-1', clientId: 'test-client' }), 2)
    assert.deepEqual(
      (await manager.listGrants({ userId: 'user-1' })).map((grant) => grant.id),
      [kept.id]
    )
  })

  test('updates the context of an owned grant', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const grant = await createTestGrant({ context: { teamId: 1 } })

    assert.isNull(await manager.updateGrant({ grantId: grant.id, userId: 'user-2', context: null }))
    assert.deepEqual((await manager.findGrant(grant.id))?.context, { teamId: 1 })

    const updated = await manager.updateGrant({ grantId: grant.id, context: null })
    assert.isNull(updated?.context)
    assert.isNull(await manager.updateGrant({ grantId: crypto.randomUUID(), context: null }))
    await assert.rejects(
      () => manager.updateGrant({ grantId: grant.id, context: 'team' as any }),
      'Grant context must be a plain object or null'
    )
  })

  test('purges grants expired beyond retention', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    await createTestGrant({ expiresAt: DateTime.now().minus({ days: 8 }) })
    const recent = await createTestGrant({ expiresAt: DateTime.now().minus({ hours: 1 }) })

    const result = await manager.purgeTokens()

    assert.equal(result.grants, 1)
    assert.deepEqual(
      (await OAuthGrant.all()).map((grant) => grant.id),
      [recent.id]
    )
  })

  test('deleting a client or a user removes their grants', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    await createTestClient({ clientId: 'other-client' })
    await createTestGrant()
    await createTestGrant({ clientId: 'other-client', userId: 'user-2' })

    await manager.revokeAllForUser('user-1')
    assert.lengthOf(await OAuthGrant.query().where('userId', 'user-1'), 0)

    await manager.deleteClient('other-client')
    assert.lengthOf(await OAuthGrant.all(), 0)
    assert.isNull(await OAuthClient.findBy('clientId', 'other-client'))
  })
})

/**
 * Wrap a store so `findGrant` keeps returning a grant revoked in the
 * meantime, to simulate a revocation racing a token issuance.
 */
function withStaleGrant(store: SesameStore, grant: OAuthGrantRecord): SesameStore {
  return new Proxy(store, {
    get(target, property) {
      if (property === 'findGrant') return async () => grant
      const value = Reflect.get(target, property)

      return typeof value === 'function' ? value.bind(target) : value
    },
  })
}

test.group('Grants | Legacy adoption', (group) => {
  setupIntegrationGroup(group)

  test('replaying an adopted legacy refresh token revokes its new grant', async ({ assert }) => {
    const manager = createManager({ refreshTokenRotationGracePeriod: 0 })
    const client = await createTestClient()
    const legacy = await createTestRefreshToken({ scopes: ['read'], grantId: null })
    const bystander = await createTestRefreshToken({ scopes: ['read'], grantId: null })
    const action = new ExchangeRefreshTokenAction()

    const rotated = await action.execute(manager, { client, refreshToken: legacy.rawRefreshToken })
    const grantId = await grantIdOf(manager, rotated.access_token)
    const adopted = await OAuthRefreshToken.query()
      .where('token', new TokenService(manager).hashToken(legacy.rawRefreshToken))
      .firstOrFail()
    assert.equal(adopted.grantId, grantId)

    await assertOAuthError(
      assert,
      () => action.execute(manager, { client, refreshToken: legacy.rawRefreshToken }),
      'invalid_grant'
    )

    assert.isNull(await manager.findGrant(grantId!))
    await assert.rejects(() => buildGuard(manager, rotated.access_token).authenticate())
    await assertOAuthError(
      assert,
      () => action.execute(manager, { client, refreshToken: rotated.refresh_token }),
      'invalid_grant'
    )
    const untouched = await action.execute(manager, {
      client,
      refreshToken: bystander.rawRefreshToken,
    })
    assert.isString(untouched.access_token)
  })

  test('reusing a legacy refresh token in the grace period keeps one grant', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const legacy = await createTestRefreshToken({ scopes: ['read'], grantId: null })
    const action = new ExchangeRefreshTokenAction()

    const rotated = await action.execute(manager, { client, refreshToken: legacy.rawRefreshToken })
    const retried = await action.execute(manager, { client, refreshToken: legacy.rawRefreshToken })

    assert.lengthOf(await OAuthGrant.all(), 1)
    assert.equal(
      await grantIdOf(manager, retried.access_token),
      await grantIdOf(manager, rotated.access_token)
    )
  })

  test('reusing an exchanged legacy code revokes its new grant', async ({ assert }) => {
    await createTestClient()
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['read'],
      grantId: null,
    })
    const input = { client, code: rawCode, redirectUri, codeVerifier }

    const tokens = await new ExchangeAuthorizationCodeAction().execute(manager, input)
    const grantId = await grantIdOf(manager, tokens.access_token)
    assert.equal((await OAuthAuthorizationCode.query().firstOrFail()).grantId, grantId)

    await assert.rejects(
      () => new ExchangeAuthorizationCodeAction().execute(manager, input),
      'Authorization code has already been consumed'
    )
    assert.isNull(await manager.findGrant(grantId!))
    await assert.rejects(() => buildGuard(manager, tokens.access_token).authenticate())
  })
})

test.group('Grants | Concurrency', (group) => {
  setupIntegrationGroup(group)

  test('a concurrent code exchange revokes the tokens of the winner', async ({ assert }) => {
    await createTestClient()
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['read'],
    })
    const input = { client, code: rawCode, redirectUri, codeVerifier }
    const action = new ExchangeAuthorizationCodeAction()

    const results = await Promise.allSettled([
      action.execute(manager, input),
      action.execute(manager, input),
    ])

    const winner = results.find((result) => result.status === 'fulfilled')
    const loser = results.find((result) => result.status === 'rejected')
    if (winner?.status !== 'fulfilled' || loser?.status !== 'rejected') {
      throw new Error('Expected exactly one successful exchange')
    }
    assert.include(loser.reason.message, 'Authorization code has already been consumed')
    assert.lengthOf(await OAuthGrant.all(), 0)
    await assert.rejects(() => buildGuard(manager, winner.value.access_token).authenticate())
  })

  test('rotation fails when the grant is revoked during the refresh', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, grantId } = await createTestRefreshToken({ scopes: ['read'] })
    const grant = (await createManager().findGrant(grantId!))!
    await OAuthGrant.query().where('id', grantId!).delete()
    const manager = new SesameManager(
      createTestConfig(),
      {} as any,
      withStaleGrant(lucidStore(), grant)
    )

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: rawRefreshToken,
        }),
      'invalid_grant'
    )
    assert.lengthOf(await OAuthAccessToken.query().where('grantId', grantId!), 1)
    assert.isNull(
      (await OAuthRefreshToken.query().where('grantId', grantId!).firstOrFail()).revokedAt
    )
  })

  test('grace-period reuse fails when the grant is revoked meanwhile', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, grantId } = await createTestRefreshToken({
      scopes: ['read'],
      revokedAt: DateTime.now().minus({ seconds: 10 }),
    })
    const grant = (await createManager().findGrant(grantId!))!
    await OAuthGrant.query().where('id', grantId!).delete()
    const manager = new SesameManager(
      createTestConfig(),
      {} as any,
      withStaleGrant(lucidStore(), grant)
    )

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: rawRefreshToken,
        }),
      'invalid_grant'
    )
    assert.lengthOf(await OAuthAccessToken.query().where('grantId', grantId!), 1)
    assert.lengthOf(await OAuthRefreshToken.query().where('grantId', grantId!), 1)
  })

  test('code exchange fails when the grant is revoked meanwhile', async ({ assert }) => {
    await createTestClient()
    const exchange = await createAuthCodeExchange({ scopes: ['read'] })
    const code = await OAuthAuthorizationCode.query().firstOrFail()
    const grant = (await exchange.manager.findGrant(code.grantId!))!
    await OAuthGrant.query().where('id', grant.id).delete()
    const manager = new SesameManager(
      createTestConfig(),
      {} as any,
      withStaleGrant(lucidStore(), grant)
    )

    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client: exchange.client,
          code: exchange.rawCode,
          redirectUri: exchange.redirectUri,
          codeVerifier: exchange.codeVerifier,
        }),
      'Grant has been revoked or has expired'
    )
    assert.lengthOf(await OAuthAccessToken.all(), 0)
    assert.isNull((await OAuthAuthorizationCode.findOrFail(code.id)).consumedAt)
  })
})

test.group('Grants | Expiry', (group) => {
  setupIntegrationGroup(group)

  test('a refresh keeps the grant alive as long as its access token', async ({ assert }) => {
    const manager = createManager({ accessTokenTtl: '1h', refreshTokenTtl: '5m' })
    const client = await createTestClient()
    const { rawRefreshToken, grantId } = await createTestRefreshToken({ scopes: ['read'] })
    await OAuthGrant.query()
      .where('id', grantId!)
      .update({ expiresAt: DateTime.now().plus({ minutes: 1 }).toSQL() })

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
    })

    const grant = await manager.findGrant(grantId!)
    const token = await manager.store.findAccessToken({
      hash: new TokenService(manager).hashToken(result.access_token),
    })
    assert.isAtLeast(grant!.expiresAt.toMillis(), token!.expiresAt.toMillis() - 1000)
  })

  test('ignores grant identifiers that are not UUIDs', async ({ assert }) => {
    const strictStore = new Proxy(lucidStore(), {
      get(target, property) {
        if (property === 'findGrant') {
          return async () => {
            throw new Error('invalid input syntax for type uuid')
          }
        }
        const value = Reflect.get(target, property)

        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const manager = new SesameManager(createTestConfig(), {} as any, strictStore)

    assert.isNull(await manager.findGrant('abc'))
    assert.isFalse(await manager.revokeGrant({ grantId: 'abc' }))
    assert.isNull(await manager.updateGrant({ grantId: 'abc', context: null }))
  })
})

test.group('Grants | Introspection and userinfo', (group) => {
  const ctx = setupHttpGroup(group, {
    jwk: testJwk,
    oidcProvider: new FakeUserProvider([{ id: 'user-1', name: 'Test User' }]),
  })

  test('reports tokens of a revoked or expired grant as inactive', async ({ client, assert }) => {
    await createTestClient({ scopes: ['read', 'openid', 'offline_access'] })
    const revoked = await createTestGrant({ scopes: ['openid'] })
    const expired = await createTestGrant({ expiresAt: DateTime.now().minus({ minutes: 1 }) })
    const accessToken = await createTestAccessToken({ scopes: ['openid'], grantId: revoked.id })
    const refreshToken = await createTestRefreshToken({ grantId: expired.id })
    await OAuthGrant.query().where('id', revoked.id).delete()

    for (const token of [accessToken.raw, refreshToken.rawRefreshToken]) {
      const response = await client.post(`${ctx.baseUrl}/oauth/introspect`).json({
        token,
        client_id: 'test-client',
        client_secret: 'test-secret',
      })
      assert.deepEqual(response.body(), { active: false })
    }

    const userinfo = await client.get(`${ctx.baseUrl}/oauth/userinfo`).bearerToken(accessToken.raw)
    userinfo.assertStatus(401)
  })
})
