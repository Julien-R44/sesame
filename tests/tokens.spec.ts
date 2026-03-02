import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import type { ApplicationService } from '@adonisjs/core/types'
import {
  createApp,
  setupDatabase,
  teardownDatabase,
  createManager,
  createTestClient,
  mockCtx,
} from './helpers.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { TokenService } from '../src/services/token_service.ts'
import { handleRefreshTokenGrant } from '../src/grants/refresh_token_grant.ts'
import TokenController from '../src/controllers/token_controller.ts'
import IntrospectController from '../src/controllers/introspect_controller.ts'
import RevokeController from '../src/controllers/revoke_controller.ts'
import { OAuthError, E_INVALID_CLIENT } from '../src/oauth_error.ts'

let app: ApplicationService

test.group('Integration | Refresh Token Grant', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('exchanges refresh token for new tokens', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'test-refresh-token'
    const hashedRefreshToken = tokenService.hashToken(rawRefreshToken)

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'old-token-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write', 'offline_access'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: hashedRefreshToken,
      accessTokenId: 'old-token-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write', 'offline_access'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const result = await handleRefreshTokenGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.equal(result.token_type, 'Bearer')
    assert.notEqual(result.refresh_token, rawRefreshToken)
  })

  test('rejects refresh token grant when the client is not allowed to use it', async ({
    assert,
  }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    const client = await createTestClient({ grantTypes: ['authorization_code'] })

    const rawRefreshToken = 'grant-type-bypass-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'grant-type-bypass-hash',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: client.clientId,
        client_secret: 'test-secret',
      },
    })

    try {
      await handleRefreshTokenGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.isTrue(
        ['invalid_client', 'unauthorized_client', 'unsupported_grant_type'].includes(
          error.oauthCode
        )
      )
    }
  })

  test('supports scope downgrading', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'downgrade-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-token-hash-2',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write', 'offline_access'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read',
      },
    })

    const result = await handleRefreshTokenGrant(ctx, manager)
    assert.equal(result.scope, 'read')
  })

  test('rejects scope escalation', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'escalation-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-token-hash-3',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'read write',
      },
    })

    try {
      await handleRefreshTokenGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
    }
  })

  test('replay detection revokes all tokens', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'replayed-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-token-hash-4',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
      revokedAt: DateTime.now().minus({ minutes: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('other-valid-token'),
      accessTokenId: 'other-token-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    try {
      await handleRefreshTokenGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_grant')
    }

    const remaining = await OAuthRefreshToken.query()
      .where('clientId', 'test-client')
      .where('userId', 'user-1')
    assert.lengthOf(remaining, 0)
  })

  test('rejects concurrent rotation of the same refresh token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'racy-refresh-token'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'racy-refresh-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const makeCtx = () =>
      mockCtx({
        manager,
        body: {
          grant_type: 'refresh_token',
          refresh_token: rawRefreshToken,
          client_id: 'test-client',
          client_secret: 'test-secret',
        },
      })

    const results = await Promise.allSettled([
      handleRefreshTokenGrant(makeCtx(), manager),
      handleRefreshTokenGrant(makeCtx(), manager),
    ])

    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
    assert.equal(results.filter((result) => result.status === 'rejected').length, 1)
  })

  test('rejects expired refresh token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'expired-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'old-token-hash-5',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ days: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    await assert.rejects(() => handleRefreshTokenGrant(ctx, manager), 'Refresh token has expired')
  })
})

test.group('Integration | Token Endpoint Dispatch', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  test('rejects unsupported grant type', async ({ assert }) => {
    const manager = createManager()
    const controller = new TokenController()
    const ctx = mockCtx({ manager, body: { grant_type: 'password' } })

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'unsupported_grant_type')
    }
  })

  test('rejects missing grant type', async ({ assert }) => {
    const manager = createManager()
    const controller = new TokenController()
    const ctx = mockCtx({ manager, body: {} })

    await assert.rejects(() => controller.handle(ctx), 'Missing required parameter: grant_type')
  })
})

test.group('Integration | Introspection', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('introspects a valid access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = (await controller.handle(ctx)) as any

    assert.isTrue(result.active)
    assert.equal(result.client_id, 'test-client')
    assert.equal(result.sub, 'user-1')
    assert.equal(result.scope, 'read')
  })

  test('rejects introspection for a confidential client without a secret', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        client_id: 'test-client',
      },
    })

    const controller = new IntrospectController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
  })

  test('returns inactive for revoked token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
      revokedAt: DateTime.now(),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })

  test('returns inactive for unknown token', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    const ctx = mockCtx({
      manager,
      body: {
        token: 'some-unknown-token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })

  test('returns inactive for missing token', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    const ctx = mockCtx({
      manager,
      body: {
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })

  test('introspects a valid refresh token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'introspect-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'some-token-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: rawRefreshToken,
        token_type_hint: 'refresh_token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new IntrospectController()
    const result = (await controller.handle(ctx)) as any

    assert.isTrue(result.active)
    assert.equal(result.client_id, 'test-client')
    assert.equal(result.sub, 'user-1')
    assert.equal(result.scope, 'read write')
  })

  test('returns inactive when another client introspects the access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()
    await createTestClient({
      clientId: 'other-client',
      name: 'Other Client',
      redirectUris: ['https://other.example.com/callback'],
      rawClientSecret: 'other-secret',
    })

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        client_id: 'other-client',
        client_secret: 'other-secret',
      },
    })

    const controller = new IntrospectController()
    const result = await controller.handle(ctx)
    assert.isFalse(result.active)
  })
})

test.group('Integration | Revocation', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('revokes an access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        token_type_hint: 'access_token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new RevokeController()
    await controller.handle(ctx)

    const record = await OAuthAccessToken.query().where('tokenHash', hash).firstOrFail()
    assert.isNotNull(record.revokedAt)
  })

  test('rejects revocation for a confidential client without a secret', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        token_type_hint: 'access_token',
        client_id: 'test-client',
      },
    })

    const controller = new RevokeController()

    try {
      await controller.handle(ctx)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_client')
    }
  })

  test('revokes a refresh token and associated access token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const rawRefreshToken = 'revoke-me-refresh'

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'linked-token-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: 'linked-token-hash',
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const ctx = mockCtx({
      manager,
      body: {
        token: rawRefreshToken,
        token_type_hint: 'refresh_token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    const controller = new RevokeController()
    await controller.handle(ctx)

    const refresh = await OAuthRefreshToken.query()
      .where('token', tokenService.hashToken(rawRefreshToken))
      .firstOrFail()
    assert.isNotNull(refresh.revokedAt)

    const access = await OAuthAccessToken.query()
      .where('tokenHash', 'linked-token-hash')
      .firstOrFail()
    assert.isNotNull(access.revokedAt)
  })

  test('always returns 200 even for unknown tokens', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    let statusCode: number | undefined
    const ctx = mockCtx({
      manager,
      body: {
        token: 'totally-unknown-token',
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })
    ctx.response.ok = (data: any) => {
      statusCode = 200

      return data
    }

    const controller = new RevokeController()
    await controller.handle(ctx)
    assert.equal(statusCode, 200)
  })
})

test.group('E_INVALID_CLIENT | WWW-Authenticate header', () => {
  test('sets WWW-Authenticate: Basic when client used Authorization header', async ({
    assert,
  }) => {
    const error = new E_INVALID_CLIENT('Client not found')
    const ctx = mockCtx({
      headers: { authorization: 'Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=' },
    })

    error.handle(error, ctx)

    assert.equal(ctx.__responseHeaders['WWW-Authenticate'], 'Basic')
  })

  test('does not set WWW-Authenticate when client used POST body credentials', async ({
    assert,
  }) => {
    const error = new E_INVALID_CLIENT('Client not found')
    const ctx = mockCtx({})

    error.handle(error, ctx)

    assert.notProperty(ctx.__responseHeaders, 'WWW-Authenticate')
  })
})
