import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import type { ApplicationService } from '@adonisjs/core/types'
import { createApp, setupDatabase, teardownDatabase, createManager } from './helpers/app.ts'
import { mockCtx } from './helpers/mock_ctx.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestAccessToken } from './helpers/create_test_access_token.ts'
import { createTestRefreshToken } from './helpers/create_test_refresh_token.ts'
import { cleanModels } from './helpers/clean_models.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { TokenService } from '../src/services/token_service.ts'
import { handleRefreshTokenGrant } from '../src/grants/refresh_token_grant.ts'
import TokenController from '../src/controllers/token_controller.ts'
import IntrospectController from '../src/controllers/introspect_controller.ts'
import RevokeController from '../src/controllers/revoke_controller.ts'
import { E_INVALID_CLIENT } from '../src/oauth_error.ts'

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

  group.each.setup(cleanModels())

  test('exchanges refresh token for new tokens', async ({ assert }) => {
    await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken()

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

  test('revokes old access token during rotation', async ({ assert }) => {
    await createTestClient()
    const { rawRefreshToken, accessTokenHash, manager } = await createTestRefreshToken()

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

    const oldAccessToken = await OAuthAccessToken.query()
      .where('tokenHash', accessTokenHash)
      .firstOrFail()
    assert.isNotNull(oldAccessToken.revokedAt)
  })

  test('rejects refresh token grant when the client is not allowed to use it', async ({
    assert,
  }) => {
    await createTestClient({ grantTypes: ['authorization_code'] })
    const { rawRefreshToken, manager } = await createTestRefreshToken({ scopes: ['read'] })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
      },
    })

    await assertOAuthError(assert, () => handleRefreshTokenGrant(ctx, manager), 'invalid_client')
  })

  test('supports scope downgrading', async ({ assert }) => {
    await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken()

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

  test('rejects narrowing OIDC scopes to profile/email without openid', async ({ assert }) => {
    await createTestClient({
      scopes: ['read', 'openid', 'profile', 'email', 'offline_access'],
    })
    const { rawRefreshToken, manager } = await createTestRefreshToken({
      scopes: ['openid', 'profile', 'email'],
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'refresh_token',
        refresh_token: rawRefreshToken,
        client_id: 'test-client',
        client_secret: 'test-secret',
        scope: 'profile email',
      },
    })

    await assertOAuthError(assert, () => handleRefreshTokenGrant(ctx, manager), 'invalid_scope', [
      'profile',
      'email',
    ])
  })

  test('rejects scope escalation', async ({ assert }) => {
    await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken({ scopes: ['read'] })

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

    await assertOAuthError(assert, () => handleRefreshTokenGrant(ctx, manager), 'invalid_scope')
  })

  test('replay detection revokes all tokens', async ({ assert }) => {
    await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    // Revoked refresh token (replayed)
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

    // Another valid refresh token for the same user+client
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

    await assertOAuthError(assert, () => handleRefreshTokenGrant(ctx, manager), 'invalid_grant')

    const remaining = await OAuthRefreshToken.query()
      .where('clientId', 'test-client')
      .where('userId', 'user-1')
    assert.lengthOf(remaining, 0)
  })

  test('rejects concurrent rotation of the same refresh token', async ({ assert }) => {
    await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken({ scopes: ['read'] })

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
    await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken({
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

    await assertOAuthError(assert, () => controller.handle(ctx), 'unsupported_grant_type')
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

  group.each.setup(cleanModels())

  test('introspects a valid access token', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })

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
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        client_id: 'test-client',
      },
    })

    const controller = new IntrospectController()

    await assertOAuthError(assert, () => controller.handle(ctx), 'invalid_client')
  })

  test('returns inactive for revoked token', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({
      scopes: ['read'],
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
    await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken({
      scopes: ['read', 'write'],
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
    await createTestClient()
    await createTestClient({
      clientId: 'other-client',
      name: 'Other Client',
      redirectUris: ['https://other.example.com/callback'],
      rawClientSecret: 'other-secret',
    })

    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })

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

  group.each.setup(cleanModels())

  test('revokes an access token', async ({ assert }) => {
    await createTestClient()
    const { raw, hash, manager } = await createTestAccessToken({ scopes: ['read'] })

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
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })

    const ctx = mockCtx({
      manager,
      body: {
        token: raw,
        token_type_hint: 'access_token',
        client_id: 'test-client',
      },
    })

    await assertOAuthError(assert, () => new RevokeController().handle(ctx), 'invalid_client')
  })

  test('revokes a refresh token and associated access token', async ({ assert }) => {
    await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)
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
  test('sets WWW-Authenticate: Basic when client used Authorization header', async ({ assert }) => {
    const error = new E_INVALID_CLIENT('Client authentication failed')
    const ctx = mockCtx({
      headers: { authorization: 'Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=' },
    })

    error.handle(error, ctx)

    assert.equal(ctx.__responseHeaders['WWW-Authenticate'], 'Basic')
  })

  test('does not set WWW-Authenticate when client used POST body credentials', async ({
    assert,
  }) => {
    const error = new E_INVALID_CLIENT('Client authentication failed')
    const ctx = mockCtx({})

    error.handle(error, ctx)

    assert.notProperty(ctx.__responseHeaders, 'WWW-Authenticate')
  })
})
