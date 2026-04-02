import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestRefreshToken } from './helpers/create_test_refresh_token.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { TokenService } from '../src/services/token_service.ts'
import { ExchangeRefreshTokenAction } from '../src/actions/exchange_refresh_token.ts'

test.group('Integration | Refresh Token Grant', (group) => {
  setupIntegrationGroup(group)

  test('exchanges refresh token for new tokens', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken()

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
    })

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.equal(result.token_type, 'Bearer')
    assert.notEqual(result.refresh_token, rawRefreshToken)
  })

  test('revokes old access token during rotation', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, accessTokenHash, manager } = await createTestRefreshToken()

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
    })

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
    const client = await createTestClient({ grantTypes: ['authorization_code'] })
    const { rawRefreshToken, manager } = await createTestRefreshToken({ scopes: ['read'] })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: rawRefreshToken,
        }),
      'invalid_client'
    )
  })

  test('supports scope downgrading', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken()

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
      scope: 'read',
    })

    assert.equal(result.scope, 'read')
  })

  test('rejects narrowing OIDC scopes to profile/email without openid', async ({ assert }) => {
    const client = await createTestClient({
      scopes: ['read', 'openid', 'profile', 'email', 'offline_access'],
    })
    const { rawRefreshToken, manager } = await createTestRefreshToken({
      scopes: ['openid', 'profile', 'email'],
    })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: rawRefreshToken,
          scope: 'profile email',
        }),
      'invalid_scope',
      ['profile', 'email']
    )
  })

  test('rejects scope escalation', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken({ scopes: ['read'] })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: rawRefreshToken,
          scope: 'read write',
        }),
      'invalid_scope'
    )
  })

  test('replay detection revokes all tokens', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    // Revoked refresh token (replayed)
    const rawRefreshToken = 'replayed-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: crypto.randomUUID(),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
      revokedAt: DateTime.now().minus({ minutes: 5 }),
    })

    // Another valid refresh token for the same user+client
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('other-valid-token'),
      accessTokenId: crypto.randomUUID(),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: rawRefreshToken,
        }),
      'invalid_grant'
    )

    const remaining = await OAuthRefreshToken.query()
      .where('clientId', 'test-client')
      .where('userId', 'user-1')
    assert.lengthOf(remaining, 0)
  })

  test('grace period allows recently-rotated refresh token reuse', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    const rawRefreshToken = 'recently-rotated-refresh'
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawRefreshToken),
      accessTokenId: crypto.randomUUID(),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
      revokedAt: DateTime.now().minus({ seconds: 30 }),
    })

    const result = await new ExchangeRefreshTokenAction().execute(manager, {
      client,
      refreshToken: rawRefreshToken,
    })

    assert.property(result, 'access_token')
    assert.property(result, 'refresh_token')
    assert.equal(result.token_type, 'Bearer')
  })

  test('rejects concurrent rotation of the same refresh token', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken({ scopes: ['read'] })

    const action = new ExchangeRefreshTokenAction()
    const results = await Promise.allSettled([
      action.execute(manager, { client, refreshToken: rawRefreshToken }),
      action.execute(manager, { client, refreshToken: rawRefreshToken }),
    ])

    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
    assert.equal(results.filter((result) => result.status === 'rejected').length, 1)
  })

  test('rejects expired refresh token', async ({ assert }) => {
    const client = await createTestClient()
    const { rawRefreshToken, manager } = await createTestRefreshToken({
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ days: 1 }),
    })

    await assert.rejects(
      () =>
        new ExchangeRefreshTokenAction().execute(manager, {
          client,
          refreshToken: rawRefreshToken,
        }),
      'Refresh token has expired'
    )
  })
})
