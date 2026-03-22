import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createPkce } from './helpers/create_pkce.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'
import { TokenService } from '../src/services/token_service.ts'
import { OAuthError, E_INVALID_CLIENT } from '../src/oauth_error.ts'
import { ClientService } from '../src/services/client_service.ts'

test.group('Integration | OAuth Error Handling', () => {
  test('OAuthError has correct properties', ({ assert }) => {
    const error = new E_INVALID_CLIENT('Client authentication failed')

    assert.equal(error.status, 401)
    assert.equal(error.oauthCode, 'invalid_client')
    assert.equal(error.message, 'Client authentication failed')
    assert.instanceOf(error, OAuthError)
  })
})

test.group('Integration | TokenService', () => {
  test('createAccessToken returns raw, hash and expiresAt', ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)

    const { raw, hash, expiresAt } = tokenService.createAccessToken()

    assert.isString(raw)
    assert.isString(hash)
    assert.notEqual(raw, hash)
    assert.instanceOf(expiresAt, Date)
    assert.equal(hash, tokenService.hashToken(raw))
  })
})

test.group('Integration | SesameManager', () => {
  test('validates scopes', ({ assert }) => {
    const manager = createManager()

    assert.deepEqual(manager.validateScopes(['read', 'write']), [])
    assert.deepEqual(manager.validateScopes(['read', 'admin']), ['admin'])
  })

  test('offline_access is always valid even when not in configured scopes', ({ assert }) => {
    const manager = createManager({ scopes: { read: 'Read access' } })

    assert.deepEqual(manager.validateScopes(['read', 'offline_access']), [])
    assert.deepEqual(manager.validateScopes(['offline_access']), [])
  })

  test('offline_access is valid even when scopes config is empty', ({ assert }) => {
    const manager = createManager({ scopes: {} })

    assert.deepEqual(manager.validateScopes(['offline_access']), [])
    assert.deepEqual(manager.validateScopes(['offline_access', 'admin']), ['admin'])
  })

  test('OIDC scopes are valid even when scopes config is empty', ({ assert }) => {
    const manager = createManager({ scopes: {} })

    assert.deepEqual(manager.validateScopes(['openid']), [])
    assert.deepEqual(manager.validateScopes(['openid', 'profile', 'email']), [])
    assert.deepEqual(manager.validateScopes(['openid', 'profile', 'admin']), ['admin'])
  })

  test('checks grant type support', ({ assert }) => {
    const manager = createManager()

    assert.isTrue(manager.isGrantTypeEnabled('authorization_code'))
    assert.isTrue(manager.isGrantTypeEnabled('refresh_token'))
    assert.isFalse(manager.isGrantTypeEnabled('client_credentials'))
  })
})

test.group('Integration | revokeAllForUser', (group) => {
  setupIntegrationGroup(group)

  test('revokes all tokens, codes and consents for a user', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const tokenService = new TokenService(manager)
    const { codeChallenge } = createPkce('revoke-all-verifier')

    const accessTokenId = crypto.randomUUID()
    await OAuthAccessToken.create({
      id: accessTokenId,
      tokenHash: 'at-1',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('rt-1'),
      accessTokenId,
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('code-1'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge,
      codeChallengeMethod: 'S256',
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    await OAuthConsent.create({
      id: crypto.randomUUID(),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
    })

    await manager.revokeAllForUser('user-1')

    const accessToken = await OAuthAccessToken.query().where('tokenHash', 'at-1').firstOrFail()
    assert.isNotNull(accessToken.revokedAt)

    const refreshToken = await OAuthRefreshToken.query()
      .where('accessTokenId', accessTokenId)
      .firstOrFail()
    assert.isNotNull(refreshToken.revokedAt)

    const codes = await OAuthAuthorizationCode.query().where('userId', 'user-1')
    assert.lengthOf(codes, 0)

    const consents = await OAuthConsent.query().where('userId', 'user-1')
    assert.lengthOf(consents, 0)
  })

  test('revokes pending authorization requests for a user', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const tokenService = new TokenService(manager)

    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('pending-1'),
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('pending-2'),
      clientId: client.clientId,
      userId: 'user-2',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    await manager.revokeAllForUser('user-1')

    const user1Pending = await OAuthPendingAuthorizationRequest.query().where('userId', 'user-1')
    assert.lengthOf(user1Pending, 0)

    const user2Pending = await OAuthPendingAuthorizationRequest.query().where('userId', 'user-2')
    assert.lengthOf(user2Pending, 1)
  })

  test('does not affect other users', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'at-user1',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'at-user2',
      clientId: client.clientId,
      userId: 'user-2',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await manager.revokeAllForUser('user-1')

    const revokedToken = await OAuthAccessToken.query().where('tokenHash', 'at-user1').firstOrFail()
    assert.isNotNull(revokedToken.revokedAt)

    const untouchedToken = await OAuthAccessToken.query()
      .where('tokenHash', 'at-user2')
      .firstOrFail()
    assert.isNull(untouchedToken.revokedAt)
  })
})

test.group('Security | Scope validation bypass (C1/C2)', () => {
  test('C1: validateScopes rejects all scopes when server scopes config is empty (except builtins)', ({
    assert,
  }) => {
    const manager = createManager({ scopes: {} })
    const invalid = manager.validateScopes(['admin', 'superuser', 'delete_all'])
    assert.deepEqual(invalid, ['admin', 'superuser', 'delete_all'])
  })

  test('C1: validateScopes allows empty scope list when server scopes config is empty', ({
    assert,
  }) => {
    const manager = createManager({ scopes: {} })
    assert.deepEqual(manager.validateScopes([]), [])
  })

  test('C2: validateClientScopes rejects any scope when client scopes are empty', ({ assert }) => {
    const service = new ClientService()
    assert.throws(
      () => service.validateClientScopes(['admin', 'delete_all'], []),
      'Scope not allowed'
    )
  })

  test('C2: validateClientScopes allows empty request when client scopes are empty', ({
    assert,
  }) => {
    const service = new ClientService()
    assert.doesNotThrow(() => service.validateClientScopes([], []))
  })
})
