import { test } from '@japa/runner'
import { createHash } from 'node:crypto'
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
import MetadataController from '../src/controllers/metadata_controller.ts'
import { OAuthError, E_INVALID_CLIENT } from '../src/oauth_error.ts'

let app: ApplicationService

test.group('Integration | Metadata Endpoints', () => {
  test('returns OAuth authorization server metadata', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)

    assert.equal(result.issuer, 'https://auth.example.com')
    assert.equal(result.authorization_endpoint, 'https://auth.example.com/oauth/authorize')
    assert.equal(result.token_endpoint, 'https://auth.example.com/oauth/token')
    assert.deepEqual(result.response_types_supported, ['code'])
    assert.deepEqual(result.code_challenge_methods_supported, ['S256'])
    assert.isTrue(result.authorization_response_iss_parameter_supported)
    assert.isDefined(result.registration_endpoint)
  })

  test('returns protected resource metadata for MCP', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.protectedResource(ctx)

    assert.equal(result.resource, 'https://auth.example.com')
    assert.deepEqual(result.authorization_servers, ['https://auth.example.com'])
    assert.isArray(result.scopes_supported)
    assert.deepEqual(result.bearer_methods_supported, ['header'])
  })

  test('returns OIDC metadata', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.oidc(ctx)

    assert.equal(result.issuer, 'https://auth.example.com')
    assert.deepEqual(result.subject_types_supported, ['public'])
    assert.isArray(result.scopes_supported)
  })

  test('hides registration endpoint when disabled', async ({ assert }) => {
    const manager = createManager({ allowDynamicRegistration: false })
    const ctx = mockCtx({ manager })

    const controller = new MetadataController()
    const result = await controller.authServer(ctx)
    assert.isUndefined(result.registration_endpoint)
  })
})

test.group('Integration | OAuth Error Handling', () => {
  test('OAuthError has correct properties', ({ assert }) => {
    const error = new E_INVALID_CLIENT('Client not found')

    assert.equal(error.status, 401)
    assert.equal(error.oauthCode, 'invalid_client')
    assert.equal(error.message, 'Client not found')
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

  test('checks grant type support', ({ assert }) => {
    const manager = createManager()

    assert.isTrue(manager.isGrantTypeEnabled('authorization_code'))
    assert.isTrue(manager.isGrantTypeEnabled('refresh_token'))
    assert.isFalse(manager.isGrantTypeEnabled('client_credentials'))
  })

  test('parses TTL strings', ({ assert }) => {
    const manager = createManager()

    assert.equal(manager.parseTtl('1h'), 3600)
    assert.equal(manager.parseTtl('30m'), 1800)
    assert.equal(manager.parseTtl('10d'), 864000)
    assert.equal(manager.parseTtl('60s'), 60)
  })

  test('throws on invalid TTL', ({ assert }) => {
    const manager = createManager()

    assert.throws(() => manager.parseTtl('invalid'))
    assert.throws(() => manager.parseTtl('10x'))
  })
})

test.group('Integration | revokeAllForUser', (group) => {
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

  test('revokes all tokens, codes and consents for a user', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const tokenService = new TokenService(manager)

    // Create access token
    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: 'at-1',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    // Create refresh token
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('rt-1'),
      accessTokenId: 'at-1',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    // Create authorization code
    const revokeVerifier = 'revoke-all-verifier'
    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('code-1'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: createHash('sha256').update(revokeVerifier).digest('base64url'),
      codeChallengeMethod: 'S256',
      expiresAt: DateTime.now().plus({ minutes: 10 }),
    })

    // Create consent
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
      .where('accessTokenId', 'at-1')
      .firstOrFail()
    assert.isNotNull(refreshToken.revokedAt)

    const codes = await OAuthAuthorizationCode.query().where('userId', 'user-1')
    assert.lengthOf(codes, 0)

    const consents = await OAuthConsent.query().where('userId', 'user-1')
    assert.lengthOf(consents, 0)
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
