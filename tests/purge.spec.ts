import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import type { ApplicationService } from '@adonisjs/core/types'
import { createApp, setupDatabase, teardownDatabase, createManager } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { cleanModels } from './helpers/clean_models.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'
import { TokenService } from '../src/services/token_service.ts'

let app: ApplicationService

test.group('SesameManager | purgeTokens', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(cleanModels())

  test('purges expired access tokens beyond retention period', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    // Expired 8 days ago (beyond default 168h retention)
    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('old-expired'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ days: 8 }),
    })

    // Expired 1 hour ago (within retention)
    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('recent-expired'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ hours: 1 }),
    })

    // Still valid
    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('still-valid'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const result = await manager.purgeTokens({ expiredOnly: true })

    assert.equal(result.accessTokens, 1)
    const remaining = await OAuthAccessToken.query()
    assert.lengthOf(remaining, 2)
    const hashes = remaining.map((t) => t.tokenHash)
    assert.includeMembers(hashes, [
      tokenService.hashToken('recent-expired'),
      tokenService.hashToken('still-valid'),
    ])
  })

  test('purges revoked access tokens and refresh tokens', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('revoked-at'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
      revokedAt: DateTime.now().minus({ hours: 1 }),
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('active-at'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('revoked-rt'),
      accessTokenId: 'x',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
      revokedAt: DateTime.now().minus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('active-rt'),
      accessTokenId: 'y',
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
    })

    const result = await manager.purgeTokens({ revokedOnly: true })

    assert.equal(result.accessTokens, 1)
    assert.equal(result.refreshTokens, 1)
    assert.equal(result.authorizationCodes, 0)

    const accessTokens = await OAuthAccessToken.query()
    assert.lengthOf(accessTokens, 1)
    assert.equal(accessTokens[0].tokenHash, tokenService.hashToken('active-at'))

    const refreshTokens = await OAuthRefreshToken.query()
    assert.lengthOf(refreshTokens, 1)
    assert.equal(refreshTokens[0].token, tokenService.hashToken('active-rt'))
  })

  test('purges expired authorization codes', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('old-code'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().minus({ days: 8 }),
    })

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('fresh-code'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 5 }),
    })

    const result = await manager.purgeTokens({ expiredOnly: true })

    assert.equal(result.authorizationCodes, 1)
    const codes = await OAuthAuthorizationCode.query()
    assert.lengthOf(codes, 1)
    assert.equal(codes[0].code, tokenService.hashToken('fresh-code'))
  })

  test('purges both revoked and expired by default', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('revoked'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
      revokedAt: DateTime.now(),
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('expired'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ days: 8 }),
    })

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('active'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const result = await manager.purgeTokens()

    assert.equal(result.accessTokens, 2)
    const remaining = await OAuthAccessToken.query()
    assert.lengthOf(remaining, 1)
    assert.equal(remaining[0].tokenHash, tokenService.hashToken('active'))
  })

  test('respects custom retention hours', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('expired-2h'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().minus({ hours: 2 }),
    })

    const result = await manager.purgeTokens({ expiredOnly: true, retentionHours: 1 })

    assert.equal(result.accessTokens, 1)
    const remaining = await OAuthAccessToken.query()
    assert.lengthOf(remaining, 0)
  })

  test('purges expired pending authorization requests without retention period', async ({
    assert,
  }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('expired-pending'),
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().minus({ minutes: 1 }),
    })

    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('active-pending'),
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().plus({ minutes: 5 }),
    })

    const result = await manager.purgeTokens()

    assert.equal(result.pendingRequests, 1)
    const remaining = await OAuthPendingAuthorizationRequest.query()
    assert.lengthOf(remaining, 1)
    assert.equal(remaining[0].token, tokenService.hashToken('active-pending'))
  })

  test('purges pending requests regardless of revokedOnly/expiredOnly flags', async ({
    assert,
  }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('expired-flag-test'),
      clientId: client.clientId,
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().minus({ minutes: 1 }),
    })

    const result = await manager.purgeTokens({ revokedOnly: true })
    assert.equal(result.pendingRequests, 1)
  })

  test('does not purge authorization codes with --revoked flag', async ({ assert }) => {
    const client = await createTestClient()
    const manager = createManager()
    const tokenService = new TokenService(manager)

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('old-code'),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().minus({ days: 8 }),
    })

    const result = await manager.purgeTokens({ revokedOnly: true })

    assert.equal(result.authorizationCodes, 0)
    const codes = await OAuthAuthorizationCode.query()
    assert.lengthOf(codes, 1)
  })
})
