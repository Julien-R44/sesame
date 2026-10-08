import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { AceFactory } from '@adonisjs/core/factories'
import SesamePurge from '../commands/sesame_purge.ts'
import { SesameManager } from '../src/sesame_manager.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'
import { TokenService } from '../src/services/token_service.ts'
import { ExchangeAuthorizationCodeAction } from '../src/actions/exchange_authorization_code.ts'
import { markFirstAuthorization } from '../src/storage/unused_clients.ts'
import { createAuthCodeExchange } from './helpers/create_auth_code_exchange.ts'

test.group('SesameManager | purgeTokens', (group) => {
  setupIntegrationGroup(group)

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
      accessTokenId: crypto.randomUUID(),
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ days: 30 }),
      revokedAt: DateTime.now().minus({ hours: 1 }),
    })

    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('active-rt'),
      accessTokenId: crypto.randomUUID(),
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

test.group('SesameManager | purgeUnusedClients', (group) => {
  setupIntegrationGroup(group)

  const dynamicMetadata = { token_endpoint_auth_method: 'none', registration: 'dynamic' }

  function createOldClient(clientId: string, metadata: Record<string, any> | null) {
    return createTestClient({ clientId, metadata, createdAt: DateTime.now().minus({ days: 40 }) })
  }

  test('deletes old dynamic clients that were never used', async ({ assert }) => {
    await createOldClient('dynamic-unused', dynamicMetadata)
    await createOldClient('legacy-dynamic-unused', { token_endpoint_auth_method: 'none' })

    const deleted = await createManager().purgeUnusedClients()

    assert.equal(deleted, 2)
    assert.lengthOf(await OAuthClient.query(), 0)
  })

  test('keeps manual, recent, and used clients', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    const expiresAt = DateTime.now().plus({ hours: 1 })

    await createOldClient('manual', null)
    await createOldClient('manual-with-metadata', { team: 'core' })
    await createTestClient({ clientId: 'recent', metadata: dynamicMetadata })
    await createOldClient('with-access-token', dynamicMetadata)
    await createOldClient('with-refresh-token', dynamicMetadata)
    await createOldClient('with-code', dynamicMetadata)
    await createOldClient('with-consent', dynamicMetadata)
    await createOldClient('with-pending', dynamicMetadata)

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: tokenService.hashToken('access'),
      clientId: 'with-access-token',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt,
    })
    await OAuthRefreshToken.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('refresh'),
      accessTokenId: crypto.randomUUID(),
      clientId: 'with-refresh-token',
      userId: 'user-1',
      scopes: ['read'],
      expiresAt,
    })
    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken('code'),
      clientId: 'with-code',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      expiresAt,
    })
    await OAuthConsent.create({
      id: crypto.randomUUID(),
      clientId: 'with-consent',
      userId: 'user-1',
      scopes: ['read'],
    })
    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken('pending'),
      clientId: 'with-pending',
      userId: 'user-1',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      expiresAt,
    })

    const deleted = await manager.purgeUnusedClients()

    assert.equal(deleted, 0)
    assert.lengthOf(await OAuthClient.query(), 8)
  })

  test('keeps an authorized client after its user is revoked and tokens are purged', async ({
    assert,
  }) => {
    await createOldClient('mcp-client', dynamicMetadata)
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      clientId: 'mcp-client',
    })

    await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })
    await manager.revokeAllForUser('user-1')
    await manager.purgeTokens()

    assert.lengthOf(await OAuthAccessToken.query(), 0)
    assert.lengthOf(await OAuthRefreshToken.query(), 0)
    assert.equal(await manager.purgeUnusedClients(), 0)

    const stored = await manager.findClient('mcp-client')
    assert.isString(stored?.metadata?.first_authorized_at)
  })

  test('keeps dynamic clients carrying first_authorized_at', async ({ assert }) => {
    await createOldClient('authorized', { ...dynamicMetadata, first_authorized_at: '2026-01-01' })

    assert.equal(await createManager().purgeUnusedClients(), 0)
  })

  test('honors olderThanDays', async ({ assert }) => {
    await createTestClient({
      clientId: 'ten-days-old',
      metadata: dynamicMetadata,
      createdAt: DateTime.now().minus({ days: 10 }),
    })

    assert.equal(await createManager().purgeUnusedClients(), 0)
    assert.equal(await createManager().purgeUnusedClients({ olderThanDays: 7 }), 1)
  })
})

test.group('sesame:purge command', () => {
  async function runPurge(args: string[]) {
    const calls: string[] = []
    const fakeManager = {
      async purgeTokens() {
        calls.push('tokens')
        return { accessTokens: 0, refreshTokens: 0, authorizationCodes: 0, pendingRequests: 0 }
      },
      async purgeUnusedClients(options: { olderThanDays: number }) {
        calls.push(`clients:${options.olderThanDays}`)
        return 2
      },
    }

    const ace = await new AceFactory().make(new URL('./', import.meta.url))
    await ace.boot()
    ace.app.container.singleton(SesameManager, () => fakeManager as any)

    const command = await ace.create(SesamePurge, args)
    await command.exec()

    return { command, calls }
  }

  test('does not purge clients by default', async ({ assert }) => {
    const { command, calls } = await runPurge([])

    assert.equal(command.exitCode, 0)
    assert.deepEqual(calls, ['tokens'])
  })

  test('purges unused clients after tokens with --clients', async ({ assert }) => {
    const { command, calls } = await runPurge(['--clients', '--client-days=7'])

    assert.equal(command.exitCode, 0)
    assert.deepEqual(calls, ['tokens', 'clients:7'])
  })

  test('defaults --client-days to 30', async ({ assert }) => {
    const { calls } = await runPurge(['--clients'])

    assert.deepEqual(calls, ['tokens', 'clients:30'])
  })
})

test.group('markFirstAuthorization', () => {
  function fakeStore() {
    const updates: any[] = []
    const store = {
      async updateClient(options: any) {
        updates.push(options)
      },
    }

    return { store: store as any, updates }
  }

  test('writes the marker once on dynamic clients', async ({ assert }) => {
    const { store, updates } = fakeStore()
    const client = { id: 'id-1', metadata: { registration: 'dynamic' } } as any

    await markFirstAuthorization({ store, client })
    await markFirstAuthorization({
      store,
      client: { ...client, metadata: updates[0].data.metadata },
    })

    assert.lengthOf(updates, 1)
    assert.equal(updates[0].id, 'id-1')
    assert.equal(updates[0].data.metadata.registration, 'dynamic')
    assert.isString(updates[0].data.metadata.first_authorized_at)
  })

  test('leaves manually created clients untouched', async ({ assert }) => {
    const { store, updates } = fakeStore()

    await markFirstAuthorization({ store, client: { id: 'a', metadata: null } as any })
    await markFirstAuthorization({ store, client: { id: 'b', metadata: { team: 'x' } } as any })

    assert.lengthOf(updates, 0)
  })
})
