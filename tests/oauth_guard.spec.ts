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
  FakeUserProvider,
  createFakeEmitter,
} from './helpers.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { TokenService } from '../src/services/token_service.ts'
import { OAuthGuard } from '../src/guard/guard.ts'
import { errors } from '@adonisjs/auth'

let app: ApplicationService

test.group('OAuthGuard', (group) => {
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

  test('authenticates with a valid token', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    const user = await guard.authenticate()

    assert.deepEqual(user, { id: 'user-1', name: 'Test User' })
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.deepEqual(guard.scopes, ['read', 'write'])
    assert.equal(guard.clientId, 'test-client')
  })

  test('throws on missing authorization header', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx()
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await assert.rejects(() => guard.authenticate(), 'Missing Bearer token')
  })

  test('throws on unknown token', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx({ headers: { authorization: 'Bearer some-random-token' } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await assert.rejects(() => guard.authenticate(), 'Invalid or expired token')
  })

  test('throws on revoked token', async ({ assert }) => {
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

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await assert.rejects(() => guard.authenticate(), 'Token has been revoked')
  })

  test('throws when the access token row is missing', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()

    const ctx = mockCtx({ headers: { authorization: 'Bearer nonexistent-token' } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    try {
      await guard.authenticate()
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, errors.E_UNAUTHORIZED_ACCESS)
    }
  })

  test('throws on M2M token (no userId)', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: null,
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await assert.rejects(() => guard.authenticate(), 'M2M tokens are not supported')
  })

  test('throws when user not found', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'nonexistent-user',
      scopes: ['read'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await assert.rejects(() => guard.authenticate(), 'User not found')
  })

  test('check() returns false instead of throwing', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx()
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    const result = await guard.check()
    assert.isFalse(result)
    assert.isFalse(guard.isAuthenticated)
  })

  test('check() returns true for valid token', async ({ assert }) => {
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

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    const result = await guard.check()
    assert.isTrue(result)
    assert.isTrue(guard.isAuthenticated)
  })

  test('authenticate() is idempotent', async ({ assert }) => {
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

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    const user1 = await guard.authenticate()
    const user2 = await guard.authenticate()
    assert.strictEqual(user1, user2)
  })

  test('hasScope checks all scopes', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.authenticate()

    assert.isTrue(guard.hasScope('read'))
    assert.isTrue(guard.hasScope('read', 'write'))
    assert.isFalse(guard.hasScope('read', 'admin'))
    assert.isFalse(guard.hasScope('admin'))
  })

  test('hasAnyScope checks any scope', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()

    const { raw, hash } = tokenService.createAccessToken()

    await OAuthAccessToken.create({
      id: crypto.randomUUID(),
      tokenHash: hash,
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read', 'write'],
      expiresAt: DateTime.now().plus({ hours: 1 }),
    })

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.authenticate()

    assert.isTrue(guard.hasAnyScope('read'))
    assert.isTrue(guard.hasAnyScope('admin', 'read'))
    assert.isFalse(guard.hasAnyScope('admin', 'delete'))
  })

  test('sets WWW-Authenticate header on authentication failure', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx()
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.check()

    assert.equal(
      ctx.__responseHeaders['WWW-Authenticate'],
      'Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"'
    )
  })

  test('getUserOrFail throws when not authenticated', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx()
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
  })

  test('getUserOrFail returns user when authenticated', async ({ assert }) => {
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

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.authenticate()
    const user = guard.getUserOrFail()
    assert.deepEqual(user, { id: 'user-1', name: 'Test User' })
  })

  test('emits authentication events', async ({ assert }) => {
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

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.authenticate()

    const eventNames = emitter.events.map((e) => e.name)
    assert.include(eventNames, 'oauth_auth:authentication_attempted')
    assert.include(eventNames, 'oauth_auth:authentication_succeeded')
    assert.notInclude(eventNames, 'oauth_auth:authentication_failed')
  })

  test('emits authentication_failed event on failure', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx()
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.check()

    const eventNames = emitter.events.map((e) => e.name)
    assert.include(eventNames, 'oauth_auth:authentication_failed')
  })

  test('WWW-Authenticate omits error attributes when no token is sent', async ({ assert }) => {
    const manager = createManager()
    const ctx = mockCtx()
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.check()

    const header = ctx.__responseHeaders['WWW-Authenticate']
    assert.equal(
      header,
      'Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"'
    )
    assert.notInclude(header, 'error=')
    assert.notInclude(header, 'error_description=')
  })

  test('WWW-Authenticate includes error attributes when token is present but invalid', async ({
    assert,
  }) => {
    const manager = createManager()
    const ctx = mockCtx({ headers: { authorization: 'Bearer some-invalid-token' } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.check()

    const header = ctx.__responseHeaders['WWW-Authenticate']
    assert.include(
      header,
      'resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"'
    )
    assert.include(header, 'error="invalid_token"')
    assert.include(header, 'error_description=')
  })

  test('WWW-Authenticate includes error attributes when token is revoked', async ({ assert }) => {
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

    const ctx = mockCtx({ headers: { authorization: `Bearer ${raw}` } })
    const emitter = createFakeEmitter()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    await guard.check()

    const header = ctx.__responseHeaders['WWW-Authenticate']
    assert.include(header, 'error="invalid_token"')
    assert.include(header, 'error_description=')
  })
})
