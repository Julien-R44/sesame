import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import type { ApplicationService } from '@adonisjs/core/types'
import { createApp, setupDatabase, teardownDatabase } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestAccessToken } from './helpers/create_test_access_token.ts'
import { createTestGuard } from './helpers/create_test_guard.ts'
import { cleanModels } from './helpers/clean_models.ts'
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

  group.each.setup(cleanModels())

  test('authenticates with a valid token', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken()
    const { guard } = createTestGuard({ manager, bearerToken: raw })

    const user = await guard.authenticate()

    assert.deepEqual(user, { id: 'user-1', name: 'Test User' })
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
    assert.deepEqual(guard.scopes, ['read', 'write'])
    assert.equal(guard.clientId, 'test-client')
  })

  test('throws on missing authorization header', async ({ assert }) => {
    const { guard } = createTestGuard({ users: [] })

    await assert.rejects(() => guard.authenticate(), 'Missing Bearer token')
  })

  test('throws on unknown token', async ({ assert }) => {
    const { guard } = createTestGuard({ bearerToken: 'some-random-token', users: [] })

    await assert.rejects(() => guard.authenticate(), 'Invalid or expired token')
  })

  test('throws on revoked token', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({
      scopes: ['read'],
      revokedAt: DateTime.now(),
    })
    const { guard } = createTestGuard({ manager, bearerToken: raw })

    await assert.rejects(() => guard.authenticate(), 'Invalid or expired token')
  })

  test('throws when the access token row is missing', async ({ assert }) => {
    await createTestClient()
    const { guard } = createTestGuard({ bearerToken: 'nonexistent-token' })

    try {
      await guard.authenticate()
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, errors.E_UNAUTHORIZED_ACCESS)
    }
  })

  test('throws on M2M token (no userId)', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ userId: null, scopes: ['read'] })
    const { guard } = createTestGuard({ manager, bearerToken: raw, users: [] })

    await assert.rejects(() => guard.authenticate(), 'Invalid or expired token')
  })

  test('throws when user not found', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({
      userId: 'nonexistent-user',
      scopes: ['read'],
    })
    const { guard } = createTestGuard({ manager, bearerToken: raw, users: [] })

    await assert.rejects(() => guard.authenticate(), 'Invalid or expired token')
  })

  test('check() returns false instead of throwing', async ({ assert }) => {
    const { guard } = createTestGuard({ users: [] })

    const result = await guard.check()
    assert.isFalse(result)
    assert.isFalse(guard.isAuthenticated)
  })

  test('check() returns true for valid token', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })
    const { guard } = createTestGuard({ manager, bearerToken: raw })

    const result = await guard.check()
    assert.isTrue(result)
    assert.isTrue(guard.isAuthenticated)
  })

  test('authenticate() is idempotent', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })
    const { guard } = createTestGuard({ manager, bearerToken: raw })

    const user1 = await guard.authenticate()
    const user2 = await guard.authenticate()
    assert.strictEqual(user1, user2)
  })

  test('hasScope checks all scopes', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken()
    const { guard } = createTestGuard({ manager, bearerToken: raw })

    await guard.authenticate()

    assert.isTrue(guard.hasScope('read'))
    assert.isTrue(guard.hasScope('read', 'write'))
    assert.isFalse(guard.hasScope('read', 'admin'))
    assert.isFalse(guard.hasScope('admin'))
  })

  test('hasAnyScope checks any scope', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken()
    const { guard } = createTestGuard({ manager, bearerToken: raw })

    await guard.authenticate()

    assert.isTrue(guard.hasAnyScope('read'))
    assert.isTrue(guard.hasAnyScope('admin', 'read'))
    assert.isFalse(guard.hasAnyScope('admin', 'delete'))
  })

  test('sets WWW-Authenticate header on authentication failure', async ({ assert }) => {
    const { guard, ctx } = createTestGuard({ users: [] })

    await guard.check()

    assert.equal(
      ctx.__responseHeaders['WWW-Authenticate'],
      'Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"'
    )
  })

  test('getUserOrFail throws when not authenticated', async ({ assert }) => {
    const { guard } = createTestGuard({ users: [] })

    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
  })

  test('getUserOrFail returns user when authenticated', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })
    const { guard } = createTestGuard({ manager, bearerToken: raw })

    await guard.authenticate()
    const user = guard.getUserOrFail()
    assert.deepEqual(user, { id: 'user-1', name: 'Test User' })
  })

  test('emits authentication events', async ({ assert }) => {
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({ scopes: ['read'] })
    const { guard, emitter } = createTestGuard({ manager, bearerToken: raw })

    await guard.authenticate()

    const eventNames = emitter.events.map((e) => e.name)
    assert.include(eventNames, 'oauth_auth:authentication_attempted')
    assert.include(eventNames, 'oauth_auth:authentication_succeeded')
    assert.notInclude(eventNames, 'oauth_auth:authentication_failed')
  })

  test('emits authentication_failed event on failure', async ({ assert }) => {
    const { guard, emitter } = createTestGuard({ users: [] })

    await guard.check()

    const eventNames = emitter.events.map((e) => e.name)
    assert.include(eventNames, 'oauth_auth:authentication_failed')
  })

  test('WWW-Authenticate omits error attributes when no token is sent', async ({ assert }) => {
    const { guard, ctx } = createTestGuard({ users: [] })

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
    const { guard, ctx } = createTestGuard({ bearerToken: 'some-invalid-token', users: [] })

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
    await createTestClient()
    const { raw, manager } = await createTestAccessToken({
      scopes: ['read'],
      revokedAt: DateTime.now(),
    })
    const { guard, ctx } = createTestGuard({ manager, bearerToken: raw })

    await guard.check()

    const header = ctx.__responseHeaders['WWW-Authenticate']
    assert.include(header, 'error="invalid_token"')
    assert.include(header, 'error_description=')
  })
})
