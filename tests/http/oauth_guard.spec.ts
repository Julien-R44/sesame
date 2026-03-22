import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'
import { setupHttpGroup, setupIntegrationGroup, createManager } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createTestAccessToken } from '../helpers/create_test_access_token.ts'
import { FakeUserProvider, createFakeEmitter } from '../helpers/fakes.ts'
import { OAuthGuard } from '../../src/guard/guard.ts'

test.group('HTTP | OAuthGuard', (group) => {
  const ctx = setupHttpGroup(group, undefined, {
    setupRoutes(router) {
      /**
       * Test route that authenticates via the OAuthGuard
       * and exposes guard internals for assertions.
       */
      router.get('/test/guard-info', async (reqCtx: any) => {
        const guard = reqCtx.auth.use('oauth')
        await guard.authenticate()

        return {
          authenticated: guard.isAuthenticated,
          scopes: guard.scopes,
          clientId: guard.clientId,
          user: guard.getUserOrFail(),
        }
      })

      /**
       * Test route that calls guard.check() (non-throwing)
       * and returns the result.
       */
      router.get('/test/guard-check', async (reqCtx: any) => {
        const guard = reqCtx.auth.use('oauth')
        const result = await guard.check()

        return { authenticated: result }
      })
    },
  })

  test('authenticates with a valid token', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken()

    const response = await client.get(`${ctx.baseUrl}/test/guard-info`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({
      authenticated: true,
      scopes: ['read', 'write'],
      clientId: 'test-client',
      user: { id: 'user-1', name: 'Test User' },
    })
  })

  test('throws 401 on missing authorization header', async ({ client }) => {
    const response = await client
      .get(`${ctx.baseUrl}/test/guard-info`)
      .header('accept', 'application/json')

    response.assertStatus(401)
  })

  test('throws 401 on unknown token', async ({ client }) => {
    const response = await client
      .get(`${ctx.baseUrl}/test/guard-info`)
      .bearerToken('some-random-token')
      .header('accept', 'application/json')

    response.assertStatus(401)
  })

  test('throws 401 on revoked token', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({
      scopes: ['read'],
      revokedAt: DateTime.now(),
    })

    const response = await client
      .get(`${ctx.baseUrl}/test/guard-info`)
      .bearerToken(raw)
      .header('accept', 'application/json')

    response.assertStatus(401)
  })

  test('throws 401 on M2M token (no userId)', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ userId: null, scopes: ['read'] })

    const response = await client
      .get(`${ctx.baseUrl}/test/guard-info`)
      .bearerToken(raw)
      .header('accept', 'application/json')

    response.assertStatus(401)
  })

  test('check() returns false without token', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/test/guard-check`)

    response.assertStatus(200)
    response.assertBodyContains({ authenticated: false })
  })

  test('check() returns true for valid token', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/guard-check`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({ authenticated: true })
  })

  test('hasScope checks all scopes', async ({ client, assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken()

    const response = await client.get(`${ctx.baseUrl}/test/guard-info`).bearerToken(raw)

    response.assertStatus(200)
    const body = response.body()
    assert.deepEqual(body.scopes, ['read', 'write'])
  })

  test('WWW-Authenticate omits error when no token is sent', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/test/guard-check`)

    response.assertStatus(200)
    response.assertHeader(
      'www-authenticate',
      'Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"'
    )
  })

  test('WWW-Authenticate includes error when token is invalid', async ({ client, assert }) => {
    const response = await client
      .get(`${ctx.baseUrl}/test/guard-check`)
      .bearerToken('some-invalid-token')

    response.assertStatus(200)
    const header = response.header('www-authenticate')
    assert.include(header, 'error="invalid_token"')
    assert.include(header, 'error_description=')
  })

  test('WWW-Authenticate includes error when token is revoked', async ({ client, assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({
      scopes: ['read'],
      revokedAt: DateTime.now(),
    })

    const response = await client.get(`${ctx.baseUrl}/test/guard-check`).bearerToken(raw)

    response.assertStatus(200)
    const header = response.header('www-authenticate')
    assert.include(header, 'error="invalid_token"')
  })
})

/**
 * Unit tests for guard internals that can't be observed via HTTP
 * (idempotency, events, getUserOrFail before auth).
 * Uses HttpContextFactory instead of mockCtx.
 */
test.group('OAuthGuard | Unit', (group) => {
  setupIntegrationGroup(group)

  function buildGuard(options?: { bearerToken?: string; users?: { id: string; name: string }[] }) {
    const manager = createManager()
    const request = new RequestFactory().merge({ url: '/' }).create()
    if (options?.bearerToken)
      request.request.headers.authorization = `Bearer ${options.bearerToken}`

    const ctx = new HttpContextFactory().merge({ request }).create()
    const provider = new FakeUserProvider(options?.users ?? [{ id: 'user-1', name: 'Test User' }])
    const emitter = createFakeEmitter()
    const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

    return { guard, emitter, ctx, manager }
  }

  test('authenticate() is idempotent', async ({ assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })
    const { guard } = buildGuard({ bearerToken: raw })

    const user1 = await guard.authenticate()
    const user2 = await guard.authenticate()
    assert.strictEqual(user1, user2)
  })

  test('getUserOrFail throws when not authenticated', ({ assert }) => {
    const { guard } = buildGuard()
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
  })

  test('emits authentication events on success', async ({ assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })
    const { guard, emitter } = buildGuard({ bearerToken: raw })

    await guard.authenticate()

    const names = emitter.events.map((e) => e.name)
    assert.include(names, 'oauth_auth:authentication_attempted')
    assert.include(names, 'oauth_auth:authentication_succeeded')
  })

  test('emits authentication_failed event on failure', async ({ assert }) => {
    const { guard, emitter } = buildGuard()

    await guard.check()

    const names = emitter.events.map((e) => e.name)
    assert.include(names, 'oauth_auth:authentication_failed')
  })
})
