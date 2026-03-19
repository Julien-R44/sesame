import { test } from '@japa/runner'
import type { ApplicationService } from '@adonisjs/core/types'
import { createApp, setupDatabase, teardownDatabase, createManager } from './helpers/app.ts'
import { mockCtx } from './helpers/mock_ctx.ts'
import { FakeUserProvider, createFakeEmitter } from './helpers/fakes.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { createTestAccessToken } from './helpers/create_test_access_token.ts'
import { cleanModels } from './helpers/clean_models.ts'
import { OAuthGuard } from '../src/guard/guard.ts'
import ScopeMiddleware from '../src/middleware/scope_middleware.ts'
import AnyScopeMiddleware from '../src/middleware/any_scope_middleware.ts'
import { E_INSUFFICIENT_SCOPE } from '../src/oauth_error.ts'

let app: ApplicationService

function mockCtxWithGuard(options: {
  headers?: Record<string, string>
  userId?: string
  sessionAuthenticated?: boolean
}) {
  const manager = createManager()
  const ctx = mockCtx({ headers: options.headers })
  const emitter = createFakeEmitter()
  const provider = new FakeUserProvider(
    options.userId ? [{ id: options.userId, name: 'Test User' }] : []
  )
  const guard = new OAuthGuard('oauth', ctx, emitter, provider, manager)

  ctx.auth = {
    use: (name: string) => {
      if (name === 'oauth') return guard

      throw new Error(`Unknown guard: ${name}`)
    },
    check: async () => options.sessionAuthenticated ?? false,
  }

  return { ctx, guard, manager }
}

function patchBearerToken(ctx: any, raw: string) {
  ctx.request.header = (name: string) =>
    name.toLowerCase() === 'authorization' ? `Bearer ${raw}` : undefined
}

test.group('Middleware | ScopeMiddleware', (group) => {
  const middleware = new ScopeMiddleware()

  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(cleanModels())

  test('throws 401 when no Bearer token is provided', async ({ assert }) => {
    const { ctx } = mockCtxWithGuard({})
    await assert.rejects(
      () => middleware.handle(ctx, async () => {}, { scopes: ['read'] }),
      'Missing Bearer token'
    )
  })

  test('throws 401 when token is invalid', async ({ assert }) => {
    const { ctx } = mockCtxWithGuard({ headers: { authorization: 'Bearer invalid-token' } })
    await assert.rejects(
      () => middleware.handle(ctx, async () => {}, { scopes: ['read'] }),
      'Invalid or expired token'
    )
  })

  test('throws 403 when token lacks a required scope', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read'] })
    patchBearerToken(ctx, raw)

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), {
        scopes: ['admin'],
      })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)
      assert.equal(error.status, 403)
      assert.deepEqual(error.missingScopes, ['admin'])
    }
  })

  test('throws 403 when token has some but not all required scopes', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read'] })
    patchBearerToken(ctx, raw)

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), {
        scopes: ['read', 'admin'],
      })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)
      assert.deepEqual(error.missingScopes, ['read', 'admin'])
    }
  })

  test('passes when token has all required scopes', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read', 'write'] })
    patchBearerToken(ctx, raw)

    let nextCalled = false
    await middleware.handle(
      ctx,
      async () => {
        nextCalled = true
      },
      { scopes: ['read', 'write'] }
    )

    assert.isTrue(nextCalled)
  })
})

test.group('Middleware | AnyScopeMiddleware', (group) => {
  const middleware = new AnyScopeMiddleware()

  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(cleanModels())

  test('throws 403 when token lacks all listed scopes', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read'] })
    patchBearerToken(ctx, raw)

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), {
        scopes: ['admin', 'delete'],
      })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)
      assert.equal(error.status, 403)
      assert.deepEqual(error.missingScopes, ['admin', 'delete'])
    }
  })

  test('passes when token has at least one listed scope', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read'] })
    patchBearerToken(ctx, raw)

    let nextCalled = false
    await middleware.handle(
      ctx,
      async () => {
        nextCalled = true
      },
      { scopes: ['admin', 'read'] }
    )

    assert.isTrue(nextCalled)
  })
})

test.group('Middleware | TransientToken (session bypass)', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(cleanModels())

  test('session-authenticated user bypasses ScopeMiddleware without Bearer token', async ({
    assert,
  }) => {
    const { ctx } = mockCtxWithGuard({ sessionAuthenticated: true })
    const middleware = new ScopeMiddleware()

    let nextCalled = false
    await middleware.handle(
      ctx,
      async () => {
        nextCalled = true
      },
      { scopes: ['admin', 'manage'] }
    )

    assert.isTrue(nextCalled)
  })

  test('session-authenticated user bypasses AnyScopeMiddleware without Bearer token', async ({
    assert,
  }) => {
    const { ctx } = mockCtxWithGuard({ sessionAuthenticated: true })
    const middleware = new AnyScopeMiddleware()

    let nextCalled = false
    await middleware.handle(
      ctx,
      async () => {
        nextCalled = true
      },
      { scopes: ['admin', 'delete'] }
    )

    assert.isTrue(nextCalled)
  })

  test('no auth at all (no Bearer, no session) throws 401', async ({ assert }) => {
    const { ctx } = mockCtxWithGuard({ sessionAuthenticated: false })
    const middleware = new ScopeMiddleware()

    await assert.rejects(
      () => middleware.handle(ctx, async () => {}, { scopes: ['read'] }),
      'Missing Bearer token'
    )
  })

  test('Bearer token present still enforces scopes even with session', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1', sessionAuthenticated: true })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read'] })
    patchBearerToken(ctx, raw)

    const middleware = new ScopeMiddleware()

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), {
        scopes: ['admin'],
      })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)
      assert.equal(error.status, 403)
    }
  })
})

test.group('Middleware | Idempotency & WWW-Authenticate', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(cleanModels())

  test('works when guard.authenticate() was already called', async ({ assert }) => {
    const { ctx, guard, manager } = mockCtxWithGuard({ userId: 'user-1' })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read', 'write'] })
    patchBearerToken(ctx, raw)

    await guard.authenticate()
    assert.isTrue(guard.authenticationAttempted)

    const middleware = new ScopeMiddleware()
    let nextCalled = false
    await middleware.handle(
      ctx,
      async () => {
        nextCalled = true
      },
      { scopes: ['read'] }
    )

    assert.isTrue(nextCalled)
  })

  test('WWW-Authenticate header contains insufficient_scope and scope names on 403', async ({
    assert,
  }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    await createTestClient()
    const { raw } = await createTestAccessToken({ manager, scopes: ['read'] })
    patchBearerToken(ctx, raw)

    const middleware = new ScopeMiddleware()

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), {
        scopes: ['admin', 'manage'],
      })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)

      error.handle(error, ctx)

      const header = ctx.__responseHeaders['WWW-Authenticate']
      assert.include(header, 'error="insufficient_scope"')
      assert.include(header, 'scope="admin manage"')
      assert.equal(ctx.__responseStatus, 403)
    }
  })
})
