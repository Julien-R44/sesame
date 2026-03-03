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
} from './helpers.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { TokenService } from '../src/services/token_service.ts'
import { OAuthGuard } from '../src/guard/guard.ts'
import { symbols } from '@adonisjs/auth'
import type { EmitterLike } from '@adonisjs/core/types/events'
import type { OAuthUserProviderContract, OAuthGuardUser, OAuthGuardEvents } from '../src/guard/types.ts'
import ScopeMiddleware from '../src/middleware/scope_middleware.ts'
import AnyScopeMiddleware from '../src/middleware/any_scope_middleware.ts'
import { E_INSUFFICIENT_SCOPE } from '../src/oauth_error.ts'

let app: ApplicationService

class FakeUserProvider implements OAuthUserProviderContract<{ id: string; name: string }> {
  declare [symbols.PROVIDER_REAL_USER]: { id: string; name: string }

  #users: Map<string, { id: string; name: string }>

  constructor(users: { id: string; name: string }[]) {
    this.#users = new Map(users.map((u) => [u.id, u]))
  }

  async createUserForGuard(user: {
    id: string
    name: string
  }): Promise<OAuthGuardUser<{ id: string; name: string }>> {
    return { getId: () => user.id, getOriginal: () => user }
  }

  async findById(
    identifier: string | number | BigInt
  ): Promise<OAuthGuardUser<{ id: string; name: string }> | null> {
    const user = this.#users.get(String(identifier))
    if (!user) return null

    return this.createUserForGuard(user)
  }
}

function createFakeEmitter() {
  const events: { name: string; data: any }[] = []
  const emitter: EmitterLike<OAuthGuardEvents<{ id: string; name: string }>> & {
    events: { name: string; data: any }[]
  } = {
    async emit(name: string, data: any) { events.push({ name, data }) },
    async emitSerial(name: string, data: any) { events.push({ name, data }) },
    listenerCount() { return 0 },
    hasListeners() { return false },
    events,
  }

  return emitter
}

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

async function createTokenForUser(options: {
  manager: ReturnType<typeof createManager>
  userId: string
  scopes: string[]
}) {
  const tokenService = new TokenService(options.manager)
  await createTestClient()

  const { raw, hash } = tokenService.createAccessToken()

  await OAuthAccessToken.create({
    id: crypto.randomUUID(),
    tokenHash: hash,
    clientId: 'test-client',
    userId: options.userId,
    scopes: options.scopes,
    expiresAt: DateTime.now().plus({ hours: 1 }),
  })

  return raw
}

function cleanModels() {
  return async () => {
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  }
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
    await assert.rejects(() => middleware.handle(ctx, async () => {}, { scopes: ['read'] }), 'Missing Bearer token')
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
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read'] })
    patchBearerToken(ctx, raw)

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), { scopes: ['admin'] })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)
      assert.equal(error.status, 403)
      assert.deepEqual(error.missingScopes, ['admin'])
    }
  })

  test('throws 403 when token has some but not all required scopes', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read'] })
    patchBearerToken(ctx, raw)

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), { scopes: ['read', 'admin'] })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)
      assert.deepEqual(error.missingScopes, ['read', 'admin'])
    }
  })

  test('passes when token has all required scopes', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read', 'write'] })
    patchBearerToken(ctx, raw)

    let nextCalled = false
    await middleware.handle(ctx, async () => { nextCalled = true }, { scopes: ['read', 'write'] })

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
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read'] })
    patchBearerToken(ctx, raw)

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), { scopes: ['admin', 'delete'] })
    } catch (error: any) {
      assert.instanceOf(error, E_INSUFFICIENT_SCOPE)
      assert.equal(error.status, 403)
      assert.deepEqual(error.missingScopes, ['admin', 'delete'])
    }
  })

  test('passes when token has at least one listed scope', async ({ assert }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read'] })
    patchBearerToken(ctx, raw)

    let nextCalled = false
    await middleware.handle(ctx, async () => { nextCalled = true }, { scopes: ['admin', 'read'] })

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

  test('session-authenticated user bypasses ScopeMiddleware without Bearer token', async ({ assert }) => {
    const { ctx } = mockCtxWithGuard({ sessionAuthenticated: true })
    const middleware = new ScopeMiddleware()

    let nextCalled = false
    await middleware.handle(ctx, async () => { nextCalled = true }, { scopes: ['admin', 'manage'] })

    assert.isTrue(nextCalled)
  })

  test('session-authenticated user bypasses AnyScopeMiddleware without Bearer token', async ({ assert }) => {
    const { ctx } = mockCtxWithGuard({ sessionAuthenticated: true })
    const middleware = new AnyScopeMiddleware()

    let nextCalled = false
    await middleware.handle(ctx, async () => { nextCalled = true }, { scopes: ['admin', 'delete'] })

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
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read'] })
    patchBearerToken(ctx, raw)

    const middleware = new ScopeMiddleware()

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), { scopes: ['admin'] })
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
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read', 'write'] })
    patchBearerToken(ctx, raw)

    await guard.authenticate()
    assert.isTrue(guard.authenticationAttempted)

    const middleware = new ScopeMiddleware()
    let nextCalled = false
    await middleware.handle(ctx, async () => { nextCalled = true }, { scopes: ['read'] })

    assert.isTrue(nextCalled)
  })

  test('WWW-Authenticate header contains insufficient_scope and scope names on 403', async ({
    assert,
  }) => {
    const { ctx, manager } = mockCtxWithGuard({ userId: 'user-1' })
    const raw = await createTokenForUser({ manager, userId: 'user-1', scopes: ['read'] })
    patchBearerToken(ctx, raw)

    const middleware = new ScopeMiddleware()

    try {
      await middleware.handle(ctx, async () => assert.fail('Should not reach next()'), { scopes: ['admin', 'manage'] })
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
