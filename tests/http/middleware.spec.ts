import { test } from '@japa/runner'
import { AuthManager } from '@adonisjs/auth'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createTestAccessToken } from '../helpers/create_test_access_token.ts'
import { OAuthGuard } from '../../src/guard/guard.ts'
import type { SesameManager } from '../../src/sesame_manager.ts'
import { FakeUserProvider, createFakeEmitter } from '../helpers/fakes.ts'
import ScopeMiddleware from '../../src/middleware/scope_middleware.ts'
import AnyScopeMiddleware from '../../src/middleware/any_scope_middleware.ts'

test.group('HTTP | ScopeMiddleware', (group) => {
  const ctx = setupHttpGroup(group, undefined, {
    setupRoutes(router) {
      router
        .get('/test/read', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new ScopeMiddleware().handle(mCtx, next, { scopes: ['read'] })
        })

      router
        .get('/test/admin', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new ScopeMiddleware().handle(mCtx, next, { scopes: ['admin'] })
        })

      router
        .get('/test/read-write', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new ScopeMiddleware().handle(mCtx, next, { scopes: ['read', 'write'] })
        })
    },
  })

  test('throws 401 when no Bearer token is provided', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/test/read`)

    response.assertStatus(401)
  })

  test('throws 401 when token is invalid', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/test/read`).bearerToken('invalid-token')

    response.assertStatus(401)
  })

  test('throws 403 when token lacks a required scope', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/admin`).bearerToken(raw)

    response.assertStatus(403)
    response.assertBodyContains({ error: 'insufficient_scope' })
  })

  test('throws 403 when token has some but not all required scopes', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/read-write`).bearerToken(raw)

    response.assertStatus(403)
    response.assertBodyContains({ error: 'insufficient_scope' })
  })

  test('passes when token has all required scopes', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read', 'write'] })

    const response = await client.get(`${ctx.baseUrl}/test/read-write`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({ ok: true })
  })

  test('WWW-Authenticate on 403 lists granted and required scopes', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/admin`).bearerToken(raw)

    response.assertStatus(403)
    response.assertHeader(
      'www-authenticate',
      'Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource", scope="read admin", error="insufficient_scope", error_description="The token does not have the required scope(s)"'
    )
  })

  test('WWW-Authenticate on 401 lists the route scopes', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/test/read-write`)

    response.assertStatus(401)
    response.assertHeader(
      'www-authenticate',
      'Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource", scope="read write"'
    )
  })

  test('WWW-Authenticate on 401 keeps the route scopes for an invalid token', async ({
    client,
    assert,
  }) => {
    const response = await client.get(`${ctx.baseUrl}/test/read-write`).bearerToken('invalid')

    response.assertStatus(401)
    const header = response.header('www-authenticate')
    assert.include(header, 'scope="read write"')
    assert.include(header, 'error="invalid_token"')
  })

  test('session-authenticated user bypasses scope check without Bearer token', async ({
    client,
  }) => {
    const response = await client
      .get(`${ctx.baseUrl}/test/admin`)
      .header('X-Test-User-Id', 'user-1')

    response.assertStatus(200)
    response.assertBodyContains({ ok: true })
  })

  test('Bearer token enforces scopes even with session header', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client
      .get(`${ctx.baseUrl}/test/admin`)
      .header('X-Test-User-Id', 'user-1')
      .bearerToken(raw)

    response.assertStatus(403)
  })
})

test.group('HTTP | AnyScopeMiddleware', (group) => {
  const ctx = setupHttpGroup(group, undefined, {
    setupRoutes(router) {
      router
        .get('/test/any-admin-delete', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new AnyScopeMiddleware().handle(mCtx, next, { scopes: ['admin', 'delete'] })
        })

      router
        .get('/test/any-admin-read', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new AnyScopeMiddleware().handle(mCtx, next, { scopes: ['admin', 'read'] })
        })
    },
  })

  test('throws 403 when token lacks all listed scopes', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/any-admin-delete`).bearerToken(raw)

    response.assertStatus(403)
    response.assertBodyContains({ error: 'insufficient_scope' })
  })

  test('WWW-Authenticate on 401 lists every accepted scope', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/test/any-admin-delete`)

    response.assertStatus(401)
    response.assertHeader(
      'www-authenticate',
      'Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource", scope="admin delete"'
    )
  })

  test('WWW-Authenticate on 403 lists granted and accepted scopes', async ({ client, assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/any-admin-delete`).bearerToken(raw)

    response.assertStatus(403)
    assert.include(response.header('www-authenticate'), 'scope="read admin delete"')
  })

  test('passes when token has at least one listed scope', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/any-admin-read`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({ ok: true })
  })

  test('session-authenticated user bypasses AnyScopeMiddleware', async ({ client }) => {
    const response = await client
      .get(`${ctx.baseUrl}/test/any-admin-delete`)
      .header('X-Test-User-Id', 'user-1')

    response.assertStatus(200)
    response.assertBodyContains({ ok: true })
  })
})

test.group('HTTP | ScopeMiddleware with @adonisjs/auth', (group) => {
  const metadata =
    'resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"'

  const ctx = setupHttpGroup(group, undefined, {
    createAuth: ({ ctx: httpCtx, guard }) =>
      new AuthManager({ default: 'oauth', guards: { oauth: () => guard } }).createAuthenticator(
        httpCtx
      ),
    setupRoutes(router) {
      router
        .get('/test/scoped', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new ScopeMiddleware().handle(mCtx, next, { scopes: ['read', 'write'] })
        })

      /**
       * Mirrors `middleware.auth({ guards: ['oauth'] })` placed before the scope middleware.
       */
      router
        .get('/test/auth-then-scoped', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await mCtx.auth.authenticateUsing(['oauth'])
          await next()
        })
        .use(async (mCtx: any, next: any) => {
          await new ScopeMiddleware().handle(mCtx, next, { scopes: ['read', 'write'] })
        })
    },
  })

  test('401 lists the route scopes when the default guard was checked first', async ({
    client,
  }) => {
    const response = await client.get(`${ctx.baseUrl}/test/scoped`)

    response.assertStatus(401)
    response.assertHeader('www-authenticate', `Bearer ${metadata}, scope="read write"`)
  })

  test('401 raised by the auth middleware cannot list the route scopes', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/test/auth-then-scoped`)

    response.assertStatus(401)
    response.assertHeader('www-authenticate', `Bearer ${metadata}`)
  })

  test('403 after the auth middleware lists granted and required scopes', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'] })

    const response = await client.get(`${ctx.baseUrl}/test/auth-then-scoped`).bearerToken(raw)

    response.assertStatus(403)
    assert.include(response.header('www-authenticate'), 'scope="read write"')
  })
})

test.group('HTTP | Scope middleware with a per-resource guard', (group) => {
  const resourceB = 'https://auth.example.com/mcp-b'
  const metadataB = `resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource/mcp-b"`
  let manager: SesameManager

  const ctx = setupHttpGroup(group, undefined, {
    createAuth: ({ ctx: httpCtx, guard }) => {
      const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
      const guardB = new OAuthGuard('mcp_b', httpCtx, createFakeEmitter(), provider, manager, {
        resource: '/mcp-b',
      })

      return new AuthManager({
        default: 'oauth',
        guards: { oauth: () => guard, mcp_b: () => guardB },
      }).createAuthenticator(httpCtx)
    },
    setupRoutes(router, sesame) {
      manager = sesame
      sesame.registerProtectedResource({ resource: '/mcp', scopes: ['read', 'write'] })
      sesame.registerProtectedResource({ resource: '/mcp-b', scopes: ['read'] })

      router
        .post('/mcp-b', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new ScopeMiddleware().handle(mCtx, next, { scopes: ['read'], guard: 'mcp_b' })
        })

      router
        .post('/mcp-b-any', async () => ({ ok: true }))
        .use(async (mCtx: any, next: any) => {
          await new AnyScopeMiddleware().handle(mCtx, next, {
            scopes: ['read', 'write'],
            guard: 'mcp_b',
          })
        })
    },
  })

  test('401 points to the protected resource metadata of the guard resource', async ({
    client,
  }) => {
    const response = await client.post(`${ctx.baseUrl}/mcp-b`)

    response.assertStatus(401)
    response.assertHeader('www-authenticate', `Bearer ${metadataB}, scope="read"`)
  })

  test('accepts a token issued for the guard resource', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['read'], resource: resourceB })

    const response = await client.post(`${ctx.baseUrl}/mcp-b`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({ ok: true })
  })

  test('rejects a token issued for another resource', async ({ client, assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({
      scopes: ['read'],
      resource: 'https://auth.example.com/mcp',
    })

    const response = await client.post(`${ctx.baseUrl}/mcp-b`).bearerToken(raw)

    response.assertStatus(401)
    assert.include(response.header('www-authenticate'), metadataB)
    assert.include(response.header('www-authenticate'), 'error="invalid_token"')
  })

  test('403 challenge points to the guard resource', async ({ client, assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['write'], resource: resourceB })

    const response = await client.post(`${ctx.baseUrl}/mcp-b`).bearerToken(raw)

    response.assertStatus(403)
    assert.include(response.header('www-authenticate'), metadataB)
    assert.include(response.header('www-authenticate'), 'scope="write read"')
  })

  test('anyScope uses the guard option', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ scopes: ['write'], resource: resourceB })

    const anonymous = await client.post(`${ctx.baseUrl}/mcp-b-any`)
    anonymous.assertStatus(401)
    anonymous.assertHeader('www-authenticate', `Bearer ${metadataB}, scope="read"`)

    const response = await client.post(`${ctx.baseUrl}/mcp-b-any`).bearerToken(raw)
    response.assertStatus(200)
  })
})
