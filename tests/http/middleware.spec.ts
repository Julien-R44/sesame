import { test } from '@japa/runner'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createTestAccessToken } from '../helpers/create_test_access_token.ts'
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
