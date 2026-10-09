import { test } from '@japa/runner'
import type { ApiClient } from '@japa/api-client'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'
import { LoggerFactory } from '@adonisjs/core/factories/logger'
import {
  createManager,
  createTestConfig,
  setupHttpGroup,
  setupIntegrationGroup,
} from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createTestGrant } from '../helpers/create_test_grant.ts'
import { createPkce } from '../helpers/create_pkce.ts'
import { createAuthCodeExchange } from '../helpers/create_auth_code_exchange.ts'
import { createTestAccessToken } from '../helpers/create_test_access_token.ts'
import { createTestRefreshToken } from '../helpers/create_test_refresh_token.ts'
import { FakeUserProvider, createFakeEmitter } from '../helpers/fakes.ts'
import { OAuthGuard } from '../../src/guard/guard.ts'
import type { OAuthGuardOptions } from '../../src/guard/types.ts'
import { SesameManager } from '../../src/sesame_manager.ts'
import { lucidStore } from '../../src/storage/drivers/lucid.ts'
import { TokenService } from '../../src/services/token_service.ts'
import { OAuthAccessToken } from '../../src/models/oauth_access_token.ts'
import { OAuthAuthorizationCode } from '../../src/models/oauth_authorization_code.ts'
import { OAuthPendingAuthorizationRequest } from '../../src/models/oauth_pending_authorization_request.ts'
import { OAuthRefreshToken } from '../../src/models/oauth_refresh_token.ts'

const MCP_A = 'https://auth.example.com/mcp-a'
const MCP_B = 'https://auth.example.com/mcp-b'
const REDIRECT_URI = 'https://app.example.com/callback'

/**
 * Register a route authenticating through a guard with the given options.
 */
function registerGuardRoute(options: {
  router: any
  manager: SesameManager
  path: string
  guard?: OAuthGuardOptions
}) {
  options.router.get(options.path, async (ctx: any) => {
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard(
      'mcp',
      ctx,
      createFakeEmitter(),
      provider,
      options.manager,
      options.guard
    )
    const authenticated = await guard.check()

    return { authenticated, audience: guard.audience }
  })
}

/**
 * Hash a raw token like Sesame does before storing it.
 */
function hashToken(manager: SesameManager, raw: string) {
  return new TokenService(manager).hashToken(raw)
}

/**
 * Send an authorization request for the test client as `user-1`.
 */
function authorize(client: ApiClient, baseUrl: string, params: Record<string, unknown>) {
  const { codeChallenge } = createPkce('resource-indicator-verifier')

  return client
    .get(`${baseUrl}/oauth/authorize`)
    .qs({
      client_id: 'test-client',
      response_type: 'code',
      redirect_uri: REDIRECT_URI,
      scope: 'read',
      state: 'resource-state',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      ...params,
    })
    .header('X-Test-User-Id', 'user-1')
    .redirects(0)
}

test.group('HTTP | Resource indicators — authorization endpoint', (group) => {
  const ctx = setupHttpGroup(group, undefined, {
    setupRoutes(_router, manager) {
      manager.registerProtectedResource({ resource: '/mcp-a' })
      manager.registerProtectedResource({ resource: '/mcp-b' })
    },
  })

  test('binds the pending request and the issued code to the resource', async ({
    client,
    assert,
  }) => {
    await createTestClient()

    const response = await authorize(client, ctx.baseUrl, {
      resource: 'HTTPS://auth.example.com/mcp-a/',
    })

    response.assertStatus(302)
    const consentUrl = new URL(response.header('location')!, 'https://auth.example.com')
    assert.equal(consentUrl.searchParams.get('resource'), MCP_A)

    const pending = await OAuthPendingAuthorizationRequest.query().firstOrFail()
    assert.equal(pending.resource, MCP_A)

    const consent = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: consentUrl.searchParams.get('auth_token') })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consent.assertStatus(302)
    const code = await OAuthAuthorizationCode.query().firstOrFail()
    assert.equal(code.resource, MCP_A)
  })

  test('binds the code directly when consent was already granted', async ({ client, assert }) => {
    await createTestClient()
    await createTestGrant({ scopes: ['read'] })

    const response = await authorize(client, ctx.baseUrl, { resource: MCP_B })

    response.assertStatus(302)
    assert.isString(new URL(response.header('location')!).searchParams.get('code'))
    const code = await OAuthAuthorizationCode.query().firstOrFail()
    assert.equal(code.resource, MCP_B)
  })

  test('keeps authorization requests without resource unbound', async ({ client, assert }) => {
    await createTestClient()

    const response = await authorize(client, ctx.baseUrl, {})

    response.assertStatus(302)
    const pending = await OAuthPendingAuthorizationRequest.query().firstOrFail()
    assert.isNull(pending.resource)
  })

  test('redirects with invalid_target for malformed resources', async ({ client, assert }) => {
    await createTestClient()

    const response = await authorize(client, ctx.baseUrl, { resource: `${MCP_A}#fragment` })

    response.assertStatus(302)
    const location = new URL(response.header('location')!)
    assert.equal(location.origin + location.pathname, REDIRECT_URI)
    assert.equal(location.searchParams.get('error'), 'invalid_target')
    assert.equal(location.searchParams.get('state'), 'resource-state')
    assert.lengthOf(await OAuthPendingAuthorizationRequest.query(), 0)
  })

  test('redirects with invalid_target for resources on another origin', async ({
    client,
    assert,
  }) => {
    await createTestClient()

    const response = await authorize(client, ctx.baseUrl, {
      resource: 'https://evil.example.com/mcp-a',
    })

    response.assertStatus(302)
    assert.equal(new URL(response.header('location')!).searchParams.get('error'), 'invalid_target')
  })

  test('redirects with invalid_target for repeated resources', async ({ client, assert }) => {
    await createTestClient()

    const response = await authorize(client, ctx.baseUrl, { resource: [MCP_A, MCP_B] })

    response.assertStatus(302)
    const location = new URL(response.header('location')!)
    assert.equal(location.searchParams.get('error'), 'invalid_target')
    assert.include(location.searchParams.get('error_description')!, 'Only one resource')
  })
})

test.group('HTTP | Resource indicators — token endpoint', (group) => {
  const ctx = setupHttpGroup(
    group,
    { grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'] },
    {
      setupRoutes(_router, manager) {
        manager.registerProtectedResource({ resource: '/mcp-a' })
        manager.registerProtectedResource({ resource: '/mcp-b' })
        ctx.manager = manager
      },
    }
  ) as ReturnType<typeof setupHttpGroup> & { manager: SesameManager }

  /**
   * Exchange an authorization code at the token endpoint.
   */
  function exchangeCode(
    client: ApiClient,
    exchange: Awaited<ReturnType<typeof createAuthCodeExchange>>,
    resource?: string
  ) {
    return client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'authorization_code',
      code: exchange.rawCode,
      redirect_uri: exchange.redirectUri,
      code_verifier: exchange.codeVerifier,
      client_id: 'test-client',
      client_secret: 'test-secret',
      ...(resource ? { resource } : {}),
    })
  }

  test('binds tokens to the resource of the authorization code', async ({ client, assert }) => {
    await createTestClient()
    const exchange = await createAuthCodeExchange({ resource: MCP_A })

    const response = await exchangeCode(client, exchange, `${MCP_A}/`)

    response.assertStatus(200)
    assert.notProperty(response.body(), 'resource')
    const accessToken = await OAuthAccessToken.query()
      .where('tokenHash', hashToken(ctx.manager, response.body().access_token))
      .firstOrFail()
    const refreshToken = await OAuthRefreshToken.query()
      .where('token', hashToken(ctx.manager, response.body().refresh_token))
      .firstOrFail()
    assert.equal(accessToken.resource, MCP_A)
    assert.equal(refreshToken.resource, MCP_A)
  })

  test('inherits the code resource when the token request omits it', async ({ client, assert }) => {
    await createTestClient()
    const exchange = await createAuthCodeExchange({ resource: MCP_A })

    const response = await exchangeCode(client, exchange)

    response.assertStatus(200)
    const accessToken = await OAuthAccessToken.query().firstOrFail()
    assert.equal(accessToken.resource, MCP_A)
  })

  test('binds an unbound code to the resource requested at the token endpoint', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const exchange = await createAuthCodeExchange()

    const response = await exchangeCode(client, exchange, MCP_B)

    response.assertStatus(200)
    const accessToken = await OAuthAccessToken.query().firstOrFail()
    assert.equal(accessToken.resource, MCP_B)
  })

  test('rejects another resource without consuming the code', async ({ client, assert }) => {
    await createTestClient()
    const exchange = await createAuthCodeExchange({ resource: MCP_A })

    const rejected = await exchangeCode(client, exchange, MCP_B)

    rejected.assertStatus(400)
    rejected.assertBodyContains({ error: 'invalid_target' })
    assert.isNotNull(await OAuthAuthorizationCode.query().first())

    const accepted = await exchangeCode(client, exchange, MCP_A)
    accepted.assertStatus(200)
  })

  test('rejects malformed resources without consuming the code', async ({ client, assert }) => {
    await createTestClient()
    const exchange = await createAuthCodeExchange()

    const response = await exchangeCode(client, exchange, 'not-a-uri')

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_target' })
    assert.isNotNull(await OAuthAuthorizationCode.query().first())
  })

  test('keeps the refresh token resource when refreshing', async ({ client, assert }) => {
    await createTestClient()
    const { rawRefreshToken } = await createTestRefreshToken({ resource: MCP_A })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      refresh_token: rawRefreshToken,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    const accessToken = await OAuthAccessToken.query()
      .where('tokenHash', hashToken(ctx.manager, response.body().access_token))
      .firstOrFail()
    const refreshToken = await OAuthRefreshToken.query()
      .where('token', hashToken(ctx.manager, response.body().refresh_token))
      .firstOrFail()
    assert.equal(accessToken.resource, MCP_A)
    assert.equal(refreshToken.resource, MCP_A)
  })

  test('keeps the resource when adopting a legacy refresh token into a grant', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const { rawRefreshToken } = await createTestRefreshToken({ grantId: null, resource: MCP_A })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      refresh_token: rawRefreshToken,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    const accessToken = await OAuthAccessToken.query()
      .where('tokenHash', hashToken(ctx.manager, response.body().access_token))
      .firstOrFail()
    const refreshToken = await OAuthRefreshToken.query()
      .where('token', hashToken(ctx.manager, response.body().refresh_token))
      .firstOrFail()
    assert.isString(accessToken.grantId)
    assert.equal(refreshToken.grantId, accessToken.grantId)
    assert.equal(accessToken.resource, MCP_A)
    assert.equal(refreshToken.resource, MCP_A)
  })

  test('rejects refreshing for another resource without rotating', async ({ client, assert }) => {
    await createTestClient()
    const { rawRefreshToken } = await createTestRefreshToken({ resource: MCP_A })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      refresh_token: rawRefreshToken,
      resource: MCP_B,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_target' })
    const refreshToken = await OAuthRefreshToken.query()
      .where('token', hashToken(ctx.manager, rawRefreshToken))
      .firstOrFail()
    assert.isNull(refreshToken.revokedAt)
  })

  test('binds an unbound refresh token to the requested resource', async ({ client, assert }) => {
    await createTestClient()
    const { rawRefreshToken } = await createTestRefreshToken()

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'refresh_token',
      refresh_token: rawRefreshToken,
      resource: MCP_B,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    const accessToken = await OAuthAccessToken.query()
      .where('tokenHash', hashToken(ctx.manager, response.body().access_token))
      .firstOrFail()
    const refreshToken = await OAuthRefreshToken.query()
      .where('token', hashToken(ctx.manager, response.body().refresh_token))
      .firstOrFail()
    assert.equal(accessToken.resource, MCP_B)
    assert.equal(refreshToken.resource, MCP_B)
  })

  test('binds client_credentials tokens to the requested resource', async ({ client, assert }) => {
    await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read'],
      userId: 'user-1',
    })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'client_credentials',
      resource: MCP_A,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(200)
    const accessToken = await OAuthAccessToken.query().firstOrFail()
    assert.equal(accessToken.resource, MCP_A)
  })

  test('rejects client_credentials requests for unknown resources', async ({ client }) => {
    await createTestClient({
      grantTypes: ['client_credentials'],
      scopes: ['read'],
      userId: 'user-1',
    })

    const response = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'client_credentials',
      resource: 'https://other.example.com/mcp',
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_target' })
  })

  test('exposes the resource as aud in introspection responses', async ({ client, assert }) => {
    await createTestClient()
    const bound = await createTestAccessToken({ resource: MCP_A })
    const unbound = await createTestAccessToken()

    const boundResponse = await client.post(`${ctx.baseUrl}/oauth/introspect`).form({
      token: bound.raw,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })
    const unboundResponse = await client.post(`${ctx.baseUrl}/oauth/introspect`).form({
      token: unbound.raw,
      client_id: 'test-client',
      client_secret: 'test-secret',
    })

    boundResponse.assertBodyContains({ active: true, aud: MCP_A })
    unboundResponse.assertBodyContains({ active: true })
    assert.notProperty(unboundResponse.body(), 'aud')
  })
})

test.group('HTTP | Resource indicators — guard audience', (group) => {
  const ctx = setupHttpGroup(group, undefined, {
    setupRoutes(router, manager) {
      manager.registerProtectedResource({ resource: '/mcp-a' })
      manager.registerProtectedResource({ resource: '/mcp-b' })

      registerGuardRoute({ router, manager, path: '/api' })
      registerGuardRoute({ router, manager, path: '/mcp-a', guard: { resource: '/mcp-a' } })
      registerGuardRoute({ router, manager, path: '/mcp-b', guard: { resource: '/mcp-b' } })
      registerGuardRoute({
        router,
        manager,
        path: '/mcp-a-strict',
        guard: { resource: '/mcp-a', requireAudience: true },
      })
    },
  })

  /**
   * Call a guarded route with a bearer token and return the guard outcome.
   */
  async function callGuard(client: ApiClient, path: string, token: string) {
    const response = await client.get(`${ctx.baseUrl}${path}`).bearerToken(token)
    response.assertStatus(200)

    return response
  }

  test('accepts tokens bound to the guard resource', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ resource: MCP_A })

    const response = await callGuard(client, '/mcp-a', raw)

    response.assertBodyContains({ authenticated: true, audience: MCP_A })
  })

  test('rejects tokens bound to another resource', async ({ client, assert }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ resource: MCP_A })

    const response = await callGuard(client, '/mcp-b', raw)

    response.assertBodyContains({ authenticated: false })
    const header = response.header('www-authenticate')
    assert.include(header, 'oauth-protected-resource/mcp-b')
    assert.include(header, 'error="invalid_token"')
    assert.include(header, 'Token audience mismatch')
  })

  test('skips the audience check on guards without resource', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ resource: MCP_A })

    const response = await callGuard(client, '/api', raw)

    response.assertBodyContains({ authenticated: true, audience: MCP_A })
  })

  test('accepts unbound tokens unless the guard requires an audience', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken()

    const lenient = await callGuard(client, '/mcp-a', raw)
    const strict = await callGuard(client, '/mcp-a-strict', raw)

    lenient.assertBodyContains({ authenticated: true, audience: null })
    strict.assertBodyContains({ authenticated: false })
  })

  test('accepts bound tokens on guards requiring an audience', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ resource: MCP_A })

    const response = await callGuard(client, '/mcp-a-strict', raw)

    response.assertBodyContains({ authenticated: true })
  })
})

test.group('HTTP | Resource indicators — guards on unregistered resources', (group) => {
  const ctx = setupHttpGroup(group, undefined, {
    setupRoutes(router, manager) {
      manager.registerProtectedResource({ resource: '/mcp-a' })
      registerGuardRoute({
        router,
        manager,
        path: '/legacy-mcp',
        guard: { resource: '/legacy-mcp' },
      })
      ctx.manager = manager
    },
  }) as ReturnType<typeof setupHttpGroup> & { manager: SesameManager }

  test('accepts tokens the authorization server issued for the guard path', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const resource = ctx.manager.resolveResource('https://auth.example.com/legacy-mcp')
    assert.equal(resource, 'https://auth.example.com')
    const { raw } = await createTestAccessToken({ resource })

    const response = await client.get(`${ctx.baseUrl}/legacy-mcp`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({ authenticated: true, audience: 'https://auth.example.com' })
  })

  test('rejects tokens bound to another registered resource', async ({ client }) => {
    await createTestClient()
    const { raw } = await createTestAccessToken({ resource: MCP_A })

    const response = await client.get(`${ctx.baseUrl}/legacy-mcp`).bearerToken(raw)

    response.assertStatus(200)
    response.assertBodyContains({ authenticated: false })
  })
})

test.group('OAuthGuard | Resource indicators — unregistered resource warning', (group) => {
  setupIntegrationGroup(group)

  /**
   * Build a guard whose request context logs into `logs`.
   */
  function buildGuard(options: {
    manager: SesameManager
    logs: string[]
    token: string
    resource: string
  }) {
    const request = new RequestFactory().merge({ url: '/' }).create()
    request.request.headers.authorization = `Bearer ${options.token}`
    const logger = new LoggerFactory().pushLogsTo(options.logs).merge({ enabled: true }).create()
    const ctx = new HttpContextFactory().merge({ request, logger }).create()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])

    return new OAuthGuard('mcp', ctx, createFakeEmitter(), provider, options.manager, {
      resource: options.resource,
    })
  }

  test('warns once when the guard resource is not registered', async ({ assert }) => {
    const manager = createManager()
    const logs: string[] = []
    await createTestClient()
    const { raw } = await createTestAccessToken({ resource: 'https://auth.example.com' })

    assert.isTrue(await buildGuard({ manager, logs, token: raw, resource: '/legacy-mcp' }).check())
    assert.isTrue(await buildGuard({ manager, logs, token: raw, resource: '/legacy-mcp' }).check())

    const warnings = logs.map((log) => JSON.parse(log)).filter((log) => log.level === 40)
    assert.lengthOf(warnings, 1)
    assert.equal(warnings[0].resource, '/legacy-mcp')
    assert.equal(warnings[0].audience, 'https://auth.example.com')
    assert.include(warnings[0].msg, 'registerProtectedResource')
  })

  test('does not warn for registered resources', async ({ assert }) => {
    const manager = new SesameManager(createTestConfig(), { get: () => {} } as any, lucidStore())
    manager.registerProtectedResource({ resource: '/mcp-a' })
    const logs: string[] = []
    await createTestClient()
    const { raw } = await createTestAccessToken({ resource: MCP_A })

    assert.isTrue(await buildGuard({ manager, logs, token: raw, resource: '/mcp-a' }).check())

    assert.lengthOf(logs, 0)
  })
})

test.group('OAuthGuard | Resource indicators — test helpers', (group) => {
  setupIntegrationGroup(group)

  test('binds loginAs tokens to the guard resource', async ({ assert }) => {
    const manager = new SesameManager(createTestConfig(), { get: () => {} } as any, lucidStore())
    manager.registerProtectedResource({ resource: '/mcp-a' })
    const ctx = new HttpContextFactory()
      .merge({ request: new RequestFactory().merge({ url: '/' }).create() })
      .create()
    const provider = new FakeUserProvider([{ id: 'user-1', name: 'Test User' }])
    const guard = new OAuthGuard('mcp', ctx, createFakeEmitter(), provider, manager, {
      resource: '/mcp-a',
      requireAudience: true,
    })

    await guard.authenticateAsClient({ id: 'user-1', name: 'Test User' })

    const token = await OAuthAccessToken.query().where('clientId', '__test_client__').firstOrFail()
    assert.equal(token.resource, MCP_A)
  })
})
