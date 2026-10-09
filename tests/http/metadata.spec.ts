import { test } from '@japa/runner'
import { setupHttpGroup } from '../helpers/app.ts'
import { getTestJwk, FakeUserProvider } from '../helpers/fakes.ts'

const jwk = await getTestJwk()

test.group('HTTP | Metadata Endpoints', (group) => {
  const ctx = setupHttpGroup(group)

  test('GET /.well-known/oauth-authorization-server returns metadata', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    response.assertStatus(200)
    response.assertBodyContains({
      issuer: 'https://auth.example.com',
      authorization_endpoint: 'https://auth.example.com/oauth/authorize',
      token_endpoint: 'https://auth.example.com/oauth/token',
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      authorization_response_iss_parameter_supported: true,
    })
  })

  test('GET /.well-known/oauth-protected-resource returns resource metadata', async ({
    client,
  }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-protected-resource`)

    response.assertStatus(200)
    response.assertBodyContains({
      resource: 'https://auth.example.com',
      authorization_servers: ['https://auth.example.com'],
      bearer_methods_supported: ['header'],
    })
  })

  test('advertises the configured and built-in scopes', async ({ client, assert }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    response.assertStatus(200)
    assert.sameMembers(response.body().scopes_supported, [
      'read',
      'write',
      'openid',
      'offline_access',
    ])
  })

  test('advertises none auth method for all endpoints', async ({ client, assert }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    response.assertStatus(200)
    const body = response.body()
    for (const methods of [
      body.token_endpoint_auth_methods_supported,
      body.introspection_endpoint_auth_methods_supported,
      body.revocation_endpoint_auth_methods_supported,
    ])
      assert.include(methods, 'none')
  })

  test('GET /jwks returns 404 when no key configured', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/jwks`)

    response.assertStatus(404)
  })
})

test.group('HTTP | Metadata — protected resource with minimal scopes', (group) => {
  const ctx = setupHttpGroup(group, { scopes: { 'mcp:full': 'Full MCP access' } })

  test('includes offline_access even with minimal scopes', async ({ client, assert }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-protected-resource`)

    response.assertStatus(200)
    const body = response.body()
    assert.include(body.scopes_supported, 'mcp:full')
    assert.include(body.scopes_supported, 'offline_access')
  })
})

test.group('HTTP | Metadata — OIDC configured', (group) => {
  const ctx = setupHttpGroup(group, { jwk, oidcProvider: new FakeUserProvider([]) })

  test('returns OIDC metadata', async ({ client, assert }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/openid-configuration`)

    response.assertStatus(200)
    const body = response.body()
    assert.equal(body.issuer, 'https://auth.example.com')
    assert.deepEqual(body.subject_types_supported, ['public'])
    assert.include(body.scopes_supported, 'offline_access')
  })

  test('advertises the same scopes in both discovery documents', async ({ client, assert }) => {
    const oidc = await client.get(`${ctx.baseUrl}/.well-known/openid-configuration`)
    const authServer = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    assert.deepEqual(authServer.body().scopes_supported, oidc.body().scopes_supported)
    assert.includeMembers(authServer.body().scopes_supported, ['openid', 'profile', 'email'])
  })
})

test.group('HTTP | Metadata — registration disabled', (group) => {
  const ctx = setupHttpGroup(group, { allowDynamicRegistration: false })

  test('hides registration endpoint when disabled', async ({ client, assert }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    response.assertStatus(200)
    assert.isUndefined(response.body().registration_endpoint)
  })
})

test.group('HTTP | Metadata — custom route prefix', (group) => {
  const ctx = setupHttpGroup(group, undefined, { routePrefix: '/auth' })

  test('uses router-generated URLs with custom prefix', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    response.assertStatus(200)
    response.assertBodyContains({
      authorization_endpoint: 'https://auth.example.com/auth/authorize',
      token_endpoint: 'https://auth.example.com/auth/token',
      introspection_endpoint: 'https://auth.example.com/auth/introspect',
      revocation_endpoint: 'https://auth.example.com/auth/revoke',
    })
  })
})

test.group('HTTP | Metadata — missing OAuth routes', (group) => {
  const ctx = setupHttpGroup(group, undefined, {
    skipOAuthRoutes: true,
  })

  test('returns 500 when OAuth routes are not registered', async ({ client }) => {
    const response = await client
      .get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)
      .header('accept', 'application/json')

    response.assertStatus(500)
    response.assertBodyContains({ error: 'server_error' })
  })
})
