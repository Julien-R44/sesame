import { test } from '@japa/runner'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'

test.group('HTTP | Dynamic Registration', (group) => {
  const ctx = setupHttpGroup(group)

  test('registers a confidential client', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'My MCP Client',
      redirect_uris: ['https://mcp-client.example.com/callback'],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    })

    response.assertStatus(201)
    response.assertHeader('cache-control', 'no-store')
    response.assertBodyContains({
      client_name: 'My MCP Client',
      redirect_uris: ['https://mcp-client.example.com/callback'],
      client_secret_expires_at: 0,
    })

    const body = response.body()
    assert.isDefined(body.client_id)
    assert.isDefined(body.client_secret)

    const record = await OAuthClient.query().where('clientId', body.client_id).firstOrFail()
    assert.equal(record.name, 'My MCP Client')
    assert.notOk(record.isPublic)
  })

  test('registers a public client', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Public MCP Client',
      redirect_uris: ['https://mcp-client.example.com/callback'],
      token_endpoint_auth_method: 'none',
    })

    response.assertStatus(201)
    response.assertBodyContains({ token_endpoint_auth_method: 'none' })

    const body = response.body()
    assert.isDefined(body.client_id)
    assert.isUndefined(body.client_secret)

    const record = await OAuthClient.query().where('clientId', body.client_id).firstOrFail()
    assert.ok(record.isPublic)
  })

  test('returns all registered metadata (RFC 7591 §3.2.1)', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Full Metadata Client',
      redirect_uris: ['https://example.com/callback'],
      token_endpoint_auth_method: 'none',
      client_uri: 'https://example.com',
      logo_uri: 'https://example.com/logo.png',
      contacts: ['admin@example.com'],
      tos_uri: 'https://example.com/tos',
      policy_uri: 'https://example.com/privacy',
      software_id: 'my-app',
      software_version: '1.0.0',
    })

    response.assertStatus(201)
    response.assertBodyContains({
      client_uri: 'https://example.com',
      logo_uri: 'https://example.com/logo.png',
      contacts: ['admin@example.com'],
      tos_uri: 'https://example.com/tos',
      policy_uri: 'https://example.com/privacy',
      software_id: 'my-app',
      software_version: '1.0.0',
    })
  })

  test('rejects invalid redirect URIs', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['not-a-valid-url'],
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('rejects missing redirect URIs', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('rejects javascript: scheme', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['javascript:alert(1)'],
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('rejects data: scheme', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['data:text/html,<script>'],
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('rejects HTTP for non-localhost hosts', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['http://evil.com/callback'],
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('rejects fragments in redirect URI', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb#frag'],
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('accepts HTTP localhost', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Localhost App',
      redirect_uris: ['http://localhost:3000/callback'],
    })

    response.assertStatus(201)

    const record = await OAuthClient.query()
      .where('clientId', response.body().client_id)
      .firstOrFail()
    assert.equal(record.name, 'Localhost App')
  })

  test('accepts HTTPS', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'HTTPS App',
      redirect_uris: ['https://example.com/callback'],
    })

    response.assertStatus(201)

    const record = await OAuthClient.query()
      .where('clientId', response.body().client_id)
      .firstOrFail()
    assert.equal(record.name, 'HTTPS App')
  })

  test('accepts custom scheme for native apps', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Native App',
      redirect_uris: ['com.example.app:/callback'],
    })

    response.assertStatus(201)

    const record = await OAuthClient.query()
      .where('clientId', response.body().client_id)
      .firstOrFail()
    assert.equal(record.name, 'Native App')
  })

  test('rejects javascript: scheme in client_uri', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      client_uri: 'javascript:alert(1)',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('rejects data: scheme in logo_uri', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      logo_uri: 'data:image/png;base64,abc',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('accepts client_uri with different host than redirect_uris', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      client_uri: 'https://other-domain.com/about',
    })

    response.assertStatus(201)
    response.assertBodyContains({ client_uri: 'https://other-domain.com/about' })
  })

  test('accepts CLI client with localhost redirect and external client_uri', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'OpenCode',
      redirect_uris: ['http://127.0.0.1:19876/mcp/oauth/callback'],
      client_uri: 'https://opencode.ai',
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    })

    response.assertStatus(201)
    response.assertBodyContains({ client_uri: 'https://opencode.ai' })
  })

  test('rejects invalid contact email', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      contacts: ['not-an-email'],
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('accepts valid contacts', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      contacts: ['admin@example.com', 'support@example.com'],
    })

    response.assertStatus(201)
    assert.isDefined(response.body().client_id)
  })

  test('ignores unknown metadata fields instead of rejecting', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      some_future_field: 'value',
      another_unknown: ['a', 'b'],
    })

    response.assertStatus(201)
    assert.isDefined(response.body().client_id)
  })

  test('accepts registration without optional metadata', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://example.com/cb'],
    })

    response.assertStatus(201)
    response.assertBodyContains({ client_name: 'Unnamed Client' })
  })

  test('rejects unknown scopes', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      scope: 'read unknown_scope',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_scope' })
  })

  test('accepts valid scopes', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      scope: 'read write',
    })

    response.assertStatus(201)
    response.assertBodyContains({ scope: 'read write' })
  })

  test('rejects client_name longer than 255 chars', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://app.example.com/callback'],
      token_endpoint_auth_method: 'none',
      client_name: 'A'.repeat(256),
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })
})

test.group('HTTP | Registration — disabled', (group) => {
  const ctx = setupHttpGroup(group, { allowDynamicRegistration: false })

  test('rejects registration when disabled', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
    })

    response.assertStatus(403)
    response.assertBodyContains({ error: 'access_denied' })
  })
})

test.group('HTTP | Registration — empty scopes config', (group) => {
  const ctx = setupHttpGroup(group, { scopes: {}, defaultScopes: [] })

  test('rejects unknown scopes when config.scopes is empty', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
      scope: 'anything custom_scope',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_scope' })
  })

  test('accepts empty scopes when config.scopes is empty', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'Test',
      redirect_uris: ['https://example.com/cb'],
    })

    response.assertStatus(201)
    response.assertBodyContains({ scope: '' })
  })
})

test.group('HTTP | Registration — OIDC scope validation', (group) => {
  const ctx = setupHttpGroup(group, { scopes: { read: 'Read access' } })

  test('rejects profile/email without openid', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      client_name: 'OIDC claims only client',
      redirect_uris: ['https://example.com/cb'],
      scope: 'profile email',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_scope' })
  })
})

test.group('HTTP | Client Info', (group) => {
  const ctx = setupHttpGroup(group)

  test('returns public info for a valid client', async ({ client }) => {
    const record = await createTestClient({ name: 'Claude Code' })

    const response = await client.get(`${ctx.baseUrl}/oauth/client-info`).qs({
      client_id: record.clientId,
    })

    response.assertStatus(200)
    response.assertBodyContains({ client_id: record.clientId, client_name: 'Claude Code' })
  })

  test('rejects missing client_id', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/oauth/client-info`)

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_request' })
  })

  test('rejects unknown client', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/oauth/client-info`).qs({
      client_id: 'non-existent',
    })

    response.assertStatus(401)
    response.assertBodyContains({ error: 'invalid_client' })
  })

  test('does not expose client_secret', async ({ client, assert }) => {
    const record = await createTestClient()

    const response = await client.get(`${ctx.baseUrl}/oauth/client-info`).qs({
      client_id: record.clientId,
    })

    response.assertStatus(200)
    assert.notProperty(response.body(), 'client_secret')
    assert.notProperty(response.body(), 'clientSecret')
  })
})
