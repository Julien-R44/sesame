import { test } from '@japa/runner'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { setupHttpGroup } from '../helpers/app.ts'

test.group('HTTP | Dynamic Registration', (group) => {
  const ctx = setupHttpGroup(group)

  test('POST /oauth/register creates a confidential client', async ({ client, assert }) => {
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

  test('POST /oauth/register creates a public client', async ({ client, assert }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://app.example.com/callback'],
      token_endpoint_auth_method: 'none',
    })

    response.assertStatus(201)
    response.assertBodyContains({ client_name: 'Unnamed Client' })

    assert.isDefined(response.body().client_id)
    assert.isUndefined(response.body().client_secret)
  })

  test('POST /oauth/register rejects invalid body', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({})

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })

  test('POST /oauth/register rejects unknown scopes', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://app.example.com/callback'],
      token_endpoint_auth_method: 'none',
      scope: 'admin superuser',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_scope' })
  })

  test('POST /oauth/register rejects client_name longer than 255 chars', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://app.example.com/callback'],
      token_endpoint_auth_method: 'none',
      client_name: 'A'.repeat(256),
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_client_metadata' })
  })
})
