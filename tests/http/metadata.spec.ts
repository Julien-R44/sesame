import { test } from '@japa/runner'
import { setupHttpGroup } from '../helpers/app.ts'

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

  test('GET /jwks returns 404 when no key configured', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/jwks`)

    response.assertStatus(404)
  })
})
