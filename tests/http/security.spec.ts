import { test } from '@japa/runner'
import { setupHttpGroup } from '../helpers/app.ts'
import { createPkce } from '../helpers/create_pkce.ts'
import { OAuthClient } from '../../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../../src/models/oauth_access_token.ts'
import { createTestGrant } from '../helpers/create_test_grant.ts'
import { ClientService } from '../../src/services/client_service.ts'

test.group('HTTP | Security | Scope validation bypass (C1+C2)', (group) => {
  const ctx = setupHttpGroup(group, { scopes: {}, defaultScopes: [] })

  test('authorize rejects arbitrary scopes with empty configs', async ({ client, assert }) => {
    const { codeChallenge } = createPkce('a'.repeat(43))

    const clientService = new ClientService()
    await OAuthClient.create({
      id: crypto.randomUUID(),
      clientId: 'bypass-client',
      clientSecret: clientService.hashSecret('secret'),
      name: 'Bypass Client',
      redirectUris: ['https://evil.example.com/callback'],
      scopes: [],
      grantTypes: ['authorization_code'],
      isPublic: false,
      isDisabled: false,
      requirePkce: true,
      type: 'confidential',
      metadata: null,
      userId: null,
    })

    await createTestGrant({
      id: crypto.randomUUID(),
      clientId: 'bypass-client',
      userId: 'user-1',
      scopes: ['admin', 'superuser'],
    })

    const response = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'bypass-client',
        response_type: 'code',
        redirect_uri: 'https://evil.example.com/callback',
        scope: 'admin superuser',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    response.assertStatus(302)
    const location = response.header('location')
    assert.include(location, 'error=invalid_scope')

    const authCodes = await OAuthAuthorizationCode.query()
      .where('clientId', 'bypass-client')
      .where('userId', 'user-1')
    assert.lengthOf(authCodes, 0)
  })

  test('dynamic registration → authorize rejects arbitrary scopes', async ({ client, assert }) => {
    const { codeChallenge } = createPkce('b'.repeat(43))

    // Step 1: Register a public client (no scopes → gets defaultScopes = [])
    const registerResponse = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://attacker.example.com/callback'],
      token_endpoint_auth_method: 'none',
    })

    registerResponse.assertStatus(201)
    const clientId = registerResponse.body().client_id

    // Step 2: Authorize with arbitrary scopes — should be rejected
    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: clientId,
        response_type: 'code',
        redirect_uri: 'https://attacker.example.com/callback',
        scope: 'admin superuser',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const location = authorizeResponse.header('location')
    assert.include(location, 'error=invalid_scope')
    assert.include(location, 'admin')

    const authCodes = await OAuthAuthorizationCode.query().where('userId', 'user-1')
    assert.lengthOf(authCodes, 0)
    const accessTokens = await OAuthAccessToken.query().where('userId', 'user-1')
    assert.lengthOf(accessTokens, 0)
  })
})

test.group('HTTP | Security | Registration validation (B5)', (group) => {
  const ctx = setupHttpGroup(group)

  test('trims client_name whitespace', async ({ client }) => {
    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://app.example.com/callback'],
      token_endpoint_auth_method: 'none',
      client_name: '  My App  ',
    })

    response.assertStatus(201)
    response.assertBodyContains({ client_name: 'My App' })
  })

  test('accepts client_name at exactly 255 characters', async ({ client }) => {
    const name = 'A'.repeat(255)

    const response = await client.post(`${ctx.baseUrl}/oauth/register`).json({
      redirect_uris: ['https://app.example.com/callback'],
      token_endpoint_auth_method: 'none',
      client_name: name,
    })

    response.assertStatus(201)
    response.assertBodyContains({ client_name: name })
  })
})
