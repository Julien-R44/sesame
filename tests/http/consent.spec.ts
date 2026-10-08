import { test } from '@japa/runner'
import type { ApiClient } from '@japa/api-client'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createPkce } from '../helpers/create_pkce.ts'
import { OAuthGrant } from '../../src/models/oauth_grant.ts'
import { OAuthPendingAuthorizationRequest } from '../../src/models/oauth_pending_authorization_request.ts'

const pkce = createPkce('consent-subset-verifier')

/**
 * Start an authorization request as user-1 and return the raw auth token.
 */
async function startAuthorization(options: { client: ApiClient; baseUrl: string; scope: string }) {
  const response = await options.client
    .get(`${options.baseUrl}/oauth/authorize`)
    .qs({
      client_id: 'test-client',
      response_type: 'code',
      redirect_uri: 'https://app.example.com/callback',
      scope: options.scope,
      state: 'subset-state',
      code_challenge: pkce.codeChallenge,
      code_challenge_method: 'S256',
    })
    .header('X-Test-User-Id', 'user-1')
    .redirects(0)

  const consentUrl = new URL(response.header('location')!, 'https://auth.example.com')

  return consentUrl.searchParams.get('auth_token')!
}

test.group('HTTP | Consent submission', (group) => {
  const ctx = setupHttpGroup(group)

  test('grants a space-delimited subset and returns the reduced scope from the token endpoint', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const authToken = await startAuthorization({
      client,
      baseUrl: ctx.baseUrl,
      scope: 'read write',
    })

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken, scope: 'read' })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)
    const redirectUrl = new URL(consentResponse.header('location')!)
    assert.equal(redirectUrl.searchParams.get('state'), 'subset-state')

    const tokenResponse = await client.post(`${ctx.baseUrl}/oauth/token`).form({
      grant_type: 'authorization_code',
      client_id: 'test-client',
      client_secret: 'test-secret',
      code: redirectUrl.searchParams.get('code'),
      redirect_uri: 'https://app.example.com/callback',
      code_verifier: pkce.codeVerifier,
    })

    tokenResponse.assertStatus(200)
    assert.equal(tokenResponse.body().scope, 'read')

    const consent = await OAuthGrant.query().firstOrFail()
    assert.deepEqual(consent.scopes, ['read'])
  })

  test('deduplicates requested scopes', async ({ client, assert }) => {
    await createTestClient()
    await startAuthorization({ client, baseUrl: ctx.baseUrl, scope: 'read read' })

    const pending = await OAuthPendingAuthorizationRequest.query().firstOrFail()
    assert.deepEqual(pending.scopes, ['read'])
  })

  test('accepts the granted scopes as an array', async ({ client, assert }) => {
    await createTestClient()
    const authToken = await startAuthorization({
      client,
      baseUrl: ctx.baseUrl,
      scope: 'read write offline_access',
    })

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .form({ accept: 'on', auth_token: authToken, scope: ['read', 'offline_access'] })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)

    const consent = await OAuthGrant.query().firstOrFail()
    assert.deepEqual(consent.scopes, ['read', 'offline_access'])
  })

  test('rejects scopes that were not requested and keeps the request pending', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const authToken = await startAuthorization({ client, baseUrl: ctx.baseUrl, scope: 'read' })

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken, scope: 'read write' })
      .header('X-Test-User-Id', 'user-1')

    consentResponse.assertStatus(400)
    consentResponse.assertBodyContains({ error: 'invalid_scope' })
    assert.lengthOf(await OAuthPendingAuthorizationRequest.all(), 1)
  })

  test('rejects a non-string scope field', async ({ client }) => {
    await createTestClient()
    const authToken = await startAuthorization({ client, baseUrl: ctx.baseUrl, scope: 'read' })

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken, scope: { read: true } })
      .header('X-Test-User-Id', 'user-1')

    consentResponse.assertStatus(400)
    consentResponse.assertBodyContains({ error: 'invalid_request' })
  })
})
