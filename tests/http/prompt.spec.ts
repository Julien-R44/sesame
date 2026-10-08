import { test } from '@japa/runner'
import type { ApiClient } from '@japa/api-client'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createPkce } from '../helpers/create_pkce.ts'
import { createTestGrant } from '../helpers/create_test_grant.ts'
import { OAuthPendingAuthorizationRequest } from '../../src/models/oauth_pending_authorization_request.ts'

const { codeChallenge } = createPkce('prompt-verifier')

/**
 * Options for an authorization request sent with a `prompt` value.
 */
interface AuthorizeWithPromptOptions {
  client: ApiClient
  baseUrl: string
  prompt: string
  userId?: string
  redirectUri?: string
}

/**
 * Send an authorization request with the given prompt and return
 * the parsed redirect location.
 */
async function authorizeWithPrompt(options: AuthorizeWithPromptOptions) {
  const request = options.client
    .get(`${options.baseUrl}/oauth/authorize`)
    .qs({
      client_id: 'test-client',
      response_type: 'code',
      redirect_uri: options.redirectUri ?? 'https://app.example.com/callback',
      scope: 'read',
      state: 'prompt-state',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      prompt: options.prompt,
    })
    .redirects(0)

  if (options.userId) request.header('X-Test-User-Id', options.userId)

  const response = await request
  const location = response.header('location')

  return { response, url: location ? new URL(location, 'https://auth.example.com') : null }
}

/**
 * Store a consent covering the `read` scope for user-1.
 */
async function grantReadConsent() {
  await createTestGrant({
    id: crypto.randomUUID(),
    clientId: 'test-client',
    userId: 'user-1',
    scopes: ['read'],
  })
}

test.group('HTTP | Authorization prompt parameter', (group) => {
  const ctx = setupHttpGroup(group)

  test('prompt=none returns login_required when the user is not authenticated', async ({
    client,
    assert,
  }) => {
    await createTestClient()

    const { response, url } = await authorizeWithPrompt({
      client,
      baseUrl: ctx.baseUrl,
      prompt: 'none',
    })

    response.assertStatus(302)
    assert.equal(url!.origin + url!.pathname, 'https://app.example.com/callback')
    assert.equal(url!.searchParams.get('error'), 'login_required')
    assert.equal(url!.searchParams.get('state'), 'prompt-state')
    assert.equal(url!.searchParams.get('iss'), 'https://auth.example.com')
  })

  test('prompt=none returns consent_required without creating a pending request', async ({
    client,
    assert,
  }) => {
    await createTestClient()

    const { url } = await authorizeWithPrompt({
      client,
      baseUrl: ctx.baseUrl,
      prompt: 'none',
      userId: 'user-1',
    })

    assert.equal(url!.origin + url!.pathname, 'https://app.example.com/callback')
    assert.equal(url!.searchParams.get('error'), 'consent_required')
    assert.equal(url!.searchParams.get('state'), 'prompt-state')
    assert.lengthOf(await OAuthPendingAuthorizationRequest.all(), 0)
  })

  test('prompt=none issues a code when stored consent covers the scopes', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    await grantReadConsent()

    const { url } = await authorizeWithPrompt({
      client,
      baseUrl: ctx.baseUrl,
      prompt: 'none',
      userId: 'user-1',
    })

    assert.equal(url!.origin + url!.pathname, 'https://app.example.com/callback')
    assert.isString(url!.searchParams.get('code'))
  })

  test('prompt=none cannot be combined with other values', async ({ client, assert }) => {
    await createTestClient()

    const { url } = await authorizeWithPrompt({
      client,
      baseUrl: ctx.baseUrl,
      prompt: 'none consent',
      userId: 'user-1',
    })

    assert.equal(url!.origin + url!.pathname, 'https://app.example.com/callback')
    assert.equal(url!.searchParams.get('error'), 'invalid_request')
  })

  test('prompt=none never redirects to an unregistered redirect_uri', async ({ client }) => {
    await createTestClient()

    const { response } = await authorizeWithPrompt({
      client,
      baseUrl: ctx.baseUrl,
      prompt: 'none',
      redirectUri: 'https://attacker.example.com/callback',
    })

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_request' })
  })

  test('prompt=consent shows the consent page even when consent is stored', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    await grantReadConsent()

    const { url } = await authorizeWithPrompt({
      client,
      baseUrl: ctx.baseUrl,
      prompt: 'consent',
      userId: 'user-1',
    })

    assert.equal(url!.pathname, '/oauth/consent')
    assert.isString(url!.searchParams.get('auth_token'))
    assert.equal(url!.searchParams.get('prompt'), 'consent')
    assert.lengthOf(await OAuthPendingAuthorizationRequest.all(), 1)
  })

  test('ignores unsupported prompt values', async ({ client, assert }) => {
    await createTestClient()
    await grantReadConsent()

    const { url } = await authorizeWithPrompt({
      client,
      baseUrl: ctx.baseUrl,
      prompt: 'login select_account',
      userId: 'user-1',
    })

    assert.equal(url!.origin + url!.pathname, 'https://app.example.com/callback')
    assert.isString(url!.searchParams.get('code'))
  })

  test('advertises supported prompt values', async ({ client }) => {
    const response = await client.get(`${ctx.baseUrl}/.well-known/oauth-authorization-server`)

    response.assertStatus(200)
    response.assertBodyContains({ prompt_values_supported: ['none', 'consent'] })
  })
})
