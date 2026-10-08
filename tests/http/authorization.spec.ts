import { test } from '@japa/runner'
import { createHash } from 'node:crypto'
import { setupHttpGroup } from '../helpers/app.ts'
import { createTestClient } from '../helpers/create_test_client.ts'
import { createPkce } from '../helpers/create_pkce.ts'
import { OAuthAuthorizationCode } from '../../src/models/oauth_authorization_code.ts'
import { createTestGrant } from '../helpers/create_test_grant.ts'
import { OAuthPendingAuthorizationRequest } from '../../src/models/oauth_pending_authorization_request.ts'
import { TokenService } from '../../src/services/token_service.ts'
import { createManager } from '../helpers/app.ts'
import { DateTime } from 'luxon'

test.group('HTTP | Authorization Flow', (group) => {
  const ctx = setupHttpGroup(group)

  test('stores an authorization request server-side and consumes it during consent', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const { codeChallenge } = createPkce('consent-verifier')

    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'opaque-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    assert.isString(authToken)
    assert.isNotNull(authToken)

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)
    const redirectUrl = new URL(consentResponse.header('location')!)
    const authCode = redirectUrl.searchParams.get('code')

    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'https://app.example.com/callback')
    assert.equal(redirectUrl.searchParams.get('state'), 'opaque-state')
    assert.isString(authCode)
    assert.isNotNull(await OAuthAuthorizationCode.query().where('clientId', 'test-client').first())
  })

  test('ignores forged OAuth parameters on consent and uses the stored request instead', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    await createTestClient({
      clientId: 'attacker-client',
      name: 'Attacker Client',
      redirectUris: ['https://attacker.example.com/callback'],
      rawClientSecret: 'attacker-secret',
    })

    const { codeChallenge: legitCodeChallenge } = createPkce('legit-verifier')

    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'legit-state',
        code_challenge: legitCodeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({
        accept: true,
        auth_token: authToken,
        client_id: 'attacker-client',
        redirect_uri: 'https://attacker.example.com/callback',
        state: 'attacker-state',
        code_challenge: createHash('sha256').update('attacker-verifier').digest('base64url'),
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)
    const redirectUrl = new URL(consentResponse.header('location')!)

    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'https://app.example.com/callback')
    assert.equal(redirectUrl.searchParams.get('state'), 'legit-state')
    assert.notEqual(
      redirectUrl.origin + redirectUrl.pathname,
      'https://attacker.example.com/callback'
    )

    const storedCode = await OAuthAuthorizationCode.query()
      .where('clientId', 'test-client')
      .firstOrFail()
    assert.equal(storedCode.redirectUri, 'https://app.example.com/callback')
    assert.deepEqual(storedCode.scopes, ['read'])
    assert.equal(storedCode.codeChallenge, legitCodeChallenge)
    assert.equal(storedCode.codeChallengeMethod, 'S256')

    const attackerCode = await OAuthAuthorizationCode.query()
      .where('clientId', 'attacker-client')
      .first()
    assert.isNull(attackerCode)
  })

  test('rejects confidential client without PKCE (OAuth 2.1)', async ({ client, assert }) => {
    await createTestClient({ requirePkce: false, isPublic: false })

    const response = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'some-state',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    response.assertStatus(302)
    const url = new URL(response.header('location')!)
    assert.equal(url.searchParams.get('error'), 'invalid_request')
    assert.include(url.searchParams.get('error_description')!, 'code_challenge')
  })

  test('includes iss parameter in error redirects (RFC 9207)', async ({ client, assert }) => {
    await createTestClient()

    const response = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'some-state',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    response.assertStatus(302)
    const url = new URL(response.header('location')!)
    assert.equal(url.searchParams.get('error'), 'invalid_request')
    assert.equal(url.searchParams.get('iss'), 'https://auth.example.com')
  })

  test('includes iss parameter when user denies consent (RFC 9207)', async ({ client, assert }) => {
    await createTestClient()
    const { codeChallenge } = createPkce('deny-verifier')

    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'denied-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: false, auth_token: authToken })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)
    const redirectUrl = new URL(consentResponse.header('location')!)
    assert.equal(redirectUrl.searchParams.get('error'), 'access_denied')
    assert.equal(redirectUrl.searchParams.get('state'), 'denied-state')
    assert.equal(redirectUrl.searchParams.get('iss'), 'https://auth.example.com')
  })

  test('pending authorization request is single-use (replay protection)', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const { codeChallenge } = createPkce('replay-verifier')

    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    // First consent — should succeed
    const consentResponse1 = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse1.assertStatus(302)
    assert.include(consentResponse1.header('location'), 'code=')

    // Second consent with same auth_token — should fail
    const consentResponse2 = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken })
      .header('X-Test-User-Id', 'user-1')

    consentResponse2.assertStatus(400)
    consentResponse2.assertBodyContains({ error: 'invalid_grant' })
  })

  test('rejects expired pending authorization request', async ({ client }) => {
    await createTestClient()
    const manager = createManager({ authorizationRequestTtl: '1s' })
    const tokenService = new TokenService(manager)

    const rawToken = tokenService.generateOpaqueToken()
    await OAuthPendingAuthorizationRequest.create({
      id: crypto.randomUUID(),
      token: tokenService.hashToken(rawToken),
      userId: 'user-1',
      clientId: 'test-client',
      redirectUri: 'https://app.example.com/callback',
      scopes: ['read'],
      state: null,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: DateTime.now().minus({ minutes: 1 }),
    })

    const response = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: rawToken })
      .header('X-Test-User-Id', 'user-1')

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_grant' })
  })

  test('rejects cross-user auth_token consumption', async ({ client, assert }) => {
    await createTestClient()
    const { codeChallenge } = createPkce('cross-user-verifier')

    // User 1 initiates the authorize flow
    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    // User 2 tries to consume user-1's auth_token
    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken })
      .header('X-Test-User-Id', 'user-2')

    consentResponse.assertStatus(400)
    consentResponse.assertBodyContains({ error: 'invalid_grant' })

    // Original user-1 can still consume the token
    const consentResponse1 = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse1.assertStatus(302)
    assert.include(consentResponse1.header('location'), 'code=')
  })

  test('pending request is cleaned up after deny', async ({ client, assert }) => {
    await createTestClient()
    const { codeChallenge } = createPkce('deny-cleanup-verifier')

    const qs = {
      client_id: 'test-client',
      response_type: 'code',
      redirect_uri: 'https://app.example.com/callback',
      scope: 'read',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    }

    // First authorize to create a pending request
    await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs(qs)
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    const pendingBefore = await OAuthPendingAuthorizationRequest.query()
    assert.lengthOf(pendingBefore, 1)

    // Second authorize to get a fresh auth_token
    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs(qs)
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: false, auth_token: authToken })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)
    assert.include(consentResponse.header('location'), 'error=access_denied')

    // Pending request should be consumed even on deny
    const manager = createManager()
    const pendingAfter = await OAuthPendingAuthorizationRequest.query().where(
      'token',
      new TokenService(manager).hashToken(authToken!)
    )
    assert.lengthOf(pendingAfter, 0)
  })

  test('skips consent and issues code directly when all scopes already consented', async ({
    client,
    assert,
  }) => {
    await createTestClient()
    const { codeChallenge } = createPkce('skip-consent-verifier')

    // Pre-create consent for 'read' scope
    await createTestGrant({
      id: crypto.randomUUID(),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
    })

    const response = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'skip-consent-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    response.assertStatus(302)
    const redirectUrl = new URL(response.header('location')!)

    // Should redirect directly with a code, not to consent page
    assert.isNotNull(redirectUrl.searchParams.get('code'))
    assert.equal(redirectUrl.searchParams.get('state'), 'skip-consent-state')
    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'https://app.example.com/callback')

    // No pending request should be created
    const pending = await OAuthPendingAuthorizationRequest.query()
    assert.lengthOf(pending, 0)
  })
  test('accepts any port for a registered loopback redirect URI (RFC 8252 §7.3)', async ({
    client,
    assert,
  }) => {
    await createTestClient({
      clientSecret: null,
      isPublic: true,
      type: 'public',
      redirectUris: ['http://127.0.0.1/callback'],
    })
    const { codeChallenge } = createPkce('loopback-verifier')

    const authorizeResponse = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'http://127.0.0.1:51234/callback',
        scope: 'read',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    authorizeResponse.assertStatus(302)
    const consentUrl = new URL(authorizeResponse.header('location')!, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentResponse = await client
      .post(`${ctx.baseUrl}/oauth/consent`)
      .json({ accept: true, auth_token: authToken })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    consentResponse.assertStatus(302)
    const redirectUrl = new URL(consentResponse.header('location')!)
    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'http://127.0.0.1:51234/callback')
    assert.isString(redirectUrl.searchParams.get('code'))
  })

  test('rejects a loopback redirect URI with a different path', async ({ client }) => {
    await createTestClient({ redirectUris: ['http://127.0.0.1/callback'] })
    const { codeChallenge } = createPkce('loopback-verifier')

    const response = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'http://127.0.0.1:51234/other',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    response.assertStatus(400)
    response.assertBodyContains({ error: 'invalid_request' })
  })
})

test.group('HTTP | Authorization Flow (openid)', (group) => {
  const ctx = setupHttpGroup(group, {
    jwk: { kty: 'RSA' },
    scopes: { read: 'Read access', profile: 'Profile', email: 'Email' },
  })

  test('explains that configured profile/email scopes still require openid', async ({
    client,
    assert,
  }) => {
    await createTestClient({ scopes: ['read', 'profile', 'email'] })

    const response = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read profile email unknown',
        state: 'scope-error-state',
      })
      .redirects(0)

    response.assertStatus(302)
    const url = new URL(response.header('location')!)

    assert.equal(url.origin + url.pathname, 'https://app.example.com/callback')
    assert.equal(url.searchParams.get('state'), 'scope-error-state')
    assert.equal(url.searchParams.get('error'), 'invalid_scope')
    assert.equal(
      url.searchParams.get('error_description'),
      'Invalid scopes: profile, email, unknown. OIDC scopes (profile, email) require the openid scope'
    )
  })

  test('rejects openid when JWK is configured without an OIDC provider', async ({
    client,
    assert,
  }) => {
    await createTestClient({ scopes: ['read', 'openid'] })
    const { codeChallenge } = createPkce('oidc-provider-required')

    const response = await client
      .get(`${ctx.baseUrl}/oauth/authorize`)
      .qs({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid read',
        state: 'oidc-misconfigured',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      .header('X-Test-User-Id', 'user-1')
      .redirects(0)

    response.assertStatus(302)
    const url = new URL(response.header('location')!)

    assert.equal(url.searchParams.get('error'), 'invalid_scope')
    assert.include(url.searchParams.get('error_description')!, 'set jwk and oidcProvider')
  })
})
