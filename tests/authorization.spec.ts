import { test } from '@japa/runner'
import { createHash } from 'node:crypto'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { mockCtx } from './helpers/mock_ctx.ts'
import { createTestClient, createTestAuthCode } from './helpers/create_test_client.ts'
import { createPkce } from './helpers/create_pkce.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { createAuthCodeExchange } from './helpers/create_auth_code_exchange.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'
import { TokenService } from '../src/services/token_service.ts'
import { ClientService } from '../src/services/client_service.ts'
import { ExchangeAuthorizationCodeAction } from '../src/actions/exchange_authorization_code.ts'
import AuthorizeController from '../src/controllers/authorize_controller.ts'
import ConsentController from '../src/controllers/consent_controller.ts'
import { DateTime } from 'luxon'

test.group('Integration | Authorization Flow', (group) => {
  setupIntegrationGroup(group)

  test('stores an authorization request server-side and consumes it during consent', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const { codeChallenge } = createPkce('consent-verifier')

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'opaque-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    const authorizeResult = (await authorizeController.handle(authorizeCtx)) as any
    const consentUrl = new URL(authorizeResult.redirectUrl, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    assert.isString(authToken)
    assert.isNotNull(authToken)

    const consentCtx = mockCtx({
      manager,
      body: {
        accept: true,
        auth_token: authToken,
      },
      auth: { user: { id: 'user-1' } },
    })

    const consentResult = (await consentController.handle(consentCtx)) as any
    const redirectUrl = new URL(consentResult.redirectUrl)
    const authCode = redirectUrl.searchParams.get('code')

    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'https://app.example.com/callback')
    assert.equal(redirectUrl.searchParams.get('state'), 'opaque-state')
    assert.isString(authCode)
    assert.isNotNull(await OAuthAuthorizationCode.query().where('clientId', 'test-client').first())
  })

  test('ignores forged OAuth parameters on consent and uses the stored request instead', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    await createTestClient({
      clientId: 'attacker-client',
      name: 'Attacker Client',
      redirectUris: ['https://attacker.example.com/callback'],
      rawClientSecret: 'attacker-secret',
    })

    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const { codeChallenge: legitCodeChallenge } = createPkce('legit-verifier')

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'legit-state',
        code_challenge: legitCodeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    const authorizeResult = (await authorizeController.handle(authorizeCtx)) as any
    const consentUrl = new URL(authorizeResult.redirectUrl, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentCtx = mockCtx({
      manager,
      body: {
        accept: true,
        auth_token: authToken,
        client_id: 'attacker-client',
        redirect_uri: 'https://attacker.example.com/callback',
        scope: 'write offline_access',
        state: 'attacker-state',
        code_challenge: createHash('sha256').update('attacker-verifier').digest('base64url'),
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    const consentResult = (await consentController.handle(consentCtx)) as any
    const redirectUrl = new URL(consentResult.redirectUrl)

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

  test('rejects confidential client without PKCE (OAuth 2.1)', async ({ assert }) => {
    await createTestClient({ requirePkce: false, isPublic: false })
    const controller = new AuthorizeController()

    const ctx = mockCtx({
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'some-state',
      },
      auth: { user: { id: 'user-1' } },
    })

    const result = (await controller.handle(ctx)) as any
    const url = new URL(result.redirectUrl)
    assert.equal(url.searchParams.get('error'), 'invalid_request')
    assert.include(url.searchParams.get('error_description'), 'code_challenge')
  })

  test('includes iss parameter in error redirects (RFC 9207)', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const controller = new AuthorizeController()

    // Missing code_challenge → redirectWithError
    const ctx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'some-state',
      },
      auth: { user: { id: 'user-1' } },
    })

    const result = (await controller.handle(ctx)) as any
    const url = new URL(result.redirectUrl)
    assert.equal(url.searchParams.get('error'), 'invalid_request')
    assert.equal(url.searchParams.get('iss'), 'https://auth.example.com')
  })

  test('rejects openid when JWK is configured without an OIDC provider', async ({ assert }) => {
    const manager = createManager({ jwk: { kty: 'RSA' } })
    await createTestClient({ scopes: ['read', 'openid'] })
    const controller = new AuthorizeController()
    const { codeChallenge } = createPkce('oidc-provider-required')

    const ctx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid read',
        state: 'oidc-misconfigured',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    const result = (await controller.handle(ctx)) as any
    const url = new URL(result.redirectUrl)

    assert.equal(url.searchParams.get('error'), 'invalid_scope')
    assert.include(url.searchParams.get('error_description'), 'set jwk and oidcProvider')
  })

  test('includes iss parameter when user denies consent (RFC 9207)', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const authMock = { user: { id: 'user-1' }, check: async () => {} }
    const { codeChallenge } = createPkce('deny-verifier')

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'denied-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: authMock,
    })

    const authorizeResult = (await authorizeController.handle(authorizeCtx)) as any
    const consentUrl = new URL(authorizeResult.redirectUrl, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentCtx = mockCtx({
      manager,
      body: {
        accept: false,
        auth_token: authToken,
      },
      auth: authMock,
    })

    const consentResult = (await consentController.handle(consentCtx)) as any
    const redirectUrl = new URL(consentResult.redirectUrl)
    assert.equal(redirectUrl.searchParams.get('error'), 'access_denied')
    assert.equal(redirectUrl.searchParams.get('state'), 'denied-state')
    assert.equal(redirectUrl.searchParams.get('iss'), 'https://auth.example.com')
  })

  test('pending authorization request is single-use (replay protection)', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const { codeChallenge } = createPkce('replay-verifier')

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    const authorizeResult = (await authorizeController.handle(authorizeCtx)) as any
    const consentUrl = new URL(authorizeResult.redirectUrl, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    // First consent — should succeed
    const consentCtx1 = mockCtx({
      manager,
      body: { accept: true, auth_token: authToken },
      auth: { user: { id: 'user-1' } },
    })
    const result1 = (await consentController.handle(consentCtx1)) as any
    assert.include(result1.redirectUrl, 'code=')

    // Second consent with same auth_token — should fail
    const consentCtx2 = mockCtx({
      manager,
      body: { accept: true, auth_token: authToken },
      auth: { user: { id: 'user-1' } },
    })
    await assert.rejects(
      () => consentController.handle(consentCtx2),
      'Authorization request not found or expired'
    )
  })

  test('rejects expired pending authorization request', async ({ assert }) => {
    const manager = createManager({ authorizationRequestTtl: '1s' })
    await createTestClient()
    const consentController = new ConsentController()
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

    const ctx = mockCtx({
      manager,
      body: { accept: true, auth_token: rawToken },
      auth: { user: { id: 'user-1' } },
    })

    await assert.rejects(
      () => consentController.handle(ctx),
      'Authorization request not found or expired'
    )
  })

  test('rejects cross-user auth_token consumption', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const { codeChallenge } = createPkce('cross-user-verifier')

    // User 1 initiates the authorize flow
    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    const authorizeResult = (await authorizeController.handle(authorizeCtx)) as any
    const consentUrl = new URL(authorizeResult.redirectUrl, 'https://auth.example.com')
    const authToken = consentUrl.searchParams.get('auth_token')

    // User 2 tries to consume user-1's auth_token
    const consentCtx = mockCtx({
      manager,
      body: { accept: true, auth_token: authToken },
      auth: { user: { id: 'user-2' } },
    })

    await assert.rejects(
      () => consentController.handle(consentCtx),
      'Authorization request not found or expired'
    )

    // Original user-1 can still consume the token
    const consentCtx1 = mockCtx({
      manager,
      body: { accept: true, auth_token: authToken },
      auth: { user: { id: 'user-1' } },
    })
    const result = (await consentController.handle(consentCtx1)) as any
    assert.include(result.redirectUrl, 'code=')
  })

  test('pending request is cleaned up after deny', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()
    const { codeChallenge } = createPkce('deny-cleanup-verifier')

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    await authorizeController.handle(authorizeCtx)
    const pendingBefore = await OAuthPendingAuthorizationRequest.query()
    assert.lengthOf(pendingBefore, 1)

    const consentUrl = new URL(
      (
        (await authorizeController.handle(
          mockCtx({
            manager,
            query: authorizeCtx.request.qs(),
            auth: { user: { id: 'user-1' } },
          })
        )) as any
      ).redirectUrl,
      'https://auth.example.com'
    )
    const authToken = consentUrl.searchParams.get('auth_token')

    const consentCtx = mockCtx({
      manager,
      body: { accept: false, auth_token: authToken },
      auth: { user: { id: 'user-1' } },
    })
    const result = (await consentController.handle(consentCtx)) as any
    assert.include(result.redirectUrl, 'error=access_denied')

    // Pending request should be consumed even on deny
    const pendingAfter = await OAuthPendingAuthorizationRequest.query().where(
      'token',
      new TokenService(manager).hashToken(authToken!)
    )
    assert.lengthOf(pendingAfter, 0)
  })

  test('skips consent and issues code directly when all scopes already consented', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    const { codeChallenge } = createPkce('skip-consent-verifier')

    // Pre-create consent for 'read' scope
    await OAuthConsent.create({
      id: crypto.randomUUID(),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
    })

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'skip-consent-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
      auth: { user: { id: 'user-1' } },
    })

    const result = (await new AuthorizeController().handle(authorizeCtx)) as any
    const redirectUrl = new URL(result.redirectUrl)

    // Should redirect directly with a code, not to consent page
    assert.isNotNull(redirectUrl.searchParams.get('code'))
    assert.equal(redirectUrl.searchParams.get('state'), 'skip-consent-state')
    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'https://app.example.com/callback')

    // No pending request should be created
    const pending = await OAuthPendingAuthorizationRequest.query()
    assert.lengthOf(pending, 0)
  })
})

test.group('Integration | Authorization Code Grant', (group) => {
  setupIntegrationGroup(group)

  test('exchanges authorization code for tokens', async ({ assert }) => {
    await createTestClient()
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['read', 'write'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.isDefined(result.access_token)
    assert.equal(result.token_type, 'Bearer')
    assert.equal(result.expires_in, 3600)
    assert.equal(result.scope, 'read write')
    assert.isDefined(result.refresh_token)
  })

  test('issues refresh token with offline_access scope', async ({ assert }) => {
    await createTestClient()
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['read', 'offline_access'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.include(result.scope, 'offline_access')
  })

  test('offline_access is accepted even when not in server or client configured scopes', async ({
    assert,
  }) => {
    const manager = createManager({ scopes: { read: 'Read access' } })
    await createTestClient({ scopes: ['read'] })
    const { client, rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      scopes: ['read', 'offline_access'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.include(result.scope, 'offline_access')
  })

  test('issues refresh token even without offline_access when refresh_token grant is enabled', async ({
    assert,
  }) => {
    const manager = createManager({ scopes: { read: 'Read access' } })
    await createTestClient({ scopes: ['read'] })
    const { client, rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      scopes: ['read'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
  })

  test('does not issue refresh token when refresh_token grant is disabled', async ({ assert }) => {
    const manager = createManager({
      scopes: { read: 'Read access' },
      grantTypes: ['authorization_code'],
    })
    await createTestClient({ scopes: ['read'], grantTypes: ['authorization_code'] })
    const { client, rawCode, codeVerifier, redirectUri } = await createAuthCodeExchange({
      manager,
      scopes: ['read'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    assert.isDefined(result.access_token)
    assert.isUndefined(result.refresh_token)
  })

  test('rejects expired authorization code', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    const client = await createTestClient()
    const rawCode = 'expired-code'
    const { codeVerifier, codeChallenge } = createPkce()

    await OAuthAuthorizationCode.create({
      id: crypto.randomUUID(),
      code: tokenService.hashToken(rawCode),
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      codeChallenge,
      codeChallengeMethod: 'S256',
      expiresAt: DateTime.now().minus({ minutes: 5 }),
    })

    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri: 'https://app.example.com/callback',
          codeVerifier,
        }),
      'Authorization code has expired'
    )
  })

  test('rejects invalid PKCE verifier', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const rawCode = 'pkce-test-code'
    const { codeChallenge } = createPkce('correct-verifier')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri: 'https://app.example.com/callback',
          codeVerifier: 'wrong-verifier-value-that-is-long-enough-for-rfc7636',
        }),
      'PKCE verification failed'
    )
  })

  test('consumes authorization code on failed PKCE so it cannot be retried', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const rawCode = 'pkce-retry-code'
    const { codeVerifier, codeChallenge } = createPkce()

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    // First attempt with wrong verifier — should fail but consume the code
    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri: 'https://app.example.com/callback',
          codeVerifier: 'wrong-verifier-value-that-is-long-enough-for-rfc7636',
        }),
      'PKCE verification failed'
    )

    // Second attempt with correct verifier — code is already consumed
    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri: 'https://app.example.com/callback',
          codeVerifier,
        }),
      'Authorization code not found'
    )
  })

  test('rejects invalid client secret', async ({ assert }) => {
    await createTestClient()
    const rawCode = 'secret-test-code'

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
    })

    const clientService = new ClientService()
    await assertOAuthError(
      assert,
      () =>
        clientService.authenticateClient({
          authorizationHeader: undefined,
          bodyClientId: 'test-client',
          bodyClientSecret: 'wrong-secret',
        }),
      'invalid_client'
    )
  })

  test('rejects authorization code exchange when granted scopes exceed client scopes', async ({
    assert,
  }) => {
    await createTestClient({ scopes: ['read'] })
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['write'],
    })

    await assertOAuthError(
      assert,
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri,
          codeVerifier,
        }),
      'invalid_scope'
    )
  })

  test('authorization code is single-use', async ({ assert }) => {
    await createTestClient()
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['read'],
    })

    const result = await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })
    assert.isDefined(result.access_token)

    await assert.rejects(
      () =>
        new ExchangeAuthorizationCodeAction().execute(manager, {
          client,
          code: rawCode,
          redirectUri,
          codeVerifier,
        }),
      'Authorization code not found'
    )
  })

  test('rejects concurrent reuse of the same authorization code', async ({ assert }) => {
    await createTestClient()
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['read'],
    })

    const action = new ExchangeAuthorizationCodeAction()
    const input = { client, code: rawCode, redirectUri, codeVerifier }

    const results = await Promise.allSettled([
      action.execute(manager, input),
      action.execute(manager, input),
    ])

    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
    assert.equal(results.filter((result) => result.status === 'rejected').length, 1)
  })

  test('creates access token record in database', async ({ assert }) => {
    await createTestClient()
    const { client, rawCode, codeVerifier, redirectUri, manager } = await createAuthCodeExchange({
      scopes: ['read'],
    })

    await new ExchangeAuthorizationCodeAction().execute(manager, {
      client,
      code: rawCode,
      redirectUri,
      codeVerifier,
    })

    const tokens = await OAuthAccessToken.query().where('clientId', 'test-client')
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].userId, 'user-1')
    assert.deepEqual(tokens[0].scopes, ['read'])
  })
})
