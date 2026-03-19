import { test } from '@japa/runner'
import { createHash } from 'node:crypto'
import type { ApplicationService } from '@adonisjs/core/types'
import {
  createApp,
  setupDatabase,
  teardownDatabase,
  createManager,
  createTestClient,
  createTestAuthCode,
  mockCtx,
} from './helpers.ts'
import { OAuthClient } from '../src/models/oauth_client.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { OAuthRefreshToken } from '../src/models/oauth_refresh_token.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'
import { TokenService } from '../src/services/token_service.ts'
import { handleAuthorizationCodeGrant } from '../src/grants/authorization_code_grant.ts'
import AuthorizeController from '../src/controllers/authorize_controller.ts'
import ConsentController from '../src/controllers/consent_controller.ts'
import { OAuthError } from '../src/oauth_error.ts'
import { DateTime } from 'luxon'

let app: ApplicationService

test.group('Integration | Authorization Flow', (group) => {
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthPendingAuthorizationRequest.query().delete()
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('stores an authorization request server-side and consumes it during consent', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    const authorizeController = new AuthorizeController()
    const consentController = new ConsentController()

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'opaque-state',
        code_challenge: createHash('sha256').update('consent-verifier').digest('base64url'),
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
    const legitCodeChallenge = createHash('sha256').update('legit-verifier').digest('base64url')

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

    const ctx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid read',
        state: 'oidc-misconfigured',
        code_challenge: createHash('sha256').update('oidc-provider-required').digest('base64url'),
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

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        state: 'denied-state',
        code_challenge: createHash('sha256').update('deny-verifier').digest('base64url'),
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

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: createHash('sha256').update('replay-verifier').digest('base64url'),
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

    // User 1 initiates the authorize flow
    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: createHash('sha256').update('cross-user-verifier').digest('base64url'),
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

    const authorizeCtx = mockCtx({
      manager,
      query: {
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'read',
        code_challenge: createHash('sha256').update('deny-cleanup-verifier').digest('base64url'),
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
        code_challenge: createHash('sha256').update('skip-consent-verifier').digest('base64url'),
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
  group.setup(async () => {
    app = await createApp()
    await setupDatabase(app)
  })

  group.teardown(async () => {
    await teardownDatabase(app)
    await app.terminate()
  })

  group.each.setup(async () => {
    await OAuthPendingAuthorizationRequest.query().delete()
    await OAuthRefreshToken.query().delete()
    await OAuthAccessToken.query().delete()
    await OAuthAuthorizationCode.query().delete()
    await OAuthConsent.query().delete()
    await OAuthClient.query().delete()
  })

  test('exchanges authorization code for tokens', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const rawCode = 'test-auth-code-123'

    const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read', 'write'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    const result = await handleAuthorizationCodeGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.equal(result.token_type, 'Bearer')
    assert.equal(result.expires_in, 3600)
    assert.equal(result.scope, 'read write')
    assert.isDefined(result.refresh_token)
  })

  test('issues refresh token with offline_access scope', async ({ assert }) => {
    const manager = createManager()
    const client = await createTestClient()
    const rawCode = 'test-code-with-refresh'
    const codeVerifier = 'another-verifier-value-for-testing-pkce-rfc7636-ok'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read', 'offline_access'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    const result = await handleAuthorizationCodeGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.include(result.scope, 'offline_access')
  })

  test('offline_access is accepted even when not in server or client configured scopes', async ({
    assert,
  }) => {
    const manager = createManager({ scopes: { read: 'Read access' } })
    const client = await createTestClient({ scopes: ['read'] })
    const rawCode = 'offline-builtin-code'
    const codeVerifier = 'offline-builtin-verifier-testing-rfc7636-format-ok'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read', 'offline_access'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: client.clientId,
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    const result = await handleAuthorizationCodeGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
    assert.include(result.scope, 'offline_access')
  })

  test('issues refresh token even without offline_access when refresh_token grant is enabled', async ({
    assert,
  }) => {
    const manager = createManager({ scopes: { read: 'Read access' } })
    const client = await createTestClient({ scopes: ['read'] })
    const rawCode = 'no-offline-access-code'
    const codeVerifier = 'no-offline-access-verifier-testing-rfc7636-format-ok'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: client.clientId,
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    const result = await handleAuthorizationCodeGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.isDefined(result.refresh_token)
  })

  test('does not issue refresh token when refresh_token grant is disabled', async ({
    assert,
  }) => {
    const manager = createManager({
      scopes: { read: 'Read access' },
      grantTypes: ['authorization_code'],
    })
    const client = await createTestClient({
      scopes: ['read'],
      grantTypes: ['authorization_code'],
    })
    const rawCode = 'no-refresh-grant-code'
    const codeVerifier = 'no-refresh-grant-verifier-testing-rfc7636-format-ok'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: client.clientId,
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    const result = await handleAuthorizationCodeGrant(ctx, manager)

    assert.isDefined(result.access_token)
    assert.isUndefined(result.refresh_token)
  })

  test('rejects expired authorization code', async ({ assert }) => {
    const manager = createManager()
    const tokenService = new TokenService(manager)
    await createTestClient()
    const rawCode = 'expired-code'
    const codeVerifier = 'verifier-for-expired-code-testing-rfc7636-compliant'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

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

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    await assert.rejects(
      () => handleAuthorizationCodeGrant(ctx, manager),
      'Authorization code has expired'
    )
  })

  test('rejects invalid PKCE verifier', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'pkce-test-code'
    const codeChallenge = createHash('sha256').update('correct-verifier').digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: 'wrong-verifier-value-that-is-long-enough-for-rfc7636',
      },
    })

    await assert.rejects(
      () => handleAuthorizationCodeGrant(ctx, manager),
      'PKCE verification failed'
    )
  })

  test('consumes authorization code on failed PKCE so it cannot be retried', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'pkce-retry-code'
    const codeVerifier = 'correct-verifier-for-retry-testing-rfc7636-compliant'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

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
    const ctx1 = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: 'wrong-verifier-value-that-is-long-enough-for-rfc7636',
      },
    })
    await assert.rejects(
      () => handleAuthorizationCodeGrant(ctx1, manager),
      'PKCE verification failed'
    )

    // Second attempt with correct verifier — code is already consumed
    const ctx2 = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })
    await assert.rejects(
      () => handleAuthorizationCodeGrant(ctx2, manager),
      'Authorization code not found'
    )
  })

  test('rejects invalid client secret', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'secret-test-code'

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'wrong-secret',
      },
    })

    await assert.rejects(
      () => handleAuthorizationCodeGrant(ctx, manager),
      'Client authentication failed'
    )
  })

  test('rejects authorization code exchange when granted scopes exceed client scopes', async ({
    assert,
  }) => {
    const manager = createManager()
    const client = await createTestClient({ scopes: ['read'] })
    const rawCode = 'client-scope-bypass'
    const codeVerifier = 'client-scope-verifier-testing-rfc7636-format-compliant'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: client.clientId,
      userId: 'user-1',
      scopes: ['write'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: client.clientId,
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    try {
      await handleAuthorizationCodeGrant(ctx, manager)
      assert.fail('Should have thrown')
    } catch (error: any) {
      assert.instanceOf(error, OAuthError)
      assert.equal(error.oauthCode, 'invalid_scope')
    }
  })

  test('authorization code is single-use', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'single-use-code'
    const codeVerifier = 'single-use-verifier-testing-rfc7636-format-compliant'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const makeCtx = () =>
      mockCtx({
        manager,
        body: {
          grant_type: 'authorization_code',
          code: rawCode,
          redirect_uri: 'https://app.example.com/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
          code_verifier: codeVerifier,
        },
      })

    const result = await handleAuthorizationCodeGrant(makeCtx(), manager)
    assert.isDefined(result.access_token)

    await assert.rejects(
      () => handleAuthorizationCodeGrant(makeCtx(), manager),
      'Authorization code not found'
    )
  })

  test('rejects concurrent reuse of the same authorization code', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'racy-auth-code'
    const codeVerifier = 'racy-auth-code-verifier-testing-rfc7636-format-ok'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const makeCtx = () =>
      mockCtx({
        manager,
        body: {
          grant_type: 'authorization_code',
          code: rawCode,
          redirect_uri: 'https://app.example.com/callback',
          client_id: 'test-client',
          client_secret: 'test-secret',
          code_verifier: codeVerifier,
        },
      })

    const results = await Promise.allSettled([
      handleAuthorizationCodeGrant(makeCtx(), manager),
      handleAuthorizationCodeGrant(makeCtx(), manager),
    ])

    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
    assert.equal(results.filter((result) => result.status === 'rejected').length, 1)
  })

  test('creates access token record in database', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const rawCode = 'db-token-code'
    const codeVerifier = 'db-token-verifier-testing-rfc7636-format-compliant'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    await createTestAuthCode({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
      redirectUri: 'https://app.example.com/callback',
      rawCode,
      codeChallenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockCtx({
      manager,
      body: {
        grant_type: 'authorization_code',
        code: rawCode,
        redirect_uri: 'https://app.example.com/callback',
        client_id: 'test-client',
        client_secret: 'test-secret',
        code_verifier: codeVerifier,
      },
    })

    await handleAuthorizationCodeGrant(ctx, manager)

    const tokens = await OAuthAccessToken.query().where('clientId', 'test-client')
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].userId, 'user-1')
    assert.deepEqual(tokens[0].scopes, ['read'])
  })
})
