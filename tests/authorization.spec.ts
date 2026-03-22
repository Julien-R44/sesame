import { test } from '@japa/runner'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient, createTestAuthCode } from './helpers/create_test_client.ts'
import { createPkce } from './helpers/create_pkce.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { createAuthCodeExchange } from './helpers/create_auth_code_exchange.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthAccessToken } from '../src/models/oauth_access_token.ts'
import { TokenService } from '../src/services/token_service.ts'
import { ClientService } from '../src/services/client_service.ts'
import { ExchangeAuthorizationCodeAction } from '../src/actions/exchange_authorization_code.ts'
import { DateTime } from 'luxon'

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
