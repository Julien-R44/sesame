import { test } from '@japa/runner'
import { DateTime } from 'luxon'
import { createManager, setupIntegrationGroup } from './helpers/app.ts'
import { createTestClient } from './helpers/create_test_client.ts'
import { assertOAuthError } from './helpers/assert_oauth_error.ts'
import { TokenService } from '../src/services/token_service.ts'
import type { SesameManager } from '../src/sesame_manager.ts'
import { OAuthAuthorizationCode } from '../src/models/oauth_authorization_code.ts'
import { OAuthConsent } from '../src/models/oauth_consent.ts'
import { OAuthPendingAuthorizationRequest } from '../src/models/oauth_pending_authorization_request.ts'

/**
 * Store a pending authorization request and return its raw auth token.
 */
async function createPendingRequest(manager: SesameManager, scopes: string[]) {
  const authToken = `auth-token-${crypto.randomUUID()}`
  await manager.store.createPendingAuthorizationRequest({
    id: crypto.randomUUID(),
    token: new TokenService(manager).hashToken(authToken),
    clientId: 'test-client',
    userId: 'user-1',
    redirectUri: 'https://app.example.com/callback',
    scopes,
    state: 'opaque-state',
    codeChallenge: 'challenge',
    codeChallengeMethod: 'S256',
    expiresAt: DateTime.now().plus({ minutes: 5 }),
  })

  return authToken
}

test.group('Integration | Approve and deny authorization', (group) => {
  setupIntegrationGroup(group)

  test('approves every requested scope by default', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read', 'write'])

    const decision = await manager.approveAuthorization({ authToken, userId: 'user-1' })

    const url = new URL(decision.redirectUrl)
    assert.equal(url.origin + url.pathname, 'https://app.example.com/callback')
    assert.isString(url.searchParams.get('code'))
    assert.equal(url.searchParams.get('state'), 'opaque-state')
    assert.equal(url.searchParams.get('iss'), 'https://auth.example.com')
    assert.equal(decision.clientId, 'test-client')
    assert.deepEqual(decision.scopes, ['read', 'write'])

    const code = await OAuthAuthorizationCode.query().firstOrFail()
    assert.deepEqual(code.scopes, ['read', 'write'])
    assert.equal(code.codeChallenge, 'challenge')
    assert.lengthOf(await OAuthPendingAuthorizationRequest.all(), 0)
  })

  test('grants a subset of the requested scopes', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read', 'write'])

    const decision = await manager.approveAuthorization({
      authToken,
      userId: 'user-1',
      scopes: ['read', 'read'],
    })

    assert.deepEqual(decision.scopes, ['read'])

    const code = await OAuthAuthorizationCode.query().firstOrFail()
    assert.deepEqual(code.scopes, ['read'])

    const consent = await OAuthConsent.query().firstOrFail()
    assert.deepEqual(consent.scopes, ['read'])
  })

  test('rejects scopes that were not requested without consuming the request', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read'])

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-1', scopes: ['write'] }),
      'invalid_scope',
      'Scopes were not requested: write'
    )

    assert.lengthOf(await OAuthPendingAuthorizationRequest.all(), 1)
    assert.lengthOf(await OAuthAuthorizationCode.all(), 0)

    const decision = await manager.approveAuthorization({ authToken, userId: 'user-1' })
    assert.deepEqual(decision.scopes, ['read'])
  })

  test('rejects an empty scope list and points to denyAuthorization', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read'])

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-1', scopes: [] }),
      'invalid_scope',
      'denyAuthorization()'
    )
  })

  test('rejects OIDC scopes granted without openid', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['openid', 'profile'])

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-1', scopes: ['profile'] }),
      'invalid_scope',
      'require the openid scope'
    )
  })

  test('rejects unknown, foreign and already consumed requests', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read'])

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken: 'unknown', userId: 'user-1' }),
      'invalid_grant'
    )
    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-2' }),
      'invalid_grant'
    )

    await manager.approveAuthorization({ authToken, userId: 'user-1' })

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-1' }),
      'invalid_grant'
    )
    await assertOAuthError(
      assert,
      () => manager.denyAuthorization({ authToken, userId: 'user-1' }),
      'invalid_grant'
    )
  })

  test('rejects approval for a disabled client', async ({ assert }) => {
    const manager = createManager()
    await createTestClient({ isDisabled: true })
    const authToken = await createPendingRequest(manager, ['read'])

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-1' }),
      'invalid_client',
      'Client is disabled'
    )
    assert.lengthOf(await OAuthAuthorizationCode.all(), 0)
  })

  test('denies a request and leaves existing consent untouched', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    await manager.store.grantConsent({
      clientId: 'test-client',
      userId: 'user-1',
      scopes: ['read'],
    })
    const authToken = await createPendingRequest(manager, ['read', 'write'])

    const decision = await manager.denyAuthorization({ authToken, userId: 'user-1' })

    const url = new URL(decision.redirectUrl)
    assert.equal(url.origin + url.pathname, 'https://app.example.com/callback')
    assert.equal(url.searchParams.get('error'), 'access_denied')
    assert.equal(url.searchParams.get('state'), 'opaque-state')
    assert.equal(url.searchParams.get('iss'), 'https://auth.example.com')
    assert.deepEqual(decision, {
      redirectUrl: decision.redirectUrl,
      clientId: 'test-client',
      scopes: [],
    })

    assert.lengthOf(await OAuthPendingAuthorizationRequest.all(), 0)
    assert.lengthOf(await OAuthAuthorizationCode.all(), 0)

    const consent = await OAuthConsent.query().firstOrFail()
    assert.deepEqual(consent.scopes, ['read'])
  })
})
