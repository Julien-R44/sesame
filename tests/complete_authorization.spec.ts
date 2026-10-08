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

  test('rejects an explicit empty list even when no scope was requested', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, [])

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-1', scopes: [] }),
      'invalid_scope',
      'denyAuthorization()'
    )
    assert.lengthOf(await OAuthAuthorizationCode.all(), 0)

    const decision = await manager.approveAuthorization({ authToken, userId: 'user-1' })
    assert.deepEqual(decision.scopes, [])
  })

  test('deduplicates requested scopes granted by default', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read', 'read'])

    const decision = await manager.approveAuthorization({ authToken, userId: 'user-1' })

    assert.deepEqual(decision.scopes, ['read'])
    const code = await OAuthAuthorizationCode.query().firstOrFail()
    assert.deepEqual(code.scopes, ['read'])
  })

  test('revalidates requested scopes granted by default against the current config', async ({
    assert,
  }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read', 'removed'])

    await assertOAuthError(
      assert,
      () => manager.approveAuthorization({ authToken, userId: 'user-1' }),
      'invalid_scope',
      'removed'
    )
    assert.lengthOf(await OAuthPendingAuthorizationRequest.all(), 1)
    assert.lengthOf(await OAuthAuthorizationCode.all(), 0)
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

  test('lets only one of two concurrent approvals succeed', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read'])
    const options = { authToken, userId: 'user-1' }

    const results = await Promise.allSettled([
      manager.approveAuthorization(options),
      manager.approveAuthorization(options),
    ])

    const rejected = results.filter((result) => result.status === 'rejected')
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1)
    assert.lengthOf(rejected, 1)
    assert.equal(rejected[0].reason.oauthCode, 'invalid_grant')
    assert.lengthOf(await OAuthAuthorizationCode.all(), 1)
  })

  test('lets only one of a concurrent approval and denial succeed', async ({ assert }) => {
    const manager = createManager()
    await createTestClient()
    const authToken = await createPendingRequest(manager, ['read'])
    const options = { authToken, userId: 'user-1' }

    const [approval, denial] = await Promise.allSettled([
      manager.approveAuthorization(options),
      manager.denyAuthorization(options),
    ])

    const rejected = [approval, denial].filter((result) => result.status === 'rejected')
    assert.lengthOf(rejected, 1)
    assert.equal(rejected[0].reason.oauthCode, 'invalid_grant')

    const codes = await OAuthAuthorizationCode.all()
    assert.lengthOf(codes, approval.status === 'fulfilled' ? 1 : 0)
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
